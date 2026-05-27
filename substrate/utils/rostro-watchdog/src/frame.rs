// SPDX-License-Identifier: Apache-2.0

//! Sans-IO frame codec for the watchdog Unix-domain socket protocol.
//!
//! Wire format:
//! ```text
//! frame      = u32 BE body_len || body
//! body       = u8 version || u8 op || op-specific payload
//! ```
//!
//! `body_len` is the length of `body` (version + op + payload), not
//! including the 4-byte length prefix itself.

use thiserror::Error;

pub const FRAME_VERSION: u8 = 1;

/// Cap on `body_len`. 64 KiB is well above any v0.1 payload (signatures
/// are 64 bytes); the cap exists to bound allocation when reading from
/// the socket, not as a protocol-level constraint.
pub const MAX_FRAME_BODY_LEN: usize = 64 * 1024;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Sign = 0x01,
    Heartbeat = 0x02,
    GetPubkey = 0x03,
    SignReply = 0x80,
    HeartbeatReply = 0x81,
    GetPubkeyReply = 0x82,
    Error = 0xFE,
}

impl Op {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x01 => Op::Sign,
            0x02 => Op::Heartbeat,
            0x03 => Op::GetPubkey,
            0x80 => Op::SignReply,
            0x81 => Op::HeartbeatReply,
            0x82 => Op::GetPubkeyReply,
            0xFE => Op::Error,
            _ => return None,
        })
    }
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("incomplete frame (need more bytes)")]
    Incomplete,
    #[error("frame body length {0} exceeds cap")]
    TooLarge(usize),
    #[error("unsupported frame version {0} (expected {FRAME_VERSION})")]
    BadVersion(u8),
    #[error("unknown op code 0x{0:02x}")]
    BadOp(u8),
}

#[derive(Debug, Clone)]
pub struct Frame<'a> {
    pub op: Op,
    pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
    pub fn new(op: Op, payload: &'a [u8]) -> Self {
        Self { op, payload }
    }

    pub fn encoded_len(&self) -> usize {
        4 + 1 + 1 + self.payload.len()
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), FrameError> {
        let body_len = 1 + 1 + self.payload.len();
        if body_len > MAX_FRAME_BODY_LEN {
            return Err(FrameError::TooLarge(body_len));
        }
        out.extend_from_slice(&(body_len as u32).to_be_bytes());
        out.push(FRAME_VERSION);
        out.push(self.op as u8);
        out.extend_from_slice(self.payload);
        Ok(())
    }

    /// Decode the first complete frame from `bytes`. Returns the frame
    /// plus the remaining unconsumed tail so callers can keep parsing a
    /// streaming buffer.
    pub fn decode(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), FrameError> {
        if bytes.len() < 4 {
            return Err(FrameError::Incomplete);
        }
        let body_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if body_len > MAX_FRAME_BODY_LEN {
            return Err(FrameError::TooLarge(body_len));
        }
        // body must hold at least version + op
        if body_len < 2 {
            return Err(FrameError::Incomplete);
        }
        if bytes.len() < 4 + body_len {
            return Err(FrameError::Incomplete);
        }
        let version = bytes[4];
        if version != FRAME_VERSION {
            return Err(FrameError::BadVersion(version));
        }
        let op_byte = bytes[5];
        let op = Op::from_u8(op_byte).ok_or(FrameError::BadOp(op_byte))?;
        let payload = &bytes[6..4 + body_len];
        let rest = &bytes[4 + body_len..];
        Ok((Frame { op, payload }, rest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_empty_payload() {
        let frame = Frame::new(Op::Heartbeat, &[]);
        let mut buf = Vec::new();
        frame.encode_into(&mut buf).unwrap();
        assert_eq!(buf.len(), frame.encoded_len());
        let (decoded, rest) = Frame::decode(&buf).unwrap();
        assert_eq!(decoded.op, Op::Heartbeat);
        assert!(decoded.payload.is_empty());
        assert!(rest.is_empty());
    }

    #[test]
    fn round_trip_with_payload() {
        let payload = b"hello watchdog";
        let frame = Frame::new(Op::Sign, payload);
        let mut buf = Vec::new();
        frame.encode_into(&mut buf).unwrap();
        let (decoded, rest) = Frame::decode(&buf).unwrap();
        assert_eq!(decoded.op, Op::Sign);
        assert_eq!(decoded.payload, payload);
        assert!(rest.is_empty());
    }

    #[test]
    fn two_frames_in_buffer() {
        let mut buf = Vec::new();
        Frame::new(Op::Heartbeat, &[]).encode_into(&mut buf).unwrap();
        Frame::new(Op::GetPubkey, &[]).encode_into(&mut buf).unwrap();
        let (first, rest) = Frame::decode(&buf).unwrap();
        assert_eq!(first.op, Op::Heartbeat);
        let (second, rest2) = Frame::decode(rest).unwrap();
        assert_eq!(second.op, Op::GetPubkey);
        assert!(rest2.is_empty());
    }

    #[test]
    fn truncated_length_prefix_is_incomplete() {
        let err = Frame::decode(&[0, 0]).unwrap_err();
        assert!(matches!(err, FrameError::Incomplete));
    }

    #[test]
    fn truncated_body_is_incomplete() {
        let mut buf = Vec::new();
        Frame::new(Op::Sign, b"abcdef").encode_into(&mut buf).unwrap();
        buf.truncate(buf.len() - 1);
        let err = Frame::decode(&buf).unwrap_err();
        assert!(matches!(err, FrameError::Incomplete));
    }

    #[test]
    fn rejects_oversized_length_prefix() {
        let huge = (MAX_FRAME_BODY_LEN + 1) as u32;
        let mut buf = huge.to_be_bytes().to_vec();
        buf.extend_from_slice(&[FRAME_VERSION, Op::Sign as u8]);
        let err = Frame::decode(&buf).unwrap_err();
        assert!(matches!(err, FrameError::TooLarge(_)));
    }

    #[test]
    fn rejects_oversized_encode() {
        let payload = vec![0u8; MAX_FRAME_BODY_LEN];
        let frame = Frame::new(Op::Sign, &payload);
        let mut buf = Vec::new();
        let err = frame.encode_into(&mut buf).unwrap_err();
        assert!(matches!(err, FrameError::TooLarge(_)));
    }

    #[test]
    fn rejects_wrong_version() {
        let mut buf = Vec::new();
        Frame::new(Op::Heartbeat, &[]).encode_into(&mut buf).unwrap();
        buf[4] = 99;
        let err = Frame::decode(&buf).unwrap_err();
        assert!(matches!(err, FrameError::BadVersion(99)));
    }

    #[test]
    fn rejects_unknown_op() {
        let mut buf = Vec::new();
        Frame::new(Op::Heartbeat, &[]).encode_into(&mut buf).unwrap();
        buf[5] = 0x42;
        let err = Frame::decode(&buf).unwrap_err();
        assert!(matches!(err, FrameError::BadOp(0x42)));
    }

    #[test]
    fn body_len_one_is_incomplete_not_corrupt() {
        // body_len = 1 can't hold version + op (2 bytes minimum)
        let mut buf = 1u32.to_be_bytes().to_vec();
        buf.push(FRAME_VERSION);
        let err = Frame::decode(&buf).unwrap_err();
        assert!(matches!(err, FrameError::Incomplete));
    }
}
