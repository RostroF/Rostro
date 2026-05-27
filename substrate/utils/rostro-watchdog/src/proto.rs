// SPDX-License-Identifier: Apache-2.0

//! Sans-IO protocol dispatch.
//!
//! Decoded request frames are turned into reply frame bytes here; the
//! `server` module is the only thing that touches sockets. This split
//! keeps the dispatch logic unit-testable without spawning sockets.
//!
//! Request payloads:
//!   * `Sign`      — `u8 sign_kind || sign_payload`
//!   * `Heartbeat` — empty
//!   * `GetPubkey` — empty
//!
//! Reply payloads:
//!   * `SignReply`        — 64-byte Ed25519 signature
//!   * `HeartbeatReply`   — `u64` BE counter
//!   * `GetPubkeyReply`   — 32-byte Ed25519 pubkey
//!   * `Error`            — `u8` error code

use crate::frame::{Frame, Op};
use crate::heartbeat::HeartbeatCounter;
use crate::sign_kind::{SignKind, SignKindError};
use crate::signer::{SignerError, WatchdogSigner};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    UnknownSignKind = 0x01,
    InvalidPayload = 0x02,
    SignerInternal = 0x03,
    Malformed = 0x04,
    UnsupportedOp = 0x05,
}

/// Dispatch a decoded request frame; append the reply frame bytes to
/// `out`. Never panics; always produces a single reply frame (either the
/// op-specific reply or an `Error`).
pub fn dispatch(frame: &Frame, signer: &WatchdogSigner, hb: &HeartbeatCounter, out: &mut Vec<u8>) {
    match frame.op {
        Op::Sign => handle_sign(frame.payload, signer, out),
        Op::Heartbeat => handle_heartbeat(hb, out),
        Op::GetPubkey => handle_get_pubkey(signer, out),
        // Reply ops and Error coming in as a request are protocol violations.
        Op::SignReply | Op::HeartbeatReply | Op::GetPubkeyReply | Op::Error => {
            encode_error(ErrorCode::UnsupportedOp, out)
        }
    }
}

fn handle_sign(payload: &[u8], signer: &WatchdogSigner, out: &mut Vec<u8>) {
    if payload.is_empty() {
        return encode_error(ErrorCode::Malformed, out);
    }
    let kind = match SignKind::from_u8(payload[0]) {
        Ok(k) => k,
        Err(_) => return encode_error(ErrorCode::UnknownSignKind, out),
    };
    let sig_payload = &payload[1..];
    match signer.sign_kind(kind, sig_payload) {
        Ok(sig) => {
            Frame::new(Op::SignReply, &sig)
                .encode_into(out)
                .expect("64-byte signature is well under MAX_FRAME_BODY_LEN");
        }
        Err(SignerError::Kind(SignKindError::Unknown(_))) => {
            encode_error(ErrorCode::UnknownSignKind, out)
        }
        Err(SignerError::Kind(_)) => encode_error(ErrorCode::InvalidPayload, out),
        Err(SignerError::SentinelKey) => encode_error(ErrorCode::SignerInternal, out),
    }
}

fn handle_heartbeat(hb: &HeartbeatCounter, out: &mut Vec<u8>) {
    let counter = hb.tick();
    Frame::new(Op::HeartbeatReply, &counter.to_be_bytes())
        .encode_into(out)
        .expect("8-byte heartbeat counter is well under cap");
}

fn handle_get_pubkey(signer: &WatchdogSigner, out: &mut Vec<u8>) {
    let pk = signer.public_key();
    Frame::new(Op::GetPubkeyReply, &pk)
        .encode_into(out)
        .expect("32-byte pubkey is well under cap");
}

fn encode_error(code: ErrorCode, out: &mut Vec<u8>) {
    Frame::new(Op::Error, &[code as u8])
        .encode_into(out)
        .expect("1-byte error code is well under cap");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dispatch_one(frame: Frame, signer: &WatchdogSigner, hb: &HeartbeatCounter) -> Vec<u8> {
        let mut out = Vec::new();
        dispatch(&frame, signer, hb, &mut out);
        out
    }

    #[test]
    fn heartbeat_increments_and_returns_counter() {
        let signer = WatchdogSigner::generate();
        let hb = HeartbeatCounter::new();
        let reply = dispatch_one(Frame::new(Op::Heartbeat, &[]), &signer, &hb);
        let (frame, _) = Frame::decode(&reply).unwrap();
        assert_eq!(frame.op, Op::HeartbeatReply);
        assert_eq!(frame.payload, &1u64.to_be_bytes());
        assert_eq!(hb.current(), 1);

        let reply2 = dispatch_one(Frame::new(Op::Heartbeat, &[]), &signer, &hb);
        let (frame2, _) = Frame::decode(&reply2).unwrap();
        assert_eq!(frame2.payload, &2u64.to_be_bytes());
    }

    #[test]
    fn get_pubkey_returns_correct_bytes() {
        let signer = WatchdogSigner::generate();
        let hb = HeartbeatCounter::new();
        let reply = dispatch_one(Frame::new(Op::GetPubkey, &[]), &signer, &hb);
        let (frame, _) = Frame::decode(&reply).unwrap();
        assert_eq!(frame.op, Op::GetPubkeyReply);
        assert_eq!(frame.payload, &signer.public_key()[..]);
    }

    #[test]
    fn sign_round_trip() {
        let signer = WatchdogSigner::generate();
        let hb = HeartbeatCounter::new();
        let mut payload = vec![SignKind::NoiseHandshake as u8];
        payload.extend_from_slice(b"noise-xx prologue bytes");
        let reply = dispatch_one(Frame::new(Op::Sign, &payload), &signer, &hb);
        let (frame, _) = Frame::decode(&reply).unwrap();
        assert_eq!(frame.op, Op::SignReply);
        assert_eq!(frame.payload.len(), 64);

        let expected = signer
            .sign_kind(SignKind::NoiseHandshake, b"noise-xx prologue bytes")
            .unwrap();
        assert_eq!(frame.payload, &expected[..]);
    }

    #[test]
    fn sign_unknown_kind_returns_error() {
        let signer = WatchdogSigner::generate();
        let hb = HeartbeatCounter::new();
        let reply = dispatch_one(Frame::new(Op::Sign, &[0xFF, 1, 2, 3]), &signer, &hb);
        let (frame, _) = Frame::decode(&reply).unwrap();
        assert_eq!(frame.op, Op::Error);
        assert_eq!(frame.payload, &[ErrorCode::UnknownSignKind as u8]);
    }

    #[test]
    fn sign_empty_payload_returns_malformed() {
        let signer = WatchdogSigner::generate();
        let hb = HeartbeatCounter::new();
        let reply = dispatch_one(Frame::new(Op::Sign, &[]), &signer, &hb);
        let (frame, _) = Frame::decode(&reply).unwrap();
        assert_eq!(frame.op, Op::Error);
        assert_eq!(frame.payload, &[ErrorCode::Malformed as u8]);
    }

    #[test]
    fn sign_oversize_payload_returns_invalid() {
        let signer = WatchdogSigner::generate();
        let hb = HeartbeatCounter::new();
        let mut payload = vec![SignKind::NoiseHandshake as u8];
        payload.extend(std::iter::repeat(0u8).take(257));
        let reply = dispatch_one(Frame::new(Op::Sign, &payload), &signer, &hb);
        let (frame, _) = Frame::decode(&reply).unwrap();
        assert_eq!(frame.op, Op::Error);
        assert_eq!(frame.payload, &[ErrorCode::InvalidPayload as u8]);
    }

    #[test]
    fn reply_op_as_request_returns_unsupported() {
        let signer = WatchdogSigner::generate();
        let hb = HeartbeatCounter::new();
        let reply = dispatch_one(Frame::new(Op::SignReply, &[0u8; 64]), &signer, &hb);
        let (frame, _) = Frame::decode(&reply).unwrap();
        assert_eq!(frame.op, Op::Error);
        assert_eq!(frame.payload, &[ErrorCode::UnsupportedOp as u8]);
    }
}
