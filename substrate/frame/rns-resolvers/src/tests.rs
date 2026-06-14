//! Behavioral tests for the `CHAT` + `MESSAGE` chat-identity records (Step 2).

use crate::mock::{new_test_ext, RnsResolvers, Test};
use crate::resolvers::{Content, Error, Records};
use frame_support::{assert_noop, assert_ok};
use frame_system::RawOrigin;
use rns_types::ddns::codec_type::RecordType;

const NAME: &[u8] = b"alice";

fn content(bytes: Vec<u8>) -> Content<Test> {
    bytes.try_into().expect("within MaxContentLen")
}

fn node() -> rns_types::DomainHash {
    rns_types::parse_name_to_node(NAME, &rns_types::RST_BASENODE).expect("valid name")
}

#[test]
fn publishes_and_resolves_chat_and_message() {
    new_test_ext().execute_with(|| {
        // CHAT = a 32-byte ed25519 mail address (the addressing key).
        let ed = vec![0x11u8; 32];
        assert_ok!(RnsResolvers::set_record(
            RawOrigin::Signed(1).into(),
            NAME.to_vec(),
            RecordType::CHAT,
            content(ed.clone()),
        ));
        // MESSAGE = opaque curve-tagged content-key bytes (app parses the
        // ContentPublicKey; the chain stores them verbatim).
        let msg = vec![0x01u8, 0xAA, 0xBB, 0xCC];
        assert_ok!(RnsResolvers::set_record(
            RawOrigin::Signed(1).into(),
            NAME.to_vec(),
            RecordType::MESSAGE,
            content(msg.clone()),
        ));

        // Both resolve from chain state under their typed records — no slot guessing.
        assert_eq!(Records::<Test>::get(node(), RecordType::CHAT).to_vec(), ed);
        assert_eq!(Records::<Test>::get(node(), RecordType::MESSAGE).to_vec(), msg);
    });
}

#[test]
fn message_is_opt_out_default_on() {
    // The chain permits a CHAT record with no MESSAGE — that's dead-drop
    // (opt-out). The default-on posture lives in the app's identity setup, not a
    // chain requirement, so CHAT alone must be valid.
    new_test_ext().execute_with(|| {
        assert_ok!(RnsResolvers::set_record(
            RawOrigin::Signed(1).into(),
            NAME.to_vec(),
            RecordType::CHAT,
            content(vec![0x22u8; 32]),
        ));
        assert!(Records::<Test>::get(node(), RecordType::MESSAGE).is_empty());
    });
}

#[test]
fn malformed_chat_key_is_rejected() {
    new_test_ext().execute_with(|| {
        // A CHAT record must be exactly 32 bytes (an ed25519 mail address).
        for bad_len in [0usize, 31, 33, 64] {
            assert_noop!(
                RnsResolvers::set_record(
                    RawOrigin::Signed(1).into(),
                    NAME.to_vec(),
                    RecordType::CHAT,
                    content(vec![0x33u8; bad_len]),
                ),
                Error::<Test>::InvalidChatKey
            );
        }
        // Nothing was written.
        assert!(Records::<Test>::get(node(), RecordType::CHAT).is_empty());
    });
}
