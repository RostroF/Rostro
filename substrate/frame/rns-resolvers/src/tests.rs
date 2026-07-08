//! Behavioral tests for the `CHAT` + `MESSAGE` chat-identity records (Step 2)
//! and the `NODE` guard-identity record + GuardNodes index (chat-spend-witness
//! Phase 2a).

use crate::mock::{new_test_ext, RnsResolvers, Test};
use crate::resolvers::{Content, Error, GuardNodes, Records};
use frame_support::{assert_noop, assert_ok};
use frame_system::RawOrigin;
use rns_types::ddns::codec_type::RecordType;

const NAME: &[u8] = b"alice";
const NAME2: &[u8] = b"bob";

fn content(bytes: Vec<u8>) -> Content<Test> {
    bytes.try_into().expect("within MaxContentLen")
}

fn node() -> rns_types::DomainHash {
    rns_types::parse_name_to_node(NAME, &rns_types::RST_BASENODE).expect("valid name")
}

fn node2() -> rns_types::DomainHash {
    rns_types::parse_name_to_node(NAME2, &rns_types::RST_BASENODE).expect("valid name")
}

fn set_node(name: &[u8], key: [u8; 32]) -> frame_support::dispatch::DispatchResult {
    RnsResolvers::set_record(
        RawOrigin::Signed(1).into(),
        name.to_vec(),
        RecordType::NODE,
        content(key.to_vec()),
    )
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

// ───────────────────────── NODE guard-identity record ──────────────────────

#[test]
fn node_record_enrols_into_guard_set() {
    new_test_ext().execute_with(|| {
        let k1 = [0xA1u8; 32];
        assert_ok!(set_node(NAME, k1));
        // The record is stored, the index points key -> name, and guard_set() sees it.
        assert_eq!(Records::<Test>::get(node(), RecordType::NODE).to_vec(), k1.to_vec());
        assert_eq!(GuardNodes::<Test>::get(k1), Some(node()));
        assert_eq!(RnsResolvers::guard_set(), vec![k1]);
    });
}

#[test]
fn node_key_must_be_32_bytes() {
    new_test_ext().execute_with(|| {
        for bad_len in [0usize, 31, 33, 64] {
            assert_noop!(
                RnsResolvers::set_record(
                    RawOrigin::Signed(1).into(),
                    NAME.to_vec(),
                    RecordType::NODE,
                    content(vec![0x44u8; bad_len]),
                ),
                Error::<Test>::InvalidNodeKey
            );
        }
        assert!(Records::<Test>::get(node(), RecordType::NODE).is_empty());
        assert!(RnsResolvers::guard_set().is_empty());
    });
}

#[test]
fn node_key_is_unique_across_names() {
    new_test_ext().execute_with(|| {
        let k1 = [0xB2u8; 32];
        assert_ok!(set_node(NAME, k1));
        // The same key cannot be claimed by a different name.
        assert_noop!(set_node(NAME2, k1), Error::<Test>::NodeKeyTaken);
        assert_eq!(GuardNodes::<Test>::get(k1), Some(node()));
        assert_eq!(RnsResolvers::guard_set(), vec![k1]);
    });
}

#[test]
fn resetting_same_key_on_same_name_is_ok() {
    new_test_ext().execute_with(|| {
        let k1 = [0xC3u8; 32];
        assert_ok!(set_node(NAME, k1));
        // Re-publishing the same key under the same name is not a collision.
        assert_ok!(set_node(NAME, k1));
        assert_eq!(GuardNodes::<Test>::get(k1), Some(node()));
        assert_eq!(RnsResolvers::guard_set(), vec![k1]);
    });
}

#[test]
fn node_key_update_replaces_old_in_index() {
    new_test_ext().execute_with(|| {
        let k1 = [0x11u8; 32];
        let k2 = [0x22u8; 32];
        assert_ok!(set_node(NAME, k1));
        // Rotate the name's NODE key: the old key leaves the index, the new enters.
        assert_ok!(set_node(NAME, k2));
        assert_eq!(GuardNodes::<Test>::get(k1), None);
        assert_eq!(GuardNodes::<Test>::get(k2), Some(node()));
        assert_eq!(Records::<Test>::get(node(), RecordType::NODE).to_vec(), k2.to_vec());
        assert_eq!(RnsResolvers::guard_set(), vec![k2]);
    });
}

#[test]
fn clearing_records_drops_guard_node() {
    new_test_ext().execute_with(|| {
        let k1 = [0xD4u8; 32];
        // clear_all_records (name destroyed) drops the index entry.
        assert_ok!(set_node(NAME, k1));
        RnsResolvers::clear_all_records(node());
        assert_eq!(GuardNodes::<Test>::get(k1), None);
        assert!(RnsResolvers::guard_set().is_empty());

        // clear_records_except_ss58 (ownership transfer) does too.
        let k2 = [0xE5u8; 32];
        assert_ok!(set_node(NAME, k2));
        RnsResolvers::clear_records_except_ss58(node());
        assert_eq!(GuardNodes::<Test>::get(k2), None);
        assert!(RnsResolvers::guard_set().is_empty());
    });
}

#[test]
fn guard_set_enumerates_all_enrolled_nodes() {
    new_test_ext().execute_with(|| {
        let k1 = [0x01u8; 32];
        let k2 = [0x02u8; 32];
        assert_ok!(set_node(NAME, k1));
        assert_ok!(set_node(NAME2, k2));
        assert_eq!(GuardNodes::<Test>::get(k1), Some(node()));
        assert_eq!(GuardNodes::<Test>::get(k2), Some(node2()));
        let mut got = RnsResolvers::guard_set();
        got.sort();
        assert_eq!(got, vec![k1, k2]);
    });
}

// ─────────────────── PREKEY / SEAL prekey-home records ─────────────────────
// (pq-chat P3b, docs/PQ-CHAT.md: the chain validates SHAPE only; the identity
// signatures inside the records are the initiating client's job to verify.
// PREKEY bundles SPK + PQSPK — one lifecycle, one record, one rotation tx;
// SEAL is deliberately separate — its decap secret lives the dead-drop TTL.)

use rns_types::ddns::codec_type::{PREKEY_RECORD_BYTES, SEAL_RECORD_BYTES};

#[test]
fn publishes_prekey_and_seal_records() {
    new_test_ext().execute_with(|| {
        let prekey = vec![0x44u8; PREKEY_RECORD_BYTES];
        let seal = vec![0x66u8; SEAL_RECORD_BYTES];
        for (rt, bytes) in [(RecordType::PREKEY, &prekey), (RecordType::SEAL, &seal)] {
            assert_ok!(RnsResolvers::set_record(
                RawOrigin::Signed(1).into(),
                NAME.to_vec(),
                rt,
                content(bytes.clone()),
            ));
        }
        assert_eq!(Records::<Test>::get(node(), RecordType::PREKEY).to_vec(), prekey);
        assert_eq!(Records::<Test>::get(node(), RecordType::SEAL).to_vec(), seal);
    });
}

#[test]
fn malformed_prekey_record_is_rejected() {
    new_test_ext().execute_with(|| {
        // PREKEY = spk(32) ‖ sig(64) ‖ pqspk_ek(1184) ‖ sig(64), exactly 1344.
        // 96 (SPK half only) and 1248 (PQSPK half only) are the likely client
        // bugs — must reject.
        for bad_len in [0usize, 96, 1248, 1343, 1345] {
            assert_noop!(
                RnsResolvers::set_record(
                    RawOrigin::Signed(1).into(),
                    NAME.to_vec(),
                    RecordType::PREKEY,
                    content(vec![0x77u8; bad_len]),
                ),
                Error::<Test>::InvalidPrekeyRecord
            );
        }
        assert!(Records::<Test>::get(node(), RecordType::PREKEY).is_empty());
    });
}

#[test]
fn malformed_seal_record_is_rejected() {
    new_test_ext().execute_with(|| {
        // SEAL = ek(1184) ‖ sig(64), exactly 1248. 1184 (ek without sig) is
        // the likely client bug — must reject.
        for bad_len in [0usize, 1184, 1247, 1249, PREKEY_RECORD_BYTES] {
            assert_noop!(
                RnsResolvers::set_record(
                    RawOrigin::Signed(1).into(),
                    NAME.to_vec(),
                    RecordType::SEAL,
                    content(vec![0x88u8; bad_len]),
                ),
                Error::<Test>::InvalidSealRecord
            );
        }
        assert!(Records::<Test>::get(node(), RecordType::SEAL).is_empty());
    });
}

#[test]
fn prekey_rotation_replaces_in_place() {
    new_test_ext().execute_with(|| {
        // Rotation = set_record on the same type: replaces content, does not
        // consume a second record slot (RecordCount stays at 1 per type).
        let old = vec![0xAAu8; PREKEY_RECORD_BYTES];
        let new = vec![0xBBu8; PREKEY_RECORD_BYTES];
        for bytes in [&old, &new] {
            assert_ok!(RnsResolvers::set_record(
                RawOrigin::Signed(1).into(),
                NAME.to_vec(),
                RecordType::PREKEY,
                content(bytes.clone()),
            ));
        }
        assert_eq!(Records::<Test>::get(node(), RecordType::PREKEY).to_vec(), new);
        assert_eq!(crate::resolvers::RecordCount::<Test>::get(node()), 1);
    });
}

#[test]
fn full_chat_identity_resolves_in_one_lookup() {
    new_test_ext().execute_with(|| {
        // The whole point of MAX_QUERY_TYPES = 4: CHAT + MESSAGE + PREKEY +
        // SEAL come back from a single lookup call.
        let chat = vec![0x11u8; 32];
        let msg = vec![0x01u8, 0xAA];
        let prekey = vec![0x22u8; PREKEY_RECORD_BYTES];
        let seal = vec![0x33u8; SEAL_RECORD_BYTES];
        for (rt, bytes) in [
            (RecordType::CHAT, &chat),
            (RecordType::MESSAGE, &msg),
            (RecordType::PREKEY, &prekey),
            (RecordType::SEAL, &seal),
        ] {
            assert_ok!(RnsResolvers::set_record(
                RawOrigin::Signed(1).into(),
                NAME.to_vec(),
                rt,
                content(bytes.clone()),
            ));
        }
        let got = RnsResolvers::lookup(
            node(),
            vec![RecordType::CHAT, RecordType::MESSAGE, RecordType::PREKEY, RecordType::SEAL],
        );
        for (rt, bytes) in [
            (RecordType::CHAT, chat),
            (RecordType::MESSAGE, msg),
            (RecordType::PREKEY, prekey),
            (RecordType::SEAL, seal),
        ] {
            assert!(got.contains(&(rt, bytes)), "{rt:?} missing from single lookup");
        }
    });
}
