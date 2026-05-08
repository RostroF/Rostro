//! Stage 4a integration tests — exercise the pallet's extrinsic
//! surface end-to-end with real Groth16 proofs.
//!
//! Uses ark-circom to produce valid proofs against the same mime_wrap
//! circuit fixtures we built in Stage 1 (symlinked in here via
//! ../zkpki-circuits/build/). The trusted setup is done in-Rust via
//! `circuit_specific_setup` (same workaround as the verifier lab) to
//! avoid the snarkjs↔ark-circom cross-tool drift.

use crate::mock::{
    ALICE, Test, compute_commitment, compute_user_otp, fixture_ec_key_pub, fixture_seed,
    new_test_ext,
};
use crate::pallet::{ConsumedNonces, Commitments, Error, Event, MimeWrapVk, ProofBytes, VkBytes};
use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use codec::Decode;
use frame_support::{assert_noop, assert_ok};
use frame_system::EventRecord;
use std::path::PathBuf;

// ────────── Fixture paths ──────────

/// Path helper that reaches into zkpki-circuits' build/ directory —
/// the same artifacts Stages 1/3 already produced. No file copying;
/// tests fail loudly if the paths don't exist so the operator knows
/// to build the circuit first.
fn circuits_build_fixture(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("zkpki-circuits");
    p.push("build");
    p.push(name);
    p
}

fn wasm_path() -> PathBuf {
    circuits_build_fixture("mime_wrap_js/mime_wrap.wasm")
}

fn r1cs_path() -> PathBuf {
    circuits_build_fixture("mime_wrap.r1cs")
}

// ────────── One-time setup: generate pk/vk + a valid proof ──────────

struct Artifacts {
    vk_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
    ec_key_pub: [u8; 32],
    commitment_c: [u8; 32],
    bucket: u64,
    user_otp: u32,
}

/// Generate a matching (pk, vk) + a valid proof for a deterministic
/// fixture. Uses in-Rust `circuit_specific_setup` so the pk/vk pair
/// is guaranteed consistent with ark-circom's constraint ordering.
///
/// Returns the VK bytes (for the pallet's storage) plus the proof +
/// public-input components (for driving `verify_and_record`).
fn produce_fixture() -> Artifacts {
    // wasmer/ark-circom need a tokio runtime active.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let _guard = rt.enter();

    let ec_key_pub = fixture_ec_key_pub();
    let seed = fixture_seed();
    let bucket: u64 = 0x0000_0000_0387_d660;
    let commitment_c = compute_commitment(&ec_key_pub, &seed);
    let user_otp = compute_user_otp(&seed, bucket);

    // Build the circuit with the fixture inputs.
    let cfg = CircomConfig::<Fr>::new(
        wasm_path().to_str().unwrap(),
        r1cs_path().to_str().unwrap(),
    )
    .expect("circom config load — check fixtures/ are built");
    let mut builder = CircomBuilder::new(cfg);

    for bit in bits_be(&commitment_c) {
        builder.push_input("commitmentC", bit as u64);
    }
    for bit in bits_be(&ec_key_pub) {
        builder.push_input("ecKeyPub", bit as u64);
    }
    for bit in bits_be(&bucket.to_be_bytes()) {
        builder.push_input("bucket", bit as u64);
    }
    for bit in u24_bits_be(user_otp) {
        builder.push_input("userOtp", bit as u64);
    }
    for bit in bits_be(&seed) {
        builder.push_input("seed", bit as u64);
    }

    let circom = builder.build().expect("circuit build");
    let circom_for_setup = circom.clone();
    let mut rng = ark_std::rand::thread_rng();
    let (pk, vk): (ProvingKey<Bn254>, VerifyingKey<Bn254>) =
        Groth16::<Bn254>::circuit_specific_setup(circom_for_setup, &mut rng)
            .expect("circuit_specific_setup");
    let proof =
        Groth16::<Bn254>::prove(&pk, circom, &mut rng).expect("prove");

    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes).unwrap();
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();

    Artifacts {
        vk_bytes,
        proof_bytes,
        ec_key_pub,
        commitment_c,
        bucket,
        user_otp,
    }
}

fn bits_be(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for &b in bytes {
        for i in (0..8).rev() {
            out.push((b >> i) & 1);
        }
    }
    out
}

fn u24_bits_be(value: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    for i in (0..24).rev() {
        out.push(((value >> i) & 1) as u8);
    }
    out
}

// ────────── Event helper ──────────

fn last_event() -> Event<Test> {
    frame_system::Pallet::<Test>::events()
        .into_iter()
        .filter_map(|record: EventRecord<_, _>| match record.event {
            crate::mock::RuntimeEvent::ZkPki(e) => Some(e),
            _ => None,
        })
        .last()
        .expect("no ZkPki events emitted")
}

// ────────── Tests ──────────

#[test]
fn register_commitment_succeeds_once() {
    new_test_ext().execute_with(|| {
        frame_system::Pallet::<Test>::set_block_number(1);

        let ec_key_pub = fixture_ec_key_pub();
        let seed = fixture_seed();
        let c = compute_commitment(&ec_key_pub, &seed);

        assert_ok!(crate::pallet::Pallet::<Test>::register_commitment(
            frame_system::RawOrigin::Signed(ALICE).into(),
            ec_key_pub,
            c,
        ));
        assert_eq!(Commitments::<Test>::get(ec_key_pub), Some(c));
        assert!(matches!(
            last_event(),
            Event::CommitmentRegistered { .. }
        ));

        // Second register with same ec_key_pub must fail.
        assert_noop!(
            crate::pallet::Pallet::<Test>::register_commitment(
                frame_system::RawOrigin::Signed(ALICE).into(),
                ec_key_pub,
                c,
            ),
            Error::<Test>::CommitmentAlreadyRegistered
        );
    });
}

#[test]
fn verify_and_record_happy_path() {
    let a = produce_fixture();
    new_test_ext().execute_with(|| {
        frame_system::Pallet::<Test>::set_block_number(1);

        // Install the VK (root origin).
        let vk: VkBytes = a.vk_bytes.clone().try_into().expect("vk within bound");
        assert_ok!(crate::pallet::Pallet::<Test>::set_verifying_key(
            frame_system::RawOrigin::Root.into(),
            vk,
        ));

        // Register commitment.
        assert_ok!(crate::pallet::Pallet::<Test>::register_commitment(
            frame_system::RawOrigin::Signed(ALICE).into(),
            a.ec_key_pub,
            a.commitment_c,
        ));

        // Sign: verify and record.
        let nonce = [0x11u8; 32];
        let proof: ProofBytes = a
            .proof_bytes
            .clone()
            .try_into()
            .expect("proof bytes within bound");
        assert_ok!(crate::pallet::Pallet::<Test>::verify_and_record(
            frame_system::RawOrigin::Signed(ALICE).into(),
            a.ec_key_pub,
            a.bucket,
            nonce,
            a.user_otp,
            proof,
        ));

        // (bucket, nonce) now recorded as consumed.
        assert!(ConsumedNonces::<Test>::contains_key((a.bucket, nonce)));
        assert!(matches!(last_event(), Event::ProofVerified { .. }));
    });
}

#[test]
fn replay_rejected() {
    let a = produce_fixture();
    new_test_ext().execute_with(|| {
        frame_system::Pallet::<Test>::set_block_number(1);
        let vk: VkBytes = a.vk_bytes.clone().try_into().unwrap();
        assert_ok!(crate::pallet::Pallet::<Test>::set_verifying_key(
            frame_system::RawOrigin::Root.into(),
            vk,
        ));
        assert_ok!(crate::pallet::Pallet::<Test>::register_commitment(
            frame_system::RawOrigin::Signed(ALICE).into(),
            a.ec_key_pub,
            a.commitment_c,
        ));

        let nonce = [0x22u8; 32];
        let proof: ProofBytes = a.proof_bytes.clone().try_into().unwrap();
        assert_ok!(crate::pallet::Pallet::<Test>::verify_and_record(
            frame_system::RawOrigin::Signed(ALICE).into(),
            a.ec_key_pub,
            a.bucket,
            nonce,
            a.user_otp,
            proof.clone(),
        ));

        // Second call with same (bucket, nonce) must reject even though
        // the proof is still valid.
        assert_noop!(
            crate::pallet::Pallet::<Test>::verify_and_record(
                frame_system::RawOrigin::Signed(ALICE).into(),
                a.ec_key_pub,
                a.bucket,
                nonce,
                a.user_otp,
                proof,
            ),
            Error::<Test>::ReplayRejected
        );
    });
}

#[test]
fn tampered_otp_rejected() {
    let a = produce_fixture();
    new_test_ext().execute_with(|| {
        frame_system::Pallet::<Test>::set_block_number(1);
        let vk: VkBytes = a.vk_bytes.clone().try_into().unwrap();
        assert_ok!(crate::pallet::Pallet::<Test>::set_verifying_key(
            frame_system::RawOrigin::Root.into(),
            vk,
        ));
        assert_ok!(crate::pallet::Pallet::<Test>::register_commitment(
            frame_system::RawOrigin::Signed(ALICE).into(),
            a.ec_key_pub,
            a.commitment_c,
        ));

        let nonce = [0x33u8; 32];
        let proof: ProofBytes = a.proof_bytes.clone().try_into().unwrap();
        // Flip a bit in user_otp — proof no longer matches public inputs.
        let tampered_otp = a.user_otp ^ 0x01;
        assert_noop!(
            crate::pallet::Pallet::<Test>::verify_and_record(
                frame_system::RawOrigin::Signed(ALICE).into(),
                a.ec_key_pub,
                a.bucket,
                nonce,
                tampered_otp,
                proof,
            ),
            Error::<Test>::ProofInvalid
        );
    });
}

#[test]
fn missing_commitment_rejected() {
    let a = produce_fixture();
    new_test_ext().execute_with(|| {
        frame_system::Pallet::<Test>::set_block_number(1);
        let vk: VkBytes = a.vk_bytes.clone().try_into().unwrap();
        assert_ok!(crate::pallet::Pallet::<Test>::set_verifying_key(
            frame_system::RawOrigin::Root.into(),
            vk,
        ));
        // NOTE: no register_commitment call — should fail at lookup.

        let nonce = [0x44u8; 32];
        let proof: ProofBytes = a.proof_bytes.clone().try_into().unwrap();
        assert_noop!(
            crate::pallet::Pallet::<Test>::verify_and_record(
                frame_system::RawOrigin::Signed(ALICE).into(),
                a.ec_key_pub,
                a.bucket,
                nonce,
                a.user_otp,
                proof,
            ),
            Error::<Test>::CommitmentNotRegistered
        );
    });
}

#[test]
fn missing_vk_rejected() {
    let a = produce_fixture();
    new_test_ext().execute_with(|| {
        frame_system::Pallet::<Test>::set_block_number(1);
        // NOTE: no set_verifying_key — should fail at VK load.
        assert_ok!(crate::pallet::Pallet::<Test>::register_commitment(
            frame_system::RawOrigin::Signed(ALICE).into(),
            a.ec_key_pub,
            a.commitment_c,
        ));

        let nonce = [0x55u8; 32];
        let proof: ProofBytes = a.proof_bytes.clone().try_into().unwrap();
        assert_noop!(
            crate::pallet::Pallet::<Test>::verify_and_record(
                frame_system::RawOrigin::Signed(ALICE).into(),
                a.ec_key_pub,
                a.bucket,
                nonce,
                a.user_otp,
                proof,
            ),
            Error::<Test>::VerifyingKeyNotSet
        );
    });
}

// ────────── Helper: unused but surfaces codec import so the
//            `compute_*` helpers in mock.rs stay used even if a test
//            trims its references to them.
#[allow(dead_code)]
fn _ensure_helpers_used() {
    let _ = MimeWrapVk::<Test>::get();
    let _ = <[u8; 32] as Decode>::decode(&mut &[0u8; 32][..]);
}
