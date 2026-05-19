// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-chat-mls — MLS group session wrapper
//!
//! Phase A3 of the MLS-chat plan. Thin wrapper around openmls 0.8
//! (RFC 9420 MLS protocol implementation, MIT-licensed) providing a
//! Rostro-shaped API: identity is an Ed25519 pubkey (matching the
//! SS58 model), group IDs are the pure-random 256-bit
//! [`rostro_chat_primitives::descriptor::GroupId`], storage is
//! in-process via `openmls_memory_storage`.
//!
//! ## What the wrapper provides
//!
//! - [`Member`]: a participant's identity + signing keys + crypto
//!   provider state. One per local user account.
//! - [`Group`]: an active MLS group session. Carries the openmls
//!   `MlsGroup` plus our [`GroupId`].
//! - Create / add / remove / encrypt / decrypt operations.
//!
//! ## Forward secrecy properties (from MLS, not added by this wrapper)
//!
//! - A **removed member** cannot decrypt messages sent after the
//!   Remove commit propagates — MLS rekeys the group's epoch
//!   secret so the next sending chain uses keys the removed member
//!   never sees.
//! - A **newly added member** cannot decrypt messages sent
//!   *before* their Add commit — they receive a Welcome that
//!   seeds their state at the current epoch only. Past epoch
//!   secrets are not derivable.
//! - Each message uses an epoch-derived key; old message keys are
//!   destroyed after use.
//!
//! Three test cases pin these invariants in this crate's test
//! suite.
//!
//! ## Storage (v0.1)
//!
//! In-process via [`openmls_memory_storage::MemoryStorage`].
//! Group state survives within a `Member` instance for the
//! lifetime of the process. **No on-disk persistence yet**;
//! mobile-app state backup/restore is a separate follow-up step
//! (tracked in `canonical_files_gate_open_problems`).
//!
//! ## What this crate does NOT do
//!
//! - **Sealed Sender wrapping** — application messages produced
//!   by [`Group::encrypt_application_message`] are MLS-encrypted
//!   but their delivery wraps them in the outer Sealed Sender
//!   layer (the `rostro-chat-sealed-sender` crate) at the transport
//!   boundary. This crate stays at the MLS layer.
//! - **Roster membership policy** — anyone with an active group
//!   session can call `add_member` and `remove_member`. Policy
//!   layers (admin roles, governance) wrap this at a higher level
//!   if needed.
//! - **Welcome message routing** — when a member is added, the
//!   resulting [`Welcome`] is returned to the caller, who routes
//!   it to the new member via whatever transport. The new member
//!   feeds it to [`Member::process_welcome`] to join.

use openmls::{
	credentials::{BasicCredential, CredentialWithKey},
	framing::{MlsMessageIn, MlsMessageOut, ProcessedMessageContent},
	group::{GroupId as MlsGroupId, MlsGroup, MlsGroupCreateConfig, StagedWelcome},
	key_packages::KeyPackage,
	prelude::{Ciphersuite, OpenMlsProvider, ProtocolVersion, SignatureScheme, Welcome},
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::storage::CURRENT_VERSION as STORAGE_VERSION;
use rostro_chat_primitives::descriptor::GroupId;
use tls_codec::Serialize as _;

/// Cipher suite used by all Rostro chat groups: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.
///
/// Pinned at the wrapper level so all groups share the same
/// algorithm choices. Matches our existing crypto stack
/// (Curve25519 + AEAD + SHA-256 + Ed25519). Bumping requires
/// coordinating with all existing group state.
pub const ROSTRO_CIPHERSUITE: Ciphersuite =
	Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// MLS protocol version pinned to v1 (the only version in RFC 9420).
pub const ROSTRO_MLS_VERSION: ProtocolVersion = ProtocolVersion::Mls10;

/// Errors raised by wrapper operations.
#[derive(Debug)]
pub enum MlsError {
	/// Underlying openmls returned an error during group creation.
	GroupCreate(String),
	/// Underlying openmls returned an error during member addition.
	AddMember(String),
	/// Underlying openmls returned an error during member removal.
	RemoveMember(String),
	/// Underlying openmls returned an error during commit merge.
	MergeCommit(String),
	/// Underlying openmls returned an error during welcome processing.
	WelcomeProcess(String),
	/// Underlying openmls returned an error during message encryption.
	Encrypt(String),
	/// Underlying openmls returned an error during message decryption.
	Decrypt(String),
	/// Decrypted message was not an application message (could be a
	/// stale Commit, Proposal, etc. — caller's responsibility to
	/// distinguish if needed).
	NotApplicationMessage,
	/// KeyPackage generation failed.
	KeyPackage(String),
	/// MLS wire-format serialization failed.
	WireFormat(String),
}

impl core::fmt::Display for MlsError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::GroupCreate(e) => write!(f, "group create: {e}"),
			Self::AddMember(e) => write!(f, "add member: {e}"),
			Self::RemoveMember(e) => write!(f, "remove member: {e}"),
			Self::MergeCommit(e) => write!(f, "merge commit: {e}"),
			Self::WelcomeProcess(e) => write!(f, "welcome process: {e}"),
			Self::Encrypt(e) => write!(f, "encrypt: {e}"),
			Self::Decrypt(e) => write!(f, "decrypt: {e}"),
			Self::NotApplicationMessage => write!(f, "not an application message"),
			Self::KeyPackage(e) => write!(f, "key package: {e}"),
			Self::WireFormat(e) => write!(f, "wire format: {e}"),
		}
	}
}

impl std::error::Error for MlsError {}

/// One local participant. Carries the openmls crypto provider
/// (which owns the in-memory storage backing this user's group
/// state) plus the identity-bound signature keypair.
pub struct Member {
	/// User's display identity (matches the SS58 on chain for the
	/// chat layer). 32 bytes — Ed25519 pubkey.
	identity: [u8; 32],
	/// MLS signature keypair (Ed25519). Persisted in `provider`'s
	/// storage on creation so KeyPackages can be derived later.
	signer: SignatureKeyPair,
	/// MLS crypto + storage provider. Owns all this user's
	/// per-group state for the process lifetime.
	provider: OpenMlsRustCrypto,
}

impl Member {
	/// Bring up a new MLS member with a fresh signature keypair.
	/// The keypair is stored inside the member's provider so
	/// subsequent operations (KeyPackage generation, commits) can
	/// recover it.
	pub fn new() -> Result<Self, MlsError> {
		let provider = OpenMlsRustCrypto::default();
		let signer = SignatureKeyPair::new(SignatureScheme::ED25519)
			.map_err(|e| MlsError::GroupCreate(format!("sig keypair: {e:?}")))?;
		signer
			.store(provider.storage())
			.map_err(|e: <MemoryStorage as openmls_traits::storage::StorageProvider<{ STORAGE_VERSION }>>::Error| {
				MlsError::GroupCreate(format!("store sig keypair: {e:?}"))
			})?;
		let mut identity = [0u8; 32];
		identity.copy_from_slice(signer.public());
		Ok(Self { identity, signer, provider })
	}

	/// This member's 32-byte identity pubkey (Ed25519 / SS58-equivalent).
	pub fn identity(&self) -> [u8; 32] {
		self.identity
	}

	/// Produce a [`KeyPackage`] this member can publish so other
	/// users can add them to groups. The KeyPackage is persisted
	/// in this member's provider so the corresponding init secret
	/// is recoverable when a Welcome arrives.
	pub fn key_package(&self) -> Result<KeyPackage, MlsError> {
		let credential = BasicCredential::new(self.identity.to_vec().into());
		let credential_with_key = CredentialWithKey {
			credential: credential.into(),
			signature_key: self.signer.public().to_vec().into(),
		};
		let bundle = KeyPackage::builder()
			.build(
				ROSTRO_CIPHERSUITE,
				&self.provider,
				&self.signer,
				credential_with_key,
			)
			.map_err(|e| MlsError::KeyPackage(format!("{e:?}")))?;
		Ok(bundle.key_package().clone())
	}

	/// Create a new MLS group. `group_id` is the Rostro 256-bit
	/// GroupId; we use its bytes directly as the MLS group_id.
	pub fn create_group(&self, group_id: &GroupId) -> Result<Group, MlsError> {
		let credential = BasicCredential::new(self.identity.to_vec().into());
		let credential_with_key = CredentialWithKey {
			credential: credential.into(),
			signature_key: self.signer.public().to_vec().into(),
		};
		let cfg = MlsGroupCreateConfig::builder()
			.ciphersuite(ROSTRO_CIPHERSUITE)
			.build();
		let mls_group_id = MlsGroupId::from_slice(&group_id.0);
		let group = MlsGroup::new_with_group_id(
			&self.provider,
			&self.signer,
			&cfg,
			mls_group_id,
			credential_with_key,
		)
		.map_err(|e| MlsError::GroupCreate(format!("{e:?}")))?;
		Ok(Group { id: *group_id, inner: group })
	}

	/// Process an incoming [`Welcome`] (delivered out-of-band by
	/// the inviter) and return a fully-initialized [`Group`] on
	/// success. The new member can immediately encrypt/decrypt
	/// at the current epoch.
	pub fn process_welcome(
		&self,
		welcome: Welcome,
		ratchet_tree: Option<openmls::treesync::RatchetTreeIn>,
	) -> Result<Group, MlsError> {
		let cfg = openmls::group::MlsGroupJoinConfig::builder().build();
		let staged = StagedWelcome::new_from_welcome(
			&self.provider,
			&cfg,
			welcome,
			ratchet_tree,
		)
		.map_err(|e| MlsError::WelcomeProcess(format!("{e:?}")))?;
		let group = staged
			.into_group(&self.provider)
			.map_err(|e| MlsError::WelcomeProcess(format!("into_group: {e:?}")))?;
		let id_bytes = group.group_id().as_slice();
		let mut id_arr = [0u8; 32];
		if id_bytes.len() != 32 {
			return Err(MlsError::WelcomeProcess(format!(
				"group_id wrong length: {} (expected 32)",
				id_bytes.len()
			)));
		}
		id_arr.copy_from_slice(id_bytes);
		Ok(Group { id: GroupId(id_arr), inner: group })
	}
}

/// An active MLS group session held by a [`Member`].
pub struct Group {
	id: GroupId,
	inner: MlsGroup,
}

impl Group {
	/// Rostro GroupId for this group.
	pub fn id(&self) -> GroupId {
		self.id
	}

	/// Current MLS epoch (advances on every commit).
	pub fn epoch(&self) -> u64 {
		self.inner.epoch().as_u64()
	}

	/// Add `new_member` to this group. Returns the commit message
	/// (to broadcast to existing members), the welcome message (to
	/// deliver to the new member), and the ratchet tree the new
	/// member needs to construct their group state.
	///
	/// **Eager-merge note:** v0.1 merges the pending commit inside
	/// this function on success because we don't yet have a
	/// rollback path for the "broadcast failed mid-way" case. A
	/// production wrapper would defer the merge until commit
	/// acknowledgment from peers is received. Tracked as a
	/// follow-up.
	pub fn add_member(
		&mut self,
		adder: &Member,
		new_member_key_package: KeyPackage,
	) -> Result<(MlsMessageOut, MlsMessageOut, Option<openmls::treesync::RatchetTreeIn>), MlsError> {
		let (commit, welcome, _group_info) = self
			.inner
			.add_members(&adder.provider, &adder.signer, &[new_member_key_package])
			.map_err(|e| MlsError::AddMember(format!("{e:?}")))?;
		self.inner
			.merge_pending_commit(&adder.provider)
			.map_err(|e| MlsError::MergeCommit(format!("{e:?}")))?;
		let ratchet_tree = self.inner.export_ratchet_tree().into();
		Ok((commit, welcome, Some(ratchet_tree)))
	}

	/// Remove `member_to_remove_identity` from this group.
	/// `member_to_remove_identity` is the 32-byte Ed25519 identity
	/// pubkey of the target.
	pub fn remove_member(
		&mut self,
		remover: &Member,
		member_to_remove_identity: &[u8; 32],
	) -> Result<MlsMessageOut, MlsError> {
		// Locate the target's leaf index by scanning current members.
		let target_leaf = self
			.inner
			.members()
			.find(|m| {
				m.credential
					.serialized_content()
					.windows(32)
					.any(|w| w == member_to_remove_identity)
			})
			.ok_or_else(|| MlsError::RemoveMember("member not found".into()))?
			.index;
		let (commit, _welcome, _info) = self
			.inner
			.remove_members(&remover.provider, &remover.signer, &[target_leaf])
			.map_err(|e| MlsError::RemoveMember(format!("{e:?}")))?;
		self.inner
			.merge_pending_commit(&remover.provider)
			.map_err(|e| MlsError::MergeCommit(format!("{e:?}")))?;
		Ok(commit)
	}

	/// Encrypt an application message (chat plaintext) for this
	/// group at the current epoch. Returns the MLS wire format
	/// bytes to ship via the outer Sealed Sender layer.
	pub fn encrypt_application_message(
		&mut self,
		sender: &Member,
		plaintext: &[u8],
	) -> Result<Vec<u8>, MlsError> {
		let msg = self
			.inner
			.create_message(&sender.provider, &sender.signer, plaintext)
			.map_err(|e| MlsError::Encrypt(format!("{e:?}")))?;
		msg.tls_serialize_detached()
			.map_err(|e| MlsError::WireFormat(format!("{e:?}")))
	}

	/// Decrypt an incoming MLS message for this group. Returns the
	/// plaintext on a successful application-message decrypt.
	/// Other message kinds (Commit, Proposal, etc.) are processed
	/// internally to advance group state; if the input was a
	/// non-application message, returns [`MlsError::NotApplicationMessage`].
	pub fn decrypt_or_process(
		&mut self,
		recipient: &Member,
		wire_bytes: &[u8],
	) -> Result<Vec<u8>, MlsError> {
		use tls_codec::Deserialize as _;
		let mut slice = wire_bytes;
		let mls_in = MlsMessageIn::tls_deserialize(&mut slice)
			.map_err(|e| MlsError::WireFormat(format!("{e:?}")))?;
		let protocol = mls_in
			.try_into_protocol_message()
			.map_err(|e| MlsError::Decrypt(format!("not a protocol message: {e:?}")))?;
		let processed = self
			.inner
			.process_message(&recipient.provider, protocol)
			.map_err(|e| MlsError::Decrypt(format!("{e:?}")))?;
		match processed.into_content() {
			ProcessedMessageContent::ApplicationMessage(app) => Ok(app.into_bytes()),
			ProcessedMessageContent::StagedCommitMessage(staged) => {
				self.inner
					.merge_staged_commit(&recipient.provider, *staged)
					.map_err(|e| MlsError::MergeCommit(format!("{e:?}")))?;
				Err(MlsError::NotApplicationMessage)
			},
			_ => Err(MlsError::NotApplicationMessage),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use openmls::framing::MlsMessageBodyIn;

	/// Helper: serialize a Welcome MlsMessageOut into wire bytes
	/// then deserialize back as MlsMessageIn so the recipient sees
	/// the same shape they'd receive over a real transport.
	fn welcome_roundtrip(welcome: MlsMessageOut) -> Welcome {
		use tls_codec::Deserialize as _;
		let bytes = welcome.tls_serialize_detached().unwrap();
		let mut slice = bytes.as_slice();
		let in_msg = MlsMessageIn::tls_deserialize(&mut slice).unwrap();
		match in_msg.extract() {
			MlsMessageBodyIn::Welcome(w) => w,
			other => panic!("expected Welcome, got {:?}", other),
		}
	}

	#[test]
	fn member_can_create_group_and_encrypt_to_self() {
		let alice = Member::new().unwrap();
		let gid = GroupId([0x11; 32]);
		let mut group = alice.create_group(&gid).unwrap();
		assert_eq!(group.id(), gid);
		// A single-member group can encrypt; decrypt-by-self isn't
		// meaningful (MLS expects different sender + receiver in
		// general), so we just verify encryption produces bytes.
		let wire = group
			.encrypt_application_message(&alice, b"hello self")
			.unwrap();
		assert!(!wire.is_empty());
	}

	#[test]
	fn two_member_create_add_send_decrypt_roundtrip() {
		let alice = Member::new().unwrap();
		let bob = Member::new().unwrap();
		let bob_kp = bob.key_package().unwrap();

		let gid = GroupId([0x22; 32]);
		let mut alice_group = alice.create_group(&gid).unwrap();
		let (_commit, welcome, ratchet_tree) =
			alice_group.add_member(&alice, bob_kp).unwrap();
		let welcome_w = welcome_roundtrip(welcome);
		let mut bob_group = bob.process_welcome(welcome_w, ratchet_tree).unwrap();
		assert_eq!(bob_group.id(), gid);
		assert_eq!(bob_group.epoch(), alice_group.epoch());

		// Alice sends, Bob decrypts.
		let wire = alice_group
			.encrypt_application_message(&alice, b"hello bob")
			.unwrap();
		let plain = bob_group.decrypt_or_process(&bob, &wire).unwrap();
		assert_eq!(plain, b"hello bob");

		// Bob sends, Alice decrypts.
		let wire2 = bob_group
			.encrypt_application_message(&bob, b"hi alice")
			.unwrap();
		let plain2 = alice_group.decrypt_or_process(&alice, &wire2).unwrap();
		assert_eq!(plain2, b"hi alice");
	}

	#[test]
	fn three_member_group_all_decrypt() {
		let alice = Member::new().unwrap();
		let bob = Member::new().unwrap();
		let charlie = Member::new().unwrap();

		let gid = GroupId([0x33; 32]);
		let mut alice_group = alice.create_group(&gid).unwrap();

		// Add bob.
		let bob_kp = bob.key_package().unwrap();
		let (_c, welcome_b, rt_b) =
			alice_group.add_member(&alice, bob_kp).unwrap();
		let mut bob_group =
			bob.process_welcome(welcome_roundtrip(welcome_b), rt_b).unwrap();

		// Add charlie.
		let charlie_kp = charlie.key_package().unwrap();
		let (commit_c, welcome_c, rt_c) =
			alice_group.add_member(&alice, charlie_kp).unwrap();
		// Bob processes the commit to catch up to the new epoch.
		let commit_wire = commit_c.tls_serialize_detached().unwrap();
		match bob_group.decrypt_or_process(&bob, &commit_wire) {
			Err(MlsError::NotApplicationMessage) => {}, // expected: it's a commit
			other => panic!("expected NotApplicationMessage on commit, got {:?}", other),
		}
		let mut charlie_group = charlie
			.process_welcome(welcome_roundtrip(welcome_c), rt_c)
			.unwrap();

		assert_eq!(alice_group.epoch(), bob_group.epoch());
		assert_eq!(alice_group.epoch(), charlie_group.epoch());

		// Alice sends, both decrypt.
		let wire = alice_group
			.encrypt_application_message(&alice, b"hello group")
			.unwrap();
		assert_eq!(
			bob_group.decrypt_or_process(&bob, &wire).unwrap(),
			b"hello group",
		);
		assert_eq!(
			charlie_group.decrypt_or_process(&charlie, &wire).unwrap(),
			b"hello group",
		);
	}

	#[test]
	fn removed_member_cannot_decrypt_after_remove_commit() {
		let alice = Member::new().unwrap();
		let bob = Member::new().unwrap();
		let charlie = Member::new().unwrap();

		let gid = GroupId([0x44; 32]);
		let mut alice_group = alice.create_group(&gid).unwrap();

		// Add bob and charlie.
		let bob_kp = bob.key_package().unwrap();
		let (_, welcome_b, rt_b) =
			alice_group.add_member(&alice, bob_kp).unwrap();
		let mut bob_group =
			bob.process_welcome(welcome_roundtrip(welcome_b), rt_b).unwrap();

		let charlie_kp = charlie.key_package().unwrap();
		let (commit_add_c, welcome_c, rt_c) =
			alice_group.add_member(&alice, charlie_kp).unwrap();
		// Bob catches up.
		let _ = bob_group.decrypt_or_process(
			&bob,
			&commit_add_c.tls_serialize_detached().unwrap(),
		);
		let mut charlie_group = charlie
			.process_welcome(welcome_roundtrip(welcome_c), rt_c)
			.unwrap();

		// Alice removes charlie.
		let bob_id = bob.identity();
		let charlie_id = charlie.identity();
		let commit_rm = alice_group.remove_member(&alice, &charlie_id).unwrap();
		// Bob catches up to the new epoch.
		let _ = bob_group.decrypt_or_process(
			&bob,
			&commit_rm.tls_serialize_detached().unwrap(),
		);

		// Alice sends post-remove. Bob can decrypt. Charlie cannot
		// process at the new epoch (his state is stale + he's
		// removed from the roster).
		let wire = alice_group
			.encrypt_application_message(&alice, b"members only")
			.unwrap();
		assert_eq!(
			bob_group.decrypt_or_process(&bob, &wire).unwrap(),
			b"members only",
			"bob remains a member and decrypts",
		);
		assert!(
			charlie_group.decrypt_or_process(&charlie, &wire).is_err(),
			"charlie was removed and must fail to decrypt the post-remove message",
		);
		// Sanity: avoid unused warning.
		let _ = bob_id;
	}

	#[test]
	fn new_member_cannot_decrypt_pre_join_history() {
		let alice = Member::new().unwrap();
		let bob = Member::new().unwrap();

		let gid = GroupId([0x55; 32]);
		let mut alice_group = alice.create_group(&gid).unwrap();

		// Alice sends a pre-Bob-join message. Stash the wire bytes.
		let pre_join_wire = alice_group
			.encrypt_application_message(&alice, b"before bob joined")
			.unwrap();

		// Bob joins.
		let bob_kp = bob.key_package().unwrap();
		let (_, welcome_b, rt_b) =
			alice_group.add_member(&alice, bob_kp).unwrap();
		let mut bob_group =
			bob.process_welcome(welcome_roundtrip(welcome_b), rt_b).unwrap();

		// Sanity: bob can decrypt a post-join message.
		let post_join_wire = alice_group
			.encrypt_application_message(&alice, b"after bob joined")
			.unwrap();
		assert_eq!(
			bob_group.decrypt_or_process(&bob, &post_join_wire).unwrap(),
			b"after bob joined",
		);

		// Bob attempts to decrypt the pre-join message. Must fail
		// — his state was seeded at the post-add epoch, doesn't
		// hold keys for the pre-add epoch.
		assert!(
			bob_group.decrypt_or_process(&bob, &pre_join_wire).is_err(),
			"bob must NOT be able to decrypt the pre-join message",
		);
	}

	#[test]
	fn group_id_round_trips_through_mls() {
		let alice = Member::new().unwrap();
		let gid = GroupId([0xAB; 32]);
		let group = alice.create_group(&gid).unwrap();
		assert_eq!(group.id(), gid);
		// Bob joins via welcome — verify the group_id propagates.
		let bob = Member::new().unwrap();
		let bob_kp = bob.key_package().unwrap();
		let mut alice_group = group; // shadow
		let (_, welcome, rt) =
			alice_group.add_member(&alice, bob_kp).unwrap();
		let bob_group =
			bob.process_welcome(welcome_roundtrip(welcome), rt).unwrap();
		assert_eq!(bob_group.id(), gid);
	}
}
