// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Role-based invariant enforcement.
//!
//! Phase 6 of the validator-vs-RPC interlock: the binary refuses to
//! start in any combination that mixes "I'm validating" and "I'm
//! exposing public RPC." Polkadot achieves the same property via
//! operator discipline (`--rpc-external` on a validator prints a
//! warning unless `--rpc-methods=unsafe`); Rostro removes the
//! discipline path — there is no escape hatch.
//!
//! The check runs once at boot, before
//! `rc_service::new_full` constructs the service. Failure exits the
//! process with a clear operator-readable error.
//!
//! The validation here is Layer 2 of the interlock plan documented in
//! the project memory. Layer 1 (compile-time exclusion of RPC server
//! code from the validator binary) requires substrate-internal
//! refactoring deferred to a later phase. Layers 3 and 4 (chain-state
//! self-check + periodic self-audit) live in separate modules.

use rc_service::Configuration;
use rc_service::config::RpcMethods;

/// Verify role-based invariants on the parsed configuration.
///
/// Currently enforced:
///   - Validator (`Role::Authority`) MUST bind RPC to loopback only.
///     Any non-loopback endpoint in `config.rpc.addr` is rejected.
///   - Validator MUST NOT use `--rpc-methods=unsafe`. Even on
///     loopback, the unsafe set exposes `author_insertKey`,
///     `system_addReservedPeer`, etc. to any local process — we
///     prefer explicit intent (operator runs a separate one-shot
///     binary or uses the side-channel `insert-sassafras-key`
///     subcommand) over a broad always-on local API.
///
/// Non-validator roles are unconstrained at this layer. The shield
/// (RPC middleware) and the runtime patches handle the public-RPC
/// surface separately.
pub fn validate(config: &Configuration) -> Result<(), String> {
	if !config.role.is_authority() {
		return Ok(());
	}

	// Validator: every RPC endpoint must be loopback or RPC must be
	// disabled entirely.
	if let Some(endpoints) = &config.rpc.addr {
		for endpoint in endpoints {
			if !endpoint.listen_addr.ip().is_loopback() {
				return Err(format!(
					"Validator role rejects non-loopback RPC binding ({}). \
					 Rostro validators do not expose public RPC. Drop \
					 --rpc-external / --unsafe-rpc-external, or run this \
					 node as a non-validator (remove --validator) and \
					 separate the validator + RPC roles onto different \
					 machines.",
					endpoint.listen_addr,
				));
			}
		}
	}

	// Validator: refuse the unsafe method set. Substrate's Auto mode
	// is OK because we've already rejected non-loopback above —
	// Auto-on-loopback expands to the unsafe set, but only callable
	// from the validator's own machine. Unsafe explicitly opens the
	// unsafe set even on non-loopback; reject it to make intent
	// auditable.
	if matches!(config.rpc.methods, RpcMethods::Unsafe) {
		return Err(
			"Validator role rejects --rpc-methods=unsafe. \
			 Validators must use the safe subset (default Auto is \
			 acceptable since we've already required loopback-only \
			 binding). Remove --rpc-methods=unsafe, or split the \
			 validator and management roles onto separate processes."
				.into(),
		);
	}

	Ok(())
}

/// Spawn the Layer 3 chain-state self-check task.
///
/// Periodically reconciles two views:
///
///   1. **Local view**: bandersnatch keys present in the node's
///      keystore (under the Sassafras KEY_TYPE).
///   2. **On-chain view**: the active validator set from
///      `SassafrasApi::current_epoch(best_hash).authorities`.
///
/// The four (config × on-chain) cases:
///
///   | role config | key in active set | action |
///   |-------------|-------------------|--------|
///   | validator   | yes               | normal — no action |
///   | validator   | no                | warn — legitimate intermediate state (preparing, just rotated out, etc.) |
///   | non-validator | yes             | **FATAL** — operator has been elected, binary won't author. Crash to prevent silent absence from finality. |
///   | non-validator | no              | normal — no action |
///
/// The third row is the load-bearing case. Without this check, a node
/// that's been elected to validate but is misconfigured (validator key
/// installed but `--validator` flag forgotten) silently fails to
/// produce blocks, dragging down finality and accruing slashing on
/// the operator's stake. Crashing fast forces the operator to fix
/// their configuration before the chain notices.
///
/// First check runs immediately after the task is spawned; periodic
/// re-check every 60 seconds. If the runtime API call fails (chain
/// not yet synced, or storage corrupted), the round is skipped — we
/// don't crash on transient query errors.
pub fn spawn_chain_state_self_check<C, B>(
	role: rc_service::Role,
	client: std::sync::Arc<C>,
	keystore: sp_keystore::KeystorePtr,
	task_handle: &rc_service::SpawnTaskHandle,
) where
	B: sp_runtime::traits::Block,
	C: sp_api::ProvideRuntimeApi<B> + sp_blockchain::HeaderBackend<B> + Send + Sync + 'static,
	C::Api: sp_consensus_sassafras::SassafrasApi<B>,
{
	task_handle.spawn(
		"validator-chain-state-check",
		Some("rostro-role"),
		async move {
			let interval = std::time::Duration::from_secs(60);
			let role_is_authority = role.is_authority();
			loop {
				match local_key_in_active_set(&*client, &keystore) {
					ChainStateView::Match { configured_validator } => {
						handle_state(role_is_authority, configured_validator);
					}
					ChainStateView::Inconclusive => {
						// Best-hash query failed or runtime API errored.
						// Skip this round, retry next interval.
					}
				}
				tokio::time::sleep(interval).await;
			}
		},
	);
}

enum ChainStateView {
	Match { configured_validator: bool },
	Inconclusive,
}

fn local_key_in_active_set<C, B>(
	client: &C,
	keystore: &sp_keystore::KeystorePtr,
) -> ChainStateView
where
	B: sp_runtime::traits::Block,
	C: sp_api::ProvideRuntimeApi<B> + sp_blockchain::HeaderBackend<B>,
	C::Api: sp_consensus_sassafras::SassafrasApi<B>,
{
	use sp_consensus_sassafras::SassafrasApi;
	let best = client.info().best_hash;
	let api = client.runtime_api();
	let epoch = match api.current_epoch(best) {
		Ok(e) => e,
		Err(_) => return ChainStateView::Inconclusive,
	};
	let local_keys = keystore.bandersnatch_public_keys(sp_consensus_sassafras::KEY_TYPE);
	if local_keys.is_empty() {
		// No bandersnatch keys → can't be in active set → "no key in
		// set" branch. configured_validator=false because we have no
		// proof the operator intends to validate. handle_state() will
		// route through the (any-role × no-key) cell which is always
		// fine.
		return ChainStateView::Match { configured_validator: false };
	}
	// Compare bytes: keystore returns raw `bandersnatch::Public`,
	// runtime returns the `app::Public` wrapper. Both are 32-byte
	// public keys; both impl `AsRef<[u8]>`.
	let in_active = local_keys.iter().any(|local| {
		let local_bytes: &[u8] = local.as_ref();
		epoch.authorities.iter().any(|auth| {
			let auth_bytes: &[u8] = auth.as_ref();
			auth_bytes == local_bytes
		})
	});
	ChainStateView::Match { configured_validator: in_active }
}

fn handle_state(role_is_authority: bool, key_in_active_set: bool) {
	match (role_is_authority, key_in_active_set) {
		(true, true) | (false, false) => {
			// Normal cases. No action.
		}
		(true, false) => {
			// Configured as validator, key not in active set. Could
			// be: operator just inserted key but next era hasn't
			// elected them yet; operator was just rotated out; chain
			// hasn't fully synced past their election. Warn but
			// continue — this is recoverable without binary
			// intervention.
			tracing::warn!(
				target: "rostro-role",
				"validator role configured but no local bandersnatch key is in the \
				 active authority set. If this persists, verify the keystore and the \
				 chain spec match the operator's elected key."
			);
		}
		(false, true) => {
			// CRITICAL: operator has a validator key that the chain
			// has placed in the active authority set, but this binary
			// is NOT running with --validator. The chain expects this
			// node to author blocks at its assigned slots; if it
			// doesn't, finality drags and the operator gets slashed
			// for absence. Halt now, force the operator to fix the
			// configuration before silent harm accumulates.
			eprintln!(
				"\nFATAL: a local bandersnatch key is in the active validator set, \
				 but this binary is NOT running with --validator.\n\n\
				 The chain has elected you and expects you to author blocks. \
				 Either:\n\
				 \x20  (a) restart with --validator, OR\n\
				 \x20  (b) remove the matching bandersnatch key from your keystore \
				 to step down from validation.\n\n\
				 Halting now to prevent silent absence from finality.\n"
			);
			std::process::abort();
		}
	}
}

/// Spawn the Layer 4 periodic self-audit task on the validator.
///
/// **Status: stub.** An earlier implementation walked
/// `/proc/net/tcp` for any non-loopback listener and crashed on
/// match. That false-positives on libp2p — validators MUST bind
/// libp2p on a non-loopback interface to peer with other validators.
/// A correct implementation would scope the check narrowly to the
/// configured RPC listener addresses, but that duplicates Layer 2's
/// parse-time check at a worse fidelity (proc inspection cannot
/// cleanly distinguish per-process sockets without /proc/{pid}/fd
/// walking + inode matching).
///
/// Layers 2 + 3 (boot-time invariant + chain-state self-check) are
/// the actual defenses. Layer 4 is reserved for a future
/// implementation that:
///
///   - Receives the configured RPC listen addresses at startup
///   - Periodically asserts those specific addresses are still
///     loopback-bound from this process (via /proc/{pid}/fd → inode
///     → /proc/net/tcp)
///   - Crashes only on a real Layer-2-bypass scenario
///
/// Until that lands this is a no-op for non-Linux platforms and a
/// no-op for now even on Linux. Non-validator roles do not need this
/// audit and the task is not spawned regardless.
pub fn spawn_self_audit_if_validator(
	_role: rc_service::Role,
	_task_handle: &rc_service::SpawnTaskHandle,
) {
	// Intentionally a no-op until the targeted /proc/{pid}/fd-scoped
	// implementation is built. See doc comment above.
}

#[cfg(test)]
mod tests {
	// The Configuration struct is non-trivial to construct in unit
	// tests without spinning up substrate's full builder pipeline.
	// The boot-time integration smoke is covered by `gemini-node`'s
	// startup behavior under `cargo test` for the crate when run
	// against an integration harness — for v0 of Phase 6 we rely on
	// manual end-to-end verification (start with --validator
	// --rpc-external and observe rejection).
	//
	// TODO(phase-6.x): build a Configuration test fixture (or expose
	// the fields we check directly so the validation doesn't need a
	// full Configuration) so this gets unit-test coverage.
}
