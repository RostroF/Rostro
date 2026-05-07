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
