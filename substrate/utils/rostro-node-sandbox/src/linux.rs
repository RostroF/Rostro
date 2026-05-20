// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Linux backend for [`crate::install`]. Phase 2 scaffold: validates
//! that the target is Linux and logs a clear warning that no
//! primitives are engaged yet. Phase 3a wires cgroup v2 self-cap,
//! Phase 3b Landlock, Phase 3c seccomp-bpf.

use super::{NodeSandboxConfig, SandboxError};

/// Phase 2 stub. Returns `Ok(())` after a warning so the supervisor's
/// integration code (Phase 4) can be written and tested against the
/// real entry point. Phase 3 fills in the body.
pub(crate) fn install(config: &NodeSandboxConfig) -> Result<(), SandboxError> {
	log::warn!(
		"rostro-node-sandbox: Phase 2 scaffold engaged (NO ISOLATION ACTIVE). \
		 rw_paths={}, ro_paths={}, mem_cap={:?}, cpu_cap={:?}. \
		 Phase 3a adds cgroup v2, 3b Landlock, 3c seccomp-bpf.",
		config.rw_paths().len(),
		config.ro_paths().len(),
		config.memory_cap(),
		config.cpu_cap(),
	);
	Ok(())
}
