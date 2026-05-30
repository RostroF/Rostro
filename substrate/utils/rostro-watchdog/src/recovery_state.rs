// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Persistent recovery-attempt counter for the watchdog's piece-B
//! recovery cascade.
//!
//! The watchdog bounds its own recovery attempts so a permanently
//! broken canonical-cache doesn't loop forever: each non-zero
//! supervisor exit consumes one attempt; once the counter hits
//! `--max-recovery-attempts`, the watchdog propagates the failure to
//! systemd and the unit enters `failed` state (operator-intervention).
//!
//! State is persisted across watchdog restarts so an attacker who
//! kills the watchdog can't reset the cap. The shape is intentionally
//! simpler than supervisor's `state.crashes` — we only track one
//! counter; no sliding window.
//!
//! File format mirrors supervisor's state file: `key=value` lines,
//! a schema version, and unknown keys ignored (forward-compat). The
//! watchdog also emits a `STATE_DELTA layer=watchdog-recovery …` line
//! to stderr on every save so journalctl operators can reconstruct
//! the counter if disk persistence fails (Cannae or filesystem
//! issues).

use std::path::Path;

pub const STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecoveryState {
	pub recovery_attempts: u32,
}

impl RecoveryState {
	pub fn load(path: &Path) -> Self {
		let raw = match std::fs::read_to_string(path) {
			Ok(s) => s,
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Self::default(),
			Err(e) => {
				log::warn!(
					"could not read recovery state at {}: {e}; starting fresh",
					path.display()
				);
				return Self::default();
			},
		};
		Self::parse(&raw).unwrap_or_else(|e| {
			log::warn!(
				"malformed recovery state at {}: {e}; starting fresh",
				path.display()
			);
			Self::default()
		})
	}

	pub fn parse(raw: &str) -> Result<Self, String> {
		let mut state = Self::default();
		let mut saw_schema = false;
		for (lineno, line) in raw.lines().enumerate() {
			let line = line.trim();
			if line.is_empty() || line.starts_with('#') {
				continue;
			}
			let (key, value) = line
				.split_once('=')
				.ok_or_else(|| format!("line {}: no '=' separator", lineno + 1))?;
			match key.trim() {
				"schema_version" => {
					let v: u32 = value.trim().parse().map_err(|e| {
						format!("line {}: bad schema_version: {e}", lineno + 1)
					})?;
					if v != STATE_SCHEMA_VERSION {
						return Err(format!(
							"schema_version {v} != expected {STATE_SCHEMA_VERSION}"
						));
					}
					saw_schema = true;
				},
				"recovery_attempts" => {
					state.recovery_attempts = value.trim().parse().map_err(|e| {
						format!("line {}: bad recovery_attempts: {e}", lineno + 1)
					})?;
				},
				_ => {
					// Forward-compat: ignore unknown keys.
				},
			}
		}
		if !saw_schema {
			return Err("missing schema_version".to_string());
		}
		Ok(state)
	}

	pub fn serialize(&self) -> String {
		let mut out = String::new();
		out.push_str(&format!("schema_version={STATE_SCHEMA_VERSION}\n"));
		out.push_str(&format!("recovery_attempts={}\n", self.recovery_attempts));
		out
	}

	pub fn save_atomic(&self, path: &Path) -> std::io::Result<()> {
		if let Some(parent) = path.parent() {
			std::fs::create_dir_all(parent)?;
		}
		let mut tmp = path.to_path_buf();
		let mut name = tmp.file_name().unwrap_or_default().to_owned();
		name.push(".tmp");
		tmp.set_file_name(name);
		std::fs::write(&tmp, self.serialize())?;
		std::fs::rename(&tmp, path)?;
		Ok(())
	}

	pub fn emit_delta_to_journal(&self) {
		eprintln!(
			"STATE_DELTA layer=watchdog-recovery schema={} recovery_attempts={}",
			STATE_SCHEMA_VERSION, self.recovery_attempts,
		);
	}

	pub fn save_and_mirror(&self, path: &Path) -> std::io::Result<()> {
		let result = self.save_atomic(path);
		self.emit_delta_to_journal();
		result
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::path::PathBuf;

	fn tmpdir() -> PathBuf {
		let mut p = std::env::temp_dir();
		let unique = format!(
			"rostro-watchdog-recovery-state-test-{}-{}",
			std::process::id(),
			std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.unwrap()
				.as_nanos(),
		);
		p.push(unique);
		std::fs::create_dir_all(&p).unwrap();
		p
	}

	#[test]
	fn default_counter_is_zero() {
		assert_eq!(RecoveryState::default().recovery_attempts, 0);
	}

	#[test]
	fn save_then_load_round_trips() {
		let dir = tmpdir();
		let p = dir.join("state");
		let s = RecoveryState { recovery_attempts: 7 };
		s.save_atomic(&p).unwrap();
		let loaded = RecoveryState::load(&p);
		assert_eq!(loaded, s);
	}

	#[test]
	fn save_is_atomic_via_rename() {
		let dir = tmpdir();
		let p = dir.join("state");
		RecoveryState::default().save_atomic(&p).unwrap();
		let mut tmp = p.clone();
		let mut name = tmp.file_name().unwrap().to_owned();
		name.push(".tmp");
		tmp.set_file_name(name);
		assert!(!tmp.exists(), "tmp must not linger after save_atomic");
	}

	#[test]
	fn parse_rejects_missing_schema() {
		assert!(RecoveryState::parse("recovery_attempts=3\n").is_err());
	}

	#[test]
	fn parse_rejects_wrong_schema() {
		let raw = format!(
			"schema_version={}\nrecovery_attempts=3\n",
			STATE_SCHEMA_VERSION + 1
		);
		assert!(RecoveryState::parse(&raw).is_err());
	}

	#[test]
	fn parse_ignores_unknown_keys_forward_compat() {
		let raw = format!(
			"schema_version={}\nrecovery_attempts=2\nfuture_thing=whatever\n",
			STATE_SCHEMA_VERSION
		);
		let s = RecoveryState::parse(&raw).unwrap();
		assert_eq!(s.recovery_attempts, 2);
	}

	#[test]
	fn load_missing_file_returns_default() {
		let dir = tmpdir();
		let p = dir.join("does-not-exist");
		assert_eq!(RecoveryState::load(&p), RecoveryState::default());
	}

	#[test]
	fn load_corrupted_returns_default() {
		let dir = tmpdir();
		let p = dir.join("state");
		std::fs::write(&p, b"\xff garbage \xfe").unwrap();
		assert_eq!(RecoveryState::load(&p), RecoveryState::default());
	}
}
