// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `mlock`-protected byte buffer.
//!
//! Wraps a `Vec<u8>` whose backing pages are pinned in resident
//! memory via `mlock()` (Unix) / `VirtualLock()` (Windows). On
//! drop, the buffer is zeroized and unlocked.
//!
//! ## Soft fallback
//!
//! `mlock` requires sufficient `RLIMIT_MEMLOCK` budget. If the
//! syscall fails, the buffer is still constructed and usable; it
//! just isn't pinned. Operators should run the relay with
//! `ulimit -l unlimited` (or `CAP_IPC_LOCK`) to guarantee
//! mlock-backed shares.
//!
//! Once the buffer is locked, the `Vec`'s heap allocation must
//! NOT move. The `Vec` struct itself can be moved (the struct is
//! three pointers — moving them doesn't relocate the heap buffer),
//! but reallocating the `Vec` (push, reserve, etc.) would
//! invalidate the lock. This wrapper is therefore **append-only-at-
//! construction**: the buffer is immutable after `new()`.

use zeroize::Zeroize;

/// A `Vec<u8>` whose heap pages are pinned via `mlock()` (best
/// effort). On drop, zeroizes the contents and releases the lock.
pub struct LockedBytes {
	bytes: Vec<u8>,
	/// Whether `mlock()` succeeded at construction.
	locked: bool,
}

impl LockedBytes {
	/// Construct a `LockedBytes` from a `Vec<u8>`. Attempts to
	/// `mlock` the buffer; if the syscall fails (RLIMIT_MEMLOCK
	/// exhausted, EPERM, etc.) the bytes are still stored — just
	/// unlocked. Caller should not depend on `locked()` returning
	/// `true`.
	pub fn new(bytes: Vec<u8>) -> Self {
		let locked = lock_pages(&bytes);
		Self { bytes, locked }
	}

	/// Returns the bytes as an immutable slice.
	pub fn as_slice(&self) -> &[u8] {
		&self.bytes
	}

	/// `true` if the underlying pages are currently `mlock`-ed.
	pub fn is_locked(&self) -> bool {
		self.locked
	}
}

impl Drop for LockedBytes {
	fn drop(&mut self) {
		if self.locked {
			unlock_pages(&self.bytes);
			self.locked = false;
		}
		self.bytes.zeroize();
	}
}

// ── platform-specific lock/unlock ─────────────────────────────────

#[cfg(unix)]
fn lock_pages(bytes: &[u8]) -> bool {
	if bytes.is_empty() {
		// mlock on a zero-length region is a no-op error on some
		// platforms; treat empty as "trivially locked".
		return true;
	}
	// SAFETY: `bytes.as_ptr()` points to a valid allocation of
	// `bytes.len()` bytes. `libc::mlock` reads no memory; it only
	// affects the kernel's page-locking state. Returns 0 on
	// success, -1 on failure (no allocator interaction).
	unsafe {
		libc::mlock(bytes.as_ptr() as *const libc::c_void, bytes.len()) == 0
	}
}

#[cfg(unix)]
fn unlock_pages(bytes: &[u8]) {
	if bytes.is_empty() {
		return;
	}
	// SAFETY: same as `lock_pages` — pointer + length name a valid
	// allocation, syscall affects only kernel state. Errors are
	// non-actionable here (best effort cleanup on drop).
	unsafe {
		let _ = libc::munlock(bytes.as_ptr() as *const libc::c_void, bytes.len());
	}
}

#[cfg(windows)]
fn lock_pages(_bytes: &[u8]) -> bool {
	// VirtualLock binding not yet wired for the Windows target.
	// Soft-fall to unlocked (the same fallback used when
	// RLIMIT_MEMLOCK is exhausted on Unix). v0.1 demo is Linux-
	// targeted; Windows lock binding is a follow-up.
	false
}

#[cfg(windows)]
fn unlock_pages(_bytes: &[u8]) {}

#[cfg(not(any(unix, windows)))]
fn lock_pages(_bytes: &[u8]) -> bool {
	false
}

#[cfg(not(any(unix, windows)))]
fn unlock_pages(_bytes: &[u8]) {}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn new_holds_bytes() {
		let lb = LockedBytes::new(vec![1, 2, 3, 4]);
		assert_eq!(lb.as_slice(), &[1, 2, 3, 4]);
	}

	#[test]
	fn empty_is_trivially_locked() {
		let lb = LockedBytes::new(Vec::new());
		assert!(lb.is_locked());
		assert!(lb.as_slice().is_empty());
	}

	#[test]
	fn drop_does_not_panic() {
		// Construct + drop a few sizes; the soft-fallback path
		// should never panic regardless of mlock outcome.
		for size in [0, 1, 1024, 4096, 64 * 1024] {
			let lb = LockedBytes::new(vec![0xAB; size]);
			drop(lb);
		}
	}

	#[test]
	fn small_mlock_likely_succeeds_on_linux() {
		// On a typical Linux host, locking 4 KiB unprivileged is
		// well within RLIMIT_MEMLOCK (64 KiB default). We don't
		// hard-assert because CI environments may vary; just
		// verify the construction completes either way.
		let lb = LockedBytes::new(vec![0u8; 4096]);
		// is_locked() may be true or false depending on RLIMIT;
		// either is acceptable.
		let _ = lb.is_locked();
	}
}
