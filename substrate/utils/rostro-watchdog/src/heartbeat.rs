// SPDX-License-Identifier: Apache-2.0

//! Monotone heartbeat counter.
//!
//! Watchdog increments the counter on each `Heartbeat` RPC and returns the
//! new value. When the short-TTL attestation cert machinery lands, the
//! latest counter value goes into the renewal payload — a frozen counter
//! means stale renewal, and peers naturally drop the node (the
//! "attack-defeats-itself" property from `watchdog-tpm-seal`).

use std::sync::atomic::{AtomicU64, Ordering};

pub struct HeartbeatCounter {
    value: AtomicU64,
}

impl HeartbeatCounter {
    pub const fn new() -> Self {
        Self { value: AtomicU64::new(0) }
    }

    pub fn current(&self) -> u64 {
        self.value.load(Ordering::SeqCst)
    }

    /// Increment and return the new value.
    pub fn tick(&self) -> u64 {
        self.value.fetch_add(1, Ordering::SeqCst) + 1
    }
}

impl Default for HeartbeatCounter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_zero() {
        let hb = HeartbeatCounter::new();
        assert_eq!(hb.current(), 0);
    }

    #[test]
    fn monotone_increment() {
        let hb = HeartbeatCounter::new();
        assert_eq!(hb.tick(), 1);
        assert_eq!(hb.tick(), 2);
        assert_eq!(hb.tick(), 3);
        assert_eq!(hb.current(), 3);
    }

    #[test]
    fn concurrent_ticks_are_monotone() {
        use std::sync::Arc;
        use std::thread;
        let hb = Arc::new(HeartbeatCounter::new());
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let hb = hb.clone();
                thread::spawn(move || {
                    for _ in 0..1000 {
                        hb.tick();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(hb.current(), 8 * 1000);
    }
}
