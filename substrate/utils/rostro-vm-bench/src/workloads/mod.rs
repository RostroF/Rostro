// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Bench workloads — each one ships two blob builders (one javm-flavor,
//! one polkavm-flavor) producing logically-equivalent RVM bytecode plus
//! a native-Rust reference implementation for correctness assertions.
//!
//! Mirrors `grey_bench`'s workload structure so the comparison sits at
//! a known, reviewable baseline before Rostro-shop-specific workloads
//! (sha256/1MB, ed25519 verify, SCALE roundtrip) get layered on top.

pub mod fib;
pub mod primes;
pub mod scale_roundtrip;
