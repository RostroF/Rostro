#!/bin/bash
# verify_pin.sh — confirm StandardMemory's run_match landed at 0x300000.
#
# The .rostro_run_match section is pinned at 0x300000 by build.rs. Both
# generic monomorphizations of run_match<M: Memory> land in that section.
# The linker concatenates them in symbol-hash order; the StandardMemory
# variant (larger body) currently sorts first via its LLVM hash.
#
# This script verifies the contract. If LLVM's hashing produces an order
# swap (e.g., after a struct-layout change), this fails loudly so a manual
# fix is required before any bench result can be trusted.
#
# Usage: scripts/verify_pin.sh <binary>
#
# The "expected size larger than 0x4000" heuristic identifies the
# StandardMemory variant — it's about 2x the DynamicMemory variant's body.

set -e

BIN="${1:-target/release/examples/trace_shapes}"

if [ ! -f "$BIN" ]; then
    echo "verify_pin: binary not found: $BIN" >&2
    exit 1
fi

# Phase 1 Pin Order Fix (2026-05-14): per-memory-type sections.
# .rostro_run_match_std @ 0x300000 — StandardMemory variant (production hot path)
# .rostro_run_match_dyn @ 0x340000 — DynamicMemory variant

check_section() {
    local section="$1"
    local expected_addr="$2"
    local label="$3"

    local line=$(objdump -t "$BIN" 2>/dev/null | \
                 awk -v sec="$section" -v addr="$expected_addr" \
                     '$4 == sec && $1 == addr {print}')

    if [ -z "$line" ]; then
        echo "verify_pin: FAILED — no symbol at $expected_addr in section $section" >&2
        objdump -t "$BIN" | grep "$section" >&2
        return 1
    fi

    local size_hex=$(echo "$line" | awk '{print $5}')
    local size=$((0x$size_hex))
    echo "verify_pin: $label at $expected_addr (${size} bytes) — OK"
    return 0
}

check_section ".rostro_run_match_std" "0000000000300000" "StandardMemory run_match" || exit 2
check_section ".rostro_run_match_dyn" "0000000000340000" "DynamicMemory run_match"  || exit 3

exit 0
