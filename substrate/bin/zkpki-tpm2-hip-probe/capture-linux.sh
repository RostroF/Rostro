#!/usr/bin/env bash
# Linux TPM 2.0 HIP capture — tpm2-tools only, no Rust required.
#
# Runs the HIP ceremony against the local TPM and writes raw output
# files to a capture directory. Post-processing (SCALE encoding,
# DER signature wrapping, SEC1 pubkey extraction, Blake2-256 of EK,
# CanonicalHipProof assembly) happens back on the dev box using
# tools/canonicalize-hip-capture in this repo.
#
# Usage:
#   ./capture-linux.sh <nonce-hex-64-chars> [output-dir]
#
# Example:
#   ./capture-linux.sh 0101010101010101010101010101010101010101010101010101010101010101
#
# Dependencies: tpm2-tools. Nothing else — no rust, no C compiler,
# no libtss2-dev. Invoking user must be in the `tss` group (so
# /dev/tpmrm0 is writable without sudo); `tpm2_getrandom --hex 16`
# is the canonical pre-flight check.

set -euo pipefail

NONCE_HEX="${1:?usage: capture-linux.sh <nonce-hex-64-chars> [output-dir]}"
OUT_DIR="${2:-hip-capture-$(date +%Y%m%d-%H%M%S)}"

if [[ ${#NONCE_HEX} -ne 64 ]]; then
    echo "nonce must be 64 hex chars (32 bytes); got ${#NONCE_HEX}" >&2
    exit 2
fi
if ! [[ "$NONCE_HEX" =~ ^[0-9a-fA-F]+$ ]]; then
    echo "nonce must be hex only" >&2
    exit 2
fi

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

# Aggressively evict any transient TPM state a prior OS left behind.
# fTPMs (AMD PSP, Intel PTT) share object memory with the host's
# firmware: Windows routinely leaves attestation / BitLocker / CNG
# handles loaded, and Linux inherits that state on dual-boot. The
# HIP ceremony needs two primaries simultaneously during TPM2_Certify;
# on an fTPM with the usual 3-slot transient budget, even one stale
# Windows handle is enough to force `TPM_RC_OBJECT_MEMORY` (0x902).
# This flush is cheap, idempotent, and only clears transients — NV
# persistent handles (Windows EK at 0x81010001 etc.) are untouched.
tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session  2>/dev/null || true
tpm2_flushcontext --saved-session   2>/dev/null || true

# Template: ECC P-256, SHA-256 name, restricted signing key under
# Endorsement. Matches the Windows probe's `ecc_p256_signing_template`.
#
# The -G / -a values below are deliberate: tpm2-tools' shorthand
# `-G ecc256` leaves the symmetric parms defaulted to AES128CFB, and
# `-a '...|restricted|sign'` without `:null` at the end of -G gives
# the TPM a TPMS_ECC_PARMS with a symmetric block that conflicts with
# the `sign` attribute — it returns `TPM_RC_SCHEME` (0x2d6) or
# `TPM_RC_ATTRIBUTES` (0x2c2). The explicit third colon-field (`:null`
# in `ecc256:ecdsa-sha256:null`) zeroes the symmetric block, which
# is required for a restricted sign key.
#
# Attribute set as hex bitfield — avoids shell splitting on `|`:
#   0x00000002  TPMA_OBJECT_FIXED_TPM
#   0x00000010  TPMA_OBJECT_FIXED_PARENT
#   0x00000020  TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
#   0x00000040  TPMA_OBJECT_USER_WITH_AUTH
#   0x00010000  TPMA_OBJECT_RESTRICTED
#   0x00040000  TPMA_OBJECT_SIGN_ENCRYPT
#   ────────────
#   0x00050072
PRIMARY_G='ecc256:ecdsa-sha256:null'
PRIMARY_A=0x00050072

echo "[1/5] creating EK-equivalent (ECC P-256 signing) under Endorsement"
# Two-step: create the primary with context save only, then
# readpublic separately. `tpm2_createprimary -u` goes through a
# TPM2B_PUBLIC marshalling path that has a regression on some
# libtss2-mu builds (surfaces as 0x90006, MU INSUFFICIENT_BUFFER).
# `tpm2_readpublic -c ctx -f tpmt` uses a different code path that
# serializes the TPMT_PUBLIC structure without the outer size
# envelope — same public area, clean marshalling.
tpm2_createprimary \
    -C e -G "$PRIMARY_G" \
    -a "$PRIMARY_A" \
    -c ek.ctx \
    > ek-createprimary.log
# Default format (-f tss) writes TPM2B_PUBLIC. `tpmt` looks like it
# should work per the spec but is not a valid -f value in
# tpm2-tools 5.x — we parse TPM2B_PUBLIC in the dev-box post-
# processor anyway.
tpm2_readpublic -c ek.ctx -o ek.pub > ek-readpublic.log

echo "[2/5] creating AIK (ECC P-256 signing) under Endorsement"
tpm2_createprimary \
    -C e -G "$PRIMARY_G" \
    -a "$PRIMARY_A" \
    -c aik.ctx \
    > aik-createprimary.log
tpm2_readpublic -c aik.ctx -o aik.pub > aik-readpublic.log

echo "[3/5] TPM2_Certify: EK signs over AIK's name"
# `-f plain` emits raw TPMT_SIGNATURE (2-byte alg + 2-byte hash +
# sized r + sized s) — the post-processor DER-wraps it. `-o` writes
# the TPMS_ATTEST payload the signature was taken over; that's the
# blob the pallet verifier parses inner pcrDigest / extraData from.
tpm2_certify \
    -C ek.ctx -c aik.ctx \
    -g sha256 \
    -o aik-certify-attest.bin \
    -s aik-certify-sig.bin \
    -f plain

echo "[4/5] reading PCRs 0, 1, 4, 7, 11 (SHA-256 bank)"
# Same PCR selection as the Windows probe. PCR 7 is the Secure Boot
# anchor; the others provide forward-only boot/firmware signal that
# we'll use in the future PCR-policy pass.
tpm2_pcrread sha256:0,1,4,7,11 -o pcrs.bin > pcrs.log

echo "[5/5] TPM2_Quote with nonce in qualifyingData"
tpm2_quote \
    -c aik.ctx \
    -l sha256:0,1,4,7,11 \
    -q "$NONCE_HEX" \
    -m quote-attest.bin \
    -s quote-sig.bin \
    -g sha256 \
    -f plain

# Clean up transient handles so they don't linger in the TPM's
# object memory across runs. The .ctx files hold saved-context
# serializations the kernel RM evicts automatically, but explicit
# flush is hygiene.
tpm2_flushcontext -t 2>/dev/null || true

# ---- Provenance capture ----
# Useful for fixture metadata so future readers know what hardware /
# kernel combo produced this capture. None of this is required for
# verification; it just documents the fixture source.
{
    echo "# tpm2-hip-probe capture provenance"
    echo ""
    echo "## Timestamp"
    date -Is
    echo ""
    echo "## Nonce (hex)"
    echo "$NONCE_HEX"
    echo ""
    echo "## Host"
    uname -a
    echo ""
    echo "## TPM version"
    cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null || echo "unknown"
    echo ""
    echo "## TPM capabilities"
    tpm2_getcap properties-fixed 2>&1 | head -40 || true
} > provenance.md

echo ""
echo "capture complete: $OUT_DIR"
echo ""
echo "files:"
ls -la
echo ""
echo "next: tar up and bring back to dev box:"
echo "  tar czf $(basename "$OUT_DIR").tar.gz -C $(dirname "$OUT_DIR") $(basename "$OUT_DIR")"
