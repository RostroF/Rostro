#![cfg_attr(not(feature = "std"), no_std)]

// Mobile app Rust layer.
// Responsibilities:
//   - Interface locally between user and TPM calls
//   - Construct genesis contract extrinsic
//   - Hand TOTP secret off to local authenticator app (never cloud-sync)
//   - Sign contract by submitting TPM public key + OTP + nonce
