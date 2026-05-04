// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Genesis-time reserved label list for the Rostro Name Service.
//!
//! The labels in [`SEED_RESERVED`] are fed into `GenesisConfig::reserved_names`
//! at chain spec build time, hashed against the runtime's `BaseNode`, and
//! stored in `ReservedList` so they cannot be registered as RNS names.
//!
//! ## Why every label here matters
//!
//! Rostro on-chain names map directly to `*.rostro.org` subdomains via the
//! snorkel's DNS rewrite. An unreserved operational label is a live DNS
//! attack weapon — register `rpc` and you control `rpc.rostro.org`; register
//! `canaria` on mainnet and you shadow the entire canary network's namespace.
//!
//! Categories below are organized by attack surface, not alphabetically, so
//! reviewers can audit "what's in this category and why" before genesis.
//!
//! ## Constraints
//!
//! - Labels must be valid per [`crate::validate_label`]: ASCII alphanumeric
//!   only, 1–63 bytes, lowercase. Hyphens and underscores are rejected at the
//!   pallet level and would be silently skipped here, so they are excluded.
//! - This is the **seed** list. Post-genesis additions go through
//!   `T::SecurityResponseTeamOrigin` (the Security Response Team's threshold
//!   signature; stubbed to root until `pallet-rostro-security-response-team`
//!   lands — see the prelaunch checklist).
//! - Single-character and pure-numeric labels are deliberately omitted; their
//!   reservation policy is governance-owned and lives in a separate module.

/// Seed list of human-readable labels reserved at chain genesis.
///
/// Pass this slice into `GenesisConfig::reserved_names` in your runtime's
/// `genesis_config_presets.rs`:
///
/// ```ignore
/// use pallet_rns_registrar::genesis_reserved::SEED_RESERVED;
/// // ...
/// reserved_names: SEED_RESERVED.iter().map(|l| l.to_vec()).collect(),
/// ```
pub const SEED_RESERVED: &[&[u8]] = &[
    // ─── Network family collisions ───────────────────────────────────────
    // These shadow the entire Rostro network family if registered. Highest
    // priority. `rst` shadows mainnet itself; `canaria` and `camino` are the
    // sister-network basenodes; `rostro` is the brand identifier.
    b"rst",
    b"rostro",
    b"canaria",
    b"camino",
    b"mainnet",
    b"testnet",
    b"canary",
    b"foundation",

    // ─── DNS operational labels (RFC 2142) ───────────────────────────────
    // Standard role addresses every domain owner is expected to host. Squat
    // these and you intercept legitimate operational mail.
    b"postmaster",
    b"hostmaster",
    b"abuse",
    b"noc",
    b"webmaster",
    b"noreply",
    b"security",

    // ─── DNS infrastructure labels ───────────────────────────────────────
    // Subdomain conventions that operate the actual rostro.org DNS zone.
    b"www",
    b"mail",
    b"smtp",
    b"imap",
    b"pop",
    b"pop3",
    b"mx",
    b"mx1",
    b"mx2",
    b"mx3",
    b"mx4",
    b"ns",
    b"ns1",
    b"ns2",
    b"ns3",
    b"ns4",
    b"ns5",
    b"ns6",
    b"ns7",
    b"ns8",
    b"dns",
    b"dns1",
    b"dns2",
    b"dns3",
    b"dns4",
    b"cdn",
    b"static",
    b"assets",

    // ─── Foundation operational subdomains under rostro.org ──────────────
    // Every label here will become a real *.rostro.org subdomain at some
    // point. Losing any to first-come-first-served is an active phishing
    // weapon. Curated together with the user 2026-05-03.
    b"rpc",
    b"ws",
    b"chainspec",
    b"telemetry",
    b"bootnodes",
    b"archive",
    b"explorer",
    b"faucet",
    b"wallet",
    b"snorkel",
    b"status",
    b"docs",
    b"blog",
    b"forum",
    b"community",
    b"support",
    b"help",
    b"download",
    b"downloads",
    b"releases",

    // ─── Service convention labels ───────────────────────────────────────
    // Common subdomain conventions across the web. Even if Rostro never
    // hosts these, third-party tooling assumes they exist.
    b"api",
    b"app",
    b"admin",
    b"auth",
    b"login",
    b"accounts",
    b"dashboard",
    b"console",
    b"portal",
    b"dev",
    b"staging",
    b"prod",
    b"test",
    b"internal",
    b"vpn",
    b"gateway",
    b"root",
    b"sudo",
    b"system",

    // ─── Foundation / legal / governance ─────────────────────────────────
    b"legal",
    b"privacy",
    b"terms",
    b"governance",
    b"treasury",
    b"vote",

    // ─── IETF special-use domain names (RFC 6761/6762) ───────────────────
    // These should never resolve via the Rostro DNS. Reserve so impersonators
    // can't claim them and have the snorkel render them as legitimate.
    b"localhost",
    b"local",
    b"example",
    b"invalid",
    b"onion",
    b"arpa",

    // ─── Major ICANN gTLDs as labels ─────────────────────────────────────
    // Lets the snorkel detect "alice.com.rst" as obviously confusing input.
    b"com",
    b"org",
    b"net",
    b"io",
    b"co",
    b"edu",
    b"gov",
    b"mil",
    b"info",
    b"biz",
    b"xyz",

    // ─── High-impersonation targets ──────────────────────────────────────
    // Curated starter list. The fellowship can extend this post-genesis as
    // new attack patterns emerge. Inclusion here is anti-phishing, not an
    // endorsement or trademark claim.
    b"google",
    b"microsoft",
    b"apple",
    b"meta",
    b"facebook",
    b"amazon",
    b"paypal",
    b"anthropic",
    b"openai",
    b"coinbase",
    b"binance",
    b"github",
    b"twitter",
    b"x",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Every entry in `SEED_RESERVED` must pass label validation. If a future
    /// edit adds an invalid label (hyphen, underscore, dot, non-ASCII), this
    /// test catches it before genesis instead of letting the `GenesisConfig`
    /// builder silently drop it.
    #[test]
    fn every_seed_label_is_a_valid_rns_label() {
        for label in SEED_RESERVED {
            assert!(
                rns_types::validate_label(label).is_some(),
                "invalid seed label: {:?}",
                core::str::from_utf8(label).unwrap_or("<non-utf8>")
            );
        }
    }

    #[test]
    fn no_duplicate_seed_labels() {
        let mut seen = std::collections::BTreeSet::new();
        for label in SEED_RESERVED {
            assert!(
                seen.insert(*label),
                "duplicate seed label: {:?}",
                core::str::from_utf8(label).unwrap_or("<non-utf8>")
            );
        }
    }
}
