#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "runtime-benchmarks")]
extern crate alloc;

pub mod migration;
pub mod nft;
pub mod origin;
pub mod price_oracle;
#[path = "price_oracle_weights.rs"]
pub mod price_oracle_weights;
pub mod registrar;
#[path = "registrar_weights.rs"]
pub mod registrar_weights;
pub mod registry;
pub mod traits;
