#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unused_must_use)]
#![forbid(clippy::missing_safety_doc)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::exhaustive_structs)]
// TODO: Uncomment this once we get rid of all of the `as` casts:
// #![deny(clippy::as_conversions)]

#[cfg(all(
    not(miri),
    target_arch = "x86_64",
    any(
        target_os = "linux",
        all(feature = "generic-sandbox", any(target_os = "macos", target_os = "freebsd"))
    ),
    feature = "std",
))]
macro_rules! if_compiler_is_supported {
    ({
        $($if_true:tt)*
    } else {
        $($if_false:tt)*
    }) => {
        $($if_true)*
    };

    ($($if_true:tt)*) => {
        $($if_true)*
    }
}

#[cfg(not(all(
    not(miri),
    target_arch = "x86_64",
    any(
        target_os = "linux",
        all(feature = "generic-sandbox", any(target_os = "macos", target_os = "freebsd"))
    ),
    feature = "std",
)))]
macro_rules! if_compiler_is_supported {
    ({
        $($if_true:tt)*
    } else {
        $($if_false:tt)*
    }) => {
        $($if_false)*
    };

    ($($if_true:tt)*) => {}
}

extern crate alloc;

mod error;

mod api;
mod config;
mod gas;
mod interpreter;
mod linker;
mod rostro_intrinsic_gas;

/// Research-grade interpreter tracing — see module docs.
pub mod trace;

/// Rostro intrinsic ABI: ecalli IDs reserved for runtime-internal crypto
/// intrinsics (`100..1023`) and their native helper bodies. Both the
/// interpreter (inline FAST_OP_ECALLI dispatch) and external consumers (e.g.,
/// the JIT runner's host-side ecalli match arm) use these helpers so the two
/// backends produce identical results on guest blobs that opt into the
/// reserved IDs via `polkavm_import(index = N)`.
pub mod rostro_intrinsics {
    pub use crate::interpreter::{
        ROSTRO_INTRINSIC_BLAKE2B_256,
        ROSTRO_INTRINSIC_DILITHIUM_VERIFY,
        ROSTRO_INTRINSIC_ED25519_VERIFY,
        ROSTRO_INTRINSIC_GOLDILOCKS_ADD,
        ROSTRO_INTRINSIC_GOLDILOCKS_INV,
        ROSTRO_INTRINSIC_GOLDILOCKS_MUL,
        ROSTRO_INTRINSIC_GOLDILOCKS_SUB,
        ROSTRO_INTRINSIC_KECCAK_256,
        ROSTRO_INTRINSIC_P521_ECDSA_VERIFY,
        ROSTRO_INTRINSIC_POSEIDON2_PERM,
        ROSTRO_INTRINSIC_SECP256K1_RECOVER,
        goldilocks_add_native, goldilocks_inv_native, goldilocks_mul_native,
        goldilocks_sub_native,
        rostro_blake2b_256, rostro_dilithium_verify, rostro_ed25519_verify,
        rostro_keccak_256, rostro_p521_ecdsa_verify_prehash,
        rostro_poseidon2_permute, rostro_secp256k1_recover,
    };

    /// CustomCodegen impl that emits direct intrinsic calls in JIT-compiled
    /// code, skipping the standard ecalli host trampoline. Goldilocks-only
    /// for now (IDs 100-103); other IDs fall through to the standard sequence.
    /// Wire via `ModuleConfig::set_custom_codegen()` (requires
    /// `Config::set_allow_experimental(true)`).
    /// Only available when the JIT compiler is compiled in — same cfg gate
    /// as `if_compiler_is_supported!`.
    #[cfg(all(
        not(miri),
        target_arch = "x86_64",
        any(
            target_os = "linux",
            all(feature = "generic-sandbox", any(target_os = "macos", target_os = "freebsd"))
        ),
        feature = "std",
    ))]
    pub use crate::rostro_intrinsic_codegen::RostroIntrinsicsCodegen;

    /// Gas pricing for the Tier 2 intrinsics. See
    /// `docs/SECURITY-AUDIT-TIER2-INTRINSICS.md` for calibration and
    /// threat-model rationale.
    pub use crate::rostro_intrinsic_gas::{
        flat_gas, intrinsic_surplus_gas, per_byte_gas, ERR_MSG_LEN_TOO_LARGE,
        MAX_INTRINSIC_MSG_LEN,
    };
}
#[cfg(feature = "std")]
mod source_cache;
mod utils;

#[cfg(feature = "std")]
mod mutex_std;

#[cfg(feature = "std")]
pub(crate) use mutex_std as mutex;

#[cfg(not(feature = "std"))]
mod mutex_no_std;

#[cfg(not(feature = "std"))]
pub(crate) use mutex_no_std as mutex;

impl<T> Default for crate::mutex::Mutex<T>
where
    T: Default,
{
    fn default() -> Self {
        Self::new(Default::default())
    }
}

#[cfg(feature = "module-cache")]
mod module_cache;

if_compiler_is_supported! {
    mod compiler;
    mod page_set;
    mod sandbox;
    mod rostro_intrinsic_codegen;

    #[cfg(all(target_os = "linux", not(feature = "export-internals-for-testing")))]
    mod generic_allocator;

    #[cfg(all(target_os = "linux", not(feature = "export-internals-for-testing")))]
    mod bit_mask;

    #[cfg(target_os = "linux")]
    mod shm_allocator;
}

// These are needed due to: https://github.com/rust-lang/rustfmt/issues/3253
#[cfg(rustfmt)]
mod bit_mask;
#[cfg(rustfmt)]
mod compiler;
#[cfg(rustfmt)]
mod generic_allocator;
#[cfg(rustfmt)]
mod page_set;
#[cfg(rustfmt)]
mod sandbox;
#[cfg(rustfmt)]
mod shm_allocator;

pub use polkavm_common::{
    abi::{MemoryMap, MemoryMapBuilder},
    program::{ProgramBlob, ProgramCounter, ProgramParts, Reg},
    utils::{ArcBytes, AsUninitSliceMut},
};

/// Miscellaneous types related to debug info.
pub mod debug_info {
    pub use polkavm_common::program::{FrameInfo, FrameKind, LineProgram, RegionInfo, SourceLocation};

    #[cfg(feature = "std")]
    pub use crate::source_cache::SourceCache;
}

/// Miscellaneous types related to program blobs.
pub mod program {
    pub use polkavm_common::program::{
        EstimateInterpreterMemoryUsageArgs, ISA_JamV1, ISA_Latest32, ISA_Latest64, ISA_ReviveV1, Imports, ImportsIter, Instruction,
        InstructionSet, InstructionSetKind, Instructions, JumpTable, JumpTableIter, Opcode, ParsedInstruction, ProgramExport,
        ProgramMemoryInfo, ProgramParseError, ProgramSymbol, RawReg,
    };

    // This is meant to be public *eventually*, but since it's still a work-in-progress
    // let's hide it for now so that only those who know what they're doing use it.
    #[doc(hidden)]
    pub use polkavm_common::assembler::assemble;
}

pub type Gas = i64;

pub use crate::api::{CompileError, Engine, MemoryAccessError, MemoryProtection, Module, RawInstance, RegValue, SetCacheSizeLimitArgs};
pub use crate::config::{BackendKind, Config, CustomCodegen, GasMeteringKind, ModuleConfig, SandboxKind};
pub use crate::error::Error;
pub use crate::gas::{Cost, CostModel, CostModelKind, CostModelRef};
pub use crate::linker::{CallError, Caller, Instance, InstancePre, Linker};
pub use crate::utils::{InterruptKind, Segfault};
pub use polkavm_common::simulator::CacheModel;

pub const RETURN_TO_HOST: u64 = polkavm_common::abi::VM_ADDR_RETURN_TO_HOST as u64;

#[cfg(test)]
mod tests;

// These need to be toplevel for the macros to work.
#[cfg(feature = "export-internals-for-testing")]
pub mod generic_allocator;

#[cfg(feature = "export-internals-for-testing")]
pub mod bit_mask;

#[cfg(feature = "export-internals-for-testing")]
#[doc(hidden)]
pub mod _for_testing {
    #[cfg(target_os = "linux")]
    if_compiler_is_supported! {
        pub use crate::shm_allocator::{ShmAllocation, ShmAllocator};
        pub fn create_shm_allocator() -> Result<crate::shm_allocator::ShmAllocator, polkavm_linux_raw::Error> {
            crate::sandbox::init_native_page_size();
            crate::shm_allocator::ShmAllocator::new()
        }

        pub use crate::page_set::PageSet;
    }
}
