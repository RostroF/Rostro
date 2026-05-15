#![allow(unknown_lints)] // Because of `non_local_definitions` on older rustc versions.
#![allow(non_local_definitions)]
#![allow(clippy::unused_self)]
#![allow(clippy::needless_pass_by_ref_mut)]
#![deny(clippy::as_conversions)]
use crate::api::{MemoryAccessError, MemoryProtection, Module, RegValue, SetCacheSizeLimitArgs};
use crate::error::Error;
use crate::gas::{CostModelKind, GasVisitor};
use crate::utils::{FlatMap, InterruptKind, Segfault};
use crate::{Gas, GasMeteringKind, ProgramCounter};
use alloc::boxed::Box;
use alloc::collections::btree_map::Entry;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::mem::MaybeUninit;
use core::num::NonZeroU32;
use core::ops::Range;
use polkavm_common::abi::VM_ADDR_RETURN_TO_HOST;
use polkavm_common::cast::cast;
use polkavm_common::operation::*;
use polkavm_common::program::{
    asm, interpreter_calculate_cache_num_entries, InstructionVisitor, RawReg, Reg, INTERPRETER_CACHE_ENTRY_SIZE,
    INTERPRETER_FLATMAP_ENTRY_SIZE,
};
use polkavm_common::utils::{align_to_next_page_usize, slice_assume_init_mut, ArcBytes, GasVisitorT};

type Target = u32;

#[derive(Copy, Clone)]
pub enum RegImm {
    Reg(Reg),
    Imm(u32),
}

impl From<Reg> for RegImm {
    #[inline]
    fn from(reg: Reg) -> Self {
        RegImm::Reg(reg)
    }
}

impl From<u32> for RegImm {
    #[inline]
    fn from(value: u32) -> Self {
        RegImm::Imm(value)
    }
}

// Define a custom trait instead of just using `Into<RegImm>` to make sure this is always inlined.
trait IntoRegImm {
    fn into(self) -> RegImm;
}

impl IntoRegImm for Reg {
    #[inline(always)]
    fn into(self) -> RegImm {
        RegImm::Reg(self)
    }
}

impl IntoRegImm for u32 {
    #[inline(always)]
    fn into(self) -> RegImm {
        RegImm::Imm(self)
    }
}

trait Memory {
    fn memory_state(instance: &InterpretedInstance) -> &Self;
    fn memory_state_mut(instance: &mut InterpretedInstance) -> &mut Self;

    fn load_impl<T: LoadTy, const DEBUG: bool>(instance: &mut InterpretedInstance, pc: ProgramCounter, dst: Reg, address: u32) -> Option<Target>;
    fn store_impl<T: StoreTy, const DEBUG: bool>(instance: &mut InterpretedInstance, pc: ProgramCounter, address: u32, value: u64) -> Option<Target>;

    /// Tier 2 intrinsic zero-copy memory access (2026-05-12).
    /// Returns a slice into guest memory at [addr, addr+len) ONLY when the
    /// range is fully contained in a single contiguous region's resident
    /// data (no synthesized zeros, no cross-region span). Caller falls back
    /// to `read_memory_into` if `None`. Designed for big-crypto intrinsic
    /// dispatch arms that pass guest memory directly to native crypto fns —
    /// no stack-buffer roundtrip.
    fn borrow_bytes(&self, addr: u32, len: u32) -> Option<&[u8]>;
    fn borrow_bytes_mut(&mut self, addr: u32, len: u32) -> Option<&mut [u8]>;
}

#[repr(align(64))]
struct CacheAligned<T>(pub T);

#[repr(C)]
struct StandardMemory {
    ro_data_size: usize,
    rw_data_original: ArcBytes,
    rw_data_size: usize,
    heap_size: u32,
    stack_size: usize,
    accessible_aux_size: usize,

    max_allocation_size: usize,
    guest_memory_limit: usize,

    stack_address_low: u32,
    stack_address_high: u32,

    _align: CacheAligned<()>,

    aux_data_address: u32,
    stack_address_low_resident: u32,
    rw_data_address: u32,
    ro_data_address: u32,

    stack: Vec<u8>,
    rw_data: Vec<u8>,
    ro_data: ArcBytes,
    aux: Vec<u8>,
}

impl StandardMemory {
    fn new() -> Self {
        Self {
            ro_data: Default::default(),
            ro_data_size: 0,
            rw_data_original: Default::default(),
            rw_data: Default::default(),
            rw_data_size: 0,
            heap_size: 0,
            stack: Default::default(),
            stack_size: 0,
            aux: Default::default(),
            accessible_aux_size: usize::MAX,

            max_allocation_size: usize::MAX,
            guest_memory_limit: usize::MAX,

            aux_data_address: 0,
            stack_address_low: 0,
            stack_address_low_resident: 0,
            stack_address_high: 0,
            rw_data_address: 0,
            ro_data_address: 0,
            _align: CacheAligned(()),
        }
    }
}

#[allow(clippy::transmute_ptr_to_ptr)]
#[inline]
fn transmute_to_uninit(slice: &[u8]) -> &[MaybeUninit<u8>] {
    // SAFETY: Transmuting `&[u8]` into `&[MaybeUninit<u8>]` is safe since the layout of `[MaybeUninit<u8>]` is guaranteed to be the same as `[u8]`.
    unsafe { core::mem::transmute(slice) }
}

// Resize in chunks for efficiency.
const RESIZE_GRANULARITY: usize = 4096;

enum SliceOrLength<'a> {
    Slice(&'a [u8]),
    Length(usize),
}

impl<'a> SliceOrLength<'a> {
    #[inline]
    fn len(&self) -> usize {
        match self {
            Self::Slice(slice) => slice.len(),
            Self::Length(length) => *length,
        }
    }

    #[inline]
    fn copy_into(&self, target: &mut [u8]) {
        match self {
            Self::Slice(slice) => target.copy_from_slice(slice),
            Self::Length(length) => {
                debug_assert_eq!(target.len(), *length);
                target.fill(0)
            }
        }
    }
}

fn reserve_memory<T>(
    vec: &mut Vec<T>,
    minimum_length: usize,
    maximum_allocation_size_in_bytes: usize,
    memory_limit: usize,
    memory_used: usize,
) -> bool {
    const {
        assert!(core::mem::size_of::<T>() > 0);
        assert!(RESIZE_GRANULARITY % core::mem::size_of::<T>() == 0);
    }

    if vec.capacity() >= minimum_length {
        return true;
    }

    let memory_used = memory_used + vec.capacity();
    let minimum_bytes = minimum_length * core::mem::size_of::<T>();
    if minimum_bytes > maximum_allocation_size_in_bytes || memory_used >= memory_limit {
        return false;
    }

    let target_bytes = minimum_bytes
        .next_power_of_two()
        .max(RESIZE_GRANULARITY)
        .min(maximum_allocation_size_in_bytes);

    let extra_bytes = target_bytes - vec.capacity();
    if extra_bytes > memory_limit - memory_used {
        return false;
    }

    let target_elements = target_bytes / core::mem::size_of::<T>();
    let current_elements = vec.len();
    vec.reserve_exact(target_elements - current_elements);
    vec.capacity() >= minimum_length
}

enum PrepareWriteResult {
    Ok(Range<usize>),
    OutOfRangeAccess,
    MemoryLimitReached,
}

impl StandardMemory {
    fn accessible_aux_size(&self) -> u32 {
        cast(self.accessible_aux_size).assert_always_fits_in_u32()
    }

    fn set_accessible_aux_size(&mut self, size: u32) {
        self.accessible_aux_size = cast(size).to_usize();
        self.aux.truncate(self.accessible_aux_size);
    }

    fn read_memory_into<'slice>(
        &mut self,
        address: u32,
        buffer: &'slice mut [MaybeUninit<u8>],
    ) -> Result<&'slice mut [u8], MemoryAccessError> {
        if address >= self.aux_data_address {
            let offset = cast(address - self.aux_data_address).to_usize();
            let offset_end = offset + buffer.len();

            if offset_end <= self.accessible_aux_size {
                let resident_range = offset.min(self.aux.len())..offset_end.min(self.aux.len());
                buffer[..resident_range.len()].copy_from_slice(&transmute_to_uninit(&self.aux)[resident_range.clone()]);
                buffer[resident_range.len()..].fill(MaybeUninit::new(0));

                // SAFETY: The buffer was initialized.
                return Ok(unsafe { slice_assume_init_mut(buffer) });
            }
        } else if address >= self.stack_address_low {
            let offset = cast(address - self.stack_address_low).to_usize();
            let offset_end = offset + buffer.len();

            if offset_end <= self.stack_size {
                let resident_offset = self.stack_size - self.stack.len();
                let non_resident_range = offset.min(resident_offset)..offset_end.min(resident_offset);
                let resident_range = offset.max(resident_offset) - resident_offset..offset_end.max(resident_offset) - resident_offset;
                buffer[..non_resident_range.len()].fill(MaybeUninit::new(0));
                buffer[non_resident_range.len()..].copy_from_slice(&transmute_to_uninit(&self.stack)[resident_range]);

                // SAFETY: The buffer was initialized.
                return Ok(unsafe { slice_assume_init_mut(buffer) });
            }
        } else if address >= self.rw_data_address {
            let offset = cast(address - self.rw_data_address).to_usize();
            let offset_end = offset + buffer.len();

            if offset_end <= self.rw_data_size {
                let resident_range = offset.min(self.rw_data.len())..offset_end.min(self.rw_data.len());
                buffer[..resident_range.len()].copy_from_slice(&transmute_to_uninit(&self.rw_data)[resident_range.clone()]);

                let non_resident_range =
                    (offset + resident_range.len()).min(self.rw_data_original.len())..offset_end.min(self.rw_data_original.len());
                buffer[resident_range.len()..resident_range.len() + non_resident_range.len()]
                    .copy_from_slice(&transmute_to_uninit(&self.rw_data_original)[non_resident_range.clone()]);
                buffer[resident_range.len() + non_resident_range.len()..].fill(MaybeUninit::new(0));

                // SAFETY: The buffer was initialized.
                return Ok(unsafe { slice_assume_init_mut(buffer) });
            }
        } else if address >= self.ro_data_address {
            let offset = cast(address - self.ro_data_address).to_usize();
            let offset_end = offset + buffer.len();

            if offset_end <= self.ro_data_size {
                let src_range = offset.min(self.ro_data.len())..offset_end.min(self.ro_data.len());
                buffer[..src_range.len()].copy_from_slice(&transmute_to_uninit(&self.ro_data)[src_range.clone()]);
                buffer[src_range.len()..].fill(MaybeUninit::new(0));

                // SAFETY: The buffer was initialized.
                return Ok(unsafe { slice_assume_init_mut(buffer) });
            }
        }

        Err(MemoryAccessError::OutOfRangeAccess {
            address,
            length: cast(buffer.len()).to_u64(),
        })
    }

    fn zero_or_write_memory(&mut self, address: u32, contents: SliceOrLength) -> Result<(), MemoryAccessError> {
        if address >= self.aux_data_address {
            let range = {
                let offset = cast(address - self.aux_data_address).to_usize();
                offset..offset + contents.len()
            };

            if range.end <= self.accessible_aux_size {
                if !self.aux_resize(range.end) {
                    return Err(MemoryAccessError::MemoryLimitReached);
                }

                if let Some(target) = self.aux.get_mut(range) {
                    contents.copy_into(target);
                    return Ok(());
                }
            }
        } else if address >= self.stack_address_low {
            match self.prepare_stack_write(cast(address).to_usize(), contents.len()) {
                PrepareWriteResult::Ok(range) => {
                    if let Some(target) = self.stack.get_mut(range) {
                        contents.copy_into(target);
                        return Ok(());
                    }
                }
                PrepareWriteResult::MemoryLimitReached => {
                    return Err(MemoryAccessError::MemoryLimitReached);
                }
                PrepareWriteResult::OutOfRangeAccess => {}
            }
        } else if address >= self.rw_data_address {
            let range = {
                let offset = cast(address - self.rw_data_address).to_usize();
                offset..offset + contents.len()
            };

            if range.end <= self.rw_data_size {
                if self.rw_data_resize(range.end) {
                    contents.copy_into(&mut self.rw_data[range]);
                    return Ok(());
                } else {
                    return Err(MemoryAccessError::MemoryLimitReached);
                }
            }
        }

        Err(MemoryAccessError::OutOfRangeAccess {
            address,
            length: cast(contents.len()).to_u64(),
        })
    }

    fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), MemoryAccessError> {
        self.zero_or_write_memory(address, SliceOrLength::Slice(data))
    }

    fn zero_memory(&mut self, address: u32, length: u32, memory_protection: Option<MemoryProtection>) -> Result<(), MemoryAccessError> {
        debug_assert!(memory_protection.is_none());
        self.zero_or_write_memory(address, SliceOrLength::Length(cast(length).to_usize()))
    }

    fn heap_size(&self) -> u32 {
        self.heap_size
    }

    fn sbrk(&mut self, module: &Module, size: u32) -> Option<u32> {
        let Some(new_heap_size) = self.heap_size.checked_add(size) else {
            log::trace!(
                "sbrk: heap size overflow; ignoring request: heap_size={} + size={} > 0xffffffff",
                self.heap_size,
                size
            );
            return None;
        };
        let memory_map = module.memory_map();
        if new_heap_size > memory_map.max_heap_size() {
            log::trace!(
                "sbrk: new heap size is too large; ignoring request: {} > {}",
                new_heap_size,
                memory_map.max_heap_size()
            );
            return None;
        }

        log::trace!("sbrk: +{} (heap size: {} -> {})", size, self.heap_size, new_heap_size);

        self.heap_size = new_heap_size;
        let heap_top = memory_map.heap_base() + new_heap_size;
        if cast(heap_top).to_usize() > cast(memory_map.rw_data_address()).to_usize() + self.rw_data_size {
            let new_size = align_to_next_page_usize(cast(memory_map.page_size()).to_usize(), cast(heap_top).to_usize()).unwrap()
                - cast(memory_map.rw_data_address()).to_usize();

            log::trace!("sbrk: growing memory: {} -> {}", self.rw_data_size, new_size);
            self.rw_data_size = new_size;
        }

        Some(heap_top)
    }

    fn mark_dirty(&mut self) {}

    fn reset_memory(&mut self, module: &Module) {
        let memory_map = module.memory_map();
        self.ro_data = module.blob().ro_data_arc().clone();
        self.ro_data_size = cast(memory_map.ro_data_size()).to_usize();
        self.rw_data.clear();
        self.rw_data_original = module.blob().rw_data_arc().clone();
        self.rw_data_size = cast(memory_map.rw_data_size()).to_usize();
        self.heap_size = 0;
        self.stack.clear();
        self.stack_size = cast(memory_map.stack_size()).to_usize();
        self.aux.clear();
        self.accessible_aux_size = cast(memory_map.aux_data_size()).to_usize();

        self.aux_data_address = memory_map.aux_data_address();
        self.stack_address_low = memory_map.stack_address_low();
        self.stack_address_high = memory_map.stack_address_high();
        self.stack_address_low_resident = self.stack_address_high;
        self.rw_data_address = memory_map.rw_data_address();
        self.ro_data_address = memory_map.ro_data_address();
    }

    #[must_use]
    #[cold]
    fn rw_data_resize(&mut self, required_size: usize) -> bool {
        if !reserve_memory(
            &mut self.rw_data,
            required_size,
            self.max_allocation_size,
            self.guest_memory_limit,
            self.stack.capacity() + self.aux.capacity(),
        ) {
            return false;
        }

        debug_assert!(self.rw_data.capacity().is_power_of_two());
        debug_assert!(self.rw_data.capacity() <= self.max_allocation_size);

        let new_length = self.rw_data.capacity().min(required_size.next_multiple_of(RESIZE_GRANULARITY));
        if self.rw_data.len() < self.rw_data_original.len() {
            let new_length_partial = new_length.min(self.rw_data_original.len());
            let old_length = self.rw_data.len();
            let bytes_to_copy = new_length_partial - old_length;

            // TODO: Use `write_copy_of_slice` once we switch to Rust 0.93.0.
            self.rw_data.spare_capacity_mut()[..bytes_to_copy]
                .copy_from_slice(transmute_to_uninit(&self.rw_data_original[old_length..old_length + bytes_to_copy]));

            debug_assert_eq!(self.rw_data.len() + bytes_to_copy, new_length_partial);

            // SAFETY: We've initialized the spare capacity, so calling `set_len` is safe.
            unsafe {
                self.rw_data.set_len(new_length_partial);
            }
        }

        debug_assert!(new_length <= self.rw_data.capacity());
        self.rw_data.resize(new_length, 0);

        true
    }

    #[must_use]
    #[cold]
    fn stack_resize(&mut self, required_size: usize) -> bool {
        let mut new_stack = Vec::new();
        if !reserve_memory(
            &mut new_stack,
            required_size,
            self.max_allocation_size,
            self.guest_memory_limit,
            self.rw_data.capacity() + self.aux.capacity(),
        ) {
            return false;
        }

        debug_assert!(new_stack.capacity().is_power_of_two());
        debug_assert!(new_stack.capacity() <= self.max_allocation_size);

        let uninitialized = new_stack.spare_capacity_mut();
        let new_size = uninitialized.len();
        let new_space = new_size - self.stack.len();
        uninitialized[..new_space].fill(MaybeUninit::new(0));
        uninitialized[new_space..].copy_from_slice(transmute_to_uninit(&self.stack));

        // SAFETY: The buffer is fully initialized.
        unsafe {
            new_stack.set_len(new_size);
        }

        self.stack = new_stack;
        self.stack_address_low_resident = self.stack_address_high - cast(self.stack.len()).assert_always_fits_in_u32();
        true
    }

    #[must_use]
    fn prepare_stack_write(&mut self, address: usize, length: usize) -> PrepareWriteResult {
        let stack_hi = cast(self.stack_address_high).to_usize();
        if address + length > stack_hi {
            return PrepareWriteResult::OutOfRangeAccess;
        }

        let required_size = stack_hi - address;
        if required_size > self.stack.len() {
            if required_size > self.stack_size {
                return PrepareWriteResult::OutOfRangeAccess;
            }

            if !self.stack_resize(required_size) {
                return PrepareWriteResult::MemoryLimitReached;
            }
        }

        let stack_lo = stack_hi - self.stack.len();
        let offset = address - stack_lo;
        PrepareWriteResult::Ok(offset..offset + length)
    }

    #[must_use]
    #[cold]
    fn aux_resize(&mut self, required_size: usize) -> bool {
        if !reserve_memory(
            &mut self.aux,
            required_size,
            self.max_allocation_size,
            self.guest_memory_limit,
            self.rw_data.capacity() + self.stack.capacity(),
        ) {
            return false;
        }

        debug_assert!(self.aux.capacity().is_power_of_two());
        debug_assert!(self.aux.capacity() <= self.max_allocation_size);

        let new_length = self.aux.capacity().min(required_size.next_multiple_of(RESIZE_GRANULARITY));
        debug_assert!(new_length <= self.aux.capacity());
        self.aux.resize(new_length, 0);
        true
    }

    #[cold]
    #[inline(never)]
    fn store_impl_slow<T: StoreTy, const DEBUG: bool>(instance: &mut InterpretedInstance, pc: ProgramCounter, address: u32, value: u64) -> Option<Target> {
        macro_rules! range {
            ($base_address:expr) => {{
                let offset = cast(address - $base_address).to_usize();
                let offset_end = offset + core::mem::size_of::<T>();
                offset..offset_end
            }};
        }

        if address >= Self::memory_state(instance).stack_address_low {
            let prep = Self::memory_state_mut(instance).prepare_stack_write(cast(address).to_usize(), core::mem::size_of::<T>());
            instance.hot_stack_low_resident = instance.standard_memory.stack_address_low_resident;
            match prep {
                PrepareWriteResult::Ok(range) => {
                    if let Some(subslice) = Self::memory_state_mut(instance).stack.get_mut(range) {
                        let value = T::into_bytes(value);
                        subslice.copy_from_slice(value.as_ref());
                        instance.on_store_ok::<T, DEBUG>()
                    } else {
                        instance.on_store_trap::<T, DEBUG>(pc, address)
                    }
                }
                PrepareWriteResult::OutOfRangeAccess => instance.on_store_trap::<T, DEBUG>(pc, address),
                PrepareWriteResult::MemoryLimitReached => instance.on_store_trap_due_to_memory_limit::<T, DEBUG>(pc, address),
            }
        } else if address >= Self::memory_state(instance).rw_data_address {
            let range = range!(Self::memory_state(instance).rw_data_address);
            if let Some(subslice) = Self::memory_state_mut(instance).rw_data.get_mut(range.clone()) {
                let value = T::into_bytes(value);
                subslice.copy_from_slice(value.as_ref());
                return instance.on_store_ok::<T, DEBUG>();
            }

            if range.end > Self::memory_state(instance).rw_data_size {
                return instance.on_store_trap::<T, DEBUG>(pc, address);
            }

            if !Self::memory_state_mut(instance).rw_data_resize(range.end) {
                return instance.on_store_trap_due_to_memory_limit::<T, DEBUG>(pc, address);
            }

            if let Some(subslice) = Self::memory_state_mut(instance).rw_data.get_mut(range) {
                let value = T::into_bytes(value);
                subslice.copy_from_slice(value.as_ref());
                instance.on_store_ok::<T, DEBUG>()
            } else {
                instance.on_store_trap::<T, DEBUG>(pc, address)
            }
        } else {
            instance.on_store_trap::<T, DEBUG>(pc, address)
        }
    }

    fn load_rw_data_slow<T: LoadTy, const DEBUG: bool>(
        instance: &mut InterpretedInstance,
        pc: ProgramCounter,
        dst: Reg,
        address: u32,
        range: Range<usize>,
    ) -> Option<Target> {
        let state = Self::memory_state(instance);
        if range.end > state.rw_data_size {
            instance.on_load_trap::<T, DEBUG>(pc, address)
        } else {
            let mut buffer = T::Slice::default();

            let resident_range = range.start.min(state.rw_data.len())..range.end.min(state.rw_data.len());
            buffer[..resident_range.len()].copy_from_slice(&state.rw_data[resident_range.clone()]);

            let non_resident_range =
                (range.start + resident_range.len()).min(state.rw_data_original.len())..range.end.min(state.rw_data_original.len());
            buffer[resident_range.len()..resident_range.len() + non_resident_range.len()]
                .copy_from_slice(&state.rw_data_original[non_resident_range]);

            instance.on_load_ok::<T, DEBUG>(dst, address, T::from_slice(buffer.as_ref()))
        }
    }

    fn load_ro_data_slow<T: LoadTy, const DEBUG: bool>(
        instance: &mut InterpretedInstance,
        pc: ProgramCounter,
        dst: Reg,
        address: u32,
        range: Range<usize>,
    ) -> Option<Target> {
        let state = Self::memory_state(instance);
        if range.end > state.ro_data_size {
            instance.on_load_trap::<T, DEBUG>(pc, address)
        } else {
            let mut buffer = T::Slice::default();
            let src_range = range.start.min(state.ro_data.len())..range.end.min(state.ro_data.len());
            buffer[..src_range.len()].copy_from_slice(&state.ro_data[src_range]);
            instance.on_load_ok::<T, DEBUG>(dst, address, T::from_slice(buffer.as_ref()))
        }
    }

    fn load_stack_slow<T: LoadTy, const DEBUG: bool>(
        instance: &mut InterpretedInstance,
        pc: ProgramCounter,
        dst: Reg,
        address: u32,
        offset: usize,
    ) -> Option<Target> {
        let state = Self::memory_state(instance);
        let offset_end = offset + core::mem::size_of::<T>();
        if offset_end > state.stack_size {
            instance.on_load_trap::<T, DEBUG>(pc, address)
        } else {
            let resident_offset = state.stack_size - state.stack.len();
            let non_resident_range = offset.min(resident_offset)..offset_end.min(resident_offset);
            let resident_range = offset.max(resident_offset) - resident_offset..offset_end.max(resident_offset) - resident_offset;
            let mut buffer = T::Slice::default();
            buffer[non_resident_range.len()..].copy_from_slice(&state.stack[resident_range]);
            instance.on_load_ok::<T, DEBUG>(dst, address, T::from_slice(buffer.as_ref()))
        }
    }

    fn load_aux_slow<T: LoadTy, const DEBUG: bool>(
        instance: &mut InterpretedInstance,
        pc: ProgramCounter,
        dst: Reg,
        address: u32,
        range: Range<usize>,
    ) -> Option<Target> {
        let state = Self::memory_state(instance);
        if range.end > state.accessible_aux_size {
            instance.on_load_trap::<T, DEBUG>(pc, address)
        } else {
            let mut buffer = T::Slice::default();
            let src_range = range.start.min(state.aux.len())..range.end.min(state.aux.len());
            buffer[..src_range.len()].copy_from_slice(&state.aux[src_range]);
            instance.on_load_ok::<T, DEBUG>(dst, address, T::from_slice(buffer.as_ref()))
        }
    }

    #[cold]
    #[inline(never)]
    fn load_impl_slow<T: LoadTy, const DEBUG: bool>(instance: &mut InterpretedInstance, pc: ProgramCounter, dst: Reg, address: u32) -> Option<Target> {
        macro_rules! range {
            ($base_address:expr) => {{
                let offset = cast(address - $base_address).to_usize();
                let offset_end = offset + core::mem::size_of::<T>();
                offset..offset_end
            }};
        }

        let state = Self::memory_state(instance);
        if address >= state.aux_data_address {
            let range = range!(state.aux_data_address);
            Self::load_aux_slow::<T, DEBUG>(instance, pc, dst, address, range)
        } else if address >= state.stack_address_low {
            Self::load_stack_slow::<T, DEBUG>(instance, pc, dst, address, cast(address - state.stack_address_low).to_usize())
        } else if address >= state.rw_data_address {
            let range = range!(state.rw_data_address);
            Self::load_rw_data_slow::<T, DEBUG>(instance, pc, dst, address, range)
        } else if address >= state.ro_data_address {
            let range = range!(state.ro_data_address);
            Self::load_ro_data_slow::<T, DEBUG>(instance, pc, dst, address, range)
        } else {
            instance.on_load_trap::<T, DEBUG>(pc, address)
        }
    }

    // Dynamic memory-only methods.
    fn is_memory_accessible(&self, _address: u32, _size: u32, _minimum_protection: MemoryProtection) -> bool {
        unimplemented!()
    }

    fn change_memory_protection(&mut self, _address: u32, _length: u32, _protection: MemoryProtection) -> Result<(), MemoryAccessError> {
        unimplemented!();
    }

    fn free_pages(&mut self, _address: u32, _length: u32) {
        unimplemented!()
    }
}

impl Memory for StandardMemory {
    #[inline(always)]
    fn memory_state(instance: &InterpretedInstance) -> &Self {
        &instance.standard_memory
    }

    #[inline(always)]
    fn memory_state_mut(instance: &mut InterpretedInstance) -> &mut Self {
        &mut instance.standard_memory
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn load_impl<T: LoadTy, const DEBUG: bool>(instance: &mut InterpretedInstance, pc: ProgramCounter, dst: Reg, address: u32) -> Option<Target> {
        let aux_addr = instance.hot_aux_address;
        let stack_low = instance.hot_stack_low_resident;
        let rw_addr = instance.hot_rw_address;
        let ro_addr = instance.hot_ro_address;
        let state = Self::memory_state(instance);
        let (offset, slice) = if address >= aux_addr {
            (cast(address - aux_addr).to_usize(), &state.aux[..])
        } else if address >= stack_low {
            (cast(address - stack_low).to_usize(), &state.stack[..])
        } else if address >= rw_addr {
            (cast(address - rw_addr).to_usize(), &state.rw_data[..])
        } else if address >= ro_addr {
            (cast(address - ro_addr).to_usize(), &state.ro_data[..])
        } else {
            return Self::load_impl_slow::<T, DEBUG>(instance, pc, dst, address);
        };

        let range = offset..offset + core::mem::size_of::<T>();
        if let Some(subslice) = slice.get(range) {
            instance.on_load_ok::<T, DEBUG>(dst, address, T::from_slice(subslice))
        } else {
            Self::load_impl_slow::<T, DEBUG>(instance, pc, dst, address)
        }
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn store_impl<T: StoreTy, const DEBUG: bool>(instance: &mut InterpretedInstance, pc: ProgramCounter, address: u32, value: u64) -> Option<Target> {
        let stack_low = instance.hot_stack_low_resident;
        let rw_addr = instance.hot_rw_address;
        let (offset, slice) = if address >= stack_low {
            (
                cast(address - stack_low).to_usize(),
                &mut Self::memory_state_mut(instance).stack[..],
            )
        } else if address >= rw_addr {
            (
                cast(address - rw_addr).to_usize(),
                &mut Self::memory_state_mut(instance).rw_data[..],
            )
        } else {
            return Self::store_impl_slow::<T, DEBUG>(instance, pc, address, value);
        };

        let range = offset..offset + core::mem::size_of::<T>();
        if let Some(subslice) = slice.get_mut(range) {
            let value = T::into_bytes(value);
            subslice.copy_from_slice(value.as_ref());
            instance.on_store_ok::<T, DEBUG>()
        } else {
            Self::store_impl_slow::<T, DEBUG>(instance, pc, address, value)
        }
    }

    fn borrow_bytes(&self, addr: u32, len: u32) -> Option<&[u8]> {
        let len = len as usize;
        // Region check mirrors load_impl's region selection. Returns a
        // contiguous slice only when the range is fully resident in one
        // region's actual data Vec (no synthesized zeros for non-resident
        // tails, no cross-region span). Falls back to None otherwise.
        if addr >= self.aux_data_address {
            let offset = (addr - self.aux_data_address) as usize;
            return self.aux.get(offset..offset.checked_add(len)?);
        }
        if addr >= self.stack_address_low_resident {
            let offset = (addr - self.stack_address_low_resident) as usize;
            return self.stack.get(offset..offset.checked_add(len)?);
        }
        if addr >= self.rw_data_address {
            let offset = (addr - self.rw_data_address) as usize;
            return self.rw_data.get(offset..offset.checked_add(len)?);
        }
        if addr >= self.ro_data_address {
            let offset = (addr - self.ro_data_address) as usize;
            return self.ro_data.get(offset..offset.checked_add(len)?);
        }
        None
    }

    fn borrow_bytes_mut(&mut self, addr: u32, len: u32) -> Option<&mut [u8]> {
        let len = len as usize;
        // ro_data is read-only; intentionally not exposed as &mut. aux/stack/
        // rw_data are mutable.
        if addr >= self.aux_data_address {
            let offset = (addr - self.aux_data_address) as usize;
            return self.aux.get_mut(offset..offset.checked_add(len)?);
        }
        if addr >= self.stack_address_low_resident {
            let offset = (addr - self.stack_address_low_resident) as usize;
            return self.stack.get_mut(offset..offset.checked_add(len)?);
        }
        if addr >= self.rw_data_address {
            let offset = (addr - self.rw_data_address) as usize;
            return self.rw_data.get_mut(offset..offset.checked_add(len)?);
        }
        // ro_data falls through to None — intentional.
        None
    }
}

struct Page {
    data: Box<[u8]>,
    is_read_only: bool,
}

impl Page {
    fn empty(page_size: u32) -> Self {
        let mut page = Vec::new();
        page.reserve_exact(cast(page_size).to_usize());
        page.resize(cast(page_size).to_usize(), 0);
        Page {
            data: page.into(),
            is_read_only: false,
        }
    }
}

impl core::ops::Deref for Page {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl core::ops::DerefMut for Page {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

pub(crate) struct DynamicMemory {
    pages: BTreeMap<u32, Page>,
    page_size: u32,
    page_size_mask: u32,
}

impl DynamicMemory {
    #[inline]
    fn round_to_page_size_down(&self, value: u32) -> u32 {
        value & !self.page_size_mask
    }

    #[inline]
    fn is_multiple_of_page_size(&self, value: u32) -> bool {
        (value & self.page_size_mask) == 0
    }

    #[inline]
    fn to_page_address(&self, address: u32, length: u32) -> (u32, u32, u32) {
        let page_address_lo = self.round_to_page_size_down(address);
        let page_address_hi = self.round_to_page_size_down(address + (length - 1));
        (self.page_size, page_address_lo, page_address_hi)
    }

    fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
            page_size: 0,
            page_size_mask: 0,
        }
    }

    fn clear(&mut self) {
        self.pages.clear()
    }

    fn is_memory_accessible(&self, address: u32, size: u32, minimum_protection: MemoryProtection) -> bool {
        // TODO: This is very slow.
        let result = each_page(self.to_page_address(address, size), address, size, |page_address, _, _, _| {
            if let Some(page) = self.pages.get(&page_address) {
                match minimum_protection {
                    MemoryProtection::ReadWrite => {
                        if page.is_read_only {
                            Err(())
                        } else {
                            Ok(())
                        }
                    }
                    MemoryProtection::Read => Ok(()),
                }
            } else {
                Err(())
            }
        });

        result.is_ok()
    }

    fn read_memory_into<'slice>(&self, address: u32, buffer: &'slice mut [MaybeUninit<u8>]) -> Result<&'slice mut [u8], MemoryAccessError> {
        each_page(
            self.to_page_address(address, cast(buffer.len()).assert_always_fits_in_u32()),
            address,
            cast(buffer.len()).assert_always_fits_in_u32(),
            |page_address, page_offset, buffer_offset, length| {
                assert!(buffer_offset + length <= buffer.len());
                assert!(page_offset + length <= cast(self.page_size).to_usize());
                let page = self.pages.get(&page_address);

                // SAFETY: Buffers are non-overlapping and the ranges are in-bounds.
                unsafe {
                    let dst = buffer.as_mut_ptr().cast::<u8>().add(buffer_offset);
                    if let Some(page) = page {
                        let src = page.as_ptr().add(page_offset);
                        core::ptr::copy_nonoverlapping(src, dst, length);
                        Ok(())
                    } else {
                        Err(MemoryAccessError::OutOfRangeAccess {
                            address: page_address + cast(page_offset).assert_always_fits_in_u32(),
                            length: cast(length).to_u64(),
                        })
                    }
                }
            },
        )?;

        // SAFETY: The buffer was initialized.
        Ok(unsafe { slice_assume_init_mut(buffer) })
    }

    fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), MemoryAccessError> {
        if !self.is_memory_accessible(address, cast(data.len()).assert_always_fits_in_u32(), MemoryProtection::ReadWrite) {
            return Err(MemoryAccessError::OutOfRangeAccess {
                address,
                length: cast(data.len()).to_u64(),
            });
        }

        let dynamic_memory = self;
        let page_size = dynamic_memory.page_size;
        each_page::<()>(
            dynamic_memory.to_page_address(address, cast(data.len()).assert_always_fits_in_u32()),
            address,
            cast(data.len()).assert_always_fits_in_u32(),
            move |page_address, page_offset, buffer_offset, length| {
                let page = dynamic_memory.pages.entry(page_address).or_insert_with(|| Page::empty(page_size));
                page[page_offset..page_offset + length].copy_from_slice(&data[buffer_offset..buffer_offset + length]);
                Ok(())
            },
        )
        .unwrap();

        Ok(())
    }

    fn zero_memory(&mut self, address: u32, length: u32, memory_protection: Option<MemoryProtection>) -> Result<(), MemoryAccessError> {
        if memory_protection.is_some() {
            debug_assert!(self.is_multiple_of_page_size(address));
            debug_assert!(self.is_multiple_of_page_size(length));
        } else if !self.is_memory_accessible(address, length, MemoryProtection::ReadWrite) {
            return Err(MemoryAccessError::OutOfRangeAccess {
                address,
                length: u64::from(length),
            });
        }

        let is_read_only = memory_protection.map(|prot| match prot {
            MemoryProtection::Read => true,
            MemoryProtection::ReadWrite => false,
        });

        let dynamic_memory = self;
        let page_size = dynamic_memory.page_size;

        each_page::<()>(
            dynamic_memory.to_page_address(address, length),
            address,
            length,
            move |page_address, page_offset, _, length| match dynamic_memory.pages.entry(page_address) {
                Entry::Occupied(mut entry) => {
                    let page = entry.get_mut();
                    page[page_offset..page_offset + length].fill(0);
                    if let Some(is_read_only) = is_read_only {
                        page.is_read_only = is_read_only;
                    }
                    Ok(())
                }
                Entry::Vacant(entry) => {
                    let mut page = Page::empty(page_size);
                    if let Some(is_read_only) = is_read_only {
                        page.is_read_only = is_read_only;
                    }
                    entry.insert(page);
                    Ok(())
                }
            },
        )
        .unwrap();

        Ok(())
    }

    fn change_memory_protection(&mut self, address: u32, length: u32, protection: MemoryProtection) -> Result<(), MemoryAccessError> {
        each_page(
            self.to_page_address(address, length),
            address,
            length,
            |page_address, page_offset, _buffer_offset, length| {
                if let Some(page) = self.pages.get_mut(&page_address) {
                    page.is_read_only = match protection {
                        MemoryProtection::Read => true,
                        MemoryProtection::ReadWrite => false,
                    };
                    Ok(())
                } else {
                    Err(MemoryAccessError::OutOfRangeAccess {
                        address: page_address + cast(page_offset).assert_always_fits_in_u32(),
                        length: cast(length).to_u64(),
                    })
                }
            },
        )?;

        Ok(())
    }

    fn free_pages(&mut self, address: u32, length: u32) {
        debug_assert!(self.is_multiple_of_page_size(address));
        debug_assert_ne!(length, 0);

        let dynamic_memory = self;
        each_page::<()>(
            dynamic_memory.to_page_address(address, length),
            address,
            length,
            move |page_address, _, _, _| {
                dynamic_memory.pages.remove(&page_address);
                Ok(())
            },
        )
        .unwrap();
    }

    fn mark_dirty(&self) {}

    fn reset_memory(&mut self, module: &Module) {
        self.clear();
        self.page_size = module.memory_map().page_size();

        let page_shift = self.page_size.ilog2();
        self.page_size_mask = (1 << page_shift) - 1;
    }

    fn accessible_aux_size(&self) -> u32 {
        unimplemented!();
    }

    fn set_accessible_aux_size(&mut self, _size: u32) {
        unimplemented!();
    }

    fn heap_size(&self) -> u32 {
        unimplemented!();
    }

    fn sbrk(&mut self, _module: &Module, _size: u32) -> Option<u32> {
        unimplemented!();
    }
}

impl Memory for DynamicMemory {
    fn memory_state(instance: &InterpretedInstance) -> &Self {
        &instance.dynamic_memory
    }

    fn memory_state_mut(instance: &mut InterpretedInstance) -> &mut Self {
        &mut instance.dynamic_memory
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn load_impl<T: LoadTy, const DEBUG: bool>(instance: &mut InterpretedInstance, pc: ProgramCounter, dst: Reg, address: u32) -> Option<Target> {
        let length = cast(core::mem::size_of::<T>()).assert_always_fits_in_u32();
        let Some(address_end) = address.checked_add(length) else {
            let page_address = Self::memory_state(instance).round_to_page_size_down(0xffffffff);
            if Self::memory_state(instance).pages.contains_key(&page_address) {
                return instance.on_load_trap::<T, DEBUG>(pc, address);
            } else {
                return instance.on_load_segfault::<T, DEBUG>(pc, address, page_address, false);
            }
        };

        let page_address_lo = Self::memory_state(instance).round_to_page_size_down(address);
        let page_address_hi = Self::memory_state(instance).round_to_page_size_down(address_end - 1);
        if page_address_lo == page_address_hi {
            if let Some(page) = Self::memory_state_mut(instance).pages.get_mut(&page_address_lo) {
                let offset = cast(address).to_usize() - cast(page_address_lo).to_usize();
                let value = T::from_slice(&page[offset..offset + core::mem::size_of::<T>()]);
                instance.on_load_ok::<T, DEBUG>(dst, address, value)
            } else {
                instance.on_load_segfault::<T, DEBUG>(pc, address, page_address_lo, false)
            }
        } else {
            let mut iter = Self::memory_state(instance).pages.range(page_address_lo..=page_address_hi);
            let lo = iter.next();
            let hi = iter.next();

            match (lo, hi) {
                (Some((_, lo)), Some((_, hi))) => {
                    let page_size = cast(Self::memory_state(instance).page_size).to_usize();
                    let lo_len = cast(page_address_hi).to_usize() - cast(address).to_usize();
                    let hi_len = core::mem::size_of::<T>() - lo_len;
                    let mut buffer = [0; 8];
                    let buffer = &mut buffer[..core::mem::size_of::<T>()];
                    buffer[..lo_len].copy_from_slice(&lo[page_size - lo_len..]);
                    buffer[lo_len..].copy_from_slice(&hi[..hi_len]);
                    instance.on_load_ok::<T, DEBUG>(dst, address, T::from_slice(buffer))
                }
                (None, _) => instance.on_load_segfault::<T, DEBUG>(pc, address, page_address_lo, false),
                (Some((page_address, _)), _) => {
                    let missing_page_address = if *page_address == page_address_lo {
                        page_address_hi
                    } else {
                        page_address_lo
                    };

                    instance.on_load_segfault::<T, DEBUG>(pc, address, missing_page_address, false)
                }
            }
        }
    }

    fn store_impl<T: StoreTy, const DEBUG: bool>(instance: &mut InterpretedInstance, pc: ProgramCounter, address: u32, value: u64) -> Option<Target> {
        let length = cast(core::mem::size_of::<T>()).assert_always_fits_in_u32();
        let Some(address_end) = address.checked_add(length) else {
            let page_address = Self::memory_state(instance).round_to_page_size_down(0xffffffff);
            if Self::memory_state(instance).pages.contains_key(&page_address) {
                return instance.on_store_trap::<T, DEBUG>(pc, address);
            } else {
                return instance.on_store_segfault::<T, DEBUG>(pc, address, page_address, false);
            }
        };

        let page_address_lo = Self::memory_state(instance).round_to_page_size_down(address);
        let page_address_hi = Self::memory_state(instance).round_to_page_size_down(address_end - 1);
        if page_address_lo == page_address_hi {
            if let Some(page) = Self::memory_state_mut(instance).pages.get_mut(&page_address_lo) {
                if page.is_read_only {
                    return instance.on_store_segfault::<T, DEBUG>(pc, address, page_address_lo, true);
                }

                let offset = cast(address).to_usize() - cast(page_address_lo).to_usize();
                let value = T::into_bytes(value);
                let value = value.as_ref();
                page[offset..offset + value.len()].copy_from_slice(value);
                instance.on_store_ok::<T, DEBUG>()
            } else {
                instance.on_store_segfault::<T, DEBUG>(pc, address, page_address_lo, false)
            }
        } else {
            let page_size = cast(Self::memory_state(instance).page_size).to_usize();
            let mut iter = Self::memory_state_mut(instance).pages.range_mut(page_address_lo..=page_address_hi);
            let lo = iter.next();
            let hi = iter.next();

            match (lo, hi) {
                (Some((_, lo)), Some((_, hi))) => {
                    if lo.is_read_only || hi.is_read_only {
                        let page_address = if lo.is_read_only { page_address_lo } else { page_address_hi };
                        return instance.on_store_segfault::<T, DEBUG>(pc, address, page_address, true);
                    }

                    let value = T::into_bytes(value);
                    let value = value.as_ref();
                    let lo_len = cast(page_address_hi).to_usize() - cast(address).to_usize();
                    let hi_len = value.len() - lo_len;
                    lo[page_size - lo_len..].copy_from_slice(&value[..lo_len]);
                    hi[..hi_len].copy_from_slice(&value[lo_len..]);
                    instance.on_store_ok::<T, DEBUG>()
                }
                (None, _) => instance.on_store_segfault::<T, DEBUG>(pc, address, page_address_lo, false),
                (Some((page_address, _)), _) => {
                    let missing_page_address = if *page_address == page_address_lo {
                        page_address_hi
                    } else {
                        page_address_lo
                    };

                    instance.on_store_segfault::<T, DEBUG>(pc, address, missing_page_address, false)
                }
            }
        }
    }

    fn borrow_bytes(&self, _addr: u32, _len: u32) -> Option<&[u8]> {
        // DynamicMemory is paginated; a [addr, addr+len) range may span pages
        // and so isn't generally borrowable as a single contiguous slice.
        // Intrinsic callers fall back to `read_memory_into` (which handles
        // multi-page reads via copy_nonoverlapping per page).
        None
    }

    fn borrow_bytes_mut(&mut self, _addr: u32, _len: u32) -> Option<&mut [u8]> {
        None
    }
}

/// RostroVM U1 (2026-05-11): map a handler identifier to its fast-path
/// opcode discriminant for `run_match`. Specific handler names get their
/// dedicated `FAST_OP_*` constant; everything else falls through to
/// `FAST_OP_UNSUPPORTED` and dispatches via the existing indirect-call
/// path inside `run_match`.
///
/// macro_rules pattern matching is order-sensitive — specific identifier
/// patterns MUST come before the catch-all `($_:ident)` arm.
///
/// To add a new opcode to the fast path:
///   1. Add a constant in `mod fast_opcode` above
///   2. Add a literal-identifier arm here mapping to that constant
///   3. Add a match arm in `run_match` implementing the operation
macro_rules! fast_op_for {
    // Phase A — minimum viable for goldilocks-mul bench
    (load_imm64) => { fast_opcode::FAST_OP_LOAD_IMM64 };
    (mul_64) => { fast_opcode::FAST_OP_MUL_64 };
    (jump) => { fast_opcode::FAST_OP_JUMP };
    (branch_less_unsigned) => { fast_opcode::FAST_OP_BRANCH_LT_U };
    // Phase B — close goldilocks-mul + poseidon2-perm hot loops
    (add_64) => { fast_opcode::FAST_OP_ADD_64 };
    (add_imm_64) => { fast_opcode::FAST_OP_ADD_IMM_64 };
    (sub_64) => { fast_opcode::FAST_OP_SUB_64 };
    (mul_imm_64) => { fast_opcode::FAST_OP_MUL_IMM_64 };
    (xor) => { fast_opcode::FAST_OP_XOR };
    (and) => { fast_opcode::FAST_OP_AND };
    (or) => { fast_opcode::FAST_OP_OR };
    (shift_logical_right_64) => { fast_opcode::FAST_OP_SHIFT_LOGICAL_RIGHT_64 };
    (shift_logical_right_imm_64) => { fast_opcode::FAST_OP_SHIFT_LOGICAL_RIGHT_IMM_64 };
    (mul_upper_unsigned_unsigned_64) => { fast_opcode::FAST_OP_MUL_UPPER_UNSIGNED_UNSIGNED_64 };
    (move_reg) => { fast_opcode::FAST_OP_MOVE_REG };
    (fallthrough) => { fast_opcode::FAST_OP_FALLTHROUGH };
    (branch_eq) => { fast_opcode::FAST_OP_BRANCH_EQ };
    (branch_not_eq) => { fast_opcode::FAST_OP_BRANCH_NE };
    // H1 Batch A1 — 32-bit basic arithmetic (2026-05-12).
    (add_32) => { fast_opcode::FAST_OP_ADD_32 };
    (sub_32) => { fast_opcode::FAST_OP_SUB_32 };
    (mul_32) => { fast_opcode::FAST_OP_MUL_32 };
    (add_imm_32) => { fast_opcode::FAST_OP_ADD_IMM_32 };
    (mul_imm_32) => { fast_opcode::FAST_OP_MUL_IMM_32 };
    (shift_logical_right_32) => { fast_opcode::FAST_OP_SHIFT_LOGICAL_RIGHT_32 };
    // H1 Batch A2 (2026-05-12) — 64-bit shifts, rotates, negate_and_add.
    (shift_logical_left_64) => { fast_opcode::FAST_OP_SHIFT_LOGICAL_LEFT_64 };
    (shift_logical_left_imm_64) => { fast_opcode::FAST_OP_SHIFT_LOGICAL_LEFT_IMM_64 };
    (shift_logical_left_imm_alt_64) => { fast_opcode::FAST_OP_SHIFT_LOGICAL_LEFT_IMM_ALT_64 };
    (shift_logical_right_imm_alt_64) => { fast_opcode::FAST_OP_SHIFT_LOGICAL_RIGHT_IMM_ALT_64 };
    (shift_arithmetic_right_64) => { fast_opcode::FAST_OP_SHIFT_ARITHMETIC_RIGHT_64 };
    (shift_arithmetic_right_imm_64) => { fast_opcode::FAST_OP_SHIFT_ARITHMETIC_RIGHT_IMM_64 };
    (shift_arithmetic_right_imm_alt_64) => { fast_opcode::FAST_OP_SHIFT_ARITHMETIC_RIGHT_IMM_ALT_64 };
    (rotate_left_64) => { fast_opcode::FAST_OP_ROTATE_LEFT_64 };
    (rotate_right_64) => { fast_opcode::FAST_OP_ROTATE_RIGHT_64 };
    (rotate_right_imm_64) => { fast_opcode::FAST_OP_ROTATE_RIGHT_IMM_64 };
    (rotate_right_imm_alt_64) => { fast_opcode::FAST_OP_ROTATE_RIGHT_IMM_ALT_64 };
    (negate_and_add_imm_64) => { fast_opcode::FAST_OP_NEGATE_AND_ADD_IMM_64 };
    // H1 Batch A3 (2026-05-12) — 32-bit shifts, rotates, negate_and_add.
    (shift_logical_left_32) => { fast_opcode::FAST_OP_SHIFT_LOGICAL_LEFT_32 };
    (shift_logical_left_imm_32) => { fast_opcode::FAST_OP_SHIFT_LOGICAL_LEFT_IMM_32 };
    (shift_logical_left_imm_alt_32) => { fast_opcode::FAST_OP_SHIFT_LOGICAL_LEFT_IMM_ALT_32 };
    (shift_logical_right_imm_32) => { fast_opcode::FAST_OP_SHIFT_LOGICAL_RIGHT_IMM_32 };
    (shift_logical_right_imm_alt_32) => { fast_opcode::FAST_OP_SHIFT_LOGICAL_RIGHT_IMM_ALT_32 };
    (shift_arithmetic_right_32) => { fast_opcode::FAST_OP_SHIFT_ARITHMETIC_RIGHT_32 };
    (shift_arithmetic_right_imm_32) => { fast_opcode::FAST_OP_SHIFT_ARITHMETIC_RIGHT_IMM_32 };
    (shift_arithmetic_right_imm_alt_32) => { fast_opcode::FAST_OP_SHIFT_ARITHMETIC_RIGHT_IMM_ALT_32 };
    (rotate_left_32) => { fast_opcode::FAST_OP_ROTATE_LEFT_32 };
    (rotate_right_32) => { fast_opcode::FAST_OP_ROTATE_RIGHT_32 };
    (rotate_right_imm_32) => { fast_opcode::FAST_OP_ROTATE_RIGHT_IMM_32 };
    (rotate_right_imm_alt_32) => { fast_opcode::FAST_OP_ROTATE_RIGHT_IMM_ALT_32 };
    (negate_and_add_imm_32) => { fast_opcode::FAST_OP_NEGATE_AND_ADD_IMM_32 };
    // H1 Batch A4 (2026-05-12) — wide-multiply signed/mixed + 32-bit unsigned variant.
    (mul_upper_signed_signed_64) => { fast_opcode::FAST_OP_MUL_UPPER_SIGNED_SIGNED_64 };
    (mul_upper_signed_signed_32) => { fast_opcode::FAST_OP_MUL_UPPER_SIGNED_SIGNED_32 };
    (mul_upper_unsigned_unsigned_32) => { fast_opcode::FAST_OP_MUL_UPPER_UNSIGNED_UNSIGNED_32 };
    (mul_upper_signed_unsigned_64) => { fast_opcode::FAST_OP_MUL_UPPER_SIGNED_UNSIGNED_64 };
    (mul_upper_signed_unsigned_32) => { fast_opcode::FAST_OP_MUL_UPPER_SIGNED_UNSIGNED_32 };
    // H1 Batch A5 (2026-05-12) — division + remainder.
    (div_unsigned_64) => { fast_opcode::FAST_OP_DIV_UNSIGNED_64 };
    (div_unsigned_32) => { fast_opcode::FAST_OP_DIV_UNSIGNED_32 };
    (div_signed_64) => { fast_opcode::FAST_OP_DIV_SIGNED_64 };
    (div_signed_32) => { fast_opcode::FAST_OP_DIV_SIGNED_32 };
    (rem_unsigned_64) => { fast_opcode::FAST_OP_REM_UNSIGNED_64 };
    (rem_unsigned_32) => { fast_opcode::FAST_OP_REM_UNSIGNED_32 };
    (rem_signed_64) => { fast_opcode::FAST_OP_REM_SIGNED_64 };
    (rem_signed_32) => { fast_opcode::FAST_OP_REM_SIGNED_32 };
    // H1 Batch A6 (2026-05-12) — comparison setters.
    (set_less_than_unsigned) => { fast_opcode::FAST_OP_SET_LESS_THAN_UNSIGNED };
    (set_less_than_signed) => { fast_opcode::FAST_OP_SET_LESS_THAN_SIGNED };
    (set_less_than_unsigned_imm) => { fast_opcode::FAST_OP_SET_LESS_THAN_UNSIGNED_IMM };
    (set_less_than_signed_imm) => { fast_opcode::FAST_OP_SET_LESS_THAN_SIGNED_IMM };
    (set_greater_than_unsigned_imm) => { fast_opcode::FAST_OP_SET_GREATER_THAN_UNSIGNED_IMM };
    (set_greater_than_signed_imm) => { fast_opcode::FAST_OP_SET_GREATER_THAN_SIGNED_IMM };
    // H1 Batch A7 (2026-05-12) — conditional moves.
    (cmov_if_zero) => { fast_opcode::FAST_OP_CMOV_IF_ZERO };
    (cmov_if_not_zero) => { fast_opcode::FAST_OP_CMOV_IF_NOT_ZERO };
    (cmov_if_zero_imm) => { fast_opcode::FAST_OP_CMOV_IF_ZERO_IMM };
    (cmov_if_not_zero_imm) => { fast_opcode::FAST_OP_CMOV_IF_NOT_ZERO_IMM };
    // H1 Batch A8 (2026-05-12) — bitmanip + immediates + min/max + bitcount + extends.
    (and_imm) => { fast_opcode::FAST_OP_AND_IMM };
    (or_imm) => { fast_opcode::FAST_OP_OR_IMM };
    (xor_imm) => { fast_opcode::FAST_OP_XOR_IMM };
    (and_inverted_32) => { fast_opcode::FAST_OP_AND_INVERTED_32 };
    (and_inverted_64) => { fast_opcode::FAST_OP_AND_INVERTED_64 };
    (or_inverted_32) => { fast_opcode::FAST_OP_OR_INVERTED_32 };
    (or_inverted_64) => { fast_opcode::FAST_OP_OR_INVERTED_64 };
    (xnor_32) => { fast_opcode::FAST_OP_XNOR_32 };
    (xnor_64) => { fast_opcode::FAST_OP_XNOR_64 };
    (maximum_32) => { fast_opcode::FAST_OP_MAXIMUM_32 };
    (maximum_64) => { fast_opcode::FAST_OP_MAXIMUM_64 };
    (maximum_unsigned_32) => { fast_opcode::FAST_OP_MAXIMUM_UNSIGNED_32 };
    (maximum_unsigned_64) => { fast_opcode::FAST_OP_MAXIMUM_UNSIGNED_64 };
    (minimum_32) => { fast_opcode::FAST_OP_MINIMUM_32 };
    (minimum_64) => { fast_opcode::FAST_OP_MINIMUM_64 };
    (minimum_unsigned_32) => { fast_opcode::FAST_OP_MINIMUM_UNSIGNED_32 };
    (minimum_unsigned_64) => { fast_opcode::FAST_OP_MINIMUM_UNSIGNED_64 };
    (count_leading_zero_bits_32) => { fast_opcode::FAST_OP_COUNT_LEADING_ZERO_BITS_32 };
    (count_leading_zero_bits_64) => { fast_opcode::FAST_OP_COUNT_LEADING_ZERO_BITS_64 };
    (count_trailing_zero_bits_32) => { fast_opcode::FAST_OP_COUNT_TRAILING_ZERO_BITS_32 };
    (count_trailing_zero_bits_64) => { fast_opcode::FAST_OP_COUNT_TRAILING_ZERO_BITS_64 };
    (count_set_bits_32) => { fast_opcode::FAST_OP_COUNT_SET_BITS_32 };
    (count_set_bits_64) => { fast_opcode::FAST_OP_COUNT_SET_BITS_64 };
    (sign_extend_8_32) => { fast_opcode::FAST_OP_SIGN_EXTEND_8_32 };
    (sign_extend_8_64) => { fast_opcode::FAST_OP_SIGN_EXTEND_8_64 };
    (sign_extend_16_32) => { fast_opcode::FAST_OP_SIGN_EXTEND_16_32 };
    (sign_extend_16_64) => { fast_opcode::FAST_OP_SIGN_EXTEND_16_64 };
    (zero_extend_16_32) => { fast_opcode::FAST_OP_ZERO_EXTEND_16_32 };
    (zero_extend_16_64) => { fast_opcode::FAST_OP_ZERO_EXTEND_16_64 };
    (reverse_byte_32) => { fast_opcode::FAST_OP_REVERSE_BYTE_32 };
    (reverse_byte_64) => { fast_opcode::FAST_OP_REVERSE_BYTE_64 };
    // H1 Batch B (2026-05-12) — branches (signed reg-reg, all _imm variants).
    (branch_less_signed) => { fast_opcode::FAST_OP_BRANCH_LT_S };
    (branch_greater_or_equal_unsigned) => { fast_opcode::FAST_OP_BRANCH_GE_U };
    (branch_greater_or_equal_signed) => { fast_opcode::FAST_OP_BRANCH_GE_S };
    (branch_eq_imm) => { fast_opcode::FAST_OP_BRANCH_EQ_IMM };
    (branch_not_eq_imm) => { fast_opcode::FAST_OP_BRANCH_NE_IMM };
    (branch_less_unsigned_imm) => { fast_opcode::FAST_OP_BRANCH_LT_U_IMM };
    (branch_less_signed_imm) => { fast_opcode::FAST_OP_BRANCH_LT_S_IMM };
    (branch_greater_or_equal_unsigned_imm) => { fast_opcode::FAST_OP_BRANCH_GE_U_IMM };
    (branch_greater_or_equal_signed_imm) => { fast_opcode::FAST_OP_BRANCH_GE_S_IMM };
    (branch_less_or_equal_signed_imm) => { fast_opcode::FAST_OP_BRANCH_LE_S_IMM };
    (branch_less_or_equal_unsigned_imm) => { fast_opcode::FAST_OP_BRANCH_LE_U_IMM };
    (branch_greater_signed_imm) => { fast_opcode::FAST_OP_BRANCH_GT_S_IMM };
    (branch_greater_unsigned_imm) => { fast_opcode::FAST_OP_BRANCH_GT_U_IMM };
    // H1 Batch C (partial, 2026-05-12) — trivial control flow.
    (load_imm) => { fast_opcode::FAST_OP_LOAD_IMM };
    (load_imm_and_jump) => { fast_opcode::FAST_OP_LOAD_IMM_AND_JUMP };
    (unlikely) => { fast_opcode::FAST_OP_UNLIKELY };
    // H1 Batch C-complex (2026-05-12) — control flow with run-loop exits.
    (trap) => { fast_opcode::FAST_OP_TRAP };
    (jump_indirect) => { fast_opcode::FAST_OP_JUMP_INDIRECT };
    (load_imm_and_jump_indirect) => { fast_opcode::FAST_OP_LOAD_IMM_AND_JUMP_INDIRECT };
    (ecalli) => { fast_opcode::FAST_OP_ECALLI };
    (sbrk) => { fast_opcode::FAST_OP_SBRK };
    // H1 Batch D (2026-05-12) — typed memory loads.
    (load_u8) => { fast_opcode::FAST_OP_LOAD_U8 };
    (load_i8) => { fast_opcode::FAST_OP_LOAD_I8 };
    (load_u16) => { fast_opcode::FAST_OP_LOAD_U16 };
    (load_i16) => { fast_opcode::FAST_OP_LOAD_I16 };
    (load_i32) => { fast_opcode::FAST_OP_LOAD_I32 };
    (load_u32) => { fast_opcode::FAST_OP_LOAD_U32 };
    (load_u64) => { fast_opcode::FAST_OP_LOAD_U64 };
    (load_indirect_u8) => { fast_opcode::FAST_OP_LOAD_INDIRECT_U8 };
    (load_indirect_i8) => { fast_opcode::FAST_OP_LOAD_INDIRECT_I8 };
    (load_indirect_u16) => { fast_opcode::FAST_OP_LOAD_INDIRECT_U16 };
    (load_indirect_i16) => { fast_opcode::FAST_OP_LOAD_INDIRECT_I16 };
    (load_indirect_i32) => { fast_opcode::FAST_OP_LOAD_INDIRECT_I32 };
    (load_indirect_u32) => { fast_opcode::FAST_OP_LOAD_INDIRECT_U32 };
    (load_indirect_u64) => { fast_opcode::FAST_OP_LOAD_INDIRECT_U64 };
    // H1 Batch E (2026-05-12) — typed memory stores.
    (store_u8) => { fast_opcode::FAST_OP_STORE_U8 };
    (store_u16) => { fast_opcode::FAST_OP_STORE_U16 };
    (store_u32) => { fast_opcode::FAST_OP_STORE_U32 };
    (store_u64) => { fast_opcode::FAST_OP_STORE_U64 };
    (store_indirect_u8) => { fast_opcode::FAST_OP_STORE_INDIRECT_U8 };
    (store_indirect_u16) => { fast_opcode::FAST_OP_STORE_INDIRECT_U16 };
    (store_indirect_u32) => { fast_opcode::FAST_OP_STORE_INDIRECT_U32 };
    (store_indirect_u64) => { fast_opcode::FAST_OP_STORE_INDIRECT_U64 };
    (store_imm_u8) => { fast_opcode::FAST_OP_STORE_IMM_U8 };
    (store_imm_u16) => { fast_opcode::FAST_OP_STORE_IMM_U16 };
    (store_imm_u32) => { fast_opcode::FAST_OP_STORE_IMM_U32 };
    (store_imm_u64) => { fast_opcode::FAST_OP_STORE_IMM_U64 };
    (store_imm_indirect_u8) => { fast_opcode::FAST_OP_STORE_IMM_INDIRECT_U8 };
    (store_imm_indirect_u16) => { fast_opcode::FAST_OP_STORE_IMM_INDIRECT_U16 };
    (store_imm_indirect_u32) => { fast_opcode::FAST_OP_STORE_IMM_INDIRECT_U32 };
    (store_imm_indirect_u64) => { fast_opcode::FAST_OP_STORE_IMM_INDIRECT_U64 };
    // H1 Batch F (2026-05-12) — memset (final landing op).
    (memset) => { fast_opcode::FAST_OP_MEMSET };
    // Cleanup Phase 1 (2026-05-12) — unresolved-branch + jump + fallthrough.
    (unresolved_branch_eq) => { fast_opcode::FAST_OP_UNRESOLVED_BRANCH_EQ };
    (unresolved_branch_not_eq) => { fast_opcode::FAST_OP_UNRESOLVED_BRANCH_NE };
    (unresolved_branch_less_unsigned) => { fast_opcode::FAST_OP_UNRESOLVED_BRANCH_LT_U };
    (unresolved_branch_less_signed) => { fast_opcode::FAST_OP_UNRESOLVED_BRANCH_LT_S };
    (unresolved_branch_greater_or_equal_unsigned) => { fast_opcode::FAST_OP_UNRESOLVED_BRANCH_GE_U };
    (unresolved_branch_greater_or_equal_signed) => { fast_opcode::FAST_OP_UNRESOLVED_BRANCH_GE_S };
    (unresolved_branch_eq_imm) => { fast_opcode::FAST_OP_UNRESOLVED_BRANCH_EQ_IMM };
    (unresolved_branch_not_eq_imm) => { fast_opcode::FAST_OP_UNRESOLVED_BRANCH_NE_IMM };
    (unresolved_branch_less_unsigned_imm) => { fast_opcode::FAST_OP_UNRESOLVED_BRANCH_LT_U_IMM };
    (unresolved_branch_less_signed_imm) => { fast_opcode::FAST_OP_UNRESOLVED_BRANCH_LT_S_IMM };
    (unresolved_branch_greater_or_equal_unsigned_imm) => { fast_opcode::FAST_OP_UNRESOLVED_BRANCH_GE_U_IMM };
    (unresolved_branch_greater_or_equal_signed_imm) => { fast_opcode::FAST_OP_UNRESOLVED_BRANCH_GE_S_IMM };
    (unresolved_branch_less_or_equal_unsigned_imm) => { fast_opcode::FAST_OP_UNRESOLVED_BRANCH_LE_U_IMM };
    (unresolved_branch_less_or_equal_signed_imm) => { fast_opcode::FAST_OP_UNRESOLVED_BRANCH_LE_S_IMM };
    (unresolved_branch_greater_unsigned_imm) => { fast_opcode::FAST_OP_UNRESOLVED_BRANCH_GT_U_IMM };
    (unresolved_branch_greater_signed_imm) => { fast_opcode::FAST_OP_UNRESOLVED_BRANCH_GT_S_IMM };
    (unresolved_jump) => { fast_opcode::FAST_OP_UNRESOLVED_JUMP };
    (unresolved_load_imm_and_jump) => { fast_opcode::FAST_OP_UNRESOLVED_LOAD_IMM_AND_JUMP };
    (unresolved_fallthrough) => { fast_opcode::FAST_OP_UNRESOLVED_FALLTHROUGH };
    // invalid_branch_trap shares semantics with FAST_OP_TRAP — both set trap state and exit.
    (invalid_branch_trap) => { fast_opcode::FAST_OP_TRAP };
    // Cleanup Phase 4a (2026-05-12) — step op for step_tracing in run_match.
    (step) => { fast_opcode::FAST_OP_STEP };
    // Cleanup Phase 4b (2026-05-12) — cache-reset op (size-limit eviction).
    (reset_cache) => { fast_opcode::FAST_OP_RESET_CACHE };
    // Tier 2 H2 (2026-05-12) — Goldilocks multiplication super-instruction.
    (goldilocks_mul) => { fast_opcode::FAST_OP_GOLDILOCKS_MUL };
    // Catch-all: any opcode name not listed above is corrupt/unrecognized at
    // emit time; it's tagged UNSUPPORTED so run_match dispatches to its trap arm.
    ($_:ident) => { fast_opcode::FAST_OP_UNSUPPORTED };
}

// H1 (2026-05-12): shared dispatch-arm shapes for `run_match`.
//
// Each macro expands inline at the match arm site, producing identical code
// to a hand-written arm — saves ~6 lines/arm without affecting what LLVM
// sees. Macros assume `self`, `inst`, `offset` are in scope at the use site
// (which they are inside `run_match`'s loop body).
//
// All 32-bit ops sign-extend the u32 result to u64 (RISC-V W-instruction
// semantics — see `set32` impl).
// `$self:tt` matches the `self` keyword (which `:ident` cannot). `$inst` and
// `$offset` are normal idents, matched via `:ident` to keep type checking tight.
// Macros are scoped to this file; call sites are inside `run_match`.
macro_rules! arm_reg_reg_reg_64 {
    ($self:tt, $inst:ident, $offset:ident; |$a:ident, $b:ident| $body:expr) => {{
        let d = transmute_reg($inst.r0 as u32);
        let s1 = transmute_reg($inst.r1 as u32);
        let s2 = transmute_reg($inst.r2 as u32);
        let $a = $self.regs[s1 as usize];
        let $b = $self.regs[s2 as usize];
        $self.regs[d as usize] = $body;
        $offset += 1;
    }};
}

macro_rules! arm_reg_reg_reg_32 {
    ($self:tt, $inst:ident, $offset:ident; |$a:ident, $b:ident| $body:expr) => {{
        let d = transmute_reg($inst.r0 as u32);
        let s1 = transmute_reg($inst.r1 as u32);
        let s2 = transmute_reg($inst.r2 as u32);
        let $a = $self.regs[s1 as usize] as u32;
        let $b = $self.regs[s2 as usize] as u32;
        let result: u32 = $body;
        $self.regs[d as usize] = result as i32 as i64 as u64;
        $offset += 1;
    }};
}

macro_rules! arm_reg_reg_imm_64 {
    ($self:tt, $inst:ident, $offset:ident; |$a:ident, $imm:ident| $body:expr) => {{
        let d = transmute_reg($inst.r0 as u32);
        let s1 = transmute_reg($inst.r1 as u32);
        let $a = $self.regs[s1 as usize];
        let $imm = $inst.imm1 as u32 as i32 as i64 as u64;
        $self.regs[d as usize] = $body;
        $offset += 1;
    }};
}

macro_rules! arm_reg_reg_imm_32 {
    ($self:tt, $inst:ident, $offset:ident; |$a:ident, $imm:ident| $body:expr) => {{
        let d = transmute_reg($inst.r0 as u32);
        let s1 = transmute_reg($inst.r1 as u32);
        let $a = $self.regs[s1 as usize] as u32;
        let $imm = $inst.imm1 as u32;
        let result: u32 = $body;
        $self.regs[d as usize] = result as i32 as i64 as u64;
        $offset += 1;
    }};
}

// Operand-swapped variant: imm is the VALUE; the second register is the COUNT.
// Used for the `_imm_alt_*` shifts/rotates where the immediate is on the left
// side of the operation (so `imm << reg` rather than `reg << imm`).
// Fields: r0 = dst, r1 = count_reg, imm1 = value (sign-extended to u64).
macro_rules! arm_alt_reg_reg_imm_64 {
    ($self:tt, $inst:ident, $offset:ident; |$value:ident, $count:ident| $body:expr) => {{
        let d = transmute_reg($inst.r0 as u32);
        let count_reg = transmute_reg($inst.r1 as u32);
        let $value = $inst.imm1 as u32 as i32 as i64 as u64;
        let $count = $self.regs[count_reg as usize];
        $self.regs[d as usize] = $body;
        $offset += 1;
    }};
}

// 32-bit operand-swapped variant. Result sign-extended u32 → u64.
macro_rules! arm_alt_reg_reg_imm_32 {
    ($self:tt, $inst:ident, $offset:ident; |$value:ident, $count:ident| $body:expr) => {{
        let d = transmute_reg($inst.r0 as u32);
        let count_reg = transmute_reg($inst.r1 as u32);
        let $value = $inst.imm1 as u32;
        let $count = $self.regs[count_reg as usize] as u32;
        let result: u32 = $body;
        $self.regs[d as usize] = result as i32 as i64 as u64;
        $offset += 1;
    }};
}

// 64-bit unary: one source register, one destination.
macro_rules! arm_reg_reg_64 {
    ($self:tt, $inst:ident, $offset:ident; |$a:ident| $body:expr) => {{
        let d = transmute_reg($inst.r0 as u32);
        let s = transmute_reg($inst.r1 as u32);
        let $a = $self.regs[s as usize];
        $self.regs[d as usize] = $body;
        $offset += 1;
    }};
}

// 32-bit unary: result is sign-extended u32 → u64.
macro_rules! arm_reg_reg_32 {
    ($self:tt, $inst:ident, $offset:ident; |$a:ident| $body:expr) => {{
        let d = transmute_reg($inst.r0 as u32);
        let s = transmute_reg($inst.r1 as u32);
        let $a = $self.regs[s as usize] as u32;
        let result: u32 = $body;
        $self.regs[d as usize] = result as i32 as i64 as u64;
        $offset += 1;
    }};
}

// Branch shapes. Fields: r0=s1, r1=s2 (reg-reg) or r0=s1, imm1=imm (reg-imm).
// target_idx = taken target, next_idx = fallthrough.
macro_rules! arm_branch_reg_reg {
    ($self:tt, $inst:ident, $offset:ident; |$a:ident, $b:ident| $cond:expr) => {{
        let s1 = transmute_reg($inst.r0 as u32);
        let s2 = transmute_reg($inst.r1 as u32);
        let $a = $self.regs[s1 as usize];
        let $b = $self.regs[s2 as usize];
        $offset = if $cond { $inst.target_idx } else { $inst.next_idx };
    }};
}

macro_rules! arm_branch_reg_imm {
    ($self:tt, $inst:ident, $offset:ident; |$a:ident, $imm:ident| $cond:expr) => {{
        let s1 = transmute_reg($inst.r0 as u32);
        let $a = $self.regs[s1 as usize];
        let $imm = $inst.imm1 as u32 as i32 as i64 as u64;
        $offset = if $cond { $inst.target_idx } else { $inst.next_idx };
    }};
}

// Typed memory load. `$T` is one of u8/i8/u16/i16/i32/u32/u64.
// H3-lite (2026-05-12): the fast path no longer writes self.compiled_offset
// before the load. load_impl's success branch returns Some(compiled_offset+1)
// which we discard — we just advance `offset` directly. The trap path
// (on_load_trap) reads self.program_counter (set just above), NOT
// compiled_offset. Eliminates a 64-bit store + the offset+1 computation per
// successful load, which dominates multi-limb crypto inner loops.
macro_rules! arm_load_nonindirect {
    ($self:tt, $inst:ident, $offset:ident; $T:ty) => {{
        let dst = transmute_reg($inst.r0 as u32);
        let address = $inst.imm1 as u32;
        if <M as Memory>::load_impl::<$T, DEBUG>($self, ProgramCounter($inst.pc), dst, address).is_some() {
            $offset += 1;
        } else {
            $self.compiled_offset = $offset;
            return $self.interrupt.clone();
        }
    }};
}

macro_rules! arm_load_indirect {
    ($self:tt, $inst:ident, $offset:ident; $T:ty) => {{
        let dst = transmute_reg($inst.r0 as u32);
        let base = transmute_reg($inst.r1 as u32);
        let address =
            ($self.regs[base as usize] as u32).wrapping_add($inst.imm1 as u32);
        if <M as Memory>::load_impl::<$T, DEBUG>($self, ProgramCounter($inst.pc), dst, address).is_some() {
            $offset += 1;
        } else {
            $self.compiled_offset = $offset;
            return $self.interrupt.clone();
        }
    }};
}

// store_*: reg-imm shape (r0=src_reg, imm1=address). Value is full u64 from reg.
macro_rules! arm_store_nonindirect {
    ($self:tt, $inst:ident, $offset:ident; $T:ty) => {{
        let src = transmute_reg($inst.r0 as u32);
        let value = $self.regs[src as usize];
        let address = $inst.imm1 as u32;
        if <M as Memory>::store_impl::<$T, DEBUG>($self, ProgramCounter($inst.pc), address, value).is_some() {
            $offset += 1;
        } else {
            $self.compiled_offset = $offset;
            return $self.interrupt.clone();
        }
    }};
}

// store_indirect_*: reg-reg-imm shape (r0=src, r1=base, imm1=offset).
macro_rules! arm_store_indirect {
    ($self:tt, $inst:ident, $offset:ident; $T:ty) => {{
        let src = transmute_reg($inst.r0 as u32);
        let base = transmute_reg($inst.r1 as u32);
        let value = $self.regs[src as usize];
        let address =
            ($self.regs[base as usize] as u32).wrapping_add($inst.imm1 as u32);
        if <M as Memory>::store_impl::<$T, DEBUG>($self, ProgramCounter($inst.pc), address, value).is_some() {
            $offset += 1;
        } else {
            $self.compiled_offset = $offset;
            return $self.interrupt.clone();
        }
    }};
}

// store_imm_*: imm-imm shape (imm1=address, imm2=value). Value is sign-extended u32 → u64.
macro_rules! arm_store_imm {
    ($self:tt, $inst:ident, $offset:ident; $T:ty) => {{
        let address = $inst.imm1 as u32;
        let value = $inst.imm2 as u32 as i32 as i64 as u64;
        if <M as Memory>::store_impl::<$T, DEBUG>($self, ProgramCounter($inst.pc), address, value).is_some() {
            $offset += 1;
        } else {
            $self.compiled_offset = $offset;
            return $self.interrupt.clone();
        }
    }};
}

// Cleanup Phase 1: direct dispatch to one-shot resolution handlers.
// All `unresolved_*` handlers take only `&mut InterpretedInstance` and read
// their args from compiled_decoded[compiled_offset]. On first execution they
// resolve their target and rewrite the inst with a real fast opcode so the
// next dispatch hits a normal arm. Direct call here lets LLVM resolve the
// handler statically — no indirect call, no jump-table break.
macro_rules! arm_unresolved {
    ($self:tt, $offset:ident, $handler:ident) => {{
        $self.compiled_offset = $offset;
        match raw_handlers::$handler::<DEBUG>($self) {
            Some(target) => $offset = target,
            None => {
                $self.compiled_offset = $offset;
                return $self.interrupt.clone();
            }
        }
    }};
}

// store_imm_indirect_*: reg-imm-imm shape (r0=base, imm1=offset, imm2=value).
macro_rules! arm_store_imm_indirect {
    ($self:tt, $inst:ident, $offset:ident; $T:ty) => {{
        let base = transmute_reg($inst.r0 as u32);
        let address =
            ($self.regs[base as usize] as u32).wrapping_add($inst.imm1 as u32);
        let value = $inst.imm2 as u32 as i32 as i64 as u64;
        if <M as Memory>::store_impl::<$T, DEBUG>($self, ProgramCounter($inst.pc), address, value).is_some() {
            $offset += 1;
        } else {
            $self.compiled_offset = $offset;
            return $self.interrupt.clone();
        }
    }};
}

// Emit macros push the predecode entry into `compiled_decoded`. run_match
// dispatches via `inst.opcode` (named match arms; cold one-shot resolution
// paths like `unresolved_branch_*` are direct calls into raw_handlers).
macro_rules! emit_raw {
    ($self:ident, $handler_name:ident::<$($generic:tt),+>($($args:tt)*)) => {
        $self.compiled_decoded.push(DecodedInst {
            bb_gas_cost: 0,
            opcode: fast_op_for!($handler_name),
            ..DecodedInst::$handler_name($($args)*)
        });
    };
}

macro_rules! emit {
    ($self:ident, $handler_name:ident($($args:tt)*)) => {
        emit_raw!($self, $handler_name::<DEBUG>($($args)*));
    };
}

macro_rules! emit_load_store {
    ($self:ident, $handler_name:ident($($args:tt)*)) => {
        $self.compiled_decoded.push(DecodedInst {
            bb_gas_cost: 0,
            opcode: fast_op_for!($handler_name),
            ..DecodedInst::$handler_name($($args)*)
        });
    };
}

macro_rules! emit_consistent_address {
    ($self:ident, $handler_name:ident($($args:tt)*)) => {
        $self.compiled_decoded.push(DecodedInst {
            bb_gas_cost: 0,
            opcode: fast_op_for!($handler_name),
            ..DecodedInst::$handler_name($($args)*)
        });
    };
}

macro_rules! emit_branch {
    ($self:ident, $name:ident, $s1:ident, $s2:ident, $i:ident) => {
        let target_true = ProgramCounter($i);
        let target_false = $self.next_program_counter();
        if $self.module.is_jump_target_valid(target_true) && $self.module.is_jump_target_valid(target_false) {
            emit!($self, $name($s1, $s2, target_true, target_false));
        } else {
            emit!($self, invalid_branch_trap($self.program_counter));
        }
    };
}

fn each_page<E>(
    (page_size, page_address_lo, page_address_hi): (u32, u32, u32),
    address: u32,
    length: u32,
    callback: impl FnMut(u32, usize, usize, usize) -> Result<(), E>,
) -> Result<(), E> {
    each_page_impl(page_size, page_address_lo, page_address_hi, address, length, callback)
}

fn each_page_impl<E>(
    page_size: u32,
    page_address_lo: u32,
    page_address_hi: u32,
    address: u32,
    length: u32,
    mut callback: impl FnMut(u32, usize, usize, usize) -> Result<(), E>,
) -> Result<(), E> {
    let page_size = cast(page_size).to_usize();
    let length = cast(length).to_usize();

    let initial_page_offset = cast(address).to_usize() - cast(page_address_lo).to_usize();
    let initial_chunk_length = core::cmp::min(length, page_size - initial_page_offset);
    callback(page_address_lo, initial_page_offset, 0, initial_chunk_length)?;

    if page_address_lo == page_address_hi {
        return Ok(());
    }

    let mut page_address_lo = cast(page_address_lo).to_u64();
    let page_address_hi = cast(page_address_hi).to_u64();
    page_address_lo += cast(page_size).to_u64();
    let mut buffer_offset = initial_chunk_length;
    while page_address_lo < page_address_hi {
        callback(cast(page_address_lo).assert_always_fits_in_u32(), 0, buffer_offset, page_size)?;
        buffer_offset += page_size;
        page_address_lo += cast(page_size).to_u64();
    }

    callback(
        cast(page_address_lo).assert_always_fits_in_u32(),
        0,
        buffer_offset,
        length - buffer_offset,
    )
}

#[test]
fn test_each_page() {
    fn run(address: u32, length: u32) -> Vec<(u32, usize, usize, usize)> {
        let page_size = 4096;
        let page_address_lo = address / page_size * page_size;
        let page_address_hi = (address + (length - 1)) / page_size * page_size;
        let mut output = Vec::new();
        each_page_impl::<()>(
            page_size,
            page_address_lo,
            page_address_hi,
            address,
            length,
            |page_address, page_offset, buffer_offset, length| {
                output.push((page_address, page_offset, buffer_offset, length));
                Ok(())
            },
        )
        .unwrap();
        output
    }

    #[rustfmt::skip]
    assert_eq!(run(0, 4096), alloc::vec![
        (0, 0, 0, 4096)
    ]);

    #[rustfmt::skip]
    assert_eq!(run(0, 100), alloc::vec![
        (0, 0, 0, 100)
    ]);

    #[rustfmt::skip]
    assert_eq!(run(96, 4000), alloc::vec![
        (0, 96, 0, 4000)
    ]);

    #[rustfmt::skip]
    assert_eq!(run(4000, 200), alloc::vec![
        (   0, 4000, 0,   96),
        (4096,    0, 96, 104),
    ]);

    #[rustfmt::skip]
    assert_eq!(run(4000, 5000), alloc::vec![
        (   0, 4000,     0,   96),
        (4096,    0,    96, 4096),
        (8192,    0,  4192,  808),
    ]);

    #[rustfmt::skip]
    assert_eq!(run(0xffffffff - 4095, 4096), alloc::vec![
        (0xfffff000, 0, 0, 4096)
    ]);

    #[rustfmt::skip]
    assert_eq!(run(0xffffffff - 4096, 4095), alloc::vec![
        (0xffffe000, 4095, 0, 1),
        (0xfffff000, 0, 1, 4094)
    ]);
}

use NonZeroU32 as CompiledOffset;

/// RostroVM U1 (2026-05-11): fast-path opcode discriminants for `run_match`.
///
/// Each constant identifies one PVM instruction handler in a way that the
/// match-dispatch loop can branch on directly (no indirect call). The
/// values are arbitrary-but-stable u8 tags; only `FAST_OP_UNSUPPORTED`
/// is reserved (0xFF) for the "no fast path implemented yet, fall back
/// to indirect call" sentinel.
///
/// Discriminants land here as we implement opcodes in `run_match`:
///   - Turn 2: Phase A — load_imm64, mul_64, jump, branch_lt_u, trap
///   - Turn 3: Phase B — add_64, add_imm_64, sub_64, mul_imm_64, xor, shl/shr_imm_64
///   - Turn 4+: Phase C — load/store_indirect, branch_eq/ne, move_reg, etc.
///
/// Goal: capture the bench-workload hot opcodes; everything else falls
/// back to the existing indirect-call dispatch. Incremental rollout, no
/// flag-day rewrite.
#[allow(dead_code)] // populated as opcodes land in run_match
pub(crate) mod fast_opcode {
    // Phase A (Turn 2 target): minimum viable — unblocks goldilocks-mul bench.
    pub const FAST_OP_LOAD_IMM64: u8 = 0;
    pub const FAST_OP_MUL_64: u8 = 1;
    pub const FAST_OP_JUMP: u8 = 2;
    pub const FAST_OP_BRANCH_LT_U: u8 = 3;
    pub const FAST_OP_TRAP: u8 = 4;

    // Phase B (Turn 3 target): unblocks poseidon2-perm bench + closes
    // most of goldilocks-mul's hot opcodes (the Goldilocks-reduce arithmetic
    // expansion).
    pub const FAST_OP_ADD_64: u8 = 5;
    pub const FAST_OP_ADD_IMM_64: u8 = 6;
    pub const FAST_OP_SUB_64: u8 = 7;
    pub const FAST_OP_MUL_IMM_64: u8 = 8;
    pub const FAST_OP_XOR: u8 = 9;
    pub const FAST_OP_AND: u8 = 10;
    pub const FAST_OP_OR: u8 = 11;
    pub const FAST_OP_SHIFT_LOGICAL_RIGHT_64: u8 = 12;
    pub const FAST_OP_SHIFT_LOGICAL_RIGHT_IMM_64: u8 = 13;
    pub const FAST_OP_MUL_UPPER_UNSIGNED_UNSIGNED_64: u8 = 14;
    pub const FAST_OP_MOVE_REG: u8 = 15;
    pub const FAST_OP_FALLTHROUGH: u8 = 16;
    pub const FAST_OP_BRANCH_EQ: u8 = 17;
    pub const FAST_OP_BRANCH_NE: u8 = 18;

    // H1 Batch A1 — 32-bit basic arithmetic.
    pub const FAST_OP_ADD_32: u8 = 19;
    pub const FAST_OP_SUB_32: u8 = 20;
    pub const FAST_OP_MUL_32: u8 = 21;
    pub const FAST_OP_ADD_IMM_32: u8 = 22;
    pub const FAST_OP_MUL_IMM_32: u8 = 23;
    pub const FAST_OP_SHIFT_LOGICAL_RIGHT_32: u8 = 24;

    // H1 Batch A2 — 64-bit shifts, rotates, negate_and_add.
    pub const FAST_OP_SHIFT_LOGICAL_LEFT_64: u8 = 25;
    pub const FAST_OP_SHIFT_LOGICAL_LEFT_IMM_64: u8 = 26;
    pub const FAST_OP_SHIFT_LOGICAL_LEFT_IMM_ALT_64: u8 = 27;
    pub const FAST_OP_SHIFT_LOGICAL_RIGHT_IMM_ALT_64: u8 = 28;
    pub const FAST_OP_SHIFT_ARITHMETIC_RIGHT_64: u8 = 29;
    pub const FAST_OP_SHIFT_ARITHMETIC_RIGHT_IMM_64: u8 = 30;
    pub const FAST_OP_SHIFT_ARITHMETIC_RIGHT_IMM_ALT_64: u8 = 31;
    pub const FAST_OP_ROTATE_LEFT_64: u8 = 32;
    pub const FAST_OP_ROTATE_RIGHT_64: u8 = 33;
    pub const FAST_OP_ROTATE_RIGHT_IMM_64: u8 = 34;
    pub const FAST_OP_ROTATE_RIGHT_IMM_ALT_64: u8 = 35;
    pub const FAST_OP_NEGATE_AND_ADD_IMM_64: u8 = 36;

    // H1 Batch A3 — 32-bit shifts, rotates, negate_and_add.
    pub const FAST_OP_SHIFT_LOGICAL_LEFT_32: u8 = 37;
    pub const FAST_OP_SHIFT_LOGICAL_LEFT_IMM_32: u8 = 38;
    pub const FAST_OP_SHIFT_LOGICAL_LEFT_IMM_ALT_32: u8 = 39;
    pub const FAST_OP_SHIFT_LOGICAL_RIGHT_IMM_32: u8 = 40;
    pub const FAST_OP_SHIFT_LOGICAL_RIGHT_IMM_ALT_32: u8 = 41;
    pub const FAST_OP_SHIFT_ARITHMETIC_RIGHT_32: u8 = 42;
    pub const FAST_OP_SHIFT_ARITHMETIC_RIGHT_IMM_32: u8 = 43;
    pub const FAST_OP_SHIFT_ARITHMETIC_RIGHT_IMM_ALT_32: u8 = 44;
    pub const FAST_OP_ROTATE_LEFT_32: u8 = 45;
    pub const FAST_OP_ROTATE_RIGHT_32: u8 = 46;
    pub const FAST_OP_ROTATE_RIGHT_IMM_32: u8 = 47;
    pub const FAST_OP_ROTATE_RIGHT_IMM_ALT_32: u8 = 48;
    pub const FAST_OP_NEGATE_AND_ADD_IMM_32: u8 = 49;

    // H1 Batch A4 — wide-multiply (signed/unsigned mixed, 32 + 64).
    // (mul_upper_unsigned_unsigned_64 is FAST_OP_MUL_UPPER_UNSIGNED_UNSIGNED_64 = 14 above.)
    pub const FAST_OP_MUL_UPPER_SIGNED_SIGNED_64: u8 = 50;
    pub const FAST_OP_MUL_UPPER_SIGNED_SIGNED_32: u8 = 51;
    pub const FAST_OP_MUL_UPPER_UNSIGNED_UNSIGNED_32: u8 = 52;
    pub const FAST_OP_MUL_UPPER_SIGNED_UNSIGNED_64: u8 = 53;
    pub const FAST_OP_MUL_UPPER_SIGNED_UNSIGNED_32: u8 = 54;

    // H1 Batch A5 — division + remainder. Helpers handle div-by-zero / INT_MIN/-1.
    pub const FAST_OP_DIV_UNSIGNED_64: u8 = 55;
    pub const FAST_OP_DIV_UNSIGNED_32: u8 = 56;
    pub const FAST_OP_DIV_SIGNED_64: u8 = 57;
    pub const FAST_OP_DIV_SIGNED_32: u8 = 58;
    pub const FAST_OP_REM_UNSIGNED_64: u8 = 59;
    pub const FAST_OP_REM_UNSIGNED_32: u8 = 60;
    pub const FAST_OP_REM_SIGNED_64: u8 = 61;
    pub const FAST_OP_REM_SIGNED_32: u8 = 62;

    // H1 Batch A6 — comparison setters (slt / sgt + _imm variants).
    pub const FAST_OP_SET_LESS_THAN_UNSIGNED: u8 = 63;
    pub const FAST_OP_SET_LESS_THAN_SIGNED: u8 = 64;
    pub const FAST_OP_SET_LESS_THAN_UNSIGNED_IMM: u8 = 65;
    pub const FAST_OP_SET_LESS_THAN_SIGNED_IMM: u8 = 66;
    pub const FAST_OP_SET_GREATER_THAN_UNSIGNED_IMM: u8 = 67;
    pub const FAST_OP_SET_GREATER_THAN_SIGNED_IMM: u8 = 68;

    // H1 Batch A7 — conditional moves. Asymmetric operand layout:
    //   cmov_if_*:     r0=d, r1=s,  r2=c              (copy reg→reg if c is zero/non-zero)
    //   cmov_if_*_imm: r0=d, r1=c,  imm1=s_imm        (write sign-extended imm if c is zero/non-zero)
    pub const FAST_OP_CMOV_IF_ZERO: u8 = 69;
    pub const FAST_OP_CMOV_IF_NOT_ZERO: u8 = 70;
    pub const FAST_OP_CMOV_IF_ZERO_IMM: u8 = 71;
    pub const FAST_OP_CMOV_IF_NOT_ZERO_IMM: u8 = 72;

    // H1 Batch A8 — bitmanip + immediates + min/max + bitcount + sign/zero extend.
    pub const FAST_OP_AND_IMM: u8 = 73;
    pub const FAST_OP_OR_IMM: u8 = 74;
    pub const FAST_OP_XOR_IMM: u8 = 75;
    pub const FAST_OP_AND_INVERTED_32: u8 = 76;
    pub const FAST_OP_AND_INVERTED_64: u8 = 77;
    pub const FAST_OP_OR_INVERTED_32: u8 = 78;
    pub const FAST_OP_OR_INVERTED_64: u8 = 79;
    pub const FAST_OP_XNOR_32: u8 = 80;
    pub const FAST_OP_XNOR_64: u8 = 81;
    pub const FAST_OP_MAXIMUM_32: u8 = 82;
    pub const FAST_OP_MAXIMUM_64: u8 = 83;
    pub const FAST_OP_MAXIMUM_UNSIGNED_32: u8 = 84;
    pub const FAST_OP_MAXIMUM_UNSIGNED_64: u8 = 85;
    pub const FAST_OP_MINIMUM_32: u8 = 86;
    pub const FAST_OP_MINIMUM_64: u8 = 87;
    pub const FAST_OP_MINIMUM_UNSIGNED_32: u8 = 88;
    pub const FAST_OP_MINIMUM_UNSIGNED_64: u8 = 89;
    pub const FAST_OP_COUNT_LEADING_ZERO_BITS_32: u8 = 90;
    pub const FAST_OP_COUNT_LEADING_ZERO_BITS_64: u8 = 91;
    pub const FAST_OP_COUNT_TRAILING_ZERO_BITS_32: u8 = 92;
    pub const FAST_OP_COUNT_TRAILING_ZERO_BITS_64: u8 = 93;
    pub const FAST_OP_COUNT_SET_BITS_32: u8 = 94;
    pub const FAST_OP_COUNT_SET_BITS_64: u8 = 95;
    pub const FAST_OP_SIGN_EXTEND_8_32: u8 = 96;
    pub const FAST_OP_SIGN_EXTEND_8_64: u8 = 97;
    pub const FAST_OP_SIGN_EXTEND_16_32: u8 = 98;
    pub const FAST_OP_SIGN_EXTEND_16_64: u8 = 99;
    pub const FAST_OP_ZERO_EXTEND_16_32: u8 = 100;
    pub const FAST_OP_ZERO_EXTEND_16_64: u8 = 101;
    pub const FAST_OP_REVERSE_BYTE_32: u8 = 102;
    pub const FAST_OP_REVERSE_BYTE_64: u8 = 103;

    // H1 Batch B — branches (signed/unsigned, reg-reg + reg-imm variants).
    // Existing fast tags: FAST_OP_BRANCH_EQ=17, FAST_OP_BRANCH_NE=18, FAST_OP_BRANCH_LT_U=3.
    pub const FAST_OP_BRANCH_LT_S: u8 = 104;
    pub const FAST_OP_BRANCH_GE_U: u8 = 105;
    pub const FAST_OP_BRANCH_GE_S: u8 = 106;
    pub const FAST_OP_BRANCH_EQ_IMM: u8 = 107;
    pub const FAST_OP_BRANCH_NE_IMM: u8 = 108;
    pub const FAST_OP_BRANCH_LT_U_IMM: u8 = 109;
    pub const FAST_OP_BRANCH_LT_S_IMM: u8 = 110;
    pub const FAST_OP_BRANCH_GE_U_IMM: u8 = 111;
    pub const FAST_OP_BRANCH_GE_S_IMM: u8 = 112;
    pub const FAST_OP_BRANCH_LE_S_IMM: u8 = 113;
    pub const FAST_OP_BRANCH_LE_U_IMM: u8 = 114;
    pub const FAST_OP_BRANCH_GT_S_IMM: u8 = 115;
    pub const FAST_OP_BRANCH_GT_U_IMM: u8 = 116;

    // H1 Batch C (partial) — trivial control flow. Complex variants
    // (jump_indirect, load_imm_and_jump_indirect, ecalli, sbrk, memset) still
    // route through the indirect-call fallback until they land in run_match.
    pub const FAST_OP_LOAD_IMM: u8 = 117;
    pub const FAST_OP_LOAD_IMM_AND_JUMP: u8 = 118;
    pub const FAST_OP_UNLIKELY: u8 = 119;

    // H1 Batch C-complex — control flow that may exit the run loop.
    // FAST_OP_TRAP (=4 above) gets a real arm now (was falling through to fallback).
    pub const FAST_OP_JUMP_INDIRECT: u8 = 120;
    pub const FAST_OP_LOAD_IMM_AND_JUMP_INDIRECT: u8 = 121;
    pub const FAST_OP_ECALLI: u8 = 122;
    pub const FAST_OP_SBRK: u8 = 123;

    // H1 Batch D — typed memory loads. `load_indirect_*` uses (base_reg + offset).
    pub const FAST_OP_LOAD_U8: u8 = 124;
    pub const FAST_OP_LOAD_I8: u8 = 125;
    pub const FAST_OP_LOAD_U16: u8 = 126;
    pub const FAST_OP_LOAD_I16: u8 = 127;
    pub const FAST_OP_LOAD_I32: u8 = 128;
    pub const FAST_OP_LOAD_U32: u8 = 129;
    pub const FAST_OP_LOAD_U64: u8 = 130;
    pub const FAST_OP_LOAD_INDIRECT_U8: u8 = 131;
    pub const FAST_OP_LOAD_INDIRECT_I8: u8 = 132;
    pub const FAST_OP_LOAD_INDIRECT_U16: u8 = 133;
    pub const FAST_OP_LOAD_INDIRECT_I16: u8 = 134;
    pub const FAST_OP_LOAD_INDIRECT_I32: u8 = 135;
    pub const FAST_OP_LOAD_INDIRECT_U32: u8 = 136;
    pub const FAST_OP_LOAD_INDIRECT_U64: u8 = 137;

    // H1 Batch E — typed memory stores. Four shapes × 4 widths.
    pub const FAST_OP_STORE_U8: u8 = 138;
    pub const FAST_OP_STORE_U16: u8 = 139;
    pub const FAST_OP_STORE_U32: u8 = 140;
    pub const FAST_OP_STORE_U64: u8 = 141;
    pub const FAST_OP_STORE_INDIRECT_U8: u8 = 142;
    pub const FAST_OP_STORE_INDIRECT_U16: u8 = 143;
    pub const FAST_OP_STORE_INDIRECT_U32: u8 = 144;
    pub const FAST_OP_STORE_INDIRECT_U64: u8 = 145;
    pub const FAST_OP_STORE_IMM_U8: u8 = 146;
    pub const FAST_OP_STORE_IMM_U16: u8 = 147;
    pub const FAST_OP_STORE_IMM_U32: u8 = 148;
    pub const FAST_OP_STORE_IMM_U64: u8 = 149;
    pub const FAST_OP_STORE_IMM_INDIRECT_U8: u8 = 150;
    pub const FAST_OP_STORE_IMM_INDIRECT_U16: u8 = 151;
    pub const FAST_OP_STORE_IMM_INDIRECT_U32: u8 = 152;
    pub const FAST_OP_STORE_IMM_INDIRECT_U64: u8 = 153;

    // H1 Batch F — memset (last opcode landing) + delete fallback unlock.
    pub const FAST_OP_MEMSET: u8 = 154;

    // Direct-dispatch tags for `unresolved_*` handlers. These are one-shot
    // self-rewriting handlers; after first execution they overwrite the inst
    // in compiled_decoded with a resolved opcode, so subsequent dispatches
    // hit a real fast arm.
    pub const FAST_OP_UNRESOLVED_BRANCH_EQ: u8 = 155;
    pub const FAST_OP_UNRESOLVED_BRANCH_NE: u8 = 156;
    pub const FAST_OP_UNRESOLVED_BRANCH_LT_U: u8 = 157;
    pub const FAST_OP_UNRESOLVED_BRANCH_LT_S: u8 = 158;
    pub const FAST_OP_UNRESOLVED_BRANCH_GE_U: u8 = 159;
    pub const FAST_OP_UNRESOLVED_BRANCH_GE_S: u8 = 160;
    pub const FAST_OP_UNRESOLVED_BRANCH_EQ_IMM: u8 = 161;
    pub const FAST_OP_UNRESOLVED_BRANCH_NE_IMM: u8 = 162;
    pub const FAST_OP_UNRESOLVED_BRANCH_LT_U_IMM: u8 = 163;
    pub const FAST_OP_UNRESOLVED_BRANCH_LT_S_IMM: u8 = 164;
    pub const FAST_OP_UNRESOLVED_BRANCH_GE_U_IMM: u8 = 165;
    pub const FAST_OP_UNRESOLVED_BRANCH_GE_S_IMM: u8 = 166;
    pub const FAST_OP_UNRESOLVED_BRANCH_LE_U_IMM: u8 = 167;
    pub const FAST_OP_UNRESOLVED_BRANCH_LE_S_IMM: u8 = 168;
    pub const FAST_OP_UNRESOLVED_BRANCH_GT_U_IMM: u8 = 169;
    pub const FAST_OP_UNRESOLVED_BRANCH_GT_S_IMM: u8 = 170;
    pub const FAST_OP_UNRESOLVED_JUMP: u8 = 171;
    pub const FAST_OP_UNRESOLVED_LOAD_IMM_AND_JUMP: u8 = 172;
    pub const FAST_OP_UNRESOLVED_FALLTHROUGH: u8 = 173;

    // Cleanup Phase 4a (2026-05-12) — step op (was visitor-only). Emitted when
    // step_tracing is enabled; on dispatch it sets InterruptKind::Step and
    // exits the run loop so the host can advance one instruction.
    pub const FAST_OP_STEP: u8 = 174;

    // Cleanup Phase 4b (2026-05-12) — cache-reset op. The cache size limiter
    // overwrites a slot's opcode with this when compiled_decoded outgrows its
    // budget; on dispatch, reset_cache clears the cache and recompiles the
    // block at the slot's source PC.
    pub const FAST_OP_RESET_CACHE: u8 = 175;

    // Tier 2 H2 (2026-05-12) — domain-specific crypto opcodes.
    // First: Goldilocks multiplication (canonical Plonky3 inner-loop op).
    // p = 2^64 - 2^32 + 1. Single opcode replaces ~20-30 decomposed PVM ops.
    pub const FAST_OP_GOLDILOCKS_MUL: u8 = 176;

    // Sentinel: handler has no fast-path arm; dispatch falls back to the
    // existing indirect-call path. Reserved at 0xFF so accidental zero-init
    // of compiled_decoded.opcode never collides with a valid implemented opcode.
    pub const FAST_OP_UNSUPPORTED: u8 = 0xFF;
}

/// Predecoded-instruction struct (40 bytes, javm field parity).
///
/// Operand layout for the dispatch arms; one entry per source PVM instruction
/// in `compiled_decoded`. Branch arms read `target_idx` (taken) and
/// `next_idx` (fallthrough), pre-resolved at emit time via `resolve_jump`.
///
/// Operand encoding:
/// - `imm1`: primary immediate. Full u64 for load_imm64 (still uses lo|hi<<32
///   packing in this single slot — the fast-path arm reads it as one u64 with
///   no reassembly). For ALU/shift/branch: zero-extended u32; sign-extension
///   to u64 happens in handlers via `get64(RegImm::Imm(_))`.
/// - `imm2`: secondary immediate when two distinct u32 values are needed
///   (store_imm `offset`+`value`, load_imm_and_jump_indirect `value`+`offset`).
///   Phase 1c replaced the pack-into-imm1-high-bits pattern for those shapes.
/// - `pc`: source program counter of this instruction (trap/step/oog
///   reporting). Stamped by compile_block_impl post-emit pass for every inst.
/// - `next_pc`: source program counter of the next sequential instruction.
///   Stamped by compile_block_impl post-emit pass. Mirrors javm's `next_pc`.
/// - `target_idx`: pre-resolved taken branch / unconditional jump target.
///   `u32::MAX` means "not set by constructor" (sentinel from
///   `DecodedInst::sentinel()`).
/// - `next_idx`: pre-resolved fallthrough/sequential index. For branches: the
///   not-taken target (set by the @define-rule constructor). For non-branches:
///   index of the next emitted inst (set by compile_block_impl post-emit
///   pass). `u32::MAX` is the constructor sentinel; post-emit converts it.
/// - `r0..r2`: register discriminants in declaration order (positional).
/// - `bb_gas_cost`: R3 per-block gas cost (non-zero only on first real op
///   of each block, or every real op under per-instruction metering).
///
/// Layout (40 bytes on 64-bit; #[repr(C)] for deterministic alignment;
/// matches javm's `size_of::<DecodedInst>() == 40` byte budget):
/// - imm1:        offset 0   (8)
/// - imm2:        offset 8   (8 — Phase 1c)
/// - pc:          offset 16  (4)
/// - next_pc:     offset 20  (4 — Phase 1c)
/// - next_idx:    offset 24  (4)
/// - target_idx:  offset 28  (4)
/// - bb_gas_cost: offset 32  (4)
/// - opcode:      offset 36  (1)
/// - r0..r2:      offset 37  (3)
/// - tail pad:    none — sums to 40 exactly
#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct DecodedInst {
    pub imm1: u64,
    pub imm2: u64,
    pub pc: u32,
    pub next_pc: u32,
    pub next_idx: u32,
    pub target_idx: u32,
    pub bb_gas_cost: u32,
    pub opcode: u8,
    pub r0: u8,
    pub r1: u8,
    pub r2: u8,
}

impl DecodedInst {
    /// Operand-zero / opcode-UNSUPPORTED base used by every per-handler
    /// constructor produced by `@define`. Callers (the emit macros)
    /// override `bb_gas_cost` and `opcode` via struct-update.
    ///
    /// Phase 1c: `target_idx` and `next_idx` default to `u32::MAX` —
    /// the "not set by constructor" sentinel. The compile_block_impl
    /// post-emit pass converts a `u32::MAX` next_idx to the real
    /// sequential index. Branch constructors (variants writing both
    /// targets) set both fields to real indices; their `u32::MAX` is
    /// never observed by the post-emit pass.
    pub fn sentinel() -> DecodedInst {
        DecodedInst {
            imm1: 0,
            imm2: 0,
            pc: 0,
            next_pc: 0,
            next_idx: u32::MAX,
            target_idx: u32::MAX,
            bb_gas_cost: 0,
            opcode: fast_opcode::FAST_OP_UNSUPPORTED,
            r0: 0,
            r1: 0,
            r2: 0,
        }
    }
}

polkavm_common::static_assert!(core::mem::size_of::<DecodedInst>() == cast(INTERPRETER_CACHE_ENTRY_SIZE).to_usize());

polkavm_common::static_assert!(core::mem::size_of::<CompiledOffset>() == cast(INTERPRETER_FLATMAP_ENTRY_SIZE).to_usize());

const MEMORY_STANDARD: usize = 0;
const MEMORY_DYNAMIC: usize = 1;

macro_rules! access_memory {
    ($self:expr, $kind:expr, |$memory:ident| $block:block) => {
        if $kind == MEMORY_STANDARD {
            let $memory = &$self.standard_memory;
            $block
        } else {
            debug_assert_eq!($kind, MEMORY_DYNAMIC);
            let $memory = &$self.dynamic_memory;
            $block
        }
    };
}

macro_rules! access_memory_mut {
    ($self:expr, $kind:expr, |$memory:ident| $block:block) => {
        if $kind == MEMORY_STANDARD {
            let $memory = &mut $self.standard_memory;
            $block
        } else {
            debug_assert_eq!($kind, MEMORY_DYNAMIC);
            let $memory = &mut $self.dynamic_memory;
            $block
        }
    };
}

pub(crate) struct InterpretedInstance {
    module: Module,
    standard_memory: StandardMemory,
    dynamic_memory: DynamicMemory,
    regs: [u64; Reg::ALL.len()],
    // Region addresses lifted out of StandardMemory for fast region-check
    // dispatch in load_impl / store_impl. Kept in sync with the canonical
    // copies inside standard_memory by `sync_hot_addresses()` at the 2 write
    // sites: after reset_memory() and after stack growth in store_impl_slow.
    // DynamicMemory mono leaves these at 0.
    hot_aux_address: u32,
    hot_stack_low_resident: u32,
    hot_rw_address: u32,
    hot_ro_address: u32,
    program_counter: ProgramCounter,
    program_counter_valid: bool,
    charge_gas_on_entry: bool,
    next_program_counter: Option<ProgramCounter>,
    next_program_counter_changed: bool,
    cycle_counter: u64,
    gas: i64,
    compiled_offset_for_block: FlatMap<CompiledOffset, true>,
    /// RostroVM U1 Turn 4 #1 (2026-05-11): single-array predecode. The hot
    /// dispatch path (both run_impl and run_match) reads only from this Vec.
    compiled_decoded: Vec<DecodedInst>,
    compiled_offset: u32,
    interrupt: InterruptKind,
    step_tracing: bool,
    unresolved_program_counter: Option<ProgramCounter>,
    /// Cleanup Phase 4c (2026-05-12): renamed from `max_cache_entries` —
    /// post-cleanup it tracks `compiled_decoded` size only. Set by
    /// `set_interpreter_cache_size_limit`; cache-eviction logic uses it to
    /// decide when to insert a `FAST_OP_RESET_CACHE` slot.
    max_cache_entries: Option<usize>,
    debug_mode: bool,
}

impl InterpretedInstance {
    pub fn new_from_module(module: Module, force_step_tracing: bool, imperfect_logger_filtering_workaround: bool) -> Self {
        let step_tracing = module.is_step_tracing() || force_step_tracing;
        let mut instance = Self {
            compiled_offset_for_block: FlatMap::new(module.code_len() + 1), // + 1 for one implicit out-of-bounds trap.
            compiled_decoded: Default::default(),
            module,
            standard_memory: StandardMemory::new(),
            dynamic_memory: DynamicMemory::new(),
            regs: [0; Reg::ALL.len()],
            hot_aux_address: 0,
            hot_stack_low_resident: 0,
            hot_rw_address: 0,
            hot_ro_address: 0,
            program_counter: ProgramCounter(!0),
            program_counter_valid: false,
            charge_gas_on_entry: true,
            next_program_counter: None,
            next_program_counter_changed: true,
            cycle_counter: 0,
            gas: 0,
            compiled_offset: 0,
            interrupt: InterruptKind::Finished,
            step_tracing,
            unresolved_program_counter: None,
            max_cache_entries: None,
            debug_mode: cfg!(test)
                || (!imperfect_logger_filtering_workaround
                    && (log::log_enabled!(target: "polkavm", log::Level::Debug)
                        || log::log_enabled!(target: "polkavm::interpreter", log::Level::Debug))),
        };

        instance.initialize_module();
        instance
    }

    #[inline]
    fn memory_kind(&self) -> usize {
        if self.module.is_dynamic_paging() {
            MEMORY_DYNAMIC
        } else {
            MEMORY_STANDARD
        }
    }

    pub fn reg(&self, reg: Reg) -> RegValue {
        let mut value = self.regs[reg.to_usize()];
        if !self.module.blob().is_64_bit() {
            value &= 0xffffffff;
        }

        value
    }

    pub fn set_reg(&mut self, reg: Reg, value: RegValue) {
        self.regs[reg.to_usize()] = if !self.module.blob().is_64_bit() {
            let value = cast(value).truncate_to_u32();
            let value = cast(value).to_signed();
            let value = cast(value).to_i64_sign_extend();
            cast(value).to_unsigned()
        } else {
            value
        };
    }

    pub fn gas(&self) -> Gas {
        self.gas
    }

    // ── Trace introspection (research only — see `polkavm::trace`) ────────
    //
    // These let an external tracer read the predecode-stamped state without
    // exposing the crate-internal `DecodedInst` type. Hot path is unaffected
    // (these are debug-only API surface; the actual run loop never calls them).

    /// Current `compiled_decoded` index. The next dispatch loop iteration
    /// will execute `compiled_decoded[compiled_offset()]`.
    pub fn trace_compiled_offset(&self) -> u32 {
        self.compiled_offset
    }

    /// Number of entries in `compiled_decoded` so far. Grows as basic
    /// blocks get compiled lazily.
    pub fn trace_compiled_decoded_len(&self) -> usize {
        self.compiled_decoded.len()
    }

    /// Snapshot the predecoded inst at `offset` as a public `InstFields`.
    /// Returns None if `offset` is out of range.
    pub fn trace_compiled_inst_at(&self, offset: u32) -> Option<crate::trace::InstFields> {
        let idx = offset as usize;
        let inst = self.compiled_decoded.get(idx)?;
        Some(crate::trace::InstFields {
            pc: inst.pc,
            next_pc: inst.next_pc,
            next_idx: inst.next_idx,
            target_idx: inst.target_idx,
            bb_gas_cost: inst.bb_gas_cost,
            opcode: inst.opcode,
            r0: inst.r0,
            r1: inst.r1,
            r2: inst.r2,
            imm1: inst.imm1,
            imm2: inst.imm2,
        })
    }

    pub fn set_gas(&mut self, gas: Gas) {
        self.gas = gas;
    }

    pub fn set_interpreter_cache_size_limit(&mut self, cache_info: Option<SetCacheSizeLimitArgs>) -> Result<(), Error> {
        let Some(SetCacheSizeLimitArgs {
            max_block_size,
            max_cache_size_bytes,
        }) = cache_info
        else {
            self.max_cache_entries = None;
            return Ok(());
        };

        let cache_entries_hard_limit = interpreter_calculate_cache_num_entries(max_cache_size_bytes);

        // Minimum compiled_decoded entries required to guarantee a tight upper
        // bound: hold at least two basic blocks (including gas-metering slot)
        // and account for precompiled stubs.
        let minimum_cache_entries = (cast(max_block_size).to_usize() + 1) * 2;

        if cache_entries_hard_limit < minimum_cache_entries {
            log::debug!(
                "interpreter cache size is too small to guarantee a tight upper bound: {} < {}; max_block_size={}, max_cache_size_bytes={}",
                cache_entries_hard_limit,
                minimum_cache_entries,
                max_block_size,
                max_cache_size_bytes
            );
            return Err(Error::from(
                "given maximum cache size is too small to guarantee a tight upper bound",
            ));
        }

        let cache_entries_soft_limit = cache_entries_hard_limit - (cast(max_block_size).to_usize() + 1);
        self.max_cache_entries = Some(cache_entries_soft_limit);
        Ok(())
    }

    pub fn set_interpreter_max_allocation_size(&mut self, value: Option<usize>) {
        self.standard_memory.max_allocation_size = value.unwrap_or(usize::MAX);
    }

    pub fn set_interpreter_guest_memory_limit(&mut self, value: Option<usize>) {
        self.standard_memory.guest_memory_limit = value.unwrap_or(usize::MAX);
    }

    pub fn program_counter(&self) -> Option<ProgramCounter> {
        if !self.program_counter_valid {
            None
        } else {
            Some(self.program_counter)
        }
    }

    pub fn next_program_counter(&self) -> Option<ProgramCounter> {
        self.next_program_counter
    }

    pub fn set_next_program_counter(&mut self, pc: ProgramCounter) {
        self.program_counter_valid = false;
        self.next_program_counter = Some(pc);
        self.next_program_counter_changed = true;
        self.charge_gas_on_entry = true;
    }

    pub fn accessible_aux_size(&self) -> u32 {
        access_memory!(self, self.memory_kind(), |memory| { memory.accessible_aux_size() })
    }

    pub fn set_accessible_aux_size(&mut self, size: u32) {
        access_memory_mut!(self, self.memory_kind(), |memory| { memory.set_accessible_aux_size(size) })
    }

    #[allow(clippy::unused_self)]
    pub fn next_native_program_counter(&self) -> Option<usize> {
        None
    }

    pub fn is_memory_accessible(&self, address: u32, size: u32, minimum_protection: MemoryProtection) -> bool {
        access_memory!(self, self.memory_kind(), |memory| {
            memory.is_memory_accessible(address, size, minimum_protection)
        })
    }

    pub fn read_memory_into<'slice>(
        &mut self,
        address: u32,
        buffer: &'slice mut [MaybeUninit<u8>],
    ) -> Result<&'slice mut [u8], MemoryAccessError> {
        access_memory_mut!(self, self.memory_kind(), |memory| { memory.read_memory_into(address, buffer) })
    }

    pub fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), MemoryAccessError> {
        access_memory_mut!(self, self.memory_kind(), |memory| { memory.write_memory(address, data) })
    }

    pub fn zero_memory(&mut self, address: u32, length: u32, memory_protection: Option<MemoryProtection>) -> Result<(), MemoryAccessError> {
        access_memory_mut!(self, self.memory_kind(), |memory| {
            memory.zero_memory(address, length, memory_protection)
        })
    }

    pub fn change_memory_protection(&mut self, address: u32, length: u32, protection: MemoryProtection) -> Result<(), MemoryAccessError> {
        access_memory_mut!(self, self.memory_kind(), |memory| {
            memory.change_memory_protection(address, length, protection)
        })
    }

    pub fn free_pages(&mut self, address: u32, length: u32) {
        access_memory_mut!(self, self.memory_kind(), |memory| { memory.free_pages(address, length) })
    }

    pub fn heap_size(&self) -> u32 {
        access_memory!(self, self.memory_kind(), |memory| { memory.heap_size() })
    }

    pub fn sbrk(&mut self, size: u32) -> Option<u32> {
        access_memory_mut!(self, self.memory_kind(), |memory| { memory.sbrk(&self.module, size) })
    }

    #[allow(clippy::unused_self)]
    pub fn pid(&self) -> Option<u32> {
        None
    }

    pub fn run(&mut self) -> Result<InterruptKind, Error> {
        // Phase 1 Pin Order Fix (2026-05-14): dispatch via per-memory-type
        // wrappers. Each wrapper has its own #[link_section] so the linker
        // gives StandardMemory and DynamicMemory variants of run_match
        // independently-pinned addresses, regardless of LLVM symbol hash
        // sort order. Was previously: self.run_match::<M>(), which produced
        // two monomorphizations in one section sorted by LLVM hash.
        Ok(if self.module.is_dynamic_paging() {
            self.run_match_dynamic()
        } else {
            self.run_match_standard()
        })
    }

    /// StandardMemory-monomorphized run_match. Body is the generic run_match
    /// inlined at compile time. Pinned at 0x300000 via .rostro_run_match_std.
    #[inline(never)]
    #[link_section = ".rostro_run_match_std"]
    fn run_match_standard(&mut self) -> InterruptKind {
        self.run_match_generic::<StandardMemory>()
    }

    /// DynamicMemory-monomorphized run_match. Pinned at 0x340000 via
    /// .rostro_run_match_dyn.
    #[inline(never)]
    #[link_section = ".rostro_run_match_dyn"]
    fn run_match_dynamic(&mut self) -> InterruptKind {
        self.run_match_generic::<DynamicMemory>()
    }


    /// Cold helper used by the inline gas check in `run_impl` / `run_match`.
    /// Mirrors the body of the old `charge_gas` handler's underflow path —
    /// sets the visitor's `NotEnoughGas` interrupt state, then returns the
    /// matching `InterruptKind` so the dispatch loop can exit.
    #[cold]
    #[inline(never)]
    fn handle_gas_underflow<const DEBUG: bool>(&mut self, pc: u32, new_gas: i64) -> InterruptKind {
        let _ = not_enough_gas_impl::<DEBUG>(self, ProgramCounter(pc), new_gas);
        self.interrupt.clone()
    }

    /// RostroVM interpreter dispatch loop.
    ///
    /// Walks `compiled_decoded` and dispatches each instruction via a `match`
    /// on `DecodedInst::opcode`. Every PVM opcode has a named arm; LLVM emits
    /// a jump table for the dispatch. Memory access calls go through `M`
    /// (StandardMemory or DynamicMemory) — monomorphized at the run() entry
    /// point so the dispatch arms have no runtime memory-kind branch.
    ///
    /// Cold paths:
    /// - `unresolved_*` ops (one-shot self-rewriting handlers; replaced with
    ///   the resolved opcode on first execution).
    /// - `Rostro intrinsics` (ecalli 100..1023): intercepted in FAST_OP_ECALLI
    ///   and dispatched inline to native intrinsic bodies — no run-loop exit.
    /// Generic run_match body. Inlined into the per-memory-type wrappers
    /// (run_match_standard / run_match_dynamic). Each wrapper has its own
    /// #[link_section] giving deterministic pin addresses.
    #[inline(always)]
    fn run_match_generic<M: Memory>(&mut self) -> InterruptKind {
        // H4 (2026-05-12): `const DEBUG: bool` removed from the generic params.
        // Halves run_match's monomorphizations (M × DEBUG = 4 → just M = 2),
        // shrinking the binary body that competes for I-cache. Trade-off:
        // debug-mode trace logging from helpers (load_impl, jump_indirect_impl,
        // etc.) is permanently off in run_match. Local const so all
        // `DEBUG`-bound generic call sites in macros + arms keep compiling.
        const DEBUG: bool = false;
        // Prologue mirrors run_impl's init — same memory mark + program-counter
        // resolution + entry gas charge. Code-duplicated rather than refactored
        // to keep run_match's diff additive in the U1 fork.
        access_memory_mut!(self, self.memory_kind(), |memory| {
            memory.mark_dirty();
        });

        if self.next_program_counter_changed {
            let Some(program_counter) = self.next_program_counter else {
                panic!("failed to run: next program counter is not set");
            };

            if let Some((offset, gas_cost)) = self.resolve_arbitrary_jump::<DEBUG>(program_counter) {
                if gas_cost > self.gas {
                    return InterruptKind::NotEnoughGas;
                }
                self.gas -= gas_cost;
                self.compiled_offset = offset;
            } else {
                self.program_counter_valid = true;
                self.program_counter = program_counter;
                return InterruptKind::Trap;
            }

            self.program_counter = program_counter;
            self.next_program_counter = None;
            self.next_program_counter_changed = false;
            self.charge_gas_on_entry = false;
        }

        let mut offset = self.compiled_offset;
        loop {
            // SAFETY: compile_block always terminates a block with a control-flow
            // op (jump/branch/trap), so falling through cannot run off the end
            // before reaching one. Branch targets are pre-resolved at emit time
            // to valid offsets within compiled_decoded.
            let idx = cast(offset).to_usize();
            let inst = unsafe { *self.compiled_decoded.get_unchecked(idx) };

            // R3: per-block inline gas check; folds the prior `charge_gas`
            // indirect call into the dispatch loop body.
            if inst.bb_gas_cost != 0 {
                let new_gas = self.gas - i64::from(inst.bb_gas_cost);
                if new_gas < 0 {
                    self.compiled_offset = offset;
                    return self.handle_gas_underflow::<DEBUG>(inst.pc, new_gas);
                }
                self.gas = new_gas;
            }

            match inst.opcode {
                fast_opcode::FAST_OP_LOAD_IMM64 => {
                    // R1: load_imm64's full u64 value lives directly in imm1
                    // (emit-time packs lo|hi<<32 → one u64). No reassembly here.
                    let dst = transmute_reg(inst.r0 as u32);
                    self.regs[dst as usize] = inst.imm1;
                    offset += 1;
                }
                fast_opcode::FAST_OP_MUL_64 => arm_reg_reg_reg_64!(self, inst, offset; |a, b| a.wrapping_mul(b)),
                fast_opcode::FAST_OP_JUMP => {
                    // jump's pre-resolved target lives in target_idx.
                    offset = inst.target_idx;
                }
                fast_opcode::FAST_OP_BRANCH_LT_U => arm_branch_reg_reg!(self, inst, offset; |a, b| a < b),
                fast_opcode::FAST_OP_ADD_64 => arm_reg_reg_reg_64!(self, inst, offset; |a, b| a.wrapping_add(b)),
                fast_opcode::FAST_OP_ADD_IMM_64 => arm_reg_reg_imm_64!(self, inst, offset; |a, imm| a.wrapping_add(imm)),
                fast_opcode::FAST_OP_SUB_64 => arm_reg_reg_reg_64!(self, inst, offset; |a, b| a.wrapping_sub(b)),
                fast_opcode::FAST_OP_MUL_IMM_64 => arm_reg_reg_imm_64!(self, inst, offset; |a, imm| a.wrapping_mul(imm)),
                fast_opcode::FAST_OP_XOR => arm_reg_reg_reg_64!(self, inst, offset; |a, b| a ^ b),
                fast_opcode::FAST_OP_AND => arm_reg_reg_reg_64!(self, inst, offset; |a, b| a & b),
                fast_opcode::FAST_OP_OR => arm_reg_reg_reg_64!(self, inst, offset; |a, b| a | b),
                fast_opcode::FAST_OP_SHIFT_LOGICAL_RIGHT_64 =>
                    arm_reg_reg_reg_64!(self, inst, offset; |a, b| a.wrapping_shr(b as u32)),
                fast_opcode::FAST_OP_SHIFT_LOGICAL_RIGHT_IMM_64 =>
                    arm_reg_reg_imm_64!(self, inst, offset; |a, imm| a.wrapping_shr(imm as u32)),
                fast_opcode::FAST_OP_MUL_UPPER_UNSIGNED_UNSIGNED_64 =>
                    arm_reg_reg_reg_64!(self, inst, offset; |a, b| mulhu64(a, b)),
                // H1 Batch A1 (2026-05-12) — 32-bit basic arithmetic.
                fast_opcode::FAST_OP_ADD_32 => arm_reg_reg_reg_32!(self, inst, offset; |a, b| a.wrapping_add(b)),
                fast_opcode::FAST_OP_SUB_32 => arm_reg_reg_reg_32!(self, inst, offset; |a, b| a.wrapping_sub(b)),
                fast_opcode::FAST_OP_MUL_32 => arm_reg_reg_reg_32!(self, inst, offset; |a, b| a.wrapping_mul(b)),
                fast_opcode::FAST_OP_ADD_IMM_32 => arm_reg_reg_imm_32!(self, inst, offset; |a, imm| a.wrapping_add(imm)),
                fast_opcode::FAST_OP_MUL_IMM_32 => arm_reg_reg_imm_32!(self, inst, offset; |a, imm| a.wrapping_mul(imm)),
                fast_opcode::FAST_OP_SHIFT_LOGICAL_RIGHT_32 =>
                    arm_reg_reg_reg_32!(self, inst, offset; |a, b| a.wrapping_shr(b)),
                // H1 Batch A2 (2026-05-12) — 64-bit shifts, rotates, negate_and_add.
                fast_opcode::FAST_OP_SHIFT_LOGICAL_LEFT_64 =>
                    arm_reg_reg_reg_64!(self, inst, offset; |a, b| a.wrapping_shl(b as u32)),
                fast_opcode::FAST_OP_SHIFT_LOGICAL_LEFT_IMM_64 =>
                    arm_reg_reg_imm_64!(self, inst, offset; |a, imm| a.wrapping_shl(imm as u32)),
                fast_opcode::FAST_OP_SHIFT_LOGICAL_LEFT_IMM_ALT_64 =>
                    arm_alt_reg_reg_imm_64!(self, inst, offset; |v, c| v.wrapping_shl(c as u32)),
                fast_opcode::FAST_OP_SHIFT_LOGICAL_RIGHT_IMM_ALT_64 =>
                    arm_alt_reg_reg_imm_64!(self, inst, offset; |v, c| v.wrapping_shr(c as u32)),
                fast_opcode::FAST_OP_SHIFT_ARITHMETIC_RIGHT_64 =>
                    arm_reg_reg_reg_64!(self, inst, offset; |a, b| (a as i64).wrapping_shr(b as u32) as u64),
                fast_opcode::FAST_OP_SHIFT_ARITHMETIC_RIGHT_IMM_64 =>
                    arm_reg_reg_imm_64!(self, inst, offset; |a, imm| (a as i64).wrapping_shr(imm as u32) as u64),
                fast_opcode::FAST_OP_SHIFT_ARITHMETIC_RIGHT_IMM_ALT_64 =>
                    arm_alt_reg_reg_imm_64!(self, inst, offset; |v, c| (v as i64).wrapping_shr(c as u32) as u64),
                fast_opcode::FAST_OP_ROTATE_LEFT_64 =>
                    arm_reg_reg_reg_64!(self, inst, offset; |a, b| a.rotate_left(b as u32)),
                fast_opcode::FAST_OP_ROTATE_RIGHT_64 =>
                    arm_reg_reg_reg_64!(self, inst, offset; |a, b| a.rotate_right(b as u32)),
                fast_opcode::FAST_OP_ROTATE_RIGHT_IMM_64 =>
                    arm_reg_reg_imm_64!(self, inst, offset; |a, imm| a.rotate_right(imm as u32)),
                fast_opcode::FAST_OP_ROTATE_RIGHT_IMM_ALT_64 =>
                    arm_alt_reg_reg_imm_64!(self, inst, offset; |v, c| v.rotate_right(c as u32)),
                fast_opcode::FAST_OP_NEGATE_AND_ADD_IMM_64 =>
                    arm_reg_reg_imm_64!(self, inst, offset; |a, imm| imm.wrapping_sub(a)),
                // H1 Batch A3 (2026-05-12) — 32-bit shifts, rotates, negate_and_add.
                fast_opcode::FAST_OP_SHIFT_LOGICAL_LEFT_32 =>
                    arm_reg_reg_reg_32!(self, inst, offset; |a, b| a.wrapping_shl(b)),
                fast_opcode::FAST_OP_SHIFT_LOGICAL_LEFT_IMM_32 =>
                    arm_reg_reg_imm_32!(self, inst, offset; |a, imm| a.wrapping_shl(imm)),
                fast_opcode::FAST_OP_SHIFT_LOGICAL_LEFT_IMM_ALT_32 =>
                    arm_alt_reg_reg_imm_32!(self, inst, offset; |v, c| v.wrapping_shl(c)),
                fast_opcode::FAST_OP_SHIFT_LOGICAL_RIGHT_IMM_32 =>
                    arm_reg_reg_imm_32!(self, inst, offset; |a, imm| a.wrapping_shr(imm)),
                fast_opcode::FAST_OP_SHIFT_LOGICAL_RIGHT_IMM_ALT_32 =>
                    arm_alt_reg_reg_imm_32!(self, inst, offset; |v, c| v.wrapping_shr(c)),
                fast_opcode::FAST_OP_SHIFT_ARITHMETIC_RIGHT_32 =>
                    arm_reg_reg_reg_32!(self, inst, offset; |a, b| (a as i32).wrapping_shr(b) as u32),
                fast_opcode::FAST_OP_SHIFT_ARITHMETIC_RIGHT_IMM_32 =>
                    arm_reg_reg_imm_32!(self, inst, offset; |a, imm| (a as i32).wrapping_shr(imm) as u32),
                fast_opcode::FAST_OP_SHIFT_ARITHMETIC_RIGHT_IMM_ALT_32 =>
                    arm_alt_reg_reg_imm_32!(self, inst, offset; |v, c| (v as i32).wrapping_shr(c) as u32),
                fast_opcode::FAST_OP_ROTATE_LEFT_32 =>
                    arm_reg_reg_reg_32!(self, inst, offset; |a, b| a.rotate_left(b)),
                fast_opcode::FAST_OP_ROTATE_RIGHT_32 =>
                    arm_reg_reg_reg_32!(self, inst, offset; |a, b| a.rotate_right(b)),
                fast_opcode::FAST_OP_ROTATE_RIGHT_IMM_32 =>
                    arm_reg_reg_imm_32!(self, inst, offset; |a, imm| a.rotate_right(imm)),
                fast_opcode::FAST_OP_ROTATE_RIGHT_IMM_ALT_32 =>
                    arm_alt_reg_reg_imm_32!(self, inst, offset; |v, c| v.rotate_right(c)),
                fast_opcode::FAST_OP_NEGATE_AND_ADD_IMM_32 =>
                    arm_reg_reg_imm_32!(self, inst, offset; |a, imm| imm.wrapping_sub(a)),
                // H1 Batch A4 (2026-05-12) — wide-multiply signed/mixed + 32-bit unsigned.
                fast_opcode::FAST_OP_MUL_UPPER_SIGNED_SIGNED_64 =>
                    arm_reg_reg_reg_64!(self, inst, offset; |a, b| mulh64(a as i64, b as i64) as u64),
                fast_opcode::FAST_OP_MUL_UPPER_SIGNED_SIGNED_32 =>
                    arm_reg_reg_reg_32!(self, inst, offset; |a, b| mulh(a as i32, b as i32) as u32),
                fast_opcode::FAST_OP_MUL_UPPER_UNSIGNED_UNSIGNED_32 =>
                    arm_reg_reg_reg_32!(self, inst, offset; |a, b| mulhu(a, b)),
                fast_opcode::FAST_OP_MUL_UPPER_SIGNED_UNSIGNED_64 =>
                    arm_reg_reg_reg_64!(self, inst, offset; |a, b| mulhsu64(a as i64, b) as u64),
                fast_opcode::FAST_OP_MUL_UPPER_SIGNED_UNSIGNED_32 =>
                    arm_reg_reg_reg_32!(self, inst, offset; |a, b| mulhsu(a as i32, b) as u32),
                // H1 Batch A5 (2026-05-12) — division + remainder.
                fast_opcode::FAST_OP_DIV_UNSIGNED_64 => arm_reg_reg_reg_64!(self, inst, offset; |a, b| divu64(a, b)),
                fast_opcode::FAST_OP_DIV_UNSIGNED_32 => arm_reg_reg_reg_32!(self, inst, offset; |a, b| divu(a, b)),
                fast_opcode::FAST_OP_DIV_SIGNED_64 =>
                    arm_reg_reg_reg_64!(self, inst, offset; |a, b| div64(a as i64, b as i64) as u64),
                fast_opcode::FAST_OP_DIV_SIGNED_32 =>
                    arm_reg_reg_reg_32!(self, inst, offset; |a, b| div(a as i32, b as i32) as u32),
                fast_opcode::FAST_OP_REM_UNSIGNED_64 => arm_reg_reg_reg_64!(self, inst, offset; |a, b| remu64(a, b)),
                fast_opcode::FAST_OP_REM_UNSIGNED_32 => arm_reg_reg_reg_32!(self, inst, offset; |a, b| remu(a, b)),
                fast_opcode::FAST_OP_REM_SIGNED_64 =>
                    arm_reg_reg_reg_64!(self, inst, offset; |a, b| rem64(a as i64, b as i64) as u64),
                fast_opcode::FAST_OP_REM_SIGNED_32 =>
                    arm_reg_reg_reg_32!(self, inst, offset; |a, b| rem(a as i32, b as i32) as u32),
                // H1 Batch A6 (2026-05-12) — comparison setters.
                fast_opcode::FAST_OP_SET_LESS_THAN_UNSIGNED =>
                    arm_reg_reg_reg_64!(self, inst, offset; |a, b| u64::from(a < b)),
                fast_opcode::FAST_OP_SET_LESS_THAN_SIGNED =>
                    arm_reg_reg_reg_64!(self, inst, offset; |a, b| u64::from((a as i64) < (b as i64))),
                fast_opcode::FAST_OP_SET_LESS_THAN_UNSIGNED_IMM =>
                    arm_reg_reg_imm_64!(self, inst, offset; |a, imm| u64::from(a < imm)),
                fast_opcode::FAST_OP_SET_LESS_THAN_SIGNED_IMM =>
                    arm_reg_reg_imm_64!(self, inst, offset; |a, imm| u64::from((a as i64) < (imm as i64))),
                fast_opcode::FAST_OP_SET_GREATER_THAN_UNSIGNED_IMM =>
                    arm_reg_reg_imm_64!(self, inst, offset; |a, imm| u64::from(a > imm)),
                fast_opcode::FAST_OP_SET_GREATER_THAN_SIGNED_IMM =>
                    arm_reg_reg_imm_64!(self, inst, offset; |a, imm| u64::from((a as i64) > (imm as i64))),
                // H1 Batch A7 (2026-05-12) — conditional moves.
                fast_opcode::FAST_OP_CMOV_IF_ZERO => {
                    let d = transmute_reg(inst.r0 as u32);
                    let s = transmute_reg(inst.r1 as u32);
                    let c = transmute_reg(inst.r2 as u32);
                    if self.regs[c as usize] == 0 {
                        self.regs[d as usize] = self.regs[s as usize];
                    }
                    offset += 1;
                }
                fast_opcode::FAST_OP_CMOV_IF_NOT_ZERO => {
                    let d = transmute_reg(inst.r0 as u32);
                    let s = transmute_reg(inst.r1 as u32);
                    let c = transmute_reg(inst.r2 as u32);
                    if self.regs[c as usize] != 0 {
                        self.regs[d as usize] = self.regs[s as usize];
                    }
                    offset += 1;
                }
                fast_opcode::FAST_OP_CMOV_IF_ZERO_IMM => {
                    let d = transmute_reg(inst.r0 as u32);
                    let c = transmute_reg(inst.r1 as u32);
                    if self.regs[c as usize] == 0 {
                        self.regs[d as usize] = inst.imm1 as u32 as i32 as i64 as u64;
                    }
                    offset += 1;
                }
                fast_opcode::FAST_OP_CMOV_IF_NOT_ZERO_IMM => {
                    let d = transmute_reg(inst.r0 as u32);
                    let c = transmute_reg(inst.r1 as u32);
                    if self.regs[c as usize] != 0 {
                        self.regs[d as usize] = inst.imm1 as u32 as i32 as i64 as u64;
                    }
                    offset += 1;
                }
                // H1 Batch A8 (2026-05-12) — bitmanip, immediates, min/max, bitcount, extends.
                fast_opcode::FAST_OP_AND_IMM => arm_reg_reg_imm_64!(self, inst, offset; |a, imm| a & imm),
                fast_opcode::FAST_OP_OR_IMM => arm_reg_reg_imm_64!(self, inst, offset; |a, imm| a | imm),
                fast_opcode::FAST_OP_XOR_IMM => arm_reg_reg_imm_64!(self, inst, offset; |a, imm| a ^ imm),
                fast_opcode::FAST_OP_AND_INVERTED_32 => arm_reg_reg_reg_32!(self, inst, offset; |a, b| a & !b),
                fast_opcode::FAST_OP_AND_INVERTED_64 => arm_reg_reg_reg_64!(self, inst, offset; |a, b| a & !b),
                fast_opcode::FAST_OP_OR_INVERTED_32 => arm_reg_reg_reg_32!(self, inst, offset; |a, b| a | !b),
                fast_opcode::FAST_OP_OR_INVERTED_64 => arm_reg_reg_reg_64!(self, inst, offset; |a, b| a | !b),
                fast_opcode::FAST_OP_XNOR_32 => arm_reg_reg_reg_32!(self, inst, offset; |a, b| !(a ^ b)),
                fast_opcode::FAST_OP_XNOR_64 => arm_reg_reg_reg_64!(self, inst, offset; |a, b| !(a ^ b)),
                fast_opcode::FAST_OP_MAXIMUM_32 =>
                    arm_reg_reg_reg_32!(self, inst, offset; |a, b| (a as i32).max(b as i32) as u32),
                fast_opcode::FAST_OP_MAXIMUM_64 =>
                    arm_reg_reg_reg_64!(self, inst, offset; |a, b| (a as i64).max(b as i64) as u64),
                fast_opcode::FAST_OP_MAXIMUM_UNSIGNED_32 => arm_reg_reg_reg_32!(self, inst, offset; |a, b| a.max(b)),
                fast_opcode::FAST_OP_MAXIMUM_UNSIGNED_64 => arm_reg_reg_reg_64!(self, inst, offset; |a, b| a.max(b)),
                fast_opcode::FAST_OP_MINIMUM_32 =>
                    arm_reg_reg_reg_32!(self, inst, offset; |a, b| (a as i32).min(b as i32) as u32),
                fast_opcode::FAST_OP_MINIMUM_64 =>
                    arm_reg_reg_reg_64!(self, inst, offset; |a, b| (a as i64).min(b as i64) as u64),
                fast_opcode::FAST_OP_MINIMUM_UNSIGNED_32 => arm_reg_reg_reg_32!(self, inst, offset; |a, b| a.min(b)),
                fast_opcode::FAST_OP_MINIMUM_UNSIGNED_64 => arm_reg_reg_reg_64!(self, inst, offset; |a, b| a.min(b)),
                fast_opcode::FAST_OP_COUNT_LEADING_ZERO_BITS_32 =>
                    arm_reg_reg_32!(self, inst, offset; |a| a.leading_zeros()),
                fast_opcode::FAST_OP_COUNT_LEADING_ZERO_BITS_64 =>
                    arm_reg_reg_64!(self, inst, offset; |a| a.leading_zeros() as u64),
                fast_opcode::FAST_OP_COUNT_TRAILING_ZERO_BITS_32 =>
                    arm_reg_reg_32!(self, inst, offset; |a| a.trailing_zeros()),
                fast_opcode::FAST_OP_COUNT_TRAILING_ZERO_BITS_64 =>
                    arm_reg_reg_64!(self, inst, offset; |a| a.trailing_zeros() as u64),
                fast_opcode::FAST_OP_COUNT_SET_BITS_32 => arm_reg_reg_32!(self, inst, offset; |a| a.count_ones()),
                fast_opcode::FAST_OP_COUNT_SET_BITS_64 =>
                    arm_reg_reg_64!(self, inst, offset; |a| a.count_ones() as u64),
                fast_opcode::FAST_OP_SIGN_EXTEND_8_32 =>
                    arm_reg_reg_32!(self, inst, offset; |a| (a as i8 as i32) as u32),
                fast_opcode::FAST_OP_SIGN_EXTEND_8_64 =>
                    arm_reg_reg_64!(self, inst, offset; |a| (a as i8 as i64) as u64),
                fast_opcode::FAST_OP_SIGN_EXTEND_16_32 =>
                    arm_reg_reg_32!(self, inst, offset; |a| (a as i16 as i32) as u32),
                fast_opcode::FAST_OP_SIGN_EXTEND_16_64 =>
                    arm_reg_reg_64!(self, inst, offset; |a| (a as i16 as i64) as u64),
                fast_opcode::FAST_OP_ZERO_EXTEND_16_32 => arm_reg_reg_32!(self, inst, offset; |a| (a as u16) as u32),
                fast_opcode::FAST_OP_ZERO_EXTEND_16_64 => arm_reg_reg_64!(self, inst, offset; |a| (a as u16) as u64),
                fast_opcode::FAST_OP_REVERSE_BYTE_32 => arm_reg_reg_32!(self, inst, offset; |a| a.swap_bytes()),
                fast_opcode::FAST_OP_REVERSE_BYTE_64 => arm_reg_reg_64!(self, inst, offset; |a| a.swap_bytes()),
                // H1 Batch B (2026-05-12) — branches (signed reg-reg + all reg-imm variants).
                fast_opcode::FAST_OP_BRANCH_LT_S =>
                    arm_branch_reg_reg!(self, inst, offset; |a, b| (a as i64) < (b as i64)),
                fast_opcode::FAST_OP_BRANCH_GE_U => arm_branch_reg_reg!(self, inst, offset; |a, b| a >= b),
                fast_opcode::FAST_OP_BRANCH_GE_S =>
                    arm_branch_reg_reg!(self, inst, offset; |a, b| (a as i64) >= (b as i64)),
                fast_opcode::FAST_OP_BRANCH_EQ_IMM => arm_branch_reg_imm!(self, inst, offset; |a, imm| a == imm),
                fast_opcode::FAST_OP_BRANCH_NE_IMM => arm_branch_reg_imm!(self, inst, offset; |a, imm| a != imm),
                fast_opcode::FAST_OP_BRANCH_LT_U_IMM => arm_branch_reg_imm!(self, inst, offset; |a, imm| a < imm),
                fast_opcode::FAST_OP_BRANCH_LT_S_IMM =>
                    arm_branch_reg_imm!(self, inst, offset; |a, imm| (a as i64) < (imm as i64)),
                fast_opcode::FAST_OP_BRANCH_GE_U_IMM => arm_branch_reg_imm!(self, inst, offset; |a, imm| a >= imm),
                fast_opcode::FAST_OP_BRANCH_GE_S_IMM =>
                    arm_branch_reg_imm!(self, inst, offset; |a, imm| (a as i64) >= (imm as i64)),
                fast_opcode::FAST_OP_BRANCH_LE_S_IMM =>
                    arm_branch_reg_imm!(self, inst, offset; |a, imm| (a as i64) <= (imm as i64)),
                fast_opcode::FAST_OP_BRANCH_LE_U_IMM => arm_branch_reg_imm!(self, inst, offset; |a, imm| a <= imm),
                fast_opcode::FAST_OP_BRANCH_GT_S_IMM =>
                    arm_branch_reg_imm!(self, inst, offset; |a, imm| (a as i64) > (imm as i64)),
                fast_opcode::FAST_OP_BRANCH_GT_U_IMM => arm_branch_reg_imm!(self, inst, offset; |a, imm| a > imm),
                // H1 Batch C (partial, 2026-05-12) — trivial control flow.
                fast_opcode::FAST_OP_LOAD_IMM => {
                    let dst = transmute_reg(inst.r0 as u32);
                    self.regs[dst as usize] = inst.imm1 as u32 as i32 as i64 as u64;
                    offset += 1;
                }
                fast_opcode::FAST_OP_LOAD_IMM_AND_JUMP => {
                    let dst = transmute_reg(inst.r0 as u32);
                    self.regs[dst as usize] = inst.imm1 as u32 as i32 as i64 as u64;
                    offset = inst.target_idx;
                }
                fast_opcode::FAST_OP_UNLIKELY => {
                    offset += 1;
                }
                // H1 Batch C-complex (2026-05-12) — control flow that may exit run loop.
                fast_opcode::FAST_OP_TRAP => {
                    self.program_counter = ProgramCounter(inst.pc);
                    self.program_counter_valid = true;
                    self.next_program_counter = None;
                    self.next_program_counter_changed = true;
                    self.unresolved_program_counter = None;
                    self.interrupt = InterruptKind::Trap;
                    self.compiled_offset = offset;
                    return InterruptKind::Trap;
                }
                fast_opcode::FAST_OP_JUMP_INDIRECT => {
                    let base = transmute_reg(inst.r0 as u32);
                    let off = inst.imm1 as u32;
                    let dynamic_address = (self.regs[base as usize] as u32).wrapping_add(off);
                    match self.jump_indirect_impl::<DEBUG>(ProgramCounter(inst.pc), dynamic_address) {
                        Some(target) => offset = target,
                        None => {
                            self.compiled_offset = offset;
                            return self.interrupt.clone();
                        }
                    }
                }
                fast_opcode::FAST_OP_LOAD_IMM_AND_JUMP_INDIRECT => {
                    let ra = transmute_reg(inst.r0 as u32);
                    let base = transmute_reg(inst.r1 as u32);
                    let value = inst.imm1 as u32;
                    let off = inst.imm2 as u32;
                    let dynamic_address = (self.regs[base as usize] as u32).wrapping_add(off);
                    self.regs[ra as usize] = value as i32 as i64 as u64;
                    match self.jump_indirect_impl::<DEBUG>(ProgramCounter(inst.pc), dynamic_address) {
                        Some(target) => offset = target,
                        None => {
                            self.compiled_offset = offset;
                            return self.interrupt.clone();
                        }
                    }
                }
                fast_opcode::FAST_OP_ECALLI => {
                    let hostcall_number = inst.imm1 as u32;
                    // Tier 2 H2 (2026-05-12) — Rostro intrinsic dispatch.
                    // Reserved IDs 0x10000..0x10FFF map to runtime-internal
                    // crypto intrinsics that the guest compiler hooks into via
                    // `polkavm_import(index = N)`. Dispatched INLINE — no run-
                    // loop exit, so each intrinsic is one fast-arm dispatch +
                    // the native body (vs ~20-30 dispatches for the decomposed
                    // PVM implementation).
                    match hostcall_number {
                        ROSTRO_INTRINSIC_GOLDILOCKS_MUL => {
                            // Arg ABI matches RISC-V/polkavm calling convention:
                            // a0 = first arg, a1 = second arg, a0 = return.
                            let a = self.regs[Reg::A0.to_usize()];
                            let b = self.regs[Reg::A1.to_usize()];
                            self.regs[Reg::A0.to_usize()] = goldilocks_mul_native(a, b);
                            offset += 1;
                        }
                        ROSTRO_INTRINSIC_GOLDILOCKS_ADD => {
                            let a = self.regs[Reg::A0.to_usize()];
                            let b = self.regs[Reg::A1.to_usize()];
                            self.regs[Reg::A0.to_usize()] = goldilocks_add_native(a, b);
                            offset += 1;
                        }
                        ROSTRO_INTRINSIC_GOLDILOCKS_SUB => {
                            let a = self.regs[Reg::A0.to_usize()];
                            let b = self.regs[Reg::A1.to_usize()];
                            self.regs[Reg::A0.to_usize()] = goldilocks_sub_native(a, b);
                            offset += 1;
                        }
                        ROSTRO_INTRINSIC_GOLDILOCKS_INV => {
                            let x = self.regs[Reg::A0.to_usize()];
                            self.regs[Reg::A0.to_usize()] = goldilocks_inv_native(x);
                            offset += 1;
                        }
                        ROSTRO_INTRINSIC_P521_ECDSA_VERIFY => {
                            // ABI: A0=vk_ptr (133B uncompressed sec1: 0x04||X||Y),
                            //      A1=sig_ptr (132B: r||s), A2=prehash_ptr,
                            //      A3=prehash_len. Returns A0 = 1 verified, 0 failed.
                            // Zero-copy borrow + shared verify body (also reused by
                            // the JIT runner's host-side dispatch).
                            let vk_ptr = self.regs[Reg::A0.to_usize()] as u32;
                            let sig_ptr = self.regs[Reg::A1.to_usize()] as u32;
                            let prehash_ptr = self.regs[Reg::A2.to_usize()] as u32;
                            let prehash_len = self.regs[Reg::A3.to_usize()] as u32;
                            let memory = <M as Memory>::memory_state(self);
                            let borrow_or_empty = |ptr: u32, len: u32| -> Option<&[u8]> {
                                if len == 0 { Some(&[]) } else { memory.borrow_bytes(ptr, len) }
                            };
                            let result: u64 = (|| {
                                let vk_bytes = memory.borrow_bytes(vk_ptr, 133)?;
                                let sig_bytes = memory.borrow_bytes(sig_ptr, 132)?;
                                let prehash = borrow_or_empty(prehash_ptr, prehash_len)?;
                                Some(rostro_p521_ecdsa_verify_prehash(vk_bytes, sig_bytes, prehash) as u64)
                            })().unwrap_or(0);
                            self.regs[Reg::A0.to_usize()] = result;
                            offset += 1;
                        }
                        ROSTRO_INTRINSIC_DILITHIUM_VERIFY => {
                            // ABI: A0=pubkey_ptr (1952B), A1=msg_ptr, A2=msg_len,
                            //      A3=sig_ptr (3309B), A4=ctx_ptr, A5=ctx_len
                            // Returns: A0 = 1 on verified, 0 otherwise.
                            // Zero-copy borrow + shared verify body (also reused by
                            // the JIT runner's host-side dispatch).
                            let pk_ptr  = self.regs[Reg::A0.to_usize()] as u32;
                            let msg_ptr = self.regs[Reg::A1.to_usize()] as u32;
                            let msg_len = self.regs[Reg::A2.to_usize()] as u32;
                            let sig_ptr = self.regs[Reg::A3.to_usize()] as u32;
                            let ctx_ptr = self.regs[Reg::A4.to_usize()] as u32;
                            let ctx_len = self.regs[Reg::A5.to_usize()] as u32;
                            let memory = <M as Memory>::memory_state(self);
                            // Empty slices on the guest side surface as dangling
                            // pointers (e.g. 0x1 for u8). Short-circuit zero-len
                            // borrows to an empty host slice rather than chasing
                            // them through borrow_bytes (which would correctly
                            // fail the region check).
                            let borrow_or_empty = |ptr: u32, len: u32| -> Option<&[u8]> {
                                if len == 0 { Some(&[]) } else { memory.borrow_bytes(ptr, len) }
                            };
                            let result: u64 = (|| {
                                let pk_bytes  = memory.borrow_bytes(pk_ptr,  1952)?;
                                let sig_bytes = memory.borrow_bytes(sig_ptr, 3309)?;
                                let msg = borrow_or_empty(msg_ptr, msg_len)?;
                                let ctx = borrow_or_empty(ctx_ptr, ctx_len)?;
                                Some(rostro_dilithium_verify(pk_bytes, msg, sig_bytes, ctx) as u64)
                            })().unwrap_or(0);
                            self.regs[Reg::A0.to_usize()] = result;
                            offset += 1;
                        }
                        ROSTRO_INTRINSIC_BLAKE2B_256 => {
                            // ABI: A0=msg_ptr, A1=msg_len, A2=out_ptr (32-byte output buffer).
                            // Returns: A0 = 0 on success, A0 = 1 on memory-access failure.
                            // The hash is owned (stack-allocated [u8; 32]), so we can
                            // release the immutable input borrow before taking the
                            // mutable output borrow — no aliasing conflict.
                            let msg_ptr = self.regs[Reg::A0.to_usize()] as u32;
                            let msg_len = self.regs[Reg::A1.to_usize()] as u32;
                            let out_ptr = self.regs[Reg::A2.to_usize()] as u32;
                            let result: u64 = (|| -> Option<u64> {
                                let hash = {
                                    let memory = <M as Memory>::memory_state(self);
                                    let msg = if msg_len == 0 { &[][..] } else { memory.borrow_bytes(msg_ptr, msg_len)? };
                                    rostro_blake2b_256(msg)
                                };
                                let memory_mut = <M as Memory>::memory_state_mut(self);
                                let out = memory_mut.borrow_bytes_mut(out_ptr, 32)?;
                                out.copy_from_slice(&hash);
                                Some(0)
                            })().unwrap_or(1);
                            self.regs[Reg::A0.to_usize()] = result;
                            offset += 1;
                        }
                        ROSTRO_INTRINSIC_KECCAK_256 => {
                            // ABI: same as BLAKE2B_256.
                            let msg_ptr = self.regs[Reg::A0.to_usize()] as u32;
                            let msg_len = self.regs[Reg::A1.to_usize()] as u32;
                            let out_ptr = self.regs[Reg::A2.to_usize()] as u32;
                            let result: u64 = (|| -> Option<u64> {
                                let hash = {
                                    let memory = <M as Memory>::memory_state(self);
                                    let msg = if msg_len == 0 { &[][..] } else { memory.borrow_bytes(msg_ptr, msg_len)? };
                                    rostro_keccak_256(msg)
                                };
                                let memory_mut = <M as Memory>::memory_state_mut(self);
                                let out = memory_mut.borrow_bytes_mut(out_ptr, 32)?;
                                out.copy_from_slice(&hash);
                                Some(0)
                            })().unwrap_or(1);
                            self.regs[Reg::A0.to_usize()] = result;
                            offset += 1;
                        }
                        ROSTRO_INTRINSIC_POSEIDON2_PERM => {
                            // ABI: A0 = state_ptr (8 little-endian u64s = 64 bytes).
                            // Returns: A0 = 0 on success, 1 on memory-access failure.
                            // Reads 8 u64s, runs the full permutation natively,
                            // writes 8 u64s back to the same address.
                            let state_ptr = self.regs[Reg::A0.to_usize()] as u32;
                            let result: u64 = (|| -> Option<u64> {
                                let mut state: [u64; POSEIDON2_WIDTH] = {
                                    let memory = <M as Memory>::memory_state(self);
                                    let bytes = memory.borrow_bytes(state_ptr, 64)?;
                                    let mut s = [0u64; POSEIDON2_WIDTH];
                                    for i in 0..POSEIDON2_WIDTH {
                                        s[i] = u64::from_le_bytes(bytes[i*8..(i+1)*8].try_into().ok()?);
                                    }
                                    s
                                };
                                rostro_poseidon2_permute(&mut state);
                                let memory_mut = <M as Memory>::memory_state_mut(self);
                                let out = memory_mut.borrow_bytes_mut(state_ptr, 64)?;
                                for i in 0..POSEIDON2_WIDTH {
                                    out[i*8..(i+1)*8].copy_from_slice(&state[i].to_le_bytes());
                                }
                                Some(0)
                            })().unwrap_or(1);
                            self.regs[Reg::A0.to_usize()] = result;
                            offset += 1;
                        }
                        _ => {
                            // Regular host call — exit run loop so host can dispatch.
                            let next_pc = self
                                .module
                                .instructions_bounded_at(ProgramCounter(inst.pc))
                                .next()
                                .unwrap()
                                .next_offset;
                            self.program_counter = ProgramCounter(inst.pc);
                            self.program_counter_valid = true;
                            self.next_program_counter = Some(next_pc);
                            self.next_program_counter_changed = true;
                            self.interrupt = InterruptKind::Ecalli(hostcall_number);
                            self.compiled_offset = offset;
                            return self.interrupt.clone();
                        }
                    }
                }
                fast_opcode::FAST_OP_SBRK => {
                    let dst = transmute_reg(inst.r0 as u32);
                    let size_reg = transmute_reg(inst.r1 as u32);
                    let size = self.regs[size_reg as usize];
                    let result =
                        size.try_into().ok().and_then(|s: u32| self.sbrk(s)).unwrap_or(0);
                    self.regs[dst as usize] = u64::from(result);
                    offset += 1;
                }
                // H1 Batch D (2026-05-12) — typed memory loads.
                fast_opcode::FAST_OP_LOAD_U8 => arm_load_nonindirect!(self, inst, offset; u8),
                fast_opcode::FAST_OP_LOAD_I8 => arm_load_nonindirect!(self, inst, offset; i8),
                fast_opcode::FAST_OP_LOAD_U16 => arm_load_nonindirect!(self, inst, offset; u16),
                fast_opcode::FAST_OP_LOAD_I16 => arm_load_nonindirect!(self, inst, offset; i16),
                fast_opcode::FAST_OP_LOAD_I32 => arm_load_nonindirect!(self, inst, offset; i32),
                fast_opcode::FAST_OP_LOAD_U32 => arm_load_nonindirect!(self, inst, offset; u32),
                fast_opcode::FAST_OP_LOAD_U64 => arm_load_nonindirect!(self, inst, offset; u64),
                fast_opcode::FAST_OP_LOAD_INDIRECT_U8 => arm_load_indirect!(self, inst, offset; u8),
                fast_opcode::FAST_OP_LOAD_INDIRECT_I8 => arm_load_indirect!(self, inst, offset; i8),
                fast_opcode::FAST_OP_LOAD_INDIRECT_U16 => arm_load_indirect!(self, inst, offset; u16),
                fast_opcode::FAST_OP_LOAD_INDIRECT_I16 => arm_load_indirect!(self, inst, offset; i16),
                fast_opcode::FAST_OP_LOAD_INDIRECT_I32 => arm_load_indirect!(self, inst, offset; i32),
                fast_opcode::FAST_OP_LOAD_INDIRECT_U32 => arm_load_indirect!(self, inst, offset; u32),
                fast_opcode::FAST_OP_LOAD_INDIRECT_U64 => arm_load_indirect!(self, inst, offset; u64),
                // H1 Batch E (2026-05-12) — typed memory stores.
                fast_opcode::FAST_OP_STORE_U8 => arm_store_nonindirect!(self, inst, offset; u8),
                fast_opcode::FAST_OP_STORE_U16 => arm_store_nonindirect!(self, inst, offset; u16),
                fast_opcode::FAST_OP_STORE_U32 => arm_store_nonindirect!(self, inst, offset; u32),
                fast_opcode::FAST_OP_STORE_U64 => arm_store_nonindirect!(self, inst, offset; u64),
                fast_opcode::FAST_OP_STORE_INDIRECT_U8 => arm_store_indirect!(self, inst, offset; u8),
                fast_opcode::FAST_OP_STORE_INDIRECT_U16 => arm_store_indirect!(self, inst, offset; u16),
                fast_opcode::FAST_OP_STORE_INDIRECT_U32 => arm_store_indirect!(self, inst, offset; u32),
                fast_opcode::FAST_OP_STORE_INDIRECT_U64 => arm_store_indirect!(self, inst, offset; u64),
                fast_opcode::FAST_OP_STORE_IMM_U8 => arm_store_imm!(self, inst, offset; u8),
                fast_opcode::FAST_OP_STORE_IMM_U16 => arm_store_imm!(self, inst, offset; u16),
                fast_opcode::FAST_OP_STORE_IMM_U32 => arm_store_imm!(self, inst, offset; u32),
                fast_opcode::FAST_OP_STORE_IMM_U64 => arm_store_imm!(self, inst, offset; u64),
                fast_opcode::FAST_OP_STORE_IMM_INDIRECT_U8 => arm_store_imm_indirect!(self, inst, offset; u8),
                fast_opcode::FAST_OP_STORE_IMM_INDIRECT_U16 => arm_store_imm_indirect!(self, inst, offset; u16),
                fast_opcode::FAST_OP_STORE_IMM_INDIRECT_U32 => arm_store_imm_indirect!(self, inst, offset; u32),
                fast_opcode::FAST_OP_STORE_IMM_INDIRECT_U64 => arm_store_imm_indirect!(self, inst, offset; u64),
                fast_opcode::FAST_OP_MOVE_REG => {
                    let d = transmute_reg(inst.r0 as u32);
                    let s = transmute_reg(inst.r1 as u32);
                    self.regs[d as usize] = self.regs[s as usize];
                    offset += 1;
                }
                fast_opcode::FAST_OP_FALLTHROUGH => {
                    offset += 1;
                }
                fast_opcode::FAST_OP_BRANCH_EQ => arm_branch_reg_reg!(self, inst, offset; |a, b| a == b),
                fast_opcode::FAST_OP_BRANCH_NE => arm_branch_reg_reg!(self, inst, offset; |a, b| a != b),
                // H1 Batch F (2026-05-12) — memset. Dispatches to the visitor's
                // memset handler (which reads args from compiled_offset). Direct
                // call to a named generic fn — no indirect call, no table break.
                fast_opcode::FAST_OP_MEMSET => {
                    // H1.1: direct call to memset's monomorphization for M.
                    self.compiled_offset = offset;
                    match raw_handlers::memset::<M, DEBUG>(self) {
                        Some(target) => offset = target,
                        None => {
                            self.compiled_offset = offset;
                            return self.interrupt.clone();
                        }
                    }
                }
                // Unresolved-handler one-shot dispatch. On first execution each
                // handler resolves its target and rewrites the inst with a
                // real fast opcode; subsequent dispatches hit a normal arm.
                fast_opcode::FAST_OP_UNRESOLVED_BRANCH_EQ =>
                    arm_unresolved!(self, offset, unresolved_branch_eq),
                fast_opcode::FAST_OP_UNRESOLVED_BRANCH_NE =>
                    arm_unresolved!(self, offset, unresolved_branch_not_eq),
                fast_opcode::FAST_OP_UNRESOLVED_BRANCH_LT_U =>
                    arm_unresolved!(self, offset, unresolved_branch_less_unsigned),
                fast_opcode::FAST_OP_UNRESOLVED_BRANCH_LT_S =>
                    arm_unresolved!(self, offset, unresolved_branch_less_signed),
                fast_opcode::FAST_OP_UNRESOLVED_BRANCH_GE_U =>
                    arm_unresolved!(self, offset, unresolved_branch_greater_or_equal_unsigned),
                fast_opcode::FAST_OP_UNRESOLVED_BRANCH_GE_S =>
                    arm_unresolved!(self, offset, unresolved_branch_greater_or_equal_signed),
                fast_opcode::FAST_OP_UNRESOLVED_BRANCH_EQ_IMM =>
                    arm_unresolved!(self, offset, unresolved_branch_eq_imm),
                fast_opcode::FAST_OP_UNRESOLVED_BRANCH_NE_IMM =>
                    arm_unresolved!(self, offset, unresolved_branch_not_eq_imm),
                fast_opcode::FAST_OP_UNRESOLVED_BRANCH_LT_U_IMM =>
                    arm_unresolved!(self, offset, unresolved_branch_less_unsigned_imm),
                fast_opcode::FAST_OP_UNRESOLVED_BRANCH_LT_S_IMM =>
                    arm_unresolved!(self, offset, unresolved_branch_less_signed_imm),
                fast_opcode::FAST_OP_UNRESOLVED_BRANCH_GE_U_IMM =>
                    arm_unresolved!(self, offset, unresolved_branch_greater_or_equal_unsigned_imm),
                fast_opcode::FAST_OP_UNRESOLVED_BRANCH_GE_S_IMM =>
                    arm_unresolved!(self, offset, unresolved_branch_greater_or_equal_signed_imm),
                fast_opcode::FAST_OP_UNRESOLVED_BRANCH_LE_U_IMM =>
                    arm_unresolved!(self, offset, unresolved_branch_less_or_equal_unsigned_imm),
                fast_opcode::FAST_OP_UNRESOLVED_BRANCH_LE_S_IMM =>
                    arm_unresolved!(self, offset, unresolved_branch_less_or_equal_signed_imm),
                fast_opcode::FAST_OP_UNRESOLVED_BRANCH_GT_U_IMM =>
                    arm_unresolved!(self, offset, unresolved_branch_greater_unsigned_imm),
                fast_opcode::FAST_OP_UNRESOLVED_BRANCH_GT_S_IMM =>
                    arm_unresolved!(self, offset, unresolved_branch_greater_signed_imm),
                fast_opcode::FAST_OP_UNRESOLVED_JUMP =>
                    arm_unresolved!(self, offset, unresolved_jump),
                fast_opcode::FAST_OP_UNRESOLVED_LOAD_IMM_AND_JUMP =>
                    arm_unresolved!(self, offset, unresolved_load_imm_and_jump),
                fast_opcode::FAST_OP_UNRESOLVED_FALLTHROUGH =>
                    arm_unresolved!(self, offset, unresolved_fallthrough),
                // Cleanup Phase 4a (2026-05-12) — step op for step_tracing.
                // Inlined from the old `raw_handlers::step` body. Sets the
                // Step interrupt and exits the run loop.
                fast_opcode::FAST_OP_STEP => {
                    self.program_counter = ProgramCounter(inst.pc);
                    self.program_counter_valid = true;
                    self.next_program_counter = Some(ProgramCounter(inst.pc));
                    self.next_program_counter_changed = false;
                    self.interrupt = InterruptKind::Step;
                    self.compiled_offset = offset + 1;
                    return InterruptKind::Step;
                }
                // Cleanup Phase 4b (2026-05-12) — cache-reset opcode.
                fast_opcode::FAST_OP_RESET_CACHE =>
                    arm_unresolved!(self, offset, reset_cache),
                // Tier 2 H2 (2026-05-12) — Goldilocks multiplication intrinsic.
                // Same operand layout as FAST_OP_MUL_64 (r0=dst, r1=a, r2=b).
                // Body is the native intrinsic — single 128-bit multiply +
                // Solinas reduction. ~5-10 x86_64 instructions.
                fast_opcode::FAST_OP_GOLDILOCKS_MUL => {
                    let d = transmute_reg(inst.r0 as u32);
                    let s1 = transmute_reg(inst.r1 as u32);
                    let s2 = transmute_reg(inst.r2 as u32);
                    let a = self.regs[s1 as usize];
                    let b = self.regs[s2 as usize];
                    self.regs[d as usize] = goldilocks_mul_native(a, b);
                    offset += 1;
                }
                // Any opcode discriminant not in the named set (including
                // UNSUPPORTED=0xFF for corrupt bytecode) traps. Should be
                // unreachable for any blob that's passed `Module::new`'s
                // validator.
                _ => {
                    self.program_counter = ProgramCounter(inst.pc);
                    self.program_counter_valid = true;
                    self.next_program_counter = None;
                    self.next_program_counter_changed = true;
                    self.unresolved_program_counter = None;
                    self.interrupt = InterruptKind::Trap;
                    self.compiled_offset = offset;
                    return InterruptKind::Trap;
                }
            }
        }
    }

    pub fn reset_memory(&mut self) {
        access_memory_mut!(self, self.memory_kind(), |memory| {
            memory.reset_memory(&self.module);
        });
        self.sync_hot_addresses();
    }

    /// Copies the four hot region addresses from `standard_memory` (which
    /// owns them) into the top-level fields read by `load_impl`/`store_impl`.
    /// DynamicMemory mono leaves all four at 0; the hot-path readers are
    /// only inlined into the StandardMemory mono of `run_match`, so this is
    /// a no-op there. Called after every site that mutates StandardMemory's
    /// canonical copies: `reset_memory`, `initialize_module`, and the stack
    /// grow path in `store_impl_slow`.
    #[inline]
    fn sync_hot_addresses(&mut self) {
        self.hot_aux_address = self.standard_memory.aux_data_address;
        self.hot_stack_low_resident = self.standard_memory.stack_address_low_resident;
        self.hot_rw_address = self.standard_memory.rw_data_address;
        self.hot_ro_address = self.standard_memory.ro_data_address;
    }

    pub fn reset_interpreter_cache(&mut self) {
        self.compiled_decoded.clear();
        self.compiled_decoded.shrink_to_fit();
        self.compiled_offset_for_block.reset();
        self.compiled_offset = 0;
    }

    fn initialize_module(&mut self) {
        if self.module.gas_metering().is_some() {
            self.gas = 0;
        }

        access_memory_mut!(self, self.memory_kind(), |memory| {
            memory.mark_dirty();
            memory.reset_memory(&self.module);
        });
        self.sync_hot_addresses();
    }

    #[inline(always)]
    fn pack_target(index: usize, is_jump_target_valid: bool) -> NonZeroU32 {
        let mut index = cast(index).assert_always_fits_in_u32();
        if is_jump_target_valid {
            index |= 1 << 31;
        }

        NonZeroU32::new(index + 1).unwrap()
    }

    #[inline(always)]
    fn unpack_target(value: NonZeroU32) -> (bool, Target) {
        let value = value.get() - 1;
        ((value >> 31) == 1, (value << 1) >> 1)
    }

    /// Resolve a jump from *within* the program.
    fn resolve_jump<const DEBUG: bool>(&mut self, program_counter: ProgramCounter) -> Option<Target> {
        if let Some(compiled_offset) = self.compiled_offset_for_block.get(program_counter.0) {
            let (is_jump_target_valid, target) = Self::unpack_target(compiled_offset);
            if !is_jump_target_valid {
                return None;
            }

            return Some(target);
        }

        if !self.module.is_jump_target_valid(program_counter) {
            return None;
        }

        self.compile_block::<DEBUG>(program_counter)
    }

    #[allow(unpredictable_function_pointer_comparisons)]
    fn extract_target_and_gas<const DEBUG: bool>(&self, compiled_offset: NonZeroU32) -> (Target, i64) {
        let (is_jump_target_valid, target) = Self::unpack_target(compiled_offset);
        if is_jump_target_valid
            || self.module.gas_metering().is_none()
            || self.module.is_per_instruction_metering()
            || !self.charge_gas_on_entry
        {
            return (target, 0);
        }

        // The block's gas cost lives in the `bb_gas_cost` field of the first
        // real DecodedInst of the block. If the block is step-traced, that
        // slot is `target + 1` (step occupies `target`); otherwise it's
        // `target` itself. Mid-block re-entry walks backward until it finds
        // a non-zero `bb_gas_cost`, which is by construction the block start.
        let mut start = cast(target).to_usize();
        if self.compiled_decoded[start].opcode == fast_opcode::FAST_OP_STEP {
            start += 1;
        }
        while start > 0 && self.compiled_decoded[start].bb_gas_cost == 0 {
            start -= 1;
        }
        let gas_cost = i64::from(self.compiled_decoded[start].bb_gas_cost);
        (target, gas_cost)
    }

    /// Resolve a jump from *outside* of the program.
    ///
    /// Unlike jumps from within the program these can start execution anywhere to support suspend/resume of the VM.
    fn resolve_arbitrary_jump<const DEBUG: bool>(&mut self, program_counter: ProgramCounter) -> Option<(Target, i64)> {
        if let Some(compiled_offset) = self.compiled_offset_for_block.get(program_counter.0) {
            return Some(self.extract_target_and_gas::<DEBUG>(compiled_offset));
        }

        if DEBUG {
            log::trace!("Resolving arbitrary jump: {program_counter}");
        }

        let basic_block_offset = match self.module.find_start_of_basic_block(program_counter) {
            Some(offset) => {
                log::trace!("  -> Found start of a basic block at: {offset}");
                offset
            }
            None => {
                if DEBUG {
                    log::trace!("  -> Start of a basic block not found!");
                }

                return None;
            }
        };
        self.compile_block::<DEBUG>(basic_block_offset)?;

        let compiled_offset = self.compiled_offset_for_block.get(program_counter.0)?;
        if basic_block_offset == program_counter {
            Some((Self::unpack_target(compiled_offset).1, 0))
        } else {
            Some(self.extract_target_and_gas::<DEBUG>(compiled_offset))
        }
    }

    /// Resolve a fallthrough.
    fn resolve_fallthrough<const DEBUG: bool>(&mut self, program_counter: ProgramCounter) -> Option<Target> {
        if let Some(compiled_offset) = self.compiled_offset_for_block.get(program_counter.0) {
            let (is_jump_target_valid, target) = Self::unpack_target(compiled_offset);
            if !is_jump_target_valid {
                return None;
            }

            return Some(target);
        }

        self.compile_block::<DEBUG>(program_counter)
    }

    #[inline(never)]
    fn compile_block<const DEBUG: bool>(&mut self, program_counter: ProgramCounter) -> Option<Target> {
        if program_counter.0 >= self.module.code_len() {
            return None;
        }

        if DEBUG {
            log::debug!("Compiling block:");
        }

        match self.module.cost_model() {
            CostModelKind::Simple(cost_model) => {
                if self.module.is_per_instruction_metering() {
                    // TODO: Remove this.
                    self.compile_block_impl::<_, DEBUG, true>(program_counter, GasVisitor::new(cost_model.clone()))
                } else {
                    self.compile_block_impl::<_, DEBUG, false>(program_counter, GasVisitor::new(cost_model.clone()))
                }
            }
            CostModelKind::Full(cost_model) => {
                use polkavm_common::simulator::Simulator;
                use polkavm_common::utils::{B32, B64};

                let blob = self.module.blob().clone(); // TODO: Unnecessary clone.
                let code = blob.code();

                if self.module.blob().is_64_bit() {
                    let gas_visitor = Simulator::<B64, ()>::new(code, blob.isa(), *cost_model, ());
                    self.compile_block_impl::<_, DEBUG, false>(program_counter, gas_visitor)
                } else {
                    let gas_visitor = Simulator::<B32, ()>::new(code, blob.isa(), *cost_model, ());
                    self.compile_block_impl::<_, DEBUG, false>(program_counter, gas_visitor)
                }
            }
        }
    }

    fn compile_block_impl<G, const DEBUG: bool, const PER_INSTRUCTION_METERING: bool>(
        &mut self,
        program_counter: ProgramCounter,
        mut gas_visitor: G,
    ) -> Option<Target>
    where
        G: GasVisitorT,
    {
        let Ok(origin) = u32::try_from(self.compiled_decoded.len()) else {
            panic!("internal compiled program counter overflow: the program is too big!");
        };

        // R3: per-block inline gas. No `charge_gas` DecodedInst is emitted; the
        // block's gas cost is stamped on the `bb_gas_cost` field of the first
        // real instruction emitted in the block, and the dispatch loops perform
        // the gas check inline before dispatching that instruction.
        let mut block_first_real_idx: Option<usize> = None;
        let mut is_jump_target_valid = self.module.is_jump_target_valid(program_counter);
        let gas_metering_enabled = self.module.gas_metering().is_some();
        for instruction in self.module.instructions_bounded_at(program_counter) {
            self.compiled_offset_for_block.insert(
                instruction.offset.0,
                Self::pack_target(self.compiled_decoded.len(), is_jump_target_valid),
            );

            is_jump_target_valid = false;

            if self.step_tracing {
                if DEBUG {
                    log::debug!("  [{}]: {}: step", self.compiled_decoded.len(), instruction.offset);
                }
                emit_consistent_address!(self, step(instruction.offset));
            }

            if gas_metering_enabled && !PER_INSTRUCTION_METERING {
                instruction.visit_parsing(&mut gas_visitor);
            }

            if DEBUG {
                log::debug!("  [{}]: {}: {}", self.compiled_decoded.len(), instruction.offset, instruction.kind);
            }

            #[cfg(debug_assertions)]
            let original_length = self.compiled_decoded.len();
            let memory_kind = self.memory_kind();
            let real_start = self.compiled_decoded.len();

            instruction.visit(&mut Compiler::<DEBUG> {
                program_counter: instruction.offset,
                next_program_counter: instruction.next_offset,
                compiled_decoded: &mut self.compiled_decoded,
                module: &self.module,
                memory_kind,
            });

            #[cfg(debug_assertions)]
            debug_assert!(
                instruction.opcode() == polkavm_common::program::Opcode::unlikely || self.compiled_decoded.len() > original_length
            );

            // Phase 1c: stamp pc + next_pc + sequential next_idx on the first
            // emitted DecodedInst for this source instruction. Mirrors javm's
            // predecode — every inst carries its source PC, next PC, and a
            // pre-resolved next index so Phase 2's sentinel dispatch can fall
            // through via `idx = inst.next_idx` without per-arm bookkeeping.
            //
            // `next_idx == u32::MAX` is the constructor sentinel for "not set":
            // branch @define-rule constructors (variants 19/20/22/23) populate
            // it with the not-taken target; everything else leaves it MAX and
            // we patch it here to the sequential next index.
            let real_end = self.compiled_decoded.len();
            if real_start < real_end {
                self.compiled_decoded[real_start].pc = instruction.offset.0;
                self.compiled_decoded[real_start].next_pc = instruction.next_offset.0;
                if self.compiled_decoded[real_start].next_idx == u32::MAX {
                    let next_idx = u32::try_from(real_end)
                        .expect("compiled_decoded length overflows u32 (predecode invariant)");
                    self.compiled_decoded[real_start].next_idx = next_idx;
                }
            }

            // Gas-metering bookkeeping always lands on the first DecodedInst emitted
            // by this source instruction. For block metering, only the block's first
            // real op carries the cost; for per-instruction metering, every real op
            // carries 1. (Phase 1c handles the pc stamp above; we just record gas
            // here.)
            if gas_metering_enabled && real_start < real_end {
                if block_first_real_idx.is_none() {
                    block_first_real_idx = Some(real_start);
                }
                if PER_INSTRUCTION_METERING {
                    self.compiled_decoded[real_start].bb_gas_cost = 1;
                }
            }

            if instruction.opcode().starts_new_basic_block() {
                break;
            }
        }

        if let Some(max_cache_entries) = self.max_cache_entries {
            let entries_added = self.compiled_decoded.len() - cast(origin).to_usize();
            if entries_added > max_cache_entries {
                let new_limit = entries_added;

                log::warn!(
                    "interpreter: predecode cache is too small: {} > {}; setting new limit to {} and resetting the cache",
                    entries_added,
                    max_cache_entries,
                    new_limit
                );

                self.max_cache_entries = Some(new_limit);
                let origin_idx = cast(origin).to_usize();
                self.compiled_decoded[origin_idx] = DecodedInst {
                    bb_gas_cost: 0,
                    opcode: fast_op_for!(reset_cache),
                    ..DecodedInst::reset_cache(program_counter)
                };
            } else if self.compiled_decoded.len() > max_cache_entries {
                log::debug!(
                    "interpreter: predecode cache size exceeded at {}: {} > {}; will reset the cache",
                    origin,
                    self.compiled_decoded.len(),
                    max_cache_entries
                );

                let origin_idx = cast(origin).to_usize();
                self.compiled_decoded[origin_idx] = DecodedInst {
                    bb_gas_cost: 0,
                    opcode: fast_op_for!(reset_cache),
                    ..DecodedInst::reset_cache(program_counter)
                };
            } else if self.compiled_decoded.capacity() > max_cache_entries {
                self.compiled_decoded.shrink_to(max_cache_entries);
            }
        }

        if gas_metering_enabled && !PER_INSTRUCTION_METERING {
            if let Some(index) = block_first_real_idx {
                let gas_cost = gas_visitor.take_block_cost().unwrap();
                self.compiled_decoded[index].bb_gas_cost = gas_cost as u32;
            }
        }

        if self.compiled_decoded.len() == cast(origin).to_usize() {
            return None;
        }

        Some(origin)
    }

    #[inline(always)]
    fn get32<const DEBUG: bool>(&self, regimm: impl IntoRegImm) -> u32 {
        match regimm.into() {
            RegImm::Reg(reg) => {
                let value = cast(self.regs[reg.to_usize()]).truncate_to_u32();
                if DEBUG {
                    log::trace!("  get: {reg} = 0x{value:x}");
                }
                value
            }
            RegImm::Imm(value) => value,
        }
    }

    #[inline(always)]
    fn get64<const DEBUG: bool>(&self, regimm: impl IntoRegImm) -> u64 {
        match regimm.into() {
            RegImm::Reg(reg) => {
                let value = self.regs[reg.to_usize()];
                if DEBUG {
                    log::trace!("  get: {reg} = 0x{value:x}");
                }
                value
            }
            RegImm::Imm(value) => {
                let value = cast(value).to_signed();
                let value = cast(value).to_i64_sign_extend();
                cast(value).to_unsigned()
            }
        }
    }

    #[inline(always)]
    fn go_to_next_instruction(&self) -> Option<Target> {
        Some(self.compiled_offset + 1)
    }

    #[inline(always)]
    fn set32<const DEBUG: bool>(&mut self, dst: Reg, value: u32) {
        let value = cast(value).to_signed();
        let value = cast(value).to_i64_sign_extend();
        let value = cast(value).to_unsigned();

        if DEBUG {
            if self.module.blob().is_64_bit() {
                log::trace!("  set: {dst} = 0x{value:x}");
            } else {
                log::trace!("  set: {dst} = 0x{:x}", cast(value).truncate_to_u32());
            }
        }

        self.regs[dst.to_usize()] = value;
    }

    #[inline(always)]
    fn set64<const DEBUG: bool>(&mut self, dst: Reg, value: u64) {
        if DEBUG {
            log::trace!("  set: {dst} = 0x{value:x}");
        }

        self.regs[dst.to_usize()] = value;
    }

    #[inline(always)]
    fn set3_32<const DEBUG: bool>(
        &mut self,
        dst: Reg,
        s1: impl IntoRegImm,
        s2: impl IntoRegImm,
        callback: impl Fn(u32, u32) -> u32,
    ) -> Option<Target> {
        let s1 = self.get32::<DEBUG>(s1);
        let s2 = self.get32::<DEBUG>(s2);
        self.set32::<DEBUG>(dst, callback(s1, s2));
        self.go_to_next_instruction()
    }

    #[inline(always)]
    fn set3_64<const DEBUG: bool>(
        &mut self,
        dst: Reg,
        s1: impl IntoRegImm,
        s2: impl IntoRegImm,
        callback: impl Fn(u64, u64) -> u64,
    ) -> Option<Target> {
        let s1 = self.get64::<DEBUG>(s1);
        let s2 = self.get64::<DEBUG>(s2);
        self.set64::<DEBUG>(dst, callback(s1, s2));
        self.go_to_next_instruction()
    }

    fn branch<const DEBUG: bool>(
        &mut self,
        s1: impl IntoRegImm,
        s2: impl IntoRegImm,
        target_true: Target,
        target_false: Target,
        callback: impl Fn(u64, u64) -> bool,
    ) -> Option<Target> {
        let s1 = self.get64::<DEBUG>(s1);
        let s2 = self.get64::<DEBUG>(s2);

        #[allow(clippy::collapsible_else_if)]
        let target = if callback(s1, s2) { target_true } else { target_false };

        Some(target)
    }

    fn segfault_impl(&mut self, program_counter: ProgramCounter, page_address: u32, is_write_protected: bool) -> Option<Target> {
        if page_address < 1024 * 16 {
            return trap_impl::<false>(self, program_counter);
        }

        self.program_counter = program_counter;
        self.program_counter_valid = true;
        self.next_program_counter = Some(program_counter);
        self.interrupt = InterruptKind::Segfault(Segfault {
            page_address,
            page_size: self.module.memory_map().page_size(),
            is_write_protected,
        });

        None
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn load<M: Memory, T: LoadTy, const DEBUG: bool>(
        &mut self,
        program_counter: ProgramCounter,
        dst: Reg,
        base: Option<Reg>,
        offset: u32,
    ) -> Option<Target> {
        assert!(core::mem::size_of::<T>() >= 1);

        let address = base
            .map_or(0, |base| cast(self.regs[base.to_usize()]).truncate_to_u32())
            .wrapping_add(offset);

        M::load_impl::<T, DEBUG>(self, program_counter, dst, address)
    }

    #[inline(never)]
    fn on_load_ok_trace<T: LoadTy>(dst: Reg, address: u32, value: u64) {
        log::trace!("  {dst} = {kind} [0x{address:x}] = 0x{value:x}", kind = core::any::type_name::<T>());
    }

    #[must_use]
    #[inline(always)]
    fn on_load_ok<T: LoadTy, const DEBUG: bool>(&mut self, dst: Reg, address: u32, value: u64) -> Option<Target> {
        if DEBUG {
            Self::on_load_ok_trace::<T>(dst, address, value);
        }

        self.set64::<false>(dst, value);
        self.go_to_next_instruction()
    }

    #[must_use]
    #[cold]
    #[inline(never)]
    fn on_load_trap<T: LoadTy, const DEBUG: bool>(&mut self, pc: ProgramCounter, address: u32) -> Option<Target> {
        if DEBUG {
            log::debug!(
                "Load of {length} bytes from 0x{address:x} failed: trap! (pc = {program_counter}, cycle = {cycle})",
                length = core::mem::size_of::<T>(),
                program_counter = pc,
                cycle = self.cycle_counter
            );
        }

        trap_impl::<DEBUG>(self, pc)
    }

    #[must_use]
    #[cold]
    #[inline(never)]
    fn on_load_segfault<T: LoadTy, const DEBUG: bool>(
        &mut self,
        pc: ProgramCounter,
        address: u32,
        page_address: u32,
        is_write_protected: bool,
    ) -> Option<Target> {
        if DEBUG {
            log::debug!(
                "Load of {length} bytes from 0x{address:x} failed: segfault! (pc = {program_counter}, cycle = {cycle})",
                length = core::mem::size_of::<T>(),
                program_counter = pc,
                cycle = self.cycle_counter
            );
        }

        self.segfault_impl(pc, page_address, is_write_protected)
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn store<M: Memory, T: StoreTy, const DEBUG: bool>(
        &mut self,
        program_counter: ProgramCounter,
        src: impl IntoRegImm,
        base: Option<Reg>,
        offset: u32,
    ) -> Option<Target> {
        assert!(core::mem::size_of::<T>() >= 1);

        let address = base
            .map_or(0, |base| cast(self.regs[base.to_usize()]).truncate_to_u32())
            .wrapping_add(offset);

        let value = match src.into() {
            RegImm::Reg(src) => {
                let value = self.regs[src.to_usize()];
                if DEBUG {
                    log::trace!("  {kind} [0x{address:x}] = {src} = 0x{value:x}", kind = core::any::type_name::<T>());
                }

                value
            }
            RegImm::Imm(value) => {
                if DEBUG {
                    log::trace!("  {kind} [0x{address:x}] = 0x{value:x}", kind = core::any::type_name::<T>());
                }

                let value = cast(value).to_signed();
                let value = cast(value).to_i64_sign_extend();
                cast(value).to_unsigned()
            }
        };

        M::store_impl::<T, DEBUG>(self, program_counter, address, value)
    }

    #[must_use]
    #[inline(always)]
    fn on_store_ok<T: StoreTy, const DEBUG: bool>(&mut self) -> Option<Target> {
        self.go_to_next_instruction()
    }

    #[must_use]
    #[cold]
    #[inline(never)]
    fn on_store_trap<T: StoreTy, const DEBUG: bool>(&mut self, pc: ProgramCounter, address: u32) -> Option<Target> {
        if DEBUG {
            log::debug!(
                "Store of {length} bytes to 0x{address:x} failed: trap! (pc = {program_counter}, cycle = {cycle})",
                length = core::mem::size_of::<T>(),
                program_counter = pc,
                cycle = self.cycle_counter
            );
        }

        trap_impl::<DEBUG>(self, pc)
    }

    #[must_use]
    #[cold]
    #[inline(never)]
    fn on_store_trap_due_to_memory_limit<T: StoreTy, const DEBUG: bool>(&mut self, pc: ProgramCounter, address: u32) -> Option<Target> {
        if DEBUG {
            log::debug!(
                "Store of {length} bytes to 0x{address:x} failed: trap due to memory limits! (pc = {program_counter}, cycle = {cycle})",
                length = core::mem::size_of::<T>(),
                program_counter = pc,
                cycle = self.cycle_counter
            );
        }

        trap_impl::<DEBUG>(self, pc)
    }

    #[cold]
    #[inline(never)]
    fn on_store_segfault<T: StoreTy, const DEBUG: bool>(
        &mut self,
        pc: ProgramCounter,
        address: u32,
        page_address: u32,
        is_write_protected: bool,
    ) -> Option<Target> {
        if DEBUG {
            log::debug!(
                "Store of {length} bytes to 0x{address:x} failed: segfault! (pc = {program_counter}, cycle = {cycle})",
                length = core::mem::size_of::<T>(),
                program_counter = pc,
                cycle = self.cycle_counter
            );
        }

        self.segfault_impl(pc, page_address, is_write_protected)
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn jump_indirect_impl<const DEBUG: bool>(&mut self, program_counter: ProgramCounter, dynamic_address: u32) -> Option<Target> {
        if dynamic_address == VM_ADDR_RETURN_TO_HOST {
            self.program_counter = ProgramCounter(!0);
            self.program_counter_valid = false;
            self.next_program_counter = None;
            self.next_program_counter_changed = true;
            self.interrupt = InterruptKind::Finished;
            return None;
        }

        let Some(target) = self.module.jump_table().get_by_address(dynamic_address) else {
            if DEBUG {
                log::trace!("Indirect jump to dynamic address {dynamic_address}: invalid (bad jump table index)");
            }

            return trap_impl::<DEBUG>(self, program_counter);
        };

        if let Some(target) = self.resolve_jump::<DEBUG>(target) {
            if DEBUG {
                log::trace!("Indirect jump to dynamic address {dynamic_address}: {target}");
            }

            Some(target)
        } else {
            if DEBUG {
                log::trace!("Indirect jump to dynamic address {dynamic_address}: invalid (bad target)");
            }

            trap_impl::<DEBUG>(self, program_counter)
        }
    }
}

trait LoadTy {
    type Slice: Default
        + core::ops::Index<core::ops::Range<usize>, Output = [u8]>
        + core::ops::IndexMut<core::ops::Range<usize>, Output = [u8]>
        + core::ops::Index<core::ops::RangeFrom<usize>, Output = [u8]>
        + core::ops::IndexMut<core::ops::RangeFrom<usize>, Output = [u8]>
        + core::ops::Index<core::ops::RangeTo<usize>, Output = [u8]>
        + core::ops::IndexMut<core::ops::RangeTo<usize>, Output = [u8]>
        + core::convert::AsRef<[u8]>;
    fn from_slice(xs: &[u8]) -> u64;
}

impl LoadTy for u8 {
    type Slice = [u8; 1];
    fn from_slice(xs: &[u8]) -> u64 {
        u64::from(xs[0])
    }
}

impl LoadTy for i8 {
    type Slice = [u8; 1];
    fn from_slice(xs: &[u8]) -> u64 {
        let value = cast(xs[0]).to_signed();
        let value = cast(value).to_i64_sign_extend();
        cast(value).to_unsigned()
    }
}

impl LoadTy for u16 {
    type Slice = [u8; 2];
    fn from_slice(xs: &[u8]) -> u64 {
        u64::from(u16::from_le_bytes([xs[0], xs[1]]))
    }
}

impl LoadTy for i16 {
    type Slice = [u8; 2];
    fn from_slice(xs: &[u8]) -> u64 {
        let value = i16::from_le_bytes([xs[0], xs[1]]);
        let value = cast(value).to_i64_sign_extend();
        cast(value).to_unsigned()
    }
}

impl LoadTy for u32 {
    type Slice = [u8; 4];
    fn from_slice(xs: &[u8]) -> u64 {
        u64::from(u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]))
    }
}

impl LoadTy for i32 {
    type Slice = [u8; 4];
    fn from_slice(xs: &[u8]) -> u64 {
        let value = i32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]);
        let value = cast(value).to_i64_sign_extend();
        cast(value).to_unsigned()
    }
}

impl LoadTy for u64 {
    type Slice = [u8; 8];
    fn from_slice(xs: &[u8]) -> u64 {
        u64::from_le_bytes([xs[0], xs[1], xs[2], xs[3], xs[4], xs[5], xs[6], xs[7]])
    }
}

trait StoreTy: Sized {
    type Array: AsRef<[u8]>;
    fn into_bytes(value: u64) -> Self::Array;
}

impl StoreTy for u8 {
    type Array = [u8; 1];

    #[inline(always)]
    fn into_bytes(value: u64) -> Self::Array {
        cast(value).truncate_to_u8().to_le_bytes()
    }
}

impl StoreTy for u16 {
    type Array = [u8; 2];

    #[inline(always)]
    fn into_bytes(value: u64) -> Self::Array {
        cast(value).truncate_to_u16().to_le_bytes()
    }
}

impl StoreTy for u32 {
    type Array = [u8; 4];

    #[inline(always)]
    fn into_bytes(value: u64) -> Self::Array {
        cast(value).truncate_to_u32().to_le_bytes()
    }
}

impl StoreTy for u64 {
    type Array = [u8; 8];

    #[inline(always)]
    fn into_bytes(value: u64) -> Self::Array {
        value.to_le_bytes()
    }
}

macro_rules! define_interpreter {
    (@define $handler_name:ident $body:block $self:ident) => {{
        impl DecodedInst {
            pub fn $handler_name() -> DecodedInst {
                DecodedInst::sentinel()
            }
        }

        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: u32) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: u32) -> DecodedInst {
                DecodedInst { imm1: a0 as u64, ..DecodedInst::sentinel() }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = inst.imm1 as u32;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: ProgramCounter) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: ProgramCounter) -> DecodedInst {
                DecodedInst { pc: a0.0, ..DecodedInst::sentinel() }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = ProgramCounter(inst.pc);
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: ProgramCounter, $a1:ident: u32) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: ProgramCounter, a1: u32) -> DecodedInst {
                DecodedInst { pc: a0.0, imm1: a1 as u64, ..DecodedInst::sentinel() }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = ProgramCounter(inst.pc);
        let $a1 = inst.imm1 as u32;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: ProgramCounter, $a1:ident: ProgramCounter) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: ProgramCounter, a1: ProgramCounter) -> DecodedInst {
                DecodedInst { pc: a0.0, target_idx: a1.0, ..DecodedInst::sentinel() }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = ProgramCounter(inst.pc);
        let $a1 = ProgramCounter(inst.target_idx);

        $body
    }};

    // (PC, u32, u32) — two unrelated u32 immediates. Phase 1c: a1 → imm1, a2 → imm2
    // (was packed into imm1 high bits). Mirrors javm's imm1/imm2 separation.
    (@define $handler_name:ident $body:block $self:ident, $a0:ident: ProgramCounter, $a1:ident: u32, $a2:ident: u32) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: ProgramCounter, a1: u32, a2: u32) -> DecodedInst {
                DecodedInst {
                    pc: a0.0,
                    imm1: a1 as u64,
                    imm2: a2 as u64,
                    ..DecodedInst::sentinel()
                }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = ProgramCounter(inst.pc);
        let $a1 = inst.imm1 as u32;
        let $a2 = inst.imm2 as u32;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: ProgramCounter, $a1:ident: Reg, $a2:ident: u32) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: ProgramCounter, a1: impl Into<Reg>, a2: u32) -> DecodedInst {
                DecodedInst {
                    pc: a0.0,
                    r0: a1.into().to_u32() as u8,
                    imm1: a2 as u64,
                    ..DecodedInst::sentinel()
                }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = ProgramCounter(inst.pc);
        let $a1 = transmute_reg(inst.r0 as u32);
        let $a2 = inst.imm1 as u32;
        $body
    }};

    // (PC, Reg, u32, u32) — store_imm_indirect: base in r0, offset → imm1,
    // value → imm2 (Phase 1c; was packed into imm1 high bits).
    (@define $handler_name:ident $body:block $self:ident, $a0:ident: ProgramCounter, $a1:ident: Reg, $a2:ident: u32, $a3:ident: u32) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: ProgramCounter, a1: impl Into<Reg>, a2: u32, a3: u32) -> DecodedInst {
                DecodedInst {
                    pc: a0.0,
                    r0: a1.into().to_u32() as u8,
                    imm1: a2 as u64,
                    imm2: a3 as u64,
                    ..DecodedInst::sentinel()
                }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = ProgramCounter(inst.pc);
        let $a1 = transmute_reg(inst.r0 as u32);
        let $a2 = inst.imm1 as u32;
        let $a3 = inst.imm2 as u32;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: ProgramCounter, $a1:ident: Reg, $a2:ident: Reg, $a3:ident: u32) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: ProgramCounter, a1: impl Into<Reg>, a2: impl Into<Reg>, a3: u32) -> DecodedInst {
                DecodedInst {
                    pc: a0.0,
                    r0: a1.into().to_u32() as u8,
                    r1: a2.into().to_u32() as u8,
                    imm1: a3 as u64,
                    ..DecodedInst::sentinel()
                }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = ProgramCounter(inst.pc);
        let $a1 = transmute_reg(inst.r0 as u32);
        let $a2 = transmute_reg(inst.r1 as u32);
        let $a3 = inst.imm1 as u32;
        $body
    }};

    // (PC, Reg, Reg, u32, u32) — load_imm_and_jump_indirect: ra in r0, base in r1,
    // value → imm1, offset → imm2 (Phase 1c; was packed into imm1 high bits).
    (@define $handler_name:ident $body:block $self:ident, $a0:ident: ProgramCounter, $a1:ident: Reg, $a2:ident: Reg, $a3:ident: u32, $a4:ident: u32) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: ProgramCounter, a1: impl Into<Reg>, a2: impl Into<Reg>, a3: u32, a4: u32) -> DecodedInst {
                DecodedInst {
                    pc: a0.0,
                    r0: a1.into().to_u32() as u8,
                    r1: a2.into().to_u32() as u8,
                    imm1: a3 as u64,
                    imm2: a4 as u64,
                    ..DecodedInst::sentinel()
                }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = ProgramCounter(inst.pc);
        let $a1 = transmute_reg(inst.r0 as u32);
        let $a2 = transmute_reg(inst.r1 as u32);
        let $a3 = inst.imm1 as u32;
        let $a4 = inst.imm2 as u32;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: Reg) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: impl Into<Reg>, a1: impl Into<Reg>) -> DecodedInst {
                DecodedInst {
                    r0: a0.into().to_u32() as u8,
                    r1: a1.into().to_u32() as u8,
                    ..DecodedInst::sentinel()
                }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = transmute_reg(inst.r0 as u32);
        let $a1 = transmute_reg(inst.r1 as u32);
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: Reg, $a2:ident: Reg) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: impl Into<Reg>, a1: impl Into<Reg>, a2: impl Into<Reg>) -> DecodedInst {
                DecodedInst {
                    r0: a0.into().to_u32() as u8,
                    r1: a1.into().to_u32() as u8,
                    r2: a2.into().to_u32() as u8,
                    ..DecodedInst::sentinel()
                }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = transmute_reg(inst.r0 as u32);
        let $a1 = transmute_reg(inst.r1 as u32);
        let $a2 = transmute_reg(inst.r2 as u32);
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: Reg, $a2:ident: u32) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: impl Into<Reg>, a1: impl Into<Reg>, a2: u32) -> DecodedInst {
                DecodedInst {
                    r0: a0.into().to_u32() as u8,
                    r1: a1.into().to_u32() as u8,
                    imm1: a2 as u64,
                    ..DecodedInst::sentinel()
                }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = transmute_reg(inst.r0 as u32);
        let $a1 = transmute_reg(inst.r1 as u32);
        let $a2 = inst.imm1 as u32;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: u32) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: impl Into<Reg>, a1: u32) -> DecodedInst {
                DecodedInst {
                    r0: a0.into().to_u32() as u8,
                    imm1: a1 as u64,
                    ..DecodedInst::sentinel()
                }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = transmute_reg(inst.r0 as u32);
        let $a1 = inst.imm1 as u32;
        $body
    }};

    // (Reg, u32, u32) — load_imm64: dst in r0, imm_lo|imm_hi packed into full u64 imm1.
    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: u32, $a2:ident: u32) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: impl Into<Reg>, a1: u32, a2: u32) -> DecodedInst {
                DecodedInst {
                    r0: a0.into().to_u32() as u8,
                    imm1: (a1 as u64) | ((a2 as u64) << 32),
                    ..DecodedInst::sentinel()
                }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = transmute_reg(inst.r0 as u32);
        let $a1 = inst.imm1 as u32;
        let $a2 = (inst.imm1 >> 32) as u32;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Target) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: Target) -> DecodedInst {
                DecodedInst { target_idx: a0, ..DecodedInst::sentinel() }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = inst.target_idx;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: u32, $a2:ident: Target) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: impl Into<Reg>, a1: u32, a2: Target) -> DecodedInst {
                DecodedInst {
                    r0: a0.into().to_u32() as u8,
                    imm1: a1 as u64,
                    target_idx: a2,
                    ..DecodedInst::sentinel()
                }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = transmute_reg(inst.r0 as u32);
        let $a1 = inst.imm1 as u32;
        let $a2 = inst.target_idx;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: Reg, $a2:ident: Target) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: impl Into<Reg>, a1: impl Into<Reg>, a2: Target) -> DecodedInst {
                DecodedInst {
                    r0: a0.into().to_u32() as u8,
                    r1: a1.into().to_u32() as u8,
                    target_idx: a2,
                    ..DecodedInst::sentinel()
                }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = transmute_reg(inst.r0 as u32);
        let $a1 = transmute_reg(inst.r1 as u32);
        let $a2 = inst.target_idx;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: Reg, $a2:ident: Target, $a3:ident: Target) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: impl Into<Reg>, a1: impl Into<Reg>, a2: Target, a3: Target) -> DecodedInst {
                DecodedInst {
                    r0: a0.into().to_u32() as u8,
                    r1: a1.into().to_u32() as u8,
                    target_idx: a2,
                    next_idx: a3,
                    ..DecodedInst::sentinel()
                }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = transmute_reg(inst.r0 as u32);
        let $a1 = transmute_reg(inst.r1 as u32);
        let $a2 = inst.target_idx;
        let $a3 = inst.next_idx;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: u32, $a2:ident: Target, $a3:ident: Target) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: impl Into<Reg>, a1: u32, a2: Target, a3: Target) -> DecodedInst {
                DecodedInst {
                    r0: a0.into().to_u32() as u8,
                    imm1: a1 as u64,
                    target_idx: a2,
                    next_idx: a3,
                    ..DecodedInst::sentinel()
                }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = transmute_reg(inst.r0 as u32);
        let $a1 = inst.imm1 as u32;
        let $a2 = inst.target_idx;
        let $a3 = inst.next_idx;
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: Reg, $a2:ident: ProgramCounter) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: impl Into<Reg>, a1: impl Into<Reg>, a2: ProgramCounter) -> DecodedInst {
                DecodedInst {
                    r0: a0.into().to_u32() as u8,
                    r1: a1.into().to_u32() as u8,
                    target_idx: a2.0,
                    ..DecodedInst::sentinel()
                }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = transmute_reg(inst.r0 as u32);
        let $a1 = transmute_reg(inst.r1 as u32);
        let $a2 = ProgramCounter(inst.target_idx);
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: Reg, $a2:ident: ProgramCounter, $a3:ident: ProgramCounter) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: impl Into<Reg>, a1: impl Into<Reg>, a2: ProgramCounter, a3: ProgramCounter) -> DecodedInst {
                DecodedInst {
                    r0: a0.into().to_u32() as u8,
                    r1: a1.into().to_u32() as u8,
                    target_idx: a2.0,
                    next_idx: a3.0,
                    ..DecodedInst::sentinel()
                }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = transmute_reg(inst.r0 as u32);
        let $a1 = transmute_reg(inst.r1 as u32);
        let $a2 = ProgramCounter(inst.target_idx);
        let $a3 = ProgramCounter(inst.next_idx);
        $body
    }};

    (@define $handler_name:ident $body:block $self:ident, $a0:ident: Reg, $a1:ident: u32, $a2:ident: ProgramCounter, $a3:ident: ProgramCounter) => {{
        impl DecodedInst {
            pub fn $handler_name(a0: impl Into<Reg>, a1: u32, a2: ProgramCounter, a3: ProgramCounter) -> DecodedInst {
                DecodedInst {
                    r0: a0.into().to_u32() as u8,
                    imm1: a1 as u64,
                    target_idx: a2.0,
                    next_idx: a3.0,
                    ..DecodedInst::sentinel()
                }
            }
        }

        let inst = $self.compiled_decoded[cast($self.compiled_offset).to_usize()];
        let $a0 = transmute_reg(inst.r0 as u32);
        let $a1 = inst.imm1 as u32;
        let $a2 = ProgramCounter(inst.target_idx);
        let $a3 = ProgramCounter(inst.next_idx);
        $body
    }};

    (@arg_names $handler_name:ident, $a0:ident: $a0_ty:ty, $a1:ident: $a1_ty:ty, $a2:ident: $a2_ty:ty) => {
        asm::$handler_name($a0, $a1, $a2)
    };

    ($(
        fn $handler_name:ident<$(M: $M_ty:ident,)? $(const $const:ident: $const_ty:ty),+>($self:ident: &mut InterpretedInstance $($arg:tt)*) -> Option<Target> $body:block
    )+) => {
        // Cleanup Phase 4c (2026-05-12): after run_impl + compiled_handlers
        // deletion, most handlers in this module are unused — only memset,
        // reset_cache, and the unresolved_* family are still called directly
        // from run_match's named arms. Silencing the dead_code warnings
        // wholesale is simpler than rewriting the define_interpreter! macro
        // to conditionally skip handlers.
        #[allow(dead_code)]
        mod raw_handlers {
            use super::*;
            $(
                #[allow(clippy::needless_lifetimes)]
                pub fn $handler_name<'a, $(M: $M_ty,)? $(const $const: $const_ty),+>($self: &'a mut InterpretedInstance) -> Option<Target> {
                    define_interpreter!(@define $handler_name $body $self $($arg)*)
                }
            )+
        }
    };
}

#[inline(always)]
fn transmute_reg(value: u32) -> Reg {
    debug_assert!(Reg::from_raw(value).is_some());

    // SAFETY: The `value` passed in here is always constructed through `reg as u32` so this is always safe.
    unsafe { core::mem::transmute(value) }
}

/// Tier 2 H2 (2026-05-12) — Rostro intrinsic ecalli IDs.
/// Reserved range 100..1023 for runtime-internal crypto intrinsics. Index must
/// fit `VM_MAXIMUM_IMPORT_COUNT = 1024`. Guests opt in via
/// `polkavm_import(index = N)` with the matching constant; the FAST_OP_ECALLI
/// dispatch arm intercepts these IDs before exiting the run loop, dispatching
/// the native body inline.
pub const ROSTRO_INTRINSIC_GOLDILOCKS_MUL: u32 = 100;
pub const ROSTRO_INTRINSIC_GOLDILOCKS_ADD: u32 = 101;
pub const ROSTRO_INTRINSIC_GOLDILOCKS_SUB: u32 = 102;
pub const ROSTRO_INTRINSIC_GOLDILOCKS_INV: u32 = 103;
// Big-crypto intrinsics (zero-copy guest-memory access via borrow_bytes).
pub const ROSTRO_INTRINSIC_DILITHIUM_VERIFY: u32 = 110; // ML-DSA-65 verify
pub const ROSTRO_INTRINSIC_P521_ECDSA_VERIFY: u32 = 111; // NIST P-521 ECDSA verify (prehashed)
// Phase 1 hashing intrinsics (2026-05-14). Take a message slice from guest
// memory, write a fixed-size digest back to a guest output buffer. Closes the
// ~2× wasmtime-cranelift gap on the most common chain-runtime hashing ops.
pub const ROSTRO_INTRINSIC_BLAKE2B_256: u32 = 120; // Blake2b-256 (32-byte digest)
pub const ROSTRO_INTRINSIC_KECCAK_256:  u32 = 121; // Keccak-256 (32-byte digest)
// Phase 2 STARK-primitive intrinsics (2026-05-15).
pub const ROSTRO_INTRINSIC_POSEIDON2_PERM: u32 = 130; // Poseidon2-Goldilocks-WIDTH8 in-place permute

/// Goldilocks field multiplication: `(a * b) mod (2^64 - 2^32 + 1)`.
///
/// Tier 2 H2 (2026-05-12). Single-opcode super-instruction replacing the
/// ~20-30 decomposed PVM ops that a Rust-compiled `goldilocks_mul` emits.
/// Native cost: ~5-10 x86_64 instructions (one 128-bit mul + a few shifts +
/// branches). The canonical Plonky3 inner-loop operation.
///
/// Implementation: Solinas-style reduction. p = 2^64 - 2^32 + 1, and
/// 2^64 ≡ 2^32 - 1 (mod p). For the 128-bit product `lo + hi * 2^64`:
///   reduced = lo + hi * (2^32 - 1) = lo + (hi_lo << 32) - hi_lo - hi_hi
/// with borrow/carry handling to stay in [0, p).
// Goldilocks field constants used by the native intrinsics.
const GOLDILOCKS_P: u64 = 0xFFFFFFFF00000001; // 2^64 - 2^32 + 1
const GOLDILOCKS_EPSILON: u64 = 0xFFFFFFFF; // 2^64 - p = 2^32 - 1

#[inline(always)]
pub fn goldilocks_mul_native(a: u64, b: u64) -> u64 {
    let prod = (a as u128).wrapping_mul(b as u128);
    let lo = prod as u64;
    let hi = (prod >> 64) as u64;
    let hi_hi = hi >> 32;
    let hi_lo = hi & 0xFFFFFFFF;

    // t = lo - hi_hi (mod p)
    let (t, borrow) = lo.overflowing_sub(hi_hi);
    let t = if borrow { t.wrapping_add(GOLDILOCKS_P) } else { t };

    // prod_lo = (hi_lo << 32) - hi_lo (this is hi_lo * (2^32 - 1))
    let prod_lo = (hi_lo << 32).wrapping_sub(hi_lo);

    // result = t + prod_lo (mod p)
    let (result, carry) = t.overflowing_add(prod_lo);
    if carry || result >= GOLDILOCKS_P {
        result.wrapping_sub(GOLDILOCKS_P)
    } else {
        result
    }
}

/// Goldilocks add: result may be non-canonical (in [0, 2^64)). Matches gp's
/// representation. ~3-5 native x86 instructions.
#[inline(always)]
pub fn goldilocks_add_native(a: u64, b: u64) -> u64 {
    let (r, c) = a.overflowing_add(b);
    if c { r.wrapping_add(GOLDILOCKS_EPSILON) } else { r }
}

/// Goldilocks sub. ~3-5 native instructions.
#[inline(always)]
pub fn goldilocks_sub_native(a: u64, b: u64) -> u64 {
    let (r, c) = a.overflowing_sub(b);
    if c { r.wrapping_sub(GOLDILOCKS_EPSILON) } else { r }
}

/// Goldilocks inverse via Fermat's little theorem: x^(p-2) mod p.
/// p-2 = 0xFFFF_FFFE_FFFF_FFFF. Native body: ~64 squares + popcount(p-2)=63
/// muls = ~127 native goldilocks_mul calls (each ~5-10 cycles). Total ~0.4-1µs.
/// Replaces a ~30µs interpreted square-and-multiply ladder = ~30-75× speedup
/// per inv.
#[inline(always)]
pub fn goldilocks_inv_native(x: u64) -> u64 {
    const EXP: u64 = GOLDILOCKS_P - 2; // 0xFFFFFFFEFFFFFFFF
    if x == 0 {
        // Fermat undefined at 0; gp::inv would return 1 (x^0=1) here too.
        return 1;
    }
    let mut result: u64 = 1;
    let mut b: u64 = x;
    let mut e: u64 = EXP;
    while e > 0 {
        if e & 1 == 1 {
            result = goldilocks_mul_native(result, b);
        }
        b = goldilocks_mul_native(b, b);
        e >>= 1;
    }
    result
}

/// extern "C" wrappers used by `RostroIntrinsicsCodegen` to call goldilocks
/// natives directly from JIT-emitted code. The default Rust ABI on x86_64
/// happens to match SysV for `(u64, u64) -> u64` today, but it isn't
/// guaranteed across compiler versions — these wrappers nail down SysV at
/// the call site so the JIT's `mov rdi/rsi; call` sequence stays sound.
pub extern "C" fn rostro_jit_goldilocks_mul(a: u64, b: u64) -> u64 {
    goldilocks_mul_native(a, b)
}

pub extern "C" fn rostro_jit_goldilocks_add(a: u64, b: u64) -> u64 {
    goldilocks_add_native(a, b)
}

pub extern "C" fn rostro_jit_goldilocks_sub(a: u64, b: u64) -> u64 {
    goldilocks_sub_native(a, b)
}

pub extern "C" fn rostro_jit_goldilocks_inv(x: u64) -> u64 {
    goldilocks_inv_native(x)
}

/// P-521 ECDSA verify-prehash. Pure-bytes API so both the interpreter
/// (zero-copy via Memory::borrow_bytes) and the JIT runner (host-side
/// after `inst.read_memory`) share one verifier body.
///
/// `vk_bytes`: 133-byte uncompressed sec1 (`0x04 || X || Y`).
/// `sig_bytes`: 132-byte raw `r || s`.
/// `prehash`: caller-supplied prehash (any length the verifier accepts).
///
/// Returns `true` on verified, `false` on any failure (parse, length, or
/// crypto). Crypto-internal errors are intentionally collapsed to `false`
/// to match the on-chain semantics ("verifies or it doesn't").
pub fn rostro_p521_ecdsa_verify_prehash(vk_bytes: &[u8], sig_bytes: &[u8], prehash: &[u8]) -> bool {
    use p521::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
    let Ok(vk) = VerifyingKey::from_sec1_bytes(vk_bytes) else { return false };
    let Ok(sig) = Signature::from_slice(sig_bytes) else { return false };
    vk.verify_prehash(prehash, &sig).is_ok()
}

/// ML-DSA-65 (Dilithium) verify. Pure-bytes API; same single-source-of-truth
/// rationale as `rostro_p521_ecdsa_verify_prehash`.
///
/// `pk_bytes`: 1952-byte ML-DSA-65 public key.
/// `sig_bytes`: 3309-byte ML-DSA-65 signature.
/// `msg`, `ctx`: caller-supplied.
pub fn rostro_dilithium_verify(pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8], ctx: &[u8]) -> bool {
    use fips204::ml_dsa_65;
    use fips204::traits::{SerDes, Verifier};
    let Ok(pk_arr) = <&[u8; 1952]>::try_from(pk_bytes) else { return false };
    let Ok(sig_arr) = <&[u8; 3309]>::try_from(sig_bytes) else { return false };
    let Ok(pk) = ml_dsa_65::PublicKey::try_from_bytes(*pk_arr) else { return false };
    pk.verify(msg, sig_arr, ctx)
}

/// Phase 1 Tier 2 (2026-05-14). Blake2b-256 hash. Returns 32 bytes.
///
/// Shared between interpreter dispatch (FAST_OP_ECALLI intercept) and the
/// JIT runner's host-side dispatch (rostro_intrinsic_codegen.rs).
#[link_section = ".rostro_intrinsic_bodies"]
pub fn rostro_blake2b_256(msg: &[u8]) -> [u8; 32] {
    use blake2::digest::{consts::U32, Digest};
    use blake2::Blake2b;
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_slice());
    out
}

/// Phase 1 Tier 2 (2026-05-14). Keccak-256 hash. Returns 32 bytes.
#[link_section = ".rostro_intrinsic_bodies"]
pub fn rostro_keccak_256(msg: &[u8]) -> [u8; 32] {
    use sha3::digest::Digest;
    use sha3::Keccak256;
    let mut hasher = Keccak256::new();
    hasher.update(msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_slice());
    out
}

// =====================================================================
// Phase 2 Tier 2 (2026-05-15). Poseidon2-Goldilocks WIDTH=8 permutation.
// Bit-exact with Plonky3's `default_goldilocks_poseidon2_8`. Vendored from
// the bench harness's gp::poseidon2 reference. Uses goldilocks_*_native
// directly — no ecalli round-trip. Replaces ~240+ goldilocks ecalli calls
// plus orchestration with one ecalli + the native body.
// =====================================================================

const POSEIDON2_WIDTH: usize = 8;

const POSEIDON2_RC_INITIAL: [[u64; POSEIDON2_WIDTH]; 4] = [
    [
        0xdd5743e7f2a5a5d9, 0xcb3a864e58ada44b, 0xffa2449ed32f8cdc, 0x42025f65d6bd13ee,
        0x7889175e25506323, 0x34b98bb03d24b737, 0xbdcc535ecc4faa2a, 0x5b20ad869fc0d033,
    ],
    [
        0xf1dda5b9259dfcb4, 0x27515210be112d59, 0x4227d1718c766c3f, 0x26d333161a5bd794,
        0x49b938957bf4b026, 0x4a56b5938b213669, 0x1120426b48c8353d, 0x6b323c3f10a56cad,
    ],
    [
        0xce57d6245ddca6b2, 0xb1fc8d402bba1eb1, 0xb5c5096ca959bd04, 0x6db55cd306d31f7f,
        0xc49d293a81cb9641, 0x1ce55a4fe979719f, 0xa92e60a9d178a4d1, 0x002cc64973bcfd8c,
    ],
    [
        0xcea721cce82fb11b, 0xe5b55eb8098ece81, 0x4e30525c6f1ddd66, 0x43c6702827070987,
        0xaca68430a7b5762a, 0x3674238634df9c93, 0x88cee1c825e33433, 0xde99ae8d74b57176,
    ],
];

const POSEIDON2_RC_FINAL: [[u64; POSEIDON2_WIDTH]; 4] = [
    [
        0x014ef1197d341346, 0x9725e20825d07394, 0xfdb25aef2c5bae3b, 0xbe5402dc598c971e,
        0x93a5711f04cdca3d, 0xc45a9a5b2f8fb97b, 0xfe8946a924933545, 0x2af997a27369091c,
    ],
    [
        0xaa62c88e0b294011, 0x058eb9d810ce9f74, 0xb3cb23eced349ae4, 0xa3648177a77b4a84,
        0x43153d905992d95d, 0xf4e2a97cda44aa4b, 0x5baa2702b908682f, 0x082923bdf4f750d1,
    ],
    [
        0x98ae09a325893803, 0xf8a6475077968838, 0xceb0735bf00b2c5f, 0x0a1a5d953888e072,
        0x2fcb190489f94475, 0xb5be06270dec69fc, 0x739cb934b09acf8b, 0x537750b75ec7f25b,
    ],
    [
        0xe9dd318bae1f3961, 0xf7462137299efe1a, 0xb1f6b8eee9adb940, 0xbdebcc8a809dfe6b,
        0x40fc1f791b178113, 0x3ac1c3362d014864, 0x9a016184bdb8aeba, 0x95f2394459fbc25e,
    ],
];

const POSEIDON2_RC_INTERNAL: [u64; 22] = [
    0x488897d85ff51f56, 0x1140737ccb162218, 0xa7eeb9215866ed35, 0x9bd2976fee49fcc9,
    0xc0c8f0de580a3fcc, 0x4fb2dae6ee8fc793, 0x343a89f35f37395b, 0x223b525a77ca72c8,
    0x56ccb62574aaa918, 0xc4d507d8027af9ed, 0xa080673cf0b7e95c, 0xf0184884eb70dcf8,
    0x044f10b0cb3d5c69, 0xe9e3f7993938f186, 0x1b761c80e772f459, 0x606cec607a1b5fac,
    0x14a0c2e1d45f03cd, 0x4eace8855398574f, 0xf905ca7103eff3e6, 0xf8c8f8d20862c059,
    0xb524fe8bdd678e5a, 0xfbb7865901a1ec41,
];

const POSEIDON2_MATRIX_DIAG: [u64; POSEIDON2_WIDTH] = [
    0xfffffffeffffffff, 0x0000000000000001, 0x0000000000000002, 0x7fffffff80000001,
    0x0000000000000003, 0x7fffffff80000000, 0xfffffffefffffffe, 0xfffffffefffffffd,
];

#[inline(always)]
fn poseidon2_sbox(x: u64) -> u64 {
    let x2 = goldilocks_mul_native(x, x);
    let x4 = goldilocks_mul_native(x2, x2);
    let x6 = goldilocks_mul_native(x4, x2);
    goldilocks_mul_native(x6, x)
}

#[inline(always)]
fn poseidon2_apply_mat4(x: &mut [u64; 4]) {
    let t01 = goldilocks_add_native(x[0], x[1]);
    let t23 = goldilocks_add_native(x[2], x[3]);
    let t0123 = goldilocks_add_native(t01, t23);
    let t01123 = goldilocks_add_native(t0123, x[1]);
    let t01233 = goldilocks_add_native(t0123, x[3]);
    let new_x3 = goldilocks_add_native(t01233, goldilocks_add_native(x[0], x[0]));
    let new_x1 = goldilocks_add_native(t01123, goldilocks_add_native(x[2], x[2]));
    x[0] = goldilocks_add_native(t01123, t01);
    x[2] = goldilocks_add_native(t01233, t23);
    x[1] = new_x1;
    x[3] = new_x3;
}

#[inline(always)]
fn poseidon2_mds_light(state: &mut [u64; POSEIDON2_WIDTH]) {
    let (head, tail) = state.split_at_mut(4);
    let h: &mut [u64; 4] = head.try_into().unwrap();
    let t: &mut [u64; 4] = tail.try_into().unwrap();
    poseidon2_apply_mat4(h);
    poseidon2_apply_mat4(t);
    let sums: [u64; 4] = [
        goldilocks_add_native(state[0], state[4]),
        goldilocks_add_native(state[1], state[5]),
        goldilocks_add_native(state[2], state[6]),
        goldilocks_add_native(state[3], state[7]),
    ];
    let mut i = 0;
    while i < POSEIDON2_WIDTH {
        state[i] = goldilocks_add_native(state[i], sums[i & 3]);
        i += 1;
    }
}

#[inline(always)]
fn poseidon2_external_round(state: &mut [u64; POSEIDON2_WIDTH], rc: &[u64; POSEIDON2_WIDTH]) {
    let mut i = 0;
    while i < POSEIDON2_WIDTH {
        state[i] = poseidon2_sbox(goldilocks_add_native(state[i], rc[i]));
        i += 1;
    }
    poseidon2_mds_light(state);
}

#[inline(always)]
fn poseidon2_internal_round(state: &mut [u64; POSEIDON2_WIDTH], rc: u64) {
    state[0] = poseidon2_sbox(goldilocks_add_native(state[0], rc));
    let mut sum = state[0];
    let mut i = 1;
    while i < POSEIDON2_WIDTH {
        sum = goldilocks_add_native(sum, state[i]);
        i += 1;
    }
    i = 0;
    while i < POSEIDON2_WIDTH {
        state[i] = goldilocks_add_native(
            goldilocks_mul_native(state[i], POSEIDON2_MATRIX_DIAG[i]),
            sum,
        );
        i += 1;
    }
}

/// Phase 2 Tier 2 (2026-05-15). Full Poseidon2-Goldilocks-WIDTH8 permutation
/// in place. Bit-exact with the bench harness's gp::permute.
#[link_section = ".rostro_intrinsic_bodies"]
pub fn rostro_poseidon2_permute(state: &mut [u64; POSEIDON2_WIDTH]) {
    poseidon2_mds_light(state);
    let mut r = 0;
    while r < 4 {
        poseidon2_external_round(state, &POSEIDON2_RC_INITIAL[r]);
        r += 1;
    }
    let mut r = 0;
    while r < 22 {
        poseidon2_internal_round(state, POSEIDON2_RC_INTERNAL[r]);
        r += 1;
    }
    let mut r = 0;
    while r < 4 {
        poseidon2_external_round(state, &POSEIDON2_RC_FINAL[r]);
        r += 1;
    }
}

fn trap_impl<const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter) -> Option<Target> {
    visitor.program_counter = program_counter;
    visitor.program_counter_valid = true;
    visitor.next_program_counter = None;
    visitor.next_program_counter_changed = true;
    visitor.unresolved_program_counter = None;
    visitor.interrupt = InterruptKind::Trap;
    None
}

fn not_enough_gas_impl<const DEBUG: bool>(
    visitor: &mut InterpretedInstance,
    program_counter: ProgramCounter,
    new_gas: i64,
) -> Option<Target> {
    match visitor.module.gas_metering().unwrap() {
        GasMeteringKind::Async => {
            visitor.gas = new_gas;
            visitor.program_counter_valid = false;
            visitor.next_program_counter = None;
            visitor.next_program_counter_changed = true;
        }
        GasMeteringKind::Sync => {
            visitor.program_counter = program_counter;
            visitor.program_counter_valid = true;
            visitor.next_program_counter = Some(program_counter);
            visitor.next_program_counter_changed = false;
        }
    }

    visitor.interrupt = InterruptKind::NotEnoughGas;
    None
}

macro_rules! handle_unresolved_branch {
    ($debug:expr, $visitor:ident, $s1:ident, $s2:ident, $tt:ident, $tf:ident, $name:ident) => {{
        if DEBUG {
            log::trace!("[{}]: jump {} if {} {} {}", $visitor.compiled_offset, $tt, $s1, $debug, $s2);
        }

        let offset = $visitor.compiled_offset;

        let target_true = $visitor.resolve_jump::<DEBUG>($tt);
        let target_false = $visitor.resolve_jump::<DEBUG>($tf);
        if let (Some(target_true), Some(target_false)) = (target_true, target_false) {
            let off_idx = cast(offset).to_usize();
            $visitor.compiled_decoded[off_idx] = DecodedInst {
                bb_gas_cost: 0,
                opcode: fast_op_for!($name),
                ..DecodedInst::$name($s1, $s2, target_true, target_false)
            };
        } else {
            // This should never happen since we've already prevalidated the targets.
            if cfg!(debug_assertions) {
                panic!("internal error: failed to resolve a branch");
            }

            let off_idx = cast(offset).to_usize();
            $visitor.compiled_decoded[off_idx] = DecodedInst {
                bb_gas_cost: 0,
                opcode: fast_op_for!(invalid_branch_trap),
                ..DecodedInst::invalid_branch_trap($tf)
            };
        }

        Some(offset)
    }};
}

define_interpreter! {
    fn charge_gas<const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, gas_cost: u32) -> Option<Target> {
        let new_gas = visitor.gas - i64::from(gas_cost);

        if DEBUG {
            log::trace!("[{}]: charge_gas: {gas_cost} ({} -> {})", visitor.compiled_offset, visitor.gas, new_gas);
        }

        if new_gas < 0 {
            not_enough_gas_impl::<DEBUG>(visitor, program_counter, new_gas)
        } else {
            visitor.gas = new_gas;
            visitor.go_to_next_instruction()
        }
    }

    fn step<const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: step", visitor.compiled_offset);
        }

        visitor.program_counter = program_counter;
        visitor.program_counter_valid = true;
        visitor.next_program_counter = Some(program_counter);
        visitor.next_program_counter_changed = false;
        visitor.interrupt = InterruptKind::Step;
        visitor.compiled_offset += 1;
        None
    }

    fn reset_cache<const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: reset_cache", visitor.compiled_offset);
        }

        visitor.reset_interpreter_cache();
        visitor.compile_block::<DEBUG>(program_counter)
    }

    fn fallthrough<const DEBUG: bool>(visitor: &mut InterpretedInstance) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: fallthrough", visitor.compiled_offset);
        }

        visitor.go_to_next_instruction()
    }

    fn trap<const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: trap", visitor.compiled_offset);
        }

        log::debug!("Trap at {}: explicit trap", program_counter);
        trap_impl::<DEBUG>(visitor, program_counter)
    }

    fn invalid_branch_trap<const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: trap (invalid branch)", visitor.compiled_offset);
        }

        log::debug!("Trap at {}: invalid branch", program_counter);
        trap_impl::<DEBUG>(visitor, program_counter)
    }

    fn sbrk<const DEBUG: bool>(visitor: &mut InterpretedInstance, dst: Reg, size: Reg) -> Option<Target> {
        let size = visitor.get64::<DEBUG>(size);
        let result = size.try_into().ok().and_then(|size| visitor.sbrk(size)).unwrap_or(0);
        visitor.set64::<DEBUG>(dst, u64::from(result));
        visitor.go_to_next_instruction()
    }

    fn memset<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: memset", visitor.compiled_offset);
        }

        let gas_metering_enabled = visitor.module.gas_metering().is_some();

        // TODO: This is very inefficient.
        let next_instruction = visitor.go_to_next_instruction();
        let mut result = next_instruction;

        let value = visitor.get32::<DEBUG>(Reg::A1);
        let mut dst = visitor.get32::<DEBUG>(Reg::A0);
        let mut count = visitor.get64::<DEBUG>(Reg::A2);
        while count > 0 {
            if gas_metering_enabled && visitor.gas == 0 {
                result = not_enough_gas_impl::<DEBUG>(visitor, program_counter, 0);
                break;
            }

            result = visitor.store::<M, u8, DEBUG>(program_counter, value, None, dst);
            if result != next_instruction {
                break;
            }

            if gas_metering_enabled {
                visitor.gas -= 1;
            }

            dst += 1;
            count -= 1;
        }

        visitor.set64::<DEBUG>(Reg::A0, u64::from(dst));
        visitor.set64::<DEBUG>(Reg::A2, count);

        result
    }

    fn ecalli<const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, hostcall_number: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: ecalli {hostcall_number}", visitor.compiled_offset);
        }

        let next_offset = visitor.module.instructions_bounded_at(program_counter).next().unwrap().next_offset;
        visitor.program_counter = program_counter;
        visitor.program_counter_valid = true;
        visitor.next_program_counter = Some(next_offset);
        visitor.next_program_counter_changed = true;
        visitor.interrupt = InterruptKind::Ecalli(hostcall_number);
        None
    }

    fn set_less_than_unsigned<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::set_less_than_unsigned(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| u64::from(s1 < s2))
    }

    fn set_less_than_signed<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::set_less_than_signed(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| u64::from(cast(s1).to_signed() < cast(s2).to_signed()))
    }

    fn shift_logical_right_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::shift_logical_right_32(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, u32::wrapping_shr)
    }

    fn shift_logical_right_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::shift_logical_right_64(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| u64::wrapping_shr(s1, cast(s2).truncate_to_u32()))
    }

    fn shift_arithmetic_right_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::shift_arithmetic_right_32(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, |s1, s2| cast(cast(s1).to_signed().wrapping_shr(s2)).to_unsigned())
    }

    fn shift_arithmetic_right_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::shift_arithmetic_right_64(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| cast(cast(s1).to_signed().wrapping_shr(cast(s2).truncate_to_u32())).to_unsigned())
    }

    fn shift_logical_left_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::shift_logical_left_32(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, u32::wrapping_shl)
    }

    fn shift_logical_left_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::shift_logical_left_64(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| u64::wrapping_shl(s1, cast(s2).truncate_to_u32()))
    }

    fn xor<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::xor(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| s1 ^ s2)
    }

    fn and<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::and(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| s1 & s2)
    }

    fn or<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::or(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| s1 | s2)
    }

    fn add_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::add_32(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, u32::wrapping_add)
    }

    fn add_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::add_64(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, u64::wrapping_add)
    }

    fn sub_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::sub_32(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, u32::wrapping_sub)
    }

    fn sub_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::sub_64(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, u64::wrapping_sub)
    }

    fn negate_and_add_imm_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::negate_and_add_imm_32(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, |s1, s2| s2.wrapping_sub(s1))
    }

    fn negate_and_add_imm_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::negate_and_add_imm_64(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| s2.wrapping_sub(s1))
    }

    fn mul_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::mul_32(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, u32::wrapping_mul)
    }

    fn mul_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::mul_64(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, u64::wrapping_mul)
    }

    fn mul_imm_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::mul_imm_32(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, u32::wrapping_mul)
    }

    fn mul_imm_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::mul_imm_64(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, u64::wrapping_mul)
    }

    fn mul_upper_signed_signed_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::mul_upper_signed_signed(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, |s1, s2| cast(mulh(cast(s1).to_signed(), cast(s2).to_signed())).to_unsigned())
    }

    fn mul_upper_signed_signed_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::mul_upper_signed_signed(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| cast(mulh64(cast(s1).to_signed(), cast(s2).to_signed())).to_unsigned())
    }

    fn mul_upper_unsigned_unsigned_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::mul_upper_unsigned_unsigned(d, s1, s2));
        }


        visitor.set3_32::<DEBUG>(d, s1, s2, mulhu)
    }

    fn mul_upper_unsigned_unsigned_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::mul_upper_unsigned_unsigned(d, s1, s2));
        }


        visitor.set3_64::<DEBUG>(d, s1, s2, mulhu64)
    }

    fn mul_upper_signed_unsigned_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::mul_upper_signed_unsigned(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, |s1, s2| cast(mulhsu(cast(s1).to_signed(), s2)).to_unsigned())
    }

    fn mul_upper_signed_unsigned_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::mul_upper_signed_unsigned(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| cast(mulhsu64(cast(s1).to_signed(), s2)).to_unsigned())
    }

    fn div_unsigned_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::div_unsigned_32(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, divu)
    }

    fn div_unsigned_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::div_unsigned_64(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, divu64)
    }

    fn div_signed_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::div_signed_32(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, |s1, s2| cast(div(cast(s1).to_signed(), cast(s2).to_signed())).to_unsigned())
    }

    fn div_signed_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::div_signed_64(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| cast(div64(cast(s1).to_signed(), cast(s2).to_signed())).to_unsigned())
    }

    fn rem_unsigned_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::rem_unsigned_32(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, remu)
    }

    fn rem_unsigned_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::rem_unsigned_64(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, remu64)
    }

    fn rem_signed_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::rem_signed_32(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, |s1, s2| cast(rem(cast(s1).to_signed(), cast(s2).to_signed())).to_unsigned())
    }

    fn rem_signed_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::rem_signed_64(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| cast(rem64(cast(s1).to_signed(), cast(s2).to_signed())).to_unsigned())
    }

    fn and_inverted_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::and_inverted(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, |s1, s2| (s1 & !s2))
    }

    fn and_inverted_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::and_inverted(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| (s1 & !s2))
    }

    fn or_inverted_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::or_inverted(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, |s1, s2| (s1 | !s2))
    }

    fn or_inverted_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::or_inverted(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| (s1 | !s2))
    }

    fn xnor_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::xnor(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, |s1, s2| !(s1 ^ s2))
    }

    fn xnor_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::xnor(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| !(s1 ^ s2))
    }

    fn maximum_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::maximum(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, |s1, s2| cast(cast(s1).to_signed().max(cast(s2).to_signed())).to_unsigned())
    }

    fn maximum_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::maximum(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| cast(cast(s1).to_signed().max(cast(s2).to_signed())).to_unsigned())
    }

    fn maximum_unsigned_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::maximum_unsigned(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, |s1, s2| s1.max(s2))
    }

    fn maximum_unsigned_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::maximum_unsigned(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| s1.max(s2))
    }

    fn minimum_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::minimum(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, |s1, s2| cast(cast(s1).to_signed().min(cast(s2).to_signed())).to_unsigned())
    }

    fn minimum_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::minimum(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| cast(cast(s1).to_signed().min(cast(s2).to_signed())).to_unsigned())
    }

    fn minimum_unsigned_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::minimum_unsigned(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, |s1, s2| s1.min(s2))
    }

    fn minimum_unsigned_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::minimum_unsigned(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| s1.min(s2))
    }

    fn rotate_left_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::rotate_left_32(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, u32::rotate_left)
    }

    fn rotate_left_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::rotate_left_64(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| u64::rotate_left(s1, cast(s2).truncate_to_u32()))
    }

    fn rotate_right_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::rotate_right_32(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, u32::rotate_right)
    }

    fn rotate_right_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::rotate_right_64(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| u64::rotate_right(s1, cast(s2).truncate_to_u32()))
    }

    fn set_less_than_unsigned_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::set_less_than_unsigned_imm(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| u64::from(s1 < s2))
    }

    fn set_greater_than_unsigned_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::set_greater_than_unsigned_imm(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| u64::from(s1 > s2))
    }

    fn set_less_than_signed_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::set_less_than_signed_imm(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| u64::from(cast(s1).to_signed() < cast(s2).to_signed()))
    }

    fn set_greater_than_signed_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::set_greater_than_signed_imm(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| u64::from(cast(s1).to_signed() > cast(s2).to_signed()))
    }

    fn shift_logical_right_imm_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::shift_logical_right_imm_32(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, u32::wrapping_shr)
    }

    fn shift_logical_right_imm_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::shift_logical_right_imm_64(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| u64::wrapping_shr(s1, cast(s2).truncate_to_u32()))
    }

    fn shift_logical_right_imm_alt_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s2: Reg, s1: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::shift_logical_right_imm_alt_32(d, s2, s1));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, u32::wrapping_shr)
    }

    fn shift_logical_right_imm_alt_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s2: Reg, s1: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::shift_logical_right_imm_alt_64(d, s2, s1));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| u64::wrapping_shr(s1, cast(s2).truncate_to_u32()))
    }

    fn shift_arithmetic_right_imm_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::shift_arithmetic_right_imm_32(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, |s1, s2| cast(i32::wrapping_shr(cast(s1).to_signed(), s2)).to_unsigned())
    }

    fn shift_arithmetic_right_imm_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::shift_arithmetic_right_imm_64(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| cast(i64::wrapping_shr(cast(s1).to_signed(), cast(s2).truncate_to_u32())).to_unsigned())
    }

    fn shift_arithmetic_right_imm_alt_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s2: Reg, s1: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::shift_arithmetic_right_imm_alt_32(d, s2, s1));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, |s1, s2| cast(i32::wrapping_shr(cast(s1).to_signed(), s2)).to_unsigned())
    }

    fn shift_arithmetic_right_imm_alt_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s2: Reg, s1: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::shift_arithmetic_right_imm_alt_64(d, s2, s1));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| cast(i64::wrapping_shr(cast(s1).to_signed(), cast(s2).truncate_to_u32())).to_unsigned())
    }

    fn shift_logical_left_imm_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::shift_logical_left_imm_32(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, u32::wrapping_shl)
    }

    fn shift_logical_left_imm_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::shift_logical_left_imm_64(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| u64::wrapping_shl(s1, cast(s2).truncate_to_u32()))
    }

    fn shift_logical_left_imm_alt_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s2: Reg, s1: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::shift_logical_left_imm_alt_32(d, s2, s1));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, u32::wrapping_shl)
    }

    fn shift_logical_left_imm_alt_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s2: Reg, s1: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::shift_logical_left_imm_alt_64(d, s2, s1));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| u64::wrapping_shl(s1, cast(s2).truncate_to_u32()))
    }

    fn or_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::or_imm(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| s1 | s2)
    }

    fn and_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::and_imm(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| s1 & s2)
    }

    fn xor_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::xor_imm(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| s1 ^ s2)
    }

    fn load_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, dst: Reg, imm: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::load_imm(dst, imm));
        }

        visitor.set32::<DEBUG>(dst, imm);
        visitor.go_to_next_instruction()
    }

    fn load_imm64<const DEBUG: bool>(visitor: &mut InterpretedInstance, dst: Reg, imm_lo: u32, imm_hi: u32) -> Option<Target> {
        let imm = cast(imm_lo).to_u64() | (cast(imm_hi).to_u64() << 32);
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::load_imm64(dst, imm));
        }

        visitor.set64::<DEBUG>(dst, imm);
        visitor.go_to_next_instruction()
    }

    fn move_reg<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::move_reg(d, s));
        }

        let imm = visitor.get64::<DEBUG>(s);
        visitor.set64::<DEBUG>(d, imm);
        visitor.go_to_next_instruction()
    }

    fn count_leading_zero_bits_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::count_leading_zero_bits_32(d, s));
        }

        visitor.set32::<DEBUG>(d, u32::leading_zeros(visitor.get32::<DEBUG>(s)));
        visitor.go_to_next_instruction()
    }

    fn count_leading_zero_bits_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::count_leading_zero_bits_64(d, s));
        }

        visitor.set64::<DEBUG>(d, cast(u64::leading_zeros(visitor.get64::<DEBUG>(s))).to_u64());
        visitor.go_to_next_instruction()
    }

    fn count_trailing_zero_bits_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::count_trailing_zero_bits_32(d, s));
        }

        visitor.set32::<DEBUG>(d, u32::trailing_zeros(visitor.get32::<DEBUG>(s)));
        visitor.go_to_next_instruction()
    }

    fn count_trailing_zero_bits_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::count_trailing_zero_bits_64(d, s));
        }

        visitor.set64::<DEBUG>(d, cast(u64::trailing_zeros(visitor.get64::<DEBUG>(s))).to_u64());
        visitor.go_to_next_instruction()
    }

    fn count_set_bits_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::count_set_bits_32(d, s));
        }

        visitor.set32::<DEBUG>(d, u32::count_ones(visitor.get32::<DEBUG>(s)));
        visitor.go_to_next_instruction()
    }

    fn count_set_bits_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::count_set_bits_64(d, s));
        }

        visitor.set64::<DEBUG>(d, cast(u64::count_ones(visitor.get64::<DEBUG>(s))).to_u64());
        visitor.go_to_next_instruction()
    }

    fn sign_extend_8_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::sign_extend_8(d, s));
        }

        let byte = cast(cast(visitor.get32::<DEBUG>(s)).truncate_to_u8()).to_signed();
        visitor.set32::<DEBUG>(d, cast(cast(byte).to_i32_sign_extend()).to_unsigned());
        visitor.go_to_next_instruction()
    }

    fn sign_extend_8_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::sign_extend_8(d, s));
        }

        let byte = cast(cast(visitor.get64::<DEBUG>(s)).truncate_to_u8()).to_signed();
        visitor.set64::<DEBUG>(d, cast(cast(byte).to_i64_sign_extend()).to_unsigned());
        visitor.go_to_next_instruction()
    }

    fn sign_extend_16_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::sign_extend_16(d, s));
        }

        let hword = cast(cast(visitor.get32::<DEBUG>(s)).truncate_to_u16()).to_signed();
        visitor.set32::<DEBUG>(d, cast(cast(hword).to_i32_sign_extend()).to_unsigned());
        visitor.go_to_next_instruction()
    }

    fn sign_extend_16_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::sign_extend_16(d, s));
        }

        let hword = cast(cast(visitor.get64::<DEBUG>(s)).truncate_to_u16()).to_signed();
        visitor.set64::<DEBUG>(d, cast(cast(hword).to_i64_sign_extend()).to_unsigned());
        visitor.go_to_next_instruction()
    }

    fn zero_extend_16_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::zero_extend_16(d, s));
        }

        let hword = cast(visitor.get32::<DEBUG>(s)).truncate_to_u16();
        visitor.set32::<DEBUG>(d, cast(hword).to_u32());
        visitor.go_to_next_instruction()
    }

    fn zero_extend_16_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::zero_extend_16(d, s));
        }

        let hword = cast(visitor.get64::<DEBUG>(s)).truncate_to_u16();
        visitor.set64::<DEBUG>(d, cast(hword).to_u64());
        visitor.go_to_next_instruction()
    }

    fn reverse_byte_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::reverse_byte(d, s));
        }

        visitor.set32::<DEBUG>(d, u32::swap_bytes(visitor.get32::<DEBUG>(s)));
        visitor.go_to_next_instruction()
    }

    fn reverse_byte_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::reverse_byte(d, s));
        }

        visitor.set64::<DEBUG>(d, u64::swap_bytes(visitor.get64::<DEBUG>(s)));
        visitor.go_to_next_instruction()
    }

    fn cmov_if_zero<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s: Reg, c: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::cmov_if_zero(d, s, c));
        }

        if visitor.get64::<DEBUG>(c) == 0 {
            let value = visitor.get64::<DEBUG>(s);
            visitor.set64::<DEBUG>(d, value);
        }

        visitor.go_to_next_instruction()
    }

    fn cmov_if_zero_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, c: Reg, s: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::cmov_if_zero_imm(d, c, s));
        }

        if visitor.get64::<DEBUG>(c) == 0 {
            visitor.set32::<DEBUG>(d, s);
        }

        visitor.go_to_next_instruction()
    }

    fn cmov_if_not_zero<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s: Reg, c: Reg) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::cmov_if_not_zero(d, s, c));
        }

        if visitor.get64::<DEBUG>(c) != 0 {
            let value = visitor.get64::<DEBUG>(s);
            visitor.set64::<DEBUG>(d, value);
        }

        visitor.go_to_next_instruction()
    }

    fn cmov_if_not_zero_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, c: Reg, s: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::cmov_if_not_zero_imm(d, c, s));
        }

        if visitor.get64::<DEBUG>(c) != 0 {
            visitor.set32::<DEBUG>(d, s);
        }

        visitor.go_to_next_instruction()
    }

    fn rotate_right_imm_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::rotate_right_imm_32(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, u32::rotate_right)
    }

    fn rotate_right_imm_alt_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::rotate_right_imm_alt_32(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s2, s1, u32::rotate_right)
    }

    fn rotate_right_imm_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::rotate_right_imm_64(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, |s1, s2| u64::rotate_right(s1, cast(s2).truncate_to_u32()))
    }

    fn rotate_right_imm_alt_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::rotate_right_imm_alt_64(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s2, s1, |s2, s1| u64::rotate_right(s2, cast(s1).truncate_to_u32()))
    }

    fn add_imm_32<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::add_imm_32(d, s1, s2));
        }

        visitor.set3_32::<DEBUG>(d, s1, s2, u32::wrapping_add)
    }

    fn add_imm_64<const DEBUG: bool>(visitor: &mut InterpretedInstance, d: Reg, s1: Reg, s2: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::add_imm_64(d, s1, s2));
        }

        visitor.set3_64::<DEBUG>(d, s1, s2, u64::wrapping_add)
    }

    fn store_imm_u8<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, offset: u32, value: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::store_imm_u8(offset, value));
        }

        visitor.store::<M, u8, DEBUG>(program_counter, value, None, offset)
    }

    fn store_imm_u16<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, offset: u32, value: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::store_imm_u16(offset, value));
        }

        visitor.store::<M, u16, DEBUG>(program_counter, value, None, offset)
    }

    fn store_imm_u32<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, offset: u32, value: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::store_imm_u32(offset, value));
        }

        visitor.store::<M, u32, DEBUG>(program_counter, value, None, offset)
    }

    fn store_imm_u64<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, offset: u32, value: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::store_imm_u64(offset, value));
        }

        visitor.store::<M, u64, DEBUG>(program_counter, value, None, offset)
    }

    fn store_imm_indirect_u8<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, base: Reg, offset: u32, value: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::store_imm_indirect_u8(base, offset, value));
        }

        visitor.store::<M, u8, DEBUG>(program_counter, value, Some(base), offset)
    }

    fn store_imm_indirect_u16<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, base: Reg, offset: u32, value: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::store_imm_indirect_u16(base, offset, value));
        }

        visitor.store::<M, u16, DEBUG>(program_counter, value, Some(base), offset)
    }

    fn store_imm_indirect_u32<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, base: Reg, offset: u32, value: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::store_imm_indirect_u32(base, offset, value));
        }

        visitor.store::<M, u32, DEBUG>(program_counter, value, Some(base), offset)
    }

    fn store_imm_indirect_u64<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, base: Reg, offset: u32, value: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::store_imm_indirect_u64(base, offset, value));
        }

        visitor.store::<M, u64, DEBUG>(program_counter, value, Some(base), offset)
    }

    fn store_indirect_u8<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, src: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::store_indirect_u8(src, base, offset));
        }

        visitor.store::<M, u8, DEBUG>(program_counter, src, Some(base), offset)
    }

    fn store_indirect_u16<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, src: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::store_indirect_u16(src, base, offset));
        }

        visitor.store::<M, u16, DEBUG>(program_counter, src, Some(base), offset)
    }

    fn store_indirect_u32<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, src: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::store_indirect_u32(src, base, offset));
        }

        visitor.store::<M, u32, DEBUG>(program_counter, src, Some(base), offset)
    }

    fn store_indirect_u64<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, src: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::store_indirect_u64(src, base, offset));
        }

        visitor.store::<M, u64, DEBUG>(program_counter, src, Some(base), offset)
    }

    fn store_u8<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, src: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::store_u8(src, offset));
        }

        visitor.store::<M, u8, DEBUG>(program_counter, src, None, offset)
    }

    fn store_u16<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, src: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::store_u16(src, offset));
        }

        visitor.store::<M, u16, DEBUG>(program_counter, src, None, offset)
    }

    fn store_u32<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, src: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::store_u32(src, offset));
        }

        visitor.store::<M, u32, DEBUG>(program_counter, src, None, offset)
    }

    fn store_u64<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, src: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::store_u64(src, offset));
        }

        visitor.store::<M, u64, DEBUG>(program_counter, src, None, offset)
    }

    fn load_u8<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, dst: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::load_u8(dst, offset));
        }

        visitor.load::<M, u8, DEBUG>(program_counter, dst, None, offset)
    }

    fn load_i8<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, dst: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::load_i8(dst, offset));
        }

        visitor.load::<M, i8, DEBUG>(program_counter, dst, None, offset)
    }

    fn load_u16<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, dst: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::load_u16(dst, offset));
        }

        visitor.load::<M, u16, DEBUG>(program_counter, dst, None, offset)
    }

    fn load_i16<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, dst: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::load_i16(dst, offset));
        }

        visitor.load::<M, i16, DEBUG>(program_counter, dst, None, offset)
    }

    fn load_u32<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, dst: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::load_u32(dst, offset));
        }

        visitor.load::<M, u32, DEBUG>(program_counter, dst, None, offset)
    }

    fn load_i32<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, dst: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::load_i32(dst, offset));
        }

        visitor.load::<M, i32, DEBUG>(program_counter, dst, None, offset)
    }

    fn load_u64<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, dst: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::load_u64(dst, offset));
        }

        visitor.load::<M, u64, DEBUG>(program_counter, dst, None, offset)
    }

    fn load_indirect_u8<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::load_indirect_u8(dst, base, offset));
        }

        visitor.load::<M, u8, DEBUG>(program_counter, dst, Some(base), offset)
    }

    fn load_indirect_i8<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::load_indirect_i8(dst, base, offset));
        }

        visitor.load::<M, i8, DEBUG>(program_counter, dst, Some(base), offset)
    }

    fn load_indirect_u16<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::load_indirect_u16(dst, base, offset));
        }

        visitor.load::<M, u16, DEBUG>(program_counter, dst, Some(base), offset)
    }

    fn load_indirect_i16<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::load_indirect_i16(dst, base, offset));
        }

        visitor.load::<M, i16, DEBUG>(program_counter, dst, Some(base), offset)
    }

    fn load_indirect_u32<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::load_indirect_u32(dst, base, offset));
        }

        visitor.load::<M, u32, DEBUG>(program_counter, dst, Some(base), offset)
    }

    fn load_indirect_i32<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::load_indirect_i32(dst, base, offset));
        }

        visitor.load::<M, i32, DEBUG>(program_counter, dst, Some(base), offset)
    }

    fn load_indirect_u64<M: Memory, const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, dst: Reg, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::load_indirect_u64(dst, base, offset));
        }

        visitor.load::<M, u64, DEBUG>(program_counter, dst, Some(base), offset)
    }

    fn branch_less_unsigned<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: Reg, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} <u {s2}", visitor.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 < s2)
    }

    fn branch_less_unsigned_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: u32, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} <u {s2}", visitor.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 < s2)
    }

    fn branch_less_signed<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: Reg, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} <s {s2}", visitor.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| cast(s1).to_signed() < cast(s2).to_signed())
    }

    fn branch_less_signed_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: u32, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} <s {s2}", visitor.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| cast(s1).to_signed() < cast(s2).to_signed())
    }

    fn branch_eq<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: Reg, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} == {s2}", visitor.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 == s2)
    }

    fn branch_eq_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: u32, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} == {s2}", visitor.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 == s2)
    }

    fn branch_not_eq<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: Reg, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} != {s2}", visitor.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 != s2)
    }

    fn branch_not_eq_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: u32, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} != {s2}", visitor.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 != s2)
    }

    fn branch_greater_or_equal_unsigned<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: Reg, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} >=u {s2}", visitor.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 >= s2)
    }

    fn branch_greater_or_equal_unsigned_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: u32, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} >=u {s2}", visitor.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 >= s2)
    }

    fn branch_greater_or_equal_signed<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: Reg, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} >=s {s2}", visitor.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| cast(s1).to_signed() >= cast(s2).to_signed())
    }

    fn branch_greater_or_equal_signed_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: u32, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} >=s {s2}", visitor.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| cast(s1).to_signed() >= cast(s2).to_signed())
    }

    fn branch_less_or_equal_unsigned_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: u32, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} <=u {s2}", visitor.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 <= s2)
    }

    fn branch_less_or_equal_signed_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: u32, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} <=s {s2}", visitor.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| cast(s1).to_signed() <= cast(s2).to_signed())
    }

    fn branch_greater_unsigned_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: u32, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} >u {s2}", visitor.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| s1 > s2)
    }

    fn branch_greater_signed_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: u32, tt: Target, tf: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{tt} if {s1} >s {s2}", visitor.compiled_offset);
        }

        visitor.branch::<DEBUG>(s1, s2, tt, tf, |s1, s2| cast(s1).to_signed() > cast(s2).to_signed())
    }

    fn jump<const DEBUG: bool>(visitor: &mut InterpretedInstance, target: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: jump ~{target}", visitor.compiled_offset);
        }

        Some(target)
    }

    fn jump_indirect<const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, base: Reg, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::jump_indirect(base, offset));
        }

        let dynamic_address = visitor.get32::<DEBUG>(base).wrapping_add(offset);
        visitor.jump_indirect_impl::<DEBUG>(program_counter, dynamic_address)
    }

    fn load_imm_and_jump_indirect<const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, ra: Reg, base: Reg, value: u32, offset: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::load_imm_and_jump_indirect(ra, base, value, offset));
        }

        let dynamic_address = visitor.get32::<DEBUG>(base).wrapping_add(offset);
        visitor.set32::<DEBUG>(ra, value);
        visitor.jump_indirect_impl::<DEBUG>(program_counter, dynamic_address)
    }

    fn load_imm_and_jump<const DEBUG: bool>(visitor: &mut InterpretedInstance, ra: Reg, value: u32, target: Target) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: {}", visitor.compiled_offset, asm::load_imm_and_jump(ra, value, target));
        }

        visitor.set32::<DEBUG>(ra, value);
        Some(target)
    }

    fn unresolved_branch_less_unsigned<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: Reg, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!("<u", visitor, s1, s2, tt, tf, branch_less_unsigned)
    }

    fn unresolved_branch_less_unsigned_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: u32, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!("<u", visitor, s1, s2, tt, tf, branch_less_unsigned_imm)
    }

    fn unresolved_branch_less_signed<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: Reg, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!("<s", visitor, s1, s2, tt, tf, branch_less_signed)
    }

    fn unresolved_branch_less_signed_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: u32, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!("<s", visitor, s1, s2, tt, tf, branch_less_signed_imm)
    }

    fn unresolved_branch_eq<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: Reg, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!("==", visitor, s1, s2, tt, tf, branch_eq)
    }

    fn unresolved_branch_eq_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: u32, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!("==", visitor, s1, s2, tt, tf, branch_eq_imm)
    }

    fn unresolved_branch_not_eq<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: Reg, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!("!=", visitor, s1, s2, tt, tf, branch_not_eq)
    }

    fn unresolved_branch_not_eq_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: u32, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!("!=", visitor, s1, s2, tt, tf, branch_not_eq_imm)
    }

    fn unresolved_branch_greater_or_equal_unsigned<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: Reg, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!(">=u", visitor, s1, s2, tt, tf, branch_greater_or_equal_unsigned)
    }

    fn unresolved_branch_greater_or_equal_unsigned_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: u32, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!(">=u", visitor, s1, s2, tt, tf, branch_greater_or_equal_unsigned_imm)
    }

    fn unresolved_branch_greater_or_equal_signed<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: Reg, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!(">=s", visitor, s1, s2, tt, tf, branch_greater_or_equal_signed)
    }

    fn unresolved_branch_greater_or_equal_signed_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: u32, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!(">=s", visitor, s1, s2, tt, tf, branch_greater_or_equal_signed_imm)
    }

    fn unresolved_branch_greater_unsigned_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: u32, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!(">u", visitor, s1, s2, tt, tf, branch_greater_unsigned_imm)
    }

    fn unresolved_branch_greater_signed_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: u32, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!(">s", visitor, s1, s2, tt, tf, branch_greater_signed_imm)
    }

    fn unresolved_branch_less_or_equal_unsigned_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: u32, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!("<=u", visitor, s1, s2, tt, tf, branch_less_or_equal_unsigned_imm)
    }

    fn unresolved_branch_less_or_equal_signed_imm<const DEBUG: bool>(visitor: &mut InterpretedInstance, s1: Reg, s2: u32, tt: ProgramCounter, tf: ProgramCounter) -> Option<Target> {
        handle_unresolved_branch!("<=s", visitor, s1, s2, tt, tf, branch_less_or_equal_signed_imm)
    }

    fn unresolved_jump<const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, jump_to: ProgramCounter) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: unresolved jump {jump_to}", visitor.compiled_offset);
        }

        if let Some(target) = visitor.resolve_jump::<DEBUG>(jump_to) {
            let offset = visitor.compiled_offset;
            if offset + 1 == target {
                if DEBUG {
                    log::trace!("  -> resolved to fallthrough");
                }
                let off_idx = cast(offset).to_usize();
                visitor.compiled_decoded[off_idx] = DecodedInst {
                    bb_gas_cost: 0,
                    opcode: fast_op_for!(fallthrough),
                    ..DecodedInst::fallthrough()
                };
            } else {
                if DEBUG {
                    log::trace!("  -> resolved to jump");
                }
                let off_idx = cast(offset).to_usize();
                visitor.compiled_decoded[off_idx] = DecodedInst {
                    bb_gas_cost: 0,
                    opcode: fast_op_for!(jump),
                    ..DecodedInst::jump(target)
                };
            }

            Some(target)
        } else {
            if DEBUG {
                log::trace!("  -> resolved to trap");
            }
            trap_impl::<DEBUG>(visitor, program_counter)
        }
    }

    fn unresolved_load_imm_and_jump<const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, ra: Reg, value: u32, jump_to: u32) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: unresolved {}", visitor.compiled_offset, asm::load_imm_and_jump(ra, value, jump_to));
        }

        visitor.set32::<DEBUG>(ra, value);

        let offset = visitor.compiled_offset;
        if let Some(target) = visitor.resolve_jump::<DEBUG>(ProgramCounter(jump_to)) {
            if DEBUG {
                log::trace!("  -> resolved to jump");
            }
            let off_idx = cast(offset).to_usize();
            visitor.compiled_decoded[off_idx] = DecodedInst {
                bb_gas_cost: 0,
                opcode: fast_op_for!(load_imm_and_jump),
                ..DecodedInst::load_imm_and_jump(ra, value, target)
            };

            Some(target)
        } else {
            if DEBUG {
                log::trace!("  -> resolved to trap");
            }
            trap_impl::<DEBUG>(visitor, program_counter)
        }
    }

    fn unresolved_fallthrough<const DEBUG: bool>(visitor: &mut InterpretedInstance, program_counter: ProgramCounter, jump_to: ProgramCounter) -> Option<Target> {
        if DEBUG {
            log::trace!("[{}]: unresolved fallthrough {jump_to}", visitor.compiled_offset);
        }

        let offset = visitor.compiled_offset;
        if let Some(target) = visitor.resolve_fallthrough::<DEBUG>(jump_to) {
            if offset + 1 == target {
                if DEBUG {
                    log::trace!("  -> resolved to fallthrough");
                }
                let off_idx = cast(offset).to_usize();
                visitor.compiled_decoded[off_idx] = DecodedInst {
                    bb_gas_cost: 0,
                    opcode: fast_op_for!(fallthrough),
                    ..DecodedInst::fallthrough()
                };
            } else {
                if DEBUG {
                    log::trace!("  -> resolved to jump");
                }
                let off_idx = cast(offset).to_usize();
                visitor.compiled_decoded[off_idx] = DecodedInst {
                    bb_gas_cost: 0,
                    opcode: fast_op_for!(jump),
                    ..DecodedInst::jump(target)
                };
            }

            Some(target)
        } else {
            if DEBUG {
                log::trace!("  -> resolved to trap");
            }
            trap_impl::<DEBUG>(visitor, program_counter)
        }
    }
}

struct Compiler<'a, const DEBUG: bool> {
    program_counter: ProgramCounter,
    next_program_counter: ProgramCounter,
    compiled_decoded: &'a mut Vec<DecodedInst>,
    module: &'a Module,
    memory_kind: usize,
}

impl<'a, const DEBUG: bool> Compiler<'a, DEBUG> {
    fn next_program_counter(&self) -> ProgramCounter {
        self.next_program_counter
    }

    #[track_caller]
    fn assert_64_bit(&self) {
        debug_assert!(self.module.blob().is_64_bit());
    }
}

impl<'a, const DEBUG: bool> InstructionVisitor for Compiler<'a, DEBUG> {
    type ReturnTy = ();

    #[cold]
    fn invalid(&mut self) -> Self::ReturnTy {
        self.trap();
    }

    fn trap(&mut self) -> Self::ReturnTy {
        emit!(self, trap(self.program_counter));
    }

    fn fallthrough(&mut self) -> Self::ReturnTy {
        let target = self.next_program_counter();
        emit!(self, unresolved_fallthrough(self.program_counter, target));
    }

    fn unlikely(&mut self) -> Self::ReturnTy {}

    fn sbrk(&mut self, dst: RawReg, size: RawReg) -> Self::ReturnTy {
        emit!(self, sbrk(dst, size));
    }

    fn memset(&mut self) -> Self::ReturnTy {
        #[allow(clippy::branches_sharing_code)]
        if self.memory_kind == MEMORY_STANDARD {
            emit_raw!(self, memset::<StandardMemory, DEBUG>(self.program_counter));
        } else {
            debug_assert_eq!(self.memory_kind, MEMORY_DYNAMIC);
            emit_raw!(self, memset::<DynamicMemory, DEBUG>(self.program_counter));
        }
    }

    fn ecalli(&mut self, imm: u32) -> Self::ReturnTy {
        emit!(self, ecalli(self.program_counter, imm));
    }

    fn set_less_than_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, set_less_than_unsigned(d, s1, s2));
    }

    fn set_less_than_signed(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, set_less_than_signed(d, s1, s2));
    }

    fn shift_logical_right_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, shift_logical_right_32(d, s1, s2));
    }

    fn shift_arithmetic_right_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, shift_arithmetic_right_32(d, s1, s2));
    }

    fn shift_logical_left_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, shift_logical_left_32(d, s1, s2));
    }

    fn shift_logical_right_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, shift_logical_right_64(d, s1, s2));
    }

    fn shift_arithmetic_right_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, shift_arithmetic_right_64(d, s1, s2));
    }

    fn shift_logical_left_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, shift_logical_left_64(d, s1, s2));
    }

    fn xor(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, xor(d, s1, s2));
    }

    fn and(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, and(d, s1, s2));
    }

    fn or(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, or(d, s1, s2));
    }

    fn add_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, add_32(d, s1, s2));
    }

    fn add_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, add_64(d, s1, s2));
    }

    fn sub_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, sub_32(d, s1, s2));
    }

    fn sub_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, sub_64(d, s1, s2));
    }

    fn negate_and_add_imm_32(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, negate_and_add_imm_32(d, s1, s2));
    }

    fn negate_and_add_imm_64(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, negate_and_add_imm_64(d, s1, s2));
    }

    fn mul_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, mul_32(d, s1, s2));
    }

    fn mul_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, mul_64(d, s1, s2));
    }

    fn mul_imm_32(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, mul_imm_32(d, s1, s2));
    }

    fn mul_imm_64(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, mul_imm_64(d, s1, s2));
    }

    fn mul_upper_signed_signed(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, mul_upper_signed_signed_64(d, s1, s2));
        } else {
            emit!(self, mul_upper_signed_signed_32(d, s1, s2));
        }
    }

    fn mul_upper_unsigned_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, mul_upper_unsigned_unsigned_64(d, s1, s2));
        } else {
            emit!(self, mul_upper_unsigned_unsigned_32(d, s1, s2));
        }
    }

    fn mul_upper_signed_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, mul_upper_signed_unsigned_64(d, s1, s2));
        } else {
            emit!(self, mul_upper_signed_unsigned_32(d, s1, s2));
        }
    }

    fn div_unsigned_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, div_unsigned_32(d, s1, s2));
    }

    fn div_signed_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, div_signed_32(d, s1, s2));
    }

    fn rem_unsigned_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, rem_unsigned_32(d, s1, s2));
    }

    fn rem_signed_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, rem_signed_32(d, s1, s2));
    }

    fn div_unsigned_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, div_unsigned_64(d, s1, s2));
    }

    fn div_signed_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, div_signed_64(d, s1, s2));
    }

    fn rem_unsigned_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, rem_unsigned_64(d, s1, s2));
    }

    fn rem_signed_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, rem_signed_64(d, s1, s2));
    }

    fn and_inverted(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, and_inverted_64(d, s1, s2));
        } else {
            emit!(self, and_inverted_32(d, s1, s2));
        }
    }

    fn or_inverted(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, or_inverted_64(d, s1, s2));
        } else {
            emit!(self, or_inverted_32(d, s1, s2));
        }
    }

    fn xnor(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, xnor_64(d, s1, s2));
        } else {
            emit!(self, xnor_32(d, s1, s2));
        }
    }

    fn maximum(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, maximum_64(d, s1, s2));
        } else {
            emit!(self, maximum_32(d, s1, s2));
        }
    }

    fn maximum_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, maximum_unsigned_64(d, s1, s2));
        } else {
            emit!(self, maximum_unsigned_32(d, s1, s2));
        }
    }

    fn minimum(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, minimum_64(d, s1, s2));
        } else {
            emit!(self, minimum_32(d, s1, s2));
        }
    }

    fn minimum_unsigned(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, minimum_unsigned_64(d, s1, s2));
        } else {
            emit!(self, minimum_unsigned_32(d, s1, s2));
        }
    }

    fn rotate_left_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, rotate_left_32(d, s1, s2));
    }

    fn rotate_left_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, rotate_left_64(d, s1, s2));
    }

    fn rotate_right_32(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        emit!(self, rotate_right_32(d, s1, s2));
    }

    fn rotate_right_64(&mut self, d: RawReg, s1: RawReg, s2: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, rotate_right_64(d, s1, s2));
    }

    fn set_less_than_unsigned_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, set_less_than_unsigned_imm(d, s1, s2));
    }

    fn set_greater_than_unsigned_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, set_greater_than_unsigned_imm(d, s1, s2));
    }

    fn set_less_than_signed_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, set_less_than_signed_imm(d, s1, s2));
    }

    fn set_greater_than_signed_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, set_greater_than_signed_imm(d, s1, s2));
    }

    fn shift_logical_right_imm_32(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, shift_logical_right_imm_32(d, s1, s2));
    }

    fn shift_logical_right_imm_alt_32(&mut self, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        emit!(self, shift_logical_right_imm_alt_32(d, s2, s1));
    }

    fn shift_arithmetic_right_imm_32(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, shift_arithmetic_right_imm_32(d, s1, s2));
    }

    fn shift_arithmetic_right_imm_alt_32(&mut self, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        emit!(self, shift_arithmetic_right_imm_alt_32(d, s2, s1));
    }

    fn shift_logical_left_imm_32(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, shift_logical_left_imm_32(d, s1, s2));
    }

    fn shift_logical_left_imm_alt_32(&mut self, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        emit!(self, shift_logical_left_imm_alt_32(d, s2, s1));
    }

    fn shift_logical_right_imm_64(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, shift_logical_right_imm_64(d, s1, s2));
    }

    fn shift_logical_right_imm_alt_64(&mut self, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        emit!(self, shift_logical_right_imm_alt_64(d, s2, s1));
    }

    fn shift_arithmetic_right_imm_64(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, shift_arithmetic_right_imm_64(d, s1, s2));
    }

    fn shift_arithmetic_right_imm_alt_64(&mut self, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        emit!(self, shift_arithmetic_right_imm_alt_64(d, s2, s1));
    }

    fn shift_logical_left_imm_64(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, shift_logical_left_imm_64(d, s1, s2));
    }

    fn shift_logical_left_imm_alt_64(&mut self, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        emit!(self, shift_logical_left_imm_alt_64(d, s2, s1));
    }

    fn or_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, or_imm(d, s1, s2));
    }

    fn and_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, and_imm(d, s1, s2));
    }

    fn xor_imm(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, xor_imm(d, s1, s2));
    }

    fn load_imm(&mut self, dst: RawReg, imm: u32) -> Self::ReturnTy {
        emit!(self, load_imm(dst, imm));
    }

    fn load_imm64(&mut self, dst: RawReg, imm: u64) -> Self::ReturnTy {
        emit!(
            self,
            load_imm64(dst, cast(imm).truncate_to_u32(), cast(imm >> 32).truncate_to_u32())
        );
    }

    fn move_reg(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        emit!(self, move_reg(d, s));
    }

    fn count_leading_zero_bits_32(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        emit!(self, count_leading_zero_bits_32(d, s));
    }

    fn count_leading_zero_bits_64(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, count_leading_zero_bits_64(d, s));
    }

    fn count_trailing_zero_bits_32(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        emit!(self, count_trailing_zero_bits_32(d, s));
    }

    fn count_trailing_zero_bits_64(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, count_trailing_zero_bits_64(d, s));
    }

    fn count_set_bits_32(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        emit!(self, count_set_bits_32(d, s));
    }

    fn count_set_bits_64(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, count_set_bits_64(d, s));
    }

    fn sign_extend_8(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, sign_extend_8_64(d, s));
        } else {
            emit!(self, sign_extend_8_32(d, s));
        }
    }

    fn sign_extend_16(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, sign_extend_16_64(d, s));
        } else {
            emit!(self, sign_extend_16_32(d, s));
        }
    }

    fn zero_extend_16(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, zero_extend_16_64(d, s));
        } else {
            emit!(self, zero_extend_16_32(d, s));
        }
    }

    fn reverse_byte(&mut self, d: RawReg, s: RawReg) -> Self::ReturnTy {
        if self.module.blob().is_64_bit() {
            emit!(self, reverse_byte_64(d, s));
        } else {
            emit!(self, reverse_byte_32(d, s));
        }
    }

    fn cmov_if_zero(&mut self, d: RawReg, s: RawReg, c: RawReg) -> Self::ReturnTy {
        emit!(self, cmov_if_zero(d, s, c));
    }

    fn cmov_if_zero_imm(&mut self, d: RawReg, c: RawReg, s: u32) -> Self::ReturnTy {
        emit!(self, cmov_if_zero_imm(d, c, s));
    }

    fn cmov_if_not_zero(&mut self, d: RawReg, s: RawReg, c: RawReg) -> Self::ReturnTy {
        emit!(self, cmov_if_not_zero(d, s, c));
    }

    fn cmov_if_not_zero_imm(&mut self, d: RawReg, c: RawReg, s: u32) -> Self::ReturnTy {
        emit!(self, cmov_if_not_zero_imm(d, c, s));
    }

    fn rotate_right_imm_32(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, rotate_right_imm_32(d, s1, s2));
    }

    fn rotate_right_imm_alt_32(&mut self, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        emit!(self, rotate_right_imm_alt_32(d, s2, s1));
    }

    fn rotate_right_imm_64(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, rotate_right_imm_64(d, s1, s2));
    }

    fn rotate_right_imm_alt_64(&mut self, d: RawReg, s2: RawReg, s1: u32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, rotate_right_imm_alt_64(d, s2, s1));
    }

    fn add_imm_64(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit!(self, add_imm_64(d, s1, s2));
    }

    fn add_imm_32(&mut self, d: RawReg, s1: RawReg, s2: u32) -> Self::ReturnTy {
        emit!(self, add_imm_32(d, s1, s2));
    }

    fn store_imm_u8(&mut self, offset: u32, value: u32) -> Self::ReturnTy {
        emit_load_store!(self, store_imm_u8(self.program_counter, offset, value));
    }

    fn store_imm_u16(&mut self, offset: u32, value: u32) -> Self::ReturnTy {
        emit_load_store!(self, store_imm_u16(self.program_counter, offset, value));
    }

    fn store_imm_u32(&mut self, offset: u32, value: u32) -> Self::ReturnTy {
        emit_load_store!(self, store_imm_u32(self.program_counter, offset, value));
    }

    fn store_imm_u64(&mut self, offset: u32, value: u32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit_load_store!(self, store_imm_u64(self.program_counter, offset, value));
    }

    fn store_imm_indirect_u8(&mut self, base: RawReg, offset: u32, value: u32) -> Self::ReturnTy {
        emit_load_store!(self, store_imm_indirect_u8(self.program_counter, base, offset, value));
    }

    fn store_imm_indirect_u16(&mut self, base: RawReg, offset: u32, value: u32) -> Self::ReturnTy {
        emit_load_store!(self, store_imm_indirect_u16(self.program_counter, base, offset, value));
    }

    fn store_imm_indirect_u32(&mut self, base: RawReg, offset: u32, value: u32) -> Self::ReturnTy {
        emit_load_store!(self, store_imm_indirect_u32(self.program_counter, base, offset, value));
    }

    fn store_imm_indirect_u64(&mut self, base: RawReg, offset: u32, value: u32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit_load_store!(self, store_imm_indirect_u64(self.program_counter, base, offset, value));
    }

    fn store_indirect_u8(&mut self, src: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        emit_load_store!(self, store_indirect_u8(self.program_counter, src, base, offset));
    }

    fn store_indirect_u16(&mut self, src: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        emit_load_store!(self, store_indirect_u16(self.program_counter, src, base, offset));
    }

    fn store_indirect_u32(&mut self, src: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        emit_load_store!(self, store_indirect_u32(self.program_counter, src, base, offset));
    }

    fn store_indirect_u64(&mut self, src: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit_load_store!(self, store_indirect_u64(self.program_counter, src, base, offset));
    }

    fn store_u8(&mut self, src: RawReg, offset: u32) -> Self::ReturnTy {
        emit_load_store!(self, store_u8(self.program_counter, src, offset));
    }

    fn store_u16(&mut self, src: RawReg, offset: u32) -> Self::ReturnTy {
        emit_load_store!(self, store_u16(self.program_counter, src, offset));
    }

    fn store_u32(&mut self, src: RawReg, offset: u32) -> Self::ReturnTy {
        emit_load_store!(self, store_u32(self.program_counter, src, offset));
    }

    fn store_u64(&mut self, src: RawReg, offset: u32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit_load_store!(self, store_u64(self.program_counter, src, offset));
    }

    fn load_u8(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        emit_load_store!(self, load_u8(self.program_counter, dst, offset));
    }

    fn load_i8(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        emit_load_store!(self, load_i8(self.program_counter, dst, offset));
    }

    fn load_u16(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        emit_load_store!(self, load_u16(self.program_counter, dst, offset));
    }

    fn load_i16(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        emit_load_store!(self, load_i16(self.program_counter, dst, offset));
    }

    fn load_i32(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        emit_load_store!(self, load_i32(self.program_counter, dst, offset));
    }

    fn load_u32(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit_load_store!(self, load_u32(self.program_counter, dst, offset));
    }

    fn load_u64(&mut self, dst: RawReg, offset: u32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit_load_store!(self, load_u64(self.program_counter, dst, offset));
    }

    fn load_indirect_u8(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        emit_load_store!(self, load_indirect_u8(self.program_counter, dst, base, offset));
    }

    fn load_indirect_i8(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        emit_load_store!(self, load_indirect_i8(self.program_counter, dst, base, offset));
    }

    fn load_indirect_u16(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        emit_load_store!(self, load_indirect_u16(self.program_counter, dst, base, offset));
    }

    fn load_indirect_i16(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        emit_load_store!(self, load_indirect_i16(self.program_counter, dst, base, offset));
    }

    fn load_indirect_i32(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        emit_load_store!(self, load_indirect_i32(self.program_counter, dst, base, offset));
    }

    fn load_indirect_u32(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit_load_store!(self, load_indirect_u32(self.program_counter, dst, base, offset));
    }

    fn load_indirect_u64(&mut self, dst: RawReg, base: RawReg, offset: u32) -> Self::ReturnTy {
        self.assert_64_bit();
        emit_load_store!(self, load_indirect_u64(self.program_counter, dst, base, offset));
    }

    fn branch_less_unsigned(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_less_unsigned, s1, s2, i);
    }

    fn branch_less_unsigned_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_less_unsigned_imm, s1, s2, i);
    }

    fn branch_less_signed(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_less_signed, s1, s2, i);
    }

    fn branch_less_signed_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_less_signed_imm, s1, s2, i);
    }

    fn branch_eq(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_eq, s1, s2, i);
    }

    fn branch_eq_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_eq_imm, s1, s2, i);
    }

    fn branch_not_eq(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_not_eq, s1, s2, i);
    }

    fn branch_not_eq_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_not_eq_imm, s1, s2, i);
    }

    fn branch_greater_or_equal_unsigned(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_greater_or_equal_unsigned, s1, s2, i);
    }

    fn branch_greater_or_equal_unsigned_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_greater_or_equal_unsigned_imm, s1, s2, i);
    }

    fn branch_greater_or_equal_signed(&mut self, s1: RawReg, s2: RawReg, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_greater_or_equal_signed, s1, s2, i);
    }

    fn branch_greater_or_equal_signed_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_greater_or_equal_signed_imm, s1, s2, i);
    }

    fn branch_less_or_equal_unsigned_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_less_or_equal_unsigned_imm, s1, s2, i);
    }

    fn branch_less_or_equal_signed_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_less_or_equal_signed_imm, s1, s2, i);
    }

    fn branch_greater_unsigned_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_greater_unsigned_imm, s1, s2, i);
    }

    fn branch_greater_signed_imm(&mut self, s1: RawReg, s2: u32, i: u32) -> Self::ReturnTy {
        emit_branch!(self, unresolved_branch_greater_signed_imm, s1, s2, i);
    }

    fn jump(&mut self, target: u32) -> Self::ReturnTy {
        emit!(self, unresolved_jump(self.program_counter, ProgramCounter(target)));
    }

    fn jump_indirect(&mut self, base: RawReg, offset: u32) -> Self::ReturnTy {
        emit!(self, jump_indirect(self.program_counter, base, offset));
    }

    fn load_imm_and_jump(&mut self, dst: RawReg, imm: u32, target: u32) -> Self::ReturnTy {
        emit!(self, unresolved_load_imm_and_jump(self.program_counter, dst, imm, target));
    }

    fn load_imm_and_jump_indirect(&mut self, ra: RawReg, base: RawReg, value: u32, offset: u32) -> Self::ReturnTy {
        emit!(self, load_imm_and_jump_indirect(self.program_counter, ra, base, value, offset));
    }
}

