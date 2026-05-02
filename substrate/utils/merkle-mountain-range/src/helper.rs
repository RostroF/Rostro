use crate::vec;
use crate::vec::Vec;

pub fn leaf_index_to_pos(index: u64) -> u64 {
    // mmr_size - H - 1, H is the height(intervals) of last peak
    leaf_index_to_mmr_size(index) - (index + 1).trailing_zeros() as u64 - 1
}

/// Rostro hardening (C): returns `true` iff `mmr_size` is the size of an MMR with
/// some specific number of leaves, i.e. it is a *canonical* MMR size.
///
/// The upstream `get_peaks` / `get_peak_map` silently normalize a non-canonical
/// `mmr_size` to "the last valid mmr <= mmr_size" and continue execution. That is
/// fine for the trusted path (gen-side) but is a footgun on the verifier side:
/// it widens the attack surface and allows an attacker to drive helper math through
/// overflow / wrap-around paths. By rejecting non-canonical sizes at every verifier
/// entrypoint we close this whole class of fragile-design pre-conditions.
///
/// Canonical sizes are 0, 1, 3, 4, 7, 8, 10, 11, 15, 16, ... — i.e. exactly the
/// values returned by `leaf_index_to_mmr_size(n) for n = 0, 1, 2, ...` (plus 0).
///
/// We test canonicality by deriving the implied leaf count from `get_peak_map`
/// (which itself silently normalizes — that's its documented behaviour) and then
/// recomputing the size with `leaf_index_to_mmr_size`. If the round-trip equals
/// `mmr_size`, the input was already canonical; if not, it wasn't.
pub fn is_canonical_mmr_size(mmr_size: u64) -> bool {
    if mmr_size == 0 {
        return true;
    }
    let leaves_count = get_peak_map(mmr_size);
    if leaves_count == 0 {
        // mmr_size != 0 but the peak map says zero leaves — non-canonical.
        return false;
    }
    // `leaves_count - 1` is the highest leaf index. For the round-trip to be safe we
    // also need `leaves_count <= 2^63` (otherwise `leaf_index_to_mmr_size` overflows;
    // see the "Integer overflow in leaf_index_to_mmr_size" finding in the audit).
    // In practice `mmr_size > 2^63` is already absurd (an MMR with 2^63 leaves needs
    // ~2^64 nodes which doesn't fit in a u64) and we reject it as non-canonical.
    // Use `>=` not `>`: at exactly `1 << 63`, `leaf_index_to_mmr_size(leaves_count - 1)`
    // hits the `2 * leaves_count` term which is `1 << 64` — silently wraps to 0 in release,
    // panics in debug. The round-trip then "happens to equal" `u64::MAX` via wrap, so a
    // strict `>` here returned `true` for `mmr_size == u64::MAX`. Reject the boundary.
    if leaves_count >= (1u64 << 63) {
        return false;
    }
    leaf_index_to_mmr_size(leaves_count - 1) == mmr_size
}

pub fn leaf_index_to_mmr_size(index: u64) -> u64 {
    // leaf index start with 0
    let leaves_count = index + 1;

    // the peak count(k) is actually the count of 1 in leaves count's binary representation
    let peak_count = leaves_count.count_ones() as u64;

    2 * leaves_count - peak_count
}

pub fn pos_height_in_tree(mut pos: u64) -> u8 {
    if pos == 0 {
        return 0;
    }

    let mut peak_size = u64::MAX >> pos.leading_zeros();
    while peak_size > 0 {
        if pos >= peak_size {
            pos -= peak_size;
        }
        peak_size >>= 1;
    }
    pos as u8
}

pub fn parent_offset(height: u8) -> u64 {
    2 << height
}

pub fn sibling_offset(height: u8) -> u64 {
    (2 << height) - 1
}

/// Returns the height of the peaks in the mmr, presented by a bitmap.
/// for example, for a mmr with 11 leaves, the mmr_size is 19, it will return 0b1011.
/// 0b1011 indicates that the left peaks are at height 0, 1 and 3.
///           14
///        /       \
///      6          13
///    /   \       /   \
///   2     5     9     12     17
///  / \   /  \  / \   /  \   /  \
/// 0   1 3   4 7   8 10  11 15  16 18
///
/// please note that when the mmr_size is invalid, it will return the bitmap of the last valid mmr.
/// in the below example, the mmr_size is 6, but it's not a valid mmr, it will return 0b11.
///   2     5
///  / \   /  \
/// 0   1 3   4
pub fn get_peak_map(mmr_size: u64) -> u64 {
    if mmr_size == 0 {
        return 0;
    }

    let mut pos = mmr_size;
    let mut peak_size = u64::MAX >> pos.leading_zeros();
    let mut peak_map = 0;
    while peak_size > 0 {
        peak_map <<= 1;
        if pos >= peak_size {
            pos -= peak_size;
            peak_map |= 1;
        }
        peak_size >>= 1;
    }

    peak_map
}

/// Returns whether `descendant_contender` is a descendant of `ancestor_contender` in a tree of the MMR.
pub fn is_descendant_pos(ancestor_contender: u64, descendant_contender: u64) -> bool {
    // NOTE: "ancestry" here refers to the hierarchy within an MMR tree, not temporal hierarchy.
    // the descendant needs to have been added to the mmr prior to the ancestor
    descendant_contender <= ancestor_contender
        // the descendant needs to be within the cone of positions descendant from the ancestor
        && descendant_contender
            >= (ancestor_contender + 1 - sibling_offset(pos_height_in_tree(ancestor_contender)))
}

/// Returns the pos of the peaks in the mmr.
/// for example, for a mmr with 11 leaves, the mmr_size is 19, it will return [14, 17, 18].
///           14
///        /       \
///      6          13
///    /   \       /   \
///   2     5     9     12     17
///  / \   /  \  / \   /  \   /  \
/// 0   1 3   4 7   8 10  11 15  16 18
///
/// please note that when the mmr_size is invalid, it will return the peaks of the last valid mmr.
/// in the below example, the mmr_size is 6, but it's not a valid mmr, it will return [2, 3].
///   2     5
///  / \   /  \
/// 0   1 3   4
pub fn get_peaks(mmr_size: u64) -> Vec<u64> {
    if mmr_size == 0 {
        return vec![];
    }

    let leading_zeros = mmr_size.leading_zeros();
    let mut pos = mmr_size;
    let mut peak_size = u64::MAX >> leading_zeros;
    let mut peaks = Vec::with_capacity(64 - leading_zeros as usize);
    let mut peaks_sum = 0;
    while peak_size > 0 {
        if pos >= peak_size {
            pos -= peak_size;
            peaks.push(peaks_sum + peak_size - 1);
            peaks_sum += peak_size;
        }
        peak_size >>= 1;
    }
    peaks
}
