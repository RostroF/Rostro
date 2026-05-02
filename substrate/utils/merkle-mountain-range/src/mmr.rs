//! Merkle Mountain Range
//!
//! references:
//! https://github.com/mimblewimble/grin/blob/master/doc/mmr.md#structure
//! https://github.com/mimblewimble/grin/blob/0ff6763ee64e5a14e70ddd4642b99789a1648a32/core/src/core/pmmr.rs#L606

use crate::ancestry_proof::{AncestryProof, NodeMerkleProof};
use crate::borrow::Cow;
use crate::collections::VecDeque;
use crate::helper::{
    get_peak_map, get_peaks, is_canonical_mmr_size, leaf_index_to_mmr_size, leaf_index_to_pos,
    parent_offset, pos_height_in_tree, sibling_offset,
};
use crate::mmr_store::{MMRBatch, MMRStoreReadOps, MMRStoreWriteOps};
use crate::util::VeqDequeExt;
use crate::vec;
use crate::vec::Vec;
use crate::{Error, Merge, Result};
use core::fmt::Debug;
use core::marker::PhantomData;

#[allow(clippy::upper_case_acronyms)]
pub struct MMR<T, M, S> {
    mmr_size: u64,
    batch: MMRBatch<T, S>,
    merge: PhantomData<M>,
}

impl<T, M, S> MMR<T, M, S> {
    pub fn new(mmr_size: u64, store: S) -> Self {
        MMR {
            mmr_size,
            batch: MMRBatch::new(store),
            merge: PhantomData,
        }
    }

    pub fn mmr_size(&self) -> u64 {
        self.mmr_size
    }

    pub fn is_empty(&self) -> bool {
        self.mmr_size == 0
    }

    pub fn batch(&self) -> &MMRBatch<T, S> {
        &self.batch
    }

    pub fn store(&self) -> &S {
        self.batch.store()
    }
}

impl<T: Clone + PartialEq, M: Merge<Item = T>, S: MMRStoreReadOps<T>> MMR<T, M, S> {
    // find internal MMR elem, the pos must exists, otherwise a error will return
    fn find_elem<'b>(&self, pos: u64, hashes: &'b [T]) -> Result<Cow<'b, T>> {
        let pos_offset = pos.checked_sub(self.mmr_size);
        if let Some(elem) = pos_offset.and_then(|i| hashes.get(i as usize)) {
            return Ok(Cow::Borrowed(elem));
        }
        let elem = self.batch.get_elem(pos)?.ok_or(Error::InconsistentStore)?;
        Ok(Cow::Owned(elem))
    }

    // push a element and return position
    pub fn push(&mut self, elem: T) -> Result<u64> {
        let mut elems = vec![elem];
        let elem_pos = self.mmr_size;
        let peak_map = get_peak_map(self.mmr_size);
        let mut pos = self.mmr_size;
        let mut peak = 1;
        while (peak_map & peak) != 0 {
            peak <<= 1;
            pos += 1;
            let left_pos = pos - peak;
            let left_elem = self.find_elem(left_pos, &elems)?;
            let right_elem = elems.last().expect("checked");
            let parent_elem = M::merge(&left_elem, right_elem)?;
            elems.push(parent_elem);
        }
        // store hashes
        self.batch.append(elem_pos, elems);
        // update mmr_size
        self.mmr_size = pos + 1;
        Ok(elem_pos)
    }

    /// get_root
    pub fn get_root(&self) -> Result<T> {
        if self.mmr_size == 0 {
            return Err(Error::GetRootOnEmpty);
        } else if self.mmr_size == 1 {
            return self.batch.get_elem(0)?.ok_or(Error::InconsistentStore);
        }
        let peaks: Vec<T> = get_peaks(self.mmr_size)
            .into_iter()
            .map(|peak_pos| {
                self.batch
                    .get_elem(peak_pos)
                    .and_then(|elem| elem.ok_or(Error::InconsistentStore))
            })
            .collect::<Result<Vec<T>>>()?;
        self.bag_rhs_peaks(peaks)?.ok_or(Error::InconsistentStore)
    }

    /// get_ancestor_root
    pub fn get_ancestor_peaks_and_root(&self, prev_mmr_size: u64) -> Result<(Vec<T>, T)> {
        if self.mmr_size == 0 {
            return Err(Error::GetRootOnEmpty);
        } else if self.mmr_size == 1 && prev_mmr_size == 1 {
            let singleton = self.batch.get_elem(0)?.ok_or(Error::InconsistentStore);
            match singleton {
                Ok(singleton) => return Ok((vec![singleton.clone()], singleton)),
                Err(e) => return Err(e),
            }
        } else if prev_mmr_size > self.mmr_size {
            return Err(Error::AncestorRootNotPredecessor);
        }
        let peaks: Result<Vec<T>> = get_peaks(prev_mmr_size)
            .into_iter()
            .map(|peak_pos| {
                self.batch
                    .get_elem(peak_pos)
                    .and_then(|elem| elem.ok_or(Error::InconsistentStore))
            })
            .collect::<Result<Vec<T>>>();
        match peaks {
            Ok(peaks) => {
                let root = self
                    .bag_rhs_peaks(peaks.clone())?
                    .ok_or(Error::InconsistentStore)?;
                return Ok((peaks, root));
            }
            Err(e) => Err(e),
        }
    }

    fn bag_rhs_peaks(&self, mut rhs_peaks: Vec<T>) -> Result<Option<T>> {
        while rhs_peaks.len() > 1 {
            let right_peak = rhs_peaks.pop().expect("pop");
            let left_peak = rhs_peaks.pop().expect("pop");
            rhs_peaks.push(M::merge_peaks(&right_peak, &left_peak)?);
        }
        Ok(rhs_peaks.pop())
    }

    /// generate merkle proof for a peak
    /// the pos_list must be sorted, otherwise the behaviour is undefined
    ///
    /// 1. find a lower tree in peak that can generate a complete merkle proof for position
    /// 2. find that tree by compare positions
    /// 3. generate proof for each positions
    fn gen_proof_for_peak(
        &self,
        proof: &mut Vec<T>,
        pos_list: Vec<u64>,
        peak_pos: u64,
    ) -> Result<()> {
        // do nothing if position itself is the peak
        if pos_list.len() == 1 && pos_list == [peak_pos] {
            return Ok(());
        }
        // take peak root from store if no positions need to be proof
        if pos_list.is_empty() {
            proof.push(
                self.batch
                    .get_elem(peak_pos)?
                    .ok_or(Error::InconsistentStore)?,
            );
            return Ok(());
        }

        let mut queue: VecDeque<_> = pos_list.into_iter().map(|pos| (pos, 0)).collect();

        // Generate sub-tree merkle proof for positions
        while let Some((pos, height)) = queue.pop_front() {
            debug_assert!(pos <= peak_pos);
            if pos == peak_pos {
                if queue.is_empty() {
                    break;
                } else {
                    return Err(Error::CorruptedProof);
                }
            }

            // calculate sibling
            let (sib_pos, parent_pos) = {
                let next_height = pos_height_in_tree(pos + 1);
                let sibling_offset = sibling_offset(height);
                if next_height > height {
                    // implies pos is right sibling
                    (pos - sibling_offset, pos + 1)
                } else {
                    // pos is left sibling
                    (pos + sibling_offset, pos + parent_offset(height))
                }
            };

            if Some(&sib_pos) == queue.front().map(|(pos, _)| pos) {
                // drop sibling
                queue.pop_front();
            } else {
                proof.push(
                    self.batch
                        .get_elem(sib_pos)?
                        .ok_or(Error::InconsistentStore)?,
                );
            }
            if parent_pos < peak_pos {
                // save pos to tree buf
                queue.push_back((parent_pos, height + 1));
            }
        }
        Ok(())
    }

    /// generate node merkle proof for a peak
    ///
    /// 1. find a lower tree in peak that can generate a complete merkle proof for position
    /// 2. find that tree by compare positions
    /// 3. generate proof for each positions
    fn gen_node_proof_for_peak(
        &self,
        proof: &mut Vec<(u64, T)>,
        pos_list: Vec<u64>,
        peak_pos: u64,
    ) -> Result<()> {
        // do nothing if position itself is the peak
        if pos_list.len() == 1 && pos_list == [peak_pos] {
            return Ok(());
        }
        // take peak root from store if no positions need to be proven
        if pos_list.is_empty() {
            proof.push((
                peak_pos,
                self.batch
                    .get_elem(peak_pos)?
                    .ok_or(Error::InconsistentStore)?,
            ));
            return Ok(());
        }

        let mut queue: VecDeque<_> = VecDeque::new();
        for value in pos_list.iter().map(|pos| (pos_height_in_tree(*pos), *pos)) {
            queue.insert_sorted(value);
        }

        // Generate sub-tree merkle proof for positions
        while let Some((height, pos)) = queue.pop_front() {
            debug_assert!(pos <= peak_pos);
            if pos == peak_pos {
                if queue.is_empty() {
                    break;
                } else {
                    continue;
                }
            }

            // calculate sibling
            let (sib_pos, parent_pos) = {
                let next_height = pos_height_in_tree(pos + 1);
                let sibling_offset = sibling_offset(height);
                if next_height > height {
                    // implies pos is right sibling
                    (pos - sibling_offset, pos + 1)
                } else {
                    // pos is left sibling
                    (pos + sibling_offset, pos + parent_offset(height))
                }
            };

            if Some(&sib_pos) == queue.front().map(|(_, pos)| pos) {
                // drop sibling
                queue.pop_front();
            } else {
                let sibling = (
                    sib_pos,
                    self.batch
                        .get_elem(sib_pos.clone())?
                        .ok_or(Error::InconsistentStore)?,
                );

                proof.push(sibling);
            }
            if parent_pos < peak_pos {
                // save pos to tree buf
                queue.insert_sorted((height + 1, parent_pos));
            }
        }
        Ok(())
    }

    /// Generate merkle proof for positions
    /// 1. sort positions
    /// 2. push merkle proof to proof by peak from left to right
    /// 3. push bagged right hand side root
    pub fn gen_proof(&self, mut pos_list: Vec<u64>) -> Result<MerkleProof<T, M>> {
        if pos_list.is_empty() {
            return Err(Error::GenProofForInvalidLeaves);
        }
        if self.mmr_size == 1 && pos_list == [0] {
            return Ok(MerkleProof::new(self.mmr_size, Vec::new()));
        }
        if pos_list.iter().any(|pos| pos_height_in_tree(*pos) > 0) {
            return Err(Error::GenProofForInvalidLeaves);
        }
        // ensure positions are sorted and unique
        pos_list.sort_unstable();
        pos_list.dedup();
        let peaks = get_peaks(self.mmr_size);
        let mut proof: Vec<T> = Vec::new();
        // generate merkle proof for each peaks
        let mut bagging_track = 0;
        for peak_pos in peaks {
            let pos_list: Vec<_> = take_while_vec(&mut pos_list, |&pos| pos <= peak_pos);
            if pos_list.is_empty() {
                bagging_track += 1;
            } else {
                bagging_track = 0;
            }
            self.gen_proof_for_peak(&mut proof, pos_list, peak_pos)?;
        }

        // ensure no remain positions
        if !pos_list.is_empty() {
            return Err(Error::GenProofForInvalidLeaves);
        }

        if bagging_track > 1 {
            let rhs_peaks = proof.split_off(proof.len() - bagging_track);
            proof.push(self.bag_rhs_peaks(rhs_peaks)?.expect("bagging rhs peaks"));
        }

        Ok(MerkleProof::new(self.mmr_size, proof))
    }

    /// Generate node merkle proof for positions
    /// 1. sort positions
    /// 2. push merkle proof to proof by peak from left to right
    /// 3. push bagged right hand side root
    pub fn gen_node_proof(&self, mut pos_list: Vec<u64>) -> Result<NodeMerkleProof<T, M>> {
        if pos_list.is_empty() {
            return Err(Error::GenProofForInvalidNodes);
        }
        if self.mmr_size == 1 && pos_list == [0] {
            return Ok(NodeMerkleProof::new(self.mmr_size, Vec::new()));
        }
        // ensure positions are sorted and unique
        pos_list.sort_unstable();
        pos_list.dedup();
        let peaks = get_peaks(self.mmr_size);
        let mut proof: Vec<(u64, T)> = Vec::new();
        // generate merkle proof for each peaks
        let mut bagging_track = 0;
        for peak_pos in peaks {
            let pos_list: Vec<_> = take_while_vec(&mut pos_list, |&pos| pos <= peak_pos);
            if pos_list.is_empty() {
                bagging_track += 1;
            } else {
                bagging_track = 0;
            }
            self.gen_node_proof_for_peak(&mut proof, pos_list, peak_pos)?;
        }

        // ensure no remain positions
        if !pos_list.is_empty() {
            return Err(Error::GenProofForInvalidNodes);
        }

        // starting from the rightmost peak, an unbroken sequence of
        // peaks that don't have descendants to be proven can be bagged
        // during the proof construction already since during verification,
        // they'll only be utilized during the bagging step anyway
        if bagging_track > 1 {
            let rhs_peaks = proof.split_off(proof.len() - bagging_track);
            proof.push((
                rhs_peaks[0].0,
                self.bag_rhs_peaks(rhs_peaks.iter().map(|(_pos, item)| item.clone()).collect())?
                    .expect("bagging rhs peaks"),
            ));
        }

        proof.sort_by_key(|(pos, _)| *pos);

        Ok(NodeMerkleProof::new(self.mmr_size, proof))
    }

    /// Generate proof that prior merkle root r' is an ancestor of current merkle proof r
    /// 1. calculate positions of peaks of old root r' given mmr size n
    /// 2. generate membership proof of peaks in root r
    /// 3. calculate r' from peaks(n)
    /// 4. return (mmr root r', peak hashes, membership proof of peaks(n) in r)
    pub fn gen_ancestry_proof(&self, prev_mmr_size: u64) -> Result<AncestryProof<T, M>> {
        let mut pos_list = get_peaks(prev_mmr_size);
        if pos_list.is_empty() {
            return Err(Error::GenProofForInvalidNodes);
        }
        if self.mmr_size == 1 && pos_list == [0] {
            return Ok(AncestryProof {
                prev_peaks: Vec::new(),
                prev_mmr_size: self.mmr_size,
                prev_peaks_proof: NodeMerkleProof::new(self.mmr_size(), Vec::new()),
            });
        }
        // ensure positions are sorted and unique
        pos_list.sort_unstable();
        pos_list.dedup();
        let peaks = get_peaks(self.mmr_size);
        let mut proof: Vec<(u64, T)> = Vec::new();
        // generate merkle proof for each peaks
        let mut bagging_track = 0;
        for peak_pos in peaks {
            let pos_list: Vec<_> = take_while_vec(&mut pos_list, |&pos| pos <= peak_pos);
            if pos_list.is_empty() {
                bagging_track += 1;
            } else {
                bagging_track = 0;
            }
            self.gen_node_proof_for_peak(&mut proof, pos_list, peak_pos)?;
        }

        // ensure no remain positions
        if !pos_list.is_empty() {
            return Err(Error::GenProofForInvalidNodes);
        }

        // starting from the rightmost peak, an unbroken sequence of
        // peaks that don't have descendants to be proven can be bagged
        // during the proof construction already since during verification,
        // they'll only be utilized during the bagging step anyway
        if bagging_track > 1 {
            let rhs_peaks = proof.split_off(proof.len() - bagging_track);
            proof.push((
                rhs_peaks[0].0,
                self.bag_rhs_peaks(rhs_peaks.iter().map(|(_pos, item)| item.clone()).collect())?
                    .expect("bagging rhs peaks"),
            ));
        }

        proof.sort_by_key(|(pos, _)| *pos);

        let (prev_peaks, _prev_root) = self.get_ancestor_peaks_and_root(prev_mmr_size)?;

        Ok(AncestryProof {
            prev_peaks,
            prev_mmr_size: prev_mmr_size,
            prev_peaks_proof: NodeMerkleProof::new(self.mmr_size, proof),
        })
    }
}

impl<T, M, S: MMRStoreWriteOps<T>> MMR<T, M, S> {
    pub fn commit(&mut self) -> Result<()> {
        self.batch.commit()
    }
}

#[derive(Debug)]
pub struct MerkleProof<T, M> {
    mmr_size: u64,
    proof: Vec<T>,
    merge: PhantomData<M>,
}

impl<T: Clone + PartialEq, M: Merge<Item = T>> MerkleProof<T, M> {
    pub fn new(mmr_size: u64, proof: Vec<T>) -> Self {
        MerkleProof {
            mmr_size,
            proof,
            merge: PhantomData,
        }
    }

    pub fn mmr_size(&self) -> u64 {
        self.mmr_size
    }

    pub fn proof_items(&self) -> &[T] {
        &self.proof
    }

    pub fn calculate_root(&self, leaves: Vec<(u64, T)>) -> Result<T> {
        // Rostro hardening (B): reject empty `leaves` at API entry. An empty leaves vec
        // combined with a proof that happens to bag to `root` would otherwise produce
        // a vacuous `Ok(true)` from `verify`. We reject upfront so callers cannot rely
        // on that semantics.
        if leaves.is_empty() {
            return Err(Error::GenProofForInvalidLeaves);
        }
        // Rostro hardening (C): validate `mmr_size` is canonical. The upstream silently
        // normalizes non-canonical `mmr_size` values via `get_peaks` / `get_peak_map`,
        // widening the verifier's attack surface (it lets an attacker drive helper math
        // through wrap-around / overflow paths). A canonical MMR size is the size of an
        // MMR with some specific number of leaves; reject anything else here.
        if !is_canonical_mmr_size(self.mmr_size) {
            return Err(Error::CorruptedProof);
        }
        calculate_root::<_, M, _>(leaves, self.mmr_size, self.proof.iter())
    }

    /// from merkle proof of leaf n to calculate merkle root of n + 1 leaves.
    /// by observe the MMR construction graph we know it is possible.
    /// https://github.com/jjyr/merkle-mountain-range#construct
    /// this is kinda tricky, but it works, and useful
    pub fn calculate_root_with_new_leaf(
        &self,
        mut leaves: Vec<(u64, T)>,
        new_pos: u64,
        new_elem: T,
        new_mmr_size: u64,
    ) -> Result<T> {
        let pos_height = pos_height_in_tree(new_pos);
        let next_height = pos_height_in_tree(new_pos + 1);
        if next_height > pos_height {
            let mut peaks_hashes =
                calculate_peaks_hashes::<_, M, _>(leaves, self.mmr_size, self.proof.iter())?;
            let peaks_pos = get_peaks(new_mmr_size);
            // Rostro hardening (D): the upstream `while peaks_pos[i] < new_pos { i += 1 }`
            // is an unbounded indexer that panics if `new_pos` exceeds every peak position
            // (e.g. attacker-supplied `new_mmr_size == 0`, which makes `peaks_pos` empty,
            // or any `new_pos` past the last peak). Replace with a bounded loop that
            // returns `Err(CorruptedProof)` instead of panicking, and additionally check
            // that `i` does not exceed `peaks_hashes.len()` before the slice-reverse
            // (the two `Vec`s are sized for `new_mmr_size` and `self.mmr_size` respectively
            // so they can desynchronize on adversarial input).
            if peaks_pos.is_empty() {
                return Err(Error::CorruptedProof);
            }
            let mut i = 0;
            while i < peaks_pos.len() && peaks_pos[i] < new_pos {
                i += 1;
            }
            if i >= peaks_pos.len() {
                return Err(Error::CorruptedProof);
            }
            if i > peaks_hashes.len() {
                return Err(Error::CorruptedProof);
            }
            peaks_hashes[i..].reverse();
            calculate_root::<_, M, _>(vec![(new_pos, new_elem)], new_mmr_size, peaks_hashes.iter())
        } else {
            leaves.push((new_pos, new_elem));
            calculate_root::<_, M, _>(leaves, new_mmr_size, self.proof.iter())
        }
    }

    pub fn verify(&self, root: T, leaves: Vec<(u64, T)>) -> Result<bool> {
        // Rostro hardening (B): reject empty leaves explicitly at the verify boundary.
        // Even though `calculate_root` would already reject this via the same check,
        // returning `Ok(false)` here gives callers a clearer "not verified" signal
        // without having to handle the `Err(GenProofForInvalidLeaves)` variant for
        // what is unambiguously a verification failure.
        if leaves.is_empty() {
            return Ok(false);
        }
        self.calculate_root(leaves)
            .map(|calculated_root| calculated_root == root)
    }

    /// Verifies a old root and all incremental leaves.
    ///
    /// If this method returns `true`, it means the following assertion are true:
    /// - The old root could be generated in the history of the current MMR.
    /// - All incremental leaves are on the current MMR.
    /// - The MMR, which could generate the old root, appends all incremental leaves, becomes the
    ///   current MMR.
    pub fn verify_incremental(&self, root: T, prev_root: T, incremental: Vec<T>) -> Result<bool> {
        // Rostro hardening (C): reject non-canonical mmr_size at the verify entry. The
        // upstream silently normalizes via `get_peak_map`; without this check an attacker
        // can drive `prev_leaves_count` close to u64::MAX and trigger arithmetic
        // overflow in `leaf_index_to_mmr_size` / `leaf_index_to_pos` (see audit findings
        // "LOW: mmr_size is not validated to be canonically formed" and
        // "LOW: Integer overflow in leaf_index_to_mmr_size").
        if !is_canonical_mmr_size(self.mmr_size) {
            return Err(Error::CorruptedProof);
        }
        let current_leaves_count = get_peak_map(self.mmr_size);
        if current_leaves_count <= incremental.len() as u64 {
            return Err(Error::CorruptedProof);
        }
        // Test if previous root is correct.
        let prev_leaves_count = current_leaves_count - incremental.len() as u64;
        let prev_peaks_positions = {
            let prev_index = prev_leaves_count - 1;
            let prev_mmr_size = leaf_index_to_mmr_size(prev_index);
            let prev_peaks_positions = get_peaks(prev_mmr_size);
            if prev_peaks_positions.len() != self.proof.len() {
                return Err(Error::CorruptedProof);
            }
            prev_peaks_positions
        };
        let current_peaks_positions = get_peaks(self.mmr_size);

        // Rostro hardening: bounds-check the indexer inside the loop. The audit MEDIUM
        // finding "verify_incremental is structurally correct only because of two
        // un-asserted invariants" identifies an OOB panic vector at the unchecked
        // `current_peaks_positions[i]` when (for non-canonical mmr_size) prev has more
        // peaks than current AND the break never fires. With hardening C above
        // forbidding non-canonical mmr_size, a canonical pair (prev, current) with
        // prev_peaks_positions.len() > current_peaks_positions.len() can occur (e.g.
        // prev = mmr_size 4 with 2 peaks, current = mmr_size 7 with 1 peak), but the
        // break at `position < current_peaks_positions[i]` always fires for valid data
        // before `i` walks off `current_peaks_positions`. We add an explicit guard
        // inside the loop so an unforeseen edge case yields `CorruptedProof` rather
        // than a panic.
        if current_peaks_positions.is_empty() {
            return Err(Error::CorruptedProof);
        }
        let mut reverse_index = prev_peaks_positions.len() - 1;
        for (i, position) in prev_peaks_positions.iter().enumerate() {
            if i >= current_peaks_positions.len() {
                // No early-break fired despite prev being longer than current —
                // structurally impossible for canonical (prev_mmr_size, mmr_size)
                // pairs where prev was an actual ancestor of current.
                return Err(Error::CorruptedProof);
            }
            if *position < current_peaks_positions[i] {
                reverse_index = i;
                break;
            }
        }
        let mut prev_peaks: Vec<_> = self.proof_items().to_vec();
        let mut reverse_peaks = prev_peaks.split_off(reverse_index);
        reverse_peaks.reverse();
        prev_peaks.extend(reverse_peaks);

        let calculated_prev_root = bagging_peaks_hashes::<T, M>(prev_peaks)?;
        if calculated_prev_root != prev_root {
            return Ok(false);
        }

        // Test if incremental leaves are correct.
        let leaves = incremental
            .into_iter()
            .enumerate()
            .map(|(index, leaf)| {
                let pos = leaf_index_to_pos(prev_leaves_count + index as u64);
                (pos, leaf)
            })
            .collect();
        self.verify(root, leaves)
    }
}

fn calculate_peak_root<'a, T: 'a, M: Merge<Item = T>, I: Iterator<Item = &'a T>>(
    leaves: Vec<(u64, T)>,
    peak_pos: u64,
    proof_iter: &mut I,
) -> Result<T> {
    debug_assert!(!leaves.is_empty(), "can't be empty");
    // (position, hash, height)

    let mut queue: VecDeque<_> = leaves
        .into_iter()
        .map(|(pos, item)| (pos, item, 0))
        .collect();

    // calculate tree root from each items
    while let Some((pos, item, height)) = queue.pop_front() {
        if pos == peak_pos {
            if queue.is_empty() {
                // return root once queue is consumed
                return Ok(item);
            } else {
                return Err(Error::CorruptedProof);
            }
        }
        // calculate sibling
        let next_height = pos_height_in_tree(pos + 1);
        let (parent_pos, parent_item) = {
            let sibling_offset = sibling_offset(height);
            if next_height > height {
                // implies pos is right sibling
                let sib_pos = pos - sibling_offset;
                let parent_pos = pos + 1;
                let parent_item = if Some(&sib_pos) == queue.front().map(|(pos, _, _)| pos) {
                    let sibling_item = queue.pop_front().map(|(_, item, _)| item).unwrap();
                    M::merge(&sibling_item, &item)?
                } else {
                    let sibling_item = proof_iter.next().ok_or(Error::CorruptedProof)?;
                    M::merge(sibling_item, &item)?
                };
                (parent_pos, parent_item)
            } else {
                // pos is left sibling
                let sib_pos = pos + sibling_offset;
                let parent_pos = pos + parent_offset(height);
                let parent_item = if Some(&sib_pos) == queue.front().map(|(pos, _, _)| pos) {
                    let sibling_item = queue.pop_front().map(|(_, item, _)| item).unwrap();
                    M::merge(&item, &sibling_item)?
                } else {
                    let sibling_item = proof_iter.next().ok_or(Error::CorruptedProof)?;
                    M::merge(&item, sibling_item)?
                };
                (parent_pos, parent_item)
            }
        };

        if parent_pos <= peak_pos {
            queue.push_back((parent_pos, parent_item, height + 1))
        } else {
            return Err(Error::CorruptedProof);
        }
    }
    Err(Error::CorruptedProof)
}

fn calculate_peaks_hashes<
    'a,
    T: 'a + Clone + PartialEq,
    M: Merge<Item = T>,
    I: Iterator<Item = &'a T>,
>(
    mut leaves: Vec<(u64, T)>,
    mmr_size: u64,
    mut proof_iter: I,
) -> Result<Vec<T>> {
    if leaves.iter().any(|(pos, _)| pos_height_in_tree(*pos) > 0) {
        return Err(Error::GenProofForInvalidLeaves);
    }

    // special handle the only 1 leaf MMR
    if mmr_size == 1 && leaves.len() == 1 && leaves[0].0 == 0 {
        return Ok(leaves.into_iter().map(|(_pos, item)| item).collect());
    }
    // ensure leaves are sorted; we no longer silently dedup (see Rostro hardening F below).
    leaves.sort_by_key(|(pos, _)| *pos);
    // Rostro hardening (F): the upstream `dedup_by(|a, b| a.0 == b.0)` silently drops
    // any leaf at a duplicate position regardless of whether its hash agrees with the
    // earlier entry. A caller that batches `[(7, h_real), (7, h_attacker)]` and trusts
    // "verify returned true ⇒ every input was authenticated" would be misled. Reject
    // duplicate positions outright; collapsing duplicate (pos, hash) pairs that agree
    // is permitted but a hash mismatch at the same position is malformed input.
    {
        let mut i = 1;
        while i < leaves.len() {
            if leaves[i - 1].0 == leaves[i].0 {
                if leaves[i - 1].1 != leaves[i].1 {
                    return Err(Error::GenProofForInvalidLeaves);
                }
                leaves.remove(i);
            } else {
                i += 1;
            }
        }
    }
    // Rostro hardening (A): record the original count to enable a redundant
    // "all leaves were consumed" check after the for-loop. Today the upstream's only
    // safety net against the Hyperbridge bug class is the single `!leaves.is_empty()`
    // line below; we add a second, independent check based on counting consumed leaves
    // so that if either check accidentally regresses (e.g. some future refactor adds a
    // skip-leaf branch in `take_while_vec`), the other still trips.
    let original_leaves_count = leaves.len();
    let mut consumed_leaves: usize = 0;
    let peaks = get_peaks(mmr_size);

    let mut peaks_hashes: Vec<T> = Vec::with_capacity(peaks.len() + 1);
    let mut bagged_break = false;
    for peak_pos in peaks {
        let mut leaves_for_peak: Vec<_> = take_while_vec(&mut leaves, |(pos, _)| *pos <= peak_pos);
        let leaves_for_peak_len = leaves_for_peak.len();
        let peak_root = if leaves_for_peak.len() == 1 && leaves_for_peak[0].0 == peak_pos {
            // leaf is the peak
            leaves_for_peak.remove(0).1
        } else if leaves_for_peak.is_empty() {
            // if empty, means the next proof is a peak root or rhs bagged root
            if let Some(peak_root) = proof_iter.next() {
                peak_root.clone()
            } else {
                // Rostro hardening (E): the upstream `break`s here on the assumption
                // that subsequent peaks are bagged in the trailing rhs-bag proof item.
                // That fallthrough-accept pattern is the structural shape of the
                // Hyperbridge Solidity bug. We instead remember that the loop was cut
                // short and validate post-loop that ALL remaining leaves were already
                // drained (so silent truncation cannot smuggle extra leaves through).
                bagged_break = true;
                break;
            }
        } else {
            calculate_peak_root::<_, M, _>(leaves_for_peak, peak_pos, &mut proof_iter)?
        };
        consumed_leaves += leaves_for_peak_len;
        peaks_hashes.push(peak_root.clone());
    }

    // Rostro hardening (A) / (E): if we broke out of the loop early, the proof tape ran
    // dry. That is only acceptable if there are NO further leaves to account for; any
    // remaining leaf would otherwise have to be matched against a peak we never visited.
    if bagged_break {
        if !leaves.is_empty() {
            return Err(Error::CorruptedProof);
        }
        // also: a `break` with the proof tape exhausted leaves no rhs-bag item to pull,
        // so subsequent peaks have no contribution to peaks_hashes — which is fine
        // because there's nothing left to consume.
    }

    // upstream check: ensure nothing left in leaves (Hyperbridge-attack safety net).
    if !leaves.is_empty() {
        return Err(Error::CorruptedProof);
    }

    // Rostro hardening (A): redundant count-based check. Bypassing the Hyperbridge
    // attack now requires fooling BOTH the line-680 emptiness check above AND this
    // count check. If either ever silently regresses, the other still rejects.
    if consumed_leaves != original_leaves_count {
        return Err(Error::CorruptedProof);
    }

    // check rhs peaks
    if let Some(rhs_peaks_hashes) = proof_iter.next() {
        peaks_hashes.push(rhs_peaks_hashes.clone());
    }
    // ensure nothing left in proof_iter
    if proof_iter.next().is_some() {
        return Err(Error::CorruptedProof);
    }
    Ok(peaks_hashes)
}

pub fn bagging_peaks_hashes<T, M: Merge<Item = T>>(mut peaks_hashes: Vec<T>) -> Result<T> {
    // bagging peaks
    // bagging from right to left via hash(right, left).
    while peaks_hashes.len() > 1 {
        let right_peak = peaks_hashes.pop().expect("pop");
        let left_peak = peaks_hashes.pop().expect("pop");
        peaks_hashes.push(M::merge_peaks(&right_peak, &left_peak)?);
    }
    peaks_hashes.pop().ok_or(Error::CorruptedProof)
}

/// merkle proof
/// 1. sort items by position
/// 2. calculate root of each peak
/// 3. bagging peaks
fn calculate_root<'a, T: 'a + Clone + PartialEq, M: Merge<Item = T>, I: Iterator<Item = &'a T>>(
    leaves: Vec<(u64, T)>,
    mmr_size: u64,
    proof_iter: I,
) -> Result<T> {
    let peaks_hashes = calculate_peaks_hashes::<_, M, _>(leaves, mmr_size, proof_iter)?;
    bagging_peaks_hashes::<_, M>(peaks_hashes)
}

pub(crate) fn take_while_vec<T, P: Fn(&T) -> bool>(v: &mut Vec<T>, p: P) -> Vec<T> {
    for i in 0..v.len() {
        if !p(&v[i]) {
            return v.drain(..i).collect();
        }
    }
    v.drain(..).collect()
}
