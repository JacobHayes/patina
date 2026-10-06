//! The index of a file's written blocks: a two-level index whose leaves
//! cover 512 blocks (2 MiB of file) each.
//!
//! The leaves sit in a `BTreeMap` by leaf number, so adding one far into a
//! hole costs a logarithmic insert and a small file is one leaf. A leaf whose
//! blocks are mostly adjacent holds a run of slots from its first block to
//! its last (a direct index); one whose blocks are spread out holds them as
//! ordered (slot, block) pairs, so a block costs at most a few dozen bytes
//! of index at any density. Leaves are shared (`Arc`) between clones and
//! copied on the first change after one, so a checkpoint's clone costs one
//! reference per leaf, not one per block. Iteration is in ascending block
//! order, which the crash merge and the snapshot depend on.
//!
//! Every change goes through [`Blocks::update`] or [`Blocks::remove_range`],
//! which keep the block count and each leaf's shape: no leaf is empty, a
//! run of slots starts and ends with a block and is at most four times as
//! long as its block count, and pairs hold only blocks.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::Block;

/// Blocks per leaf, as a shift.
const SHIFT: u32 = 9;
const MASK: u64 = (1 << SHIFT) - 1;

/// A leaf's blocks, by slot within the leaf.
#[derive(Clone, Debug)]
enum Slots {
    /// Slots `first..first + slots.len()`: a direct index for adjacent
    /// blocks.
    Run {
        first: usize,
        slots: Vec<Option<Block>>,
    },
    /// Ordered (slot, block) pairs for spread-out blocks; a pair holds `None`
    /// only while a change is being made to it.
    Pairs(Vec<(u16, Option<Block>)>),
    /// One block, held inline (a small file's, or a lone one far out); `None`
    /// only while it is being made.
    One { slot: usize, block: Option<Block> },
}

#[derive(Clone, Debug)]
struct Leaf {
    slots: Slots,
    /// The present blocks.
    present: usize,
}

impl Default for Leaf {
    fn default() -> Self {
        Self {
            slots: Slots::Pairs(Vec::new()),
            present: 0,
        }
    }
}

impl Leaf {
    fn get(&self, slot: usize) -> Option<&Block> {
        match &self.slots {
            Slots::Run { first, slots } => slots.get(slot.checked_sub(*first)?)?.as_ref(),
            Slots::Pairs(pairs) => {
                let at = pairs
                    .binary_search_by_key(&(slot as u16), |(s, _)| *s)
                    .ok()?;
                pairs[at].1.as_ref()
            }
            Slots::One { slot: at, block } => block.as_ref().filter(|_| *at == slot),
        }
    }

    /// The slots a run would span with `slot` added.
    fn span_with(&self, slot: usize) -> usize {
        match &self.slots {
            Slots::Run { slots, .. } if slots.is_empty() => 1,
            Slots::Run { first, slots } => (first + slots.len()).max(slot + 1) - (*first).min(slot),
            Slots::Pairs(pairs) => match (pairs.first(), pairs.last()) {
                (Some((low, _)), Some((high, _))) => {
                    (*high as usize).max(slot) + 1 - (*low as usize).min(slot)
                }
                _ => 1,
            },
            Slots::One { slot: at, .. } => (*at).max(slot) + 1 - (*at).min(slot),
        }
    }

    /// Hold the blocks as a run when a run of them would be at most twice as
    /// long as their count, and as pairs when it grows past four times.
    /// `span` counts `adding`, a slot about to be filled, when there is one:
    /// a run made for it starts at the lower of it and the first block.
    fn reshape(&mut self, span: usize, adding: Option<usize>) {
        match &mut self.slots {
            Slots::Pairs(pairs) if self.present >= 2 && span <= 2 * self.present => {
                let first =
                    adding.map_or(pairs[0].0 as usize, |slot| slot.min(pairs[0].0 as usize));
                let mut slots = Vec::with_capacity(span);
                slots.resize(span, None);
                for (slot, block) in pairs.drain(..) {
                    slots[slot as usize - first] = block;
                }
                self.slots = Slots::Run { first, slots };
            }
            Slots::Run { first, slots } if span > 4 * self.present.max(1) => {
                let first = *first;
                let pairs = slots
                    .drain(..)
                    .enumerate()
                    .filter_map(|(i, block)| block.map(|block| ((first + i) as u16, Some(block))))
                    .collect();
                self.slots = Slots::Pairs(pairs);
            }
            _ => {}
        }
    }

    /// The slot `slot` (`None` for a hole), made room for.
    fn entry(&mut self, slot: usize) -> &mut Option<Block> {
        if self.get(slot).is_none() {
            if self.present == 0 {
                self.slots = Slots::One { slot, block: None };
            } else if let Slots::One { slot: at, block } = &mut self.slots {
                let mut pairs = Vec::with_capacity(2);
                pairs.push((*at as u16, block.take()));
                self.slots = Slots::Pairs(pairs);
            }
            let span = self.span_with(slot);
            self.reshape(span, Some(slot));
        }
        match &mut self.slots {
            Slots::Run { first, slots } => {
                if slots.is_empty() {
                    *first = slot;
                } else if slot < *first {
                    grow(slots, *first - slot);
                    slots.splice(0..0, std::iter::repeat_n(None, *first - slot));
                    *first = slot;
                }
                let at = slot - *first;
                if slots.len() <= at {
                    grow(slots, at + 1 - slots.len());
                    slots.resize(at + 1, None);
                }
                &mut slots[at]
            }
            Slots::Pairs(pairs) => {
                let at = match pairs.binary_search_by_key(&(slot as u16), |(s, _)| *s) {
                    Ok(at) => at,
                    Err(at) => {
                        if pairs.is_empty() {
                            // A lone block costs one pair, not a vector's
                            // first growth step of four.
                            pairs.reserve_exact(1);
                        }
                        pairs.insert(at, (slot as u16, None));
                        at
                    }
                };
                &mut pairs[at].1
            }
            Slots::One { block, .. } => block,
        }
    }

    /// Drop what emptied, after a change: empty slots at a run's ends, empty
    /// pairs; and reshape.
    fn settle(&mut self) {
        match &mut self.slots {
            Slots::Run { first, slots } => {
                while slots.last().is_some_and(Option::is_none) {
                    slots.pop();
                }
                let lead = slots.iter().take_while(|slot| slot.is_none()).count();
                if lead != 0 {
                    slots.drain(..lead);
                    *first += lead;
                }
                if slots.capacity() > 2 * slots.len() {
                    slots.shrink_to_fit();
                }
                let span = slots.len();
                self.reshape(span, None);
            }
            Slots::Pairs(pairs) => {
                pairs.retain(|(_, block)| block.is_some());
                if pairs.capacity() > 2 * pairs.len() {
                    pairs.shrink_to_fit();
                }
                if let [(slot, block)] = pairs.as_mut_slice() {
                    self.slots = Slots::One {
                        slot: *slot as usize,
                        block: block.take(),
                    };
                }
            }
            Slots::One { .. } => {}
        }
    }

    /// Take the blocks in slots `low..high`: how many, and the last one.
    fn take_range(&mut self, low: usize, high: usize) -> (usize, Option<Block>) {
        let mut taken = 0;
        let mut last = None;
        let mut take = |block: &mut Option<Block>| {
            if let Some(block) = block.take() {
                taken += 1;
                last = Some(block);
            }
        };
        match &mut self.slots {
            Slots::Run { first, slots } => {
                let from = low.saturating_sub(*first).min(slots.len());
                let to = high.saturating_sub(*first).min(slots.len());
                slots[from..to].iter_mut().for_each(&mut take);
            }
            Slots::Pairs(pairs) => {
                let from = pairs.partition_point(|(s, _)| (*s as usize) < low);
                let to = pairs.partition_point(|(s, _)| (*s as usize) < high);
                pairs[from..to]
                    .iter_mut()
                    .for_each(|(_, block)| take(block));
            }
            Slots::One { slot, block } if (low..high).contains(slot) => take(block),
            Slots::One { .. } => {}
        }
        self.present -= taken;
        self.settle();
        (taken, last)
    }

    /// Whether any block sits in slots `low..high`.
    fn any_in(&self, low: usize, high: usize) -> bool {
        match &self.slots {
            Slots::Run { first, slots } => {
                let from = low.saturating_sub(*first).min(slots.len());
                let to = high.saturating_sub(*first).min(slots.len());
                slots[from..to].iter().any(Option::is_some)
            }
            Slots::Pairs(pairs) => {
                let from = pairs.partition_point(|(s, _)| (*s as usize) < low);
                pairs.get(from).is_some_and(|(s, _)| (*s as usize) < high)
            }
            Slots::One { slot, block } => block.is_some() && (low..high).contains(slot),
        }
    }

    /// The blocks, in order, with their block index from `base`.
    fn blocks(&self, base: u64) -> LeafBlocks<'_> {
        LeafBlocks {
            leaf: self,
            base,
            at: 0,
        }
    }

    fn last(&self) -> Option<&Block> {
        match &self.slots {
            Slots::Run { slots, .. } => slots.iter().rev().flatten().next(),
            Slots::Pairs(pairs) => pairs.iter().rev().find_map(|(_, block)| block.as_ref()),
            Slots::One { block, .. } => block.as_ref(),
        }
    }
}

/// Make room for `more` slots in a run: double as a vector does, but never
/// past a leaf's 512.
fn grow(slots: &mut Vec<Option<Block>>, more: usize) {
    let wanted = slots.len() + more;
    if wanted > slots.capacity() {
        let target = (slots.capacity() * 2).clamp(wanted, (MASK + 1) as usize);
        slots.reserve_exact(target - slots.len());
    }
}

struct LeafBlocks<'a> {
    leaf: &'a Leaf,
    base: u64,
    at: usize,
}

impl<'a> Iterator for LeafBlocks<'a> {
    type Item = (u64, &'a Block);

    fn next(&mut self) -> Option<Self::Item> {
        match &self.leaf.slots {
            Slots::Run { first, slots } => {
                while let Some(slot) = slots.get(self.at) {
                    self.at += 1;
                    if let Some(block) = slot {
                        return Some((self.base + (first + self.at - 1) as u64, block));
                    }
                }
                None
            }
            Slots::Pairs(pairs) => {
                while let Some((slot, block)) = pairs.get(self.at) {
                    self.at += 1;
                    if let Some(block) = block {
                        return Some((self.base + *slot as u64, block));
                    }
                }
                None
            }
            Slots::One { slot, block } => {
                let first = self.at == 0;
                self.at = 1;
                block
                    .as_ref()
                    .filter(|_| first)
                    .map(|block| (self.base + *slot as u64, block))
            }
        }
    }
}

/// A leaf as its holder keeps it: the head leaf owned, the others shared.
trait Holder {
    fn leaf(&self) -> &Leaf;
    /// The leaf to change, copied first when a clone still shares it.
    fn leaf_mut(&mut self) -> &mut Leaf;
}

impl Holder for Leaf {
    fn leaf(&self) -> &Leaf {
        self
    }

    fn leaf_mut(&mut self) -> &mut Leaf {
        self
    }
}

impl Holder for Arc<Leaf> {
    fn leaf(&self) -> &Leaf {
        self
    }

    fn leaf_mut(&mut self) -> &mut Leaf {
        Arc::make_mut(self)
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct Blocks {
    /// Leaf 0, the file's first 2 MiB, owned outside the map: a small file
    /// allocates no map node and no shared leaf, and its lookups skip the
    /// search. A clone copies it (at most 512 references).
    head: Option<Leaf>,
    /// The other leaves, by leaf number, shared between clones.
    leaves: BTreeMap<u64, Arc<Leaf>>,
    /// The present blocks.
    count: u64,
}

impl Blocks {
    pub(super) fn len(&self) -> u64 {
        self.count
    }

    fn leaf(&self, number: u64) -> Option<&Leaf> {
        if number == 0 {
            self.head.as_ref()
        } else {
            self.leaves.get(&number).map(|leaf| &**leaf)
        }
    }

    fn drop_leaf(&mut self, number: u64) {
        if number == 0 {
            self.head = None;
        } else {
            self.leaves.remove(&number);
        }
    }

    /// The leaves from leaf `start` on, in ascending order.
    fn leaves_from(&self, start: u64) -> impl Iterator<Item = (u64, &Leaf)> {
        let head = if start == 0 { self.head.as_ref() } else { None };
        head.map(|leaf| (0, leaf)).into_iter().chain(
            self.leaves
                .range(start.max(1)..)
                .map(|(number, leaf)| (*number, &**leaf)),
        )
    }

    pub(super) fn get(&self, index: u64) -> Option<&Block> {
        self.leaf(index >> SHIFT)?.get((index & MASK) as usize)
    }

    pub(super) fn contains(&self, index: u64) -> bool {
        self.get(index).is_some()
    }

    /// Change block `index` through `change`, which sees its slot (`None`
    /// for a hole) and may fill, replace or empty it; the count and the
    /// leaf's shape follow.
    pub(super) fn update<R>(
        &mut self,
        index: u64,
        change: impl FnOnce(&mut Option<Block>) -> R,
    ) -> R {
        let number = index >> SHIFT;
        let leaf = if number == 0 {
            self.head.get_or_insert_with(Leaf::default)
        } else {
            Arc::make_mut(self.leaves.entry(number).or_default())
        };
        let slot = leaf.entry((index & MASK) as usize);
        let was = slot.is_some();
        let answer = change(slot);
        let is = slot.is_some();
        match (was, is) {
            (false, true) => {
                leaf.present += 1;
                self.count += 1;
            }
            (true, false) => {
                leaf.present -= 1;
                self.count -= 1;
            }
            _ => {}
        }
        if !is {
            leaf.settle();
            if leaf.present == 0 {
                self.drop_leaf(number);
            }
        }
        answer
    }

    /// Block `index` to change in place, when it is written.
    pub(super) fn get_mut(&mut self, index: u64) -> Option<&mut Block> {
        let (number, slot) = (index >> SHIFT, (index & MASK) as usize);
        self.leaf(number)?.get(slot)?;
        let leaf = if number == 0 {
            self.head.as_mut()?
        } else {
            Arc::make_mut(self.leaves.get_mut(&number)?)
        };
        leaf.entry(slot).as_mut()
    }

    pub(super) fn insert(&mut self, index: u64, block: Block) -> Option<Block> {
        self.update(index, |slot| slot.replace(block))
    }

    pub(super) fn remove(&mut self, index: u64) -> Option<Block> {
        if !self.contains(index) {
            return None;
        }
        self.update(index, Option::take)
    }

    /// Remove the blocks in `first..end` (none when the range is empty or
    /// reversed); answers the last one removed.
    pub(super) fn remove_range(&mut self, first: u64, end: u64) -> Option<Block> {
        if first >= end {
            return None;
        }
        let mut removed = None;
        let mut emptied = Vec::new();
        let (low_leaf, high_leaf) = (first >> SHIFT, (end - 1) >> SHIFT);
        let mut clear = |number: u64, holder: &mut dyn Holder| {
            let base = number << SHIFT;
            let low = first.saturating_sub(base) as usize;
            let high = (end - base).min(MASK + 1) as usize;
            let leaf = holder.leaf();
            if low == 0 && high == (MASK + 1) as usize {
                // The whole leaf goes: no copy of a shared one.
                self.count -= leaf.present as u64;
                removed = leaf.last().cloned().or(removed.take());
                emptied.push(number);
                return;
            }
            if !leaf.any_in(low, high) {
                return;
            }
            let leaf = holder.leaf_mut();
            let (taken, last) = leaf.take_range(low, high);
            self.count -= taken as u64;
            removed = last.or(removed.take());
            if leaf.present == 0 {
                emptied.push(number);
            }
        };
        if low_leaf == 0
            && let Some(head) = self.head.as_mut()
        {
            clear(0, head);
        }
        if high_leaf >= 1 {
            for (number, leaf) in self.leaves.range_mut(low_leaf.max(1)..=high_leaf) {
                clear(*number, leaf);
            }
        }
        for number in emptied {
            self.drop_leaf(number);
        }
        removed
    }

    /// Every block, in ascending order.
    pub(super) fn iter(&self) -> impl Iterator<Item = (u64, &Block)> {
        self.leaves_from(0)
            .flat_map(|(number, leaf)| leaf.blocks(number << SHIFT))
    }

    /// The blocks in `first..end`, in ascending order.
    pub(super) fn range(&self, first: u64, end: u64) -> impl Iterator<Item = (u64, &Block)> {
        self.leaves_from(first >> SHIFT)
            .take_while(move |(number, _)| *number << SHIFT < end)
            .flat_map(|(number, leaf)| leaf.blocks(number << SHIFT))
            .skip_while(move |(index, _)| *index < first)
            .take_while(move |(index, _)| *index < end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    /// The shape invariant: no leaf empty, each counting its blocks, a run
    /// starting and ending with a block, at most four times its count and
    /// holding at most twice its length, pairs holding only blocks.
    fn assert_shape(blocks: &Blocks, context: &str) {
        for (number, leaf) in blocks.leaves_from(0) {
            assert!(leaf.present > 0, "{context}: leaf {number} empty");
            match &leaf.slots {
                Slots::Run { slots, .. } => {
                    assert!(
                        slots.first().is_some_and(Option::is_some)
                            && slots.last().is_some_and(Option::is_some),
                        "{context}: leaf {number}'s run has an empty end"
                    );
                    assert!(slots.len() <= 4 * leaf.present, "{context}: leaf {number}");
                    assert!(
                        slots.capacity() <= 2 * slots.len(),
                        "{context}: leaf {number} holds {} slots for {}",
                        slots.capacity(),
                        slots.len()
                    );
                    assert_eq!(leaf.present, slots.iter().flatten().count(), "{context}");
                }
                Slots::Pairs(pairs) => {
                    assert!(pairs.iter().all(|(_, block)| block.is_some()), "{context}");
                    assert_eq!(leaf.present, pairs.len(), "{context}");
                }
                Slots::One { block, .. } => {
                    assert!(block.is_some(), "{context}");
                    assert_eq!(leaf.present, 1, "{context}");
                }
            }
        }
    }

    /// The index answers as an ordered map does, and keeps its shape after
    /// every step, over a seeded mix of inserts, removals and range removals
    /// across leaves, near and far.
    #[test]
    fn the_index_answers_as_an_ordered_map() {
        let mut blocks = Blocks::default();
        let mut model: BTreeMap<u64, Block> = BTreeMap::new();
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        // Indices cluster in a few leaves near 0, sparsely in the middle of
        // them, in a narrow band of one leaf (so its blocks keep turning
        // from pairs into a run and back), and in one far out.
        let pick = |r: u64| match r % 5 {
            0 => r % 200,
            1 => (1 << 40) + r % 70,
            2 => 5 * (MASK + 1) + 100 + r % 12,
            _ => r % 3 * (MASK + 1) + r % (MASK + 1),
        };
        for step in 0..8000u64 {
            let r = next();
            let index = pick(r >> 8);
            match r % 5 {
                0 | 1 => {
                    let block: Block = Arc::from(&step.to_le_bytes()[..]);
                    assert_eq!(
                        blocks.insert(index, block.clone()).is_some(),
                        model.insert(index, block).is_some()
                    );
                }
                2 => {
                    assert_eq!(
                        blocks.remove(index).is_some(),
                        model.remove(&index).is_some()
                    );
                }
                3 => {
                    let end = index + (r >> 40) % 150;
                    blocks.remove_range(index, end);
                    model.retain(|i, _| *i < index || *i >= end);
                }
                _ => {
                    let end = index + (r >> 40) % 300;
                    let got: Vec<u64> = blocks.range(index, end).map(|(i, _)| i).collect();
                    let want: Vec<u64> = model.range(index..end).map(|(i, _)| *i).collect();
                    assert_eq!(got, want, "range {index}..{end}");
                }
            }
            assert_eq!(blocks.len(), model.len() as u64);
            assert_eq!(
                blocks.get(index).map(|b| b.to_vec()),
                model.get(&index).map(|b| b.to_vec())
            );
            assert_shape(&blocks, &format!("step {step}"));
        }
        let got: Vec<(u64, Vec<u8>)> = blocks.iter().map(|(i, b)| (i, b.to_vec())).collect();
        let want: Vec<(u64, Vec<u8>)> = model.iter().map(|(i, b)| (*i, b.to_vec())).collect();
        assert_eq!(got, want);
        // A clone shares every leaf past the head until one of them changes.
        let copy = blocks.clone();
        assert!(
            copy.leaves
                .values()
                .zip(blocks.leaves.values())
                .all(|(a, b)| Arc::ptr_eq(a, b))
        );
    }

    #[test]
    fn a_run_made_for_a_slot_below_the_first_block_starts_at_it() {
        // Blocks 10 and 11, then 9: the pairs become a run from 9, three
        // slots long, with no empty slot at either end.
        let mut blocks = Blocks::default();
        for index in [10, 11, 9] {
            blocks.insert(index, Arc::from(&[1u8][..]));
            assert_shape(&blocks, &format!("after {index}"));
        }
        let leaf = blocks.head.as_ref().unwrap();
        assert!(matches!(&leaf.slots, Slots::Run { first: 9, slots } if slots.len() == 3));
    }
}
