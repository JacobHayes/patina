//! Per-range state of the address space, kept the way the kernel keeps
//! per-VMA state: non-overlapping `[start, end)` ranges, each with a value,
//! clipped when part of a range is unmapped or re-set and moved when it is
//! remapped.

use std::collections::BTreeMap;

pub(super) struct Ranges<T: Copy> {
    map: BTreeMap<usize, (usize, T)>,
}

impl<T: Copy> Ranges<T> {
    pub(super) const fn new() -> Self {
        Ranges {
            map: BTreeMap::new(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub(super) fn clear(&mut self) {
        self.map.clear();
    }

    /// Remove `[from, to)`, answering the pieces it covered; the parts of a
    /// range outside it stay.
    pub(super) fn cut(&mut self, from: usize, to: usize) -> Vec<(usize, usize, T)> {
        let overlapping: Vec<usize> = self
            .map
            .range(..to)
            .filter(|(_, (end, _))| *end > from)
            .map(|(start, _)| *start)
            .collect();
        let mut pieces = Vec::new();
        for start in overlapping {
            let (end, value) = self.map.remove(&start).expect("listed above");
            for (kept_start, kept_end) in [(start, from.min(end)), (to.max(start), end)] {
                if kept_start < kept_end {
                    self.map.insert(kept_start, (kept_end, value));
                }
            }
            pieces.push((start.max(from), end.min(to), value));
        }
        pieces
    }

    /// `[from, to)` has `value` now.
    pub(super) fn set(&mut self, from: usize, to: usize, value: T) {
        self.cut(from, to);
        if from < to {
            self.map.insert(from, (to, value));
        }
    }

    /// The range containing `addr`, whole.
    pub(super) fn containing(&self, addr: usize) -> Option<(usize, usize, T)> {
        self.map
            .range(..=addr)
            .next_back()
            .filter(|(_, (end, _))| addr < *end)
            .map(|(start, (end, value))| (*start, *end, *value))
    }

    /// The value at `addr`.
    pub(super) fn at(&self, addr: usize) -> Option<T> {
        self.containing(addr).map(|(_, _, value)| value)
    }

    /// The ranges within `[from, to)`, clipped to it.
    pub(super) fn within(&self, from: usize, to: usize) -> Vec<(usize, usize, T)> {
        self.map
            .range(..to)
            .filter(|(_, (end, _))| *end > from)
            .map(|(start, (end, value))| ((*start).max(from), (*end).min(to), *value))
            .collect()
    }

    /// Every range.
    pub(super) fn all(&self) -> impl Iterator<Item = (usize, usize, T)> + '_ {
        self.map
            .iter()
            .map(|(start, (end, value))| (*start, *end, *value))
    }

    /// The bytes the ranges cover within `[from, to)`.
    pub(super) fn covered(&self, from: usize, to: usize) -> usize {
        self.within(from, to)
            .iter()
            .map(|(start, end, _)| end - start)
            .sum()
    }

    /// The bytes every range covers.
    pub(super) fn total(&self) -> usize {
        self.map.iter().map(|(start, (end, _))| end - start).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::Ranges;

    #[test]
    fn cutting_splits_a_range_and_answers_the_middle() {
        let mut ranges = Ranges::new();
        ranges.set(0x1000, 0x5000, 'a');
        assert_eq!(ranges.cut(0x2000, 0x3000), vec![(0x2000, 0x3000, 'a')]);
        assert_eq!(
            ranges.all().collect::<Vec<_>>(),
            vec![(0x1000, 0x2000, 'a'), (0x3000, 0x5000, 'a')]
        );
        assert_eq!(ranges.at(0x2800), None);
        assert_eq!(ranges.at(0x4fff), Some('a'));
        assert_eq!(ranges.at(0x5000), None);
        assert_eq!(ranges.containing(0x4000), Some((0x3000, 0x5000, 'a')));
        assert_eq!(ranges.total(), 0x3000);
    }

    #[test]
    fn setting_over_ranges_replaces_what_it_covers() {
        let mut ranges = Ranges::new();
        ranges.set(0x1000, 0x3000, 'a');
        ranges.set(0x4000, 0x6000, 'b');
        ranges.set(0x2000, 0x5000, 'c');
        assert_eq!(
            ranges.all().collect::<Vec<_>>(),
            vec![
                (0x1000, 0x2000, 'a'),
                (0x2000, 0x5000, 'c'),
                (0x5000, 0x6000, 'b')
            ]
        );
        assert_eq!(
            ranges.within(0x1800, 0x2800),
            vec![(0x1800, 0x2000, 'a'), (0x2000, 0x2800, 'c')]
        );
        assert_eq!(ranges.covered(0x0, 0x1800), 0x800);
        ranges.clear();
        assert!(ranges.is_empty());
    }
}
