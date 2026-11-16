//! File contents as a sparse, copy-on-write byte image.
//!
//! Blocks of 4096 bytes are shared through `Rc`, grouped in segments of 256 blocks (1 MiB)
//! that are shared too. An absent block or segment reads as zeros. Cloning costs one pointer
//! per segment; changing a byte copies at most one segment's pointer array and one block.
//! So the crash models can keep several images of a file (page cache, running transaction,
//! disk) and snapshots of all of them at a cost proportional to what changed, and a 64 MiB
//! file made by `set_len` costs nothing until it is written.
//!
//! Invariant: bytes of a present block at or beyond `len` are zero, so growing the image
//! exposes zeros, as `Vec::resize` did.

use std::collections::BTreeMap;
use std::rc::Rc;

pub const BLOCK: u64 = 4096;
const SEG: u64 = 256;
type Block = [u8; BLOCK as usize];
type Seg = [Option<Rc<Block>>; SEG as usize];

#[derive(Clone, Default)]
pub struct Content {
    len: u64,
    segs: BTreeMap<u64, Rc<Seg>>,
}

const ZERO: Block = [0; BLOCK as usize];

fn empty_seg() -> Rc<Seg> {
    Rc::new(std::array::from_fn(|_| None))
}

impl Content {
    pub fn new() -> Content {
        Content::default()
    }

    pub fn from_slice(b: &[u8]) -> Content {
        let mut c = Content::new();
        c.write(0, b);
        c
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Block `b` if present (it may still hold zeros).
    pub fn block(&self, b: u64) -> Option<&Block> {
        self.segs
            .get(&(b / SEG))
            .and_then(|s| s[(b % SEG) as usize].as_deref())
    }

    fn block_rc(&self, b: u64) -> Option<&Rc<Block>> {
        self.segs
            .get(&(b / SEG))
            .and_then(|s| s[(b % SEG) as usize].as_ref())
    }

    fn slot(&mut self, b: u64) -> &mut Option<Rc<Block>> {
        let s = self.segs.entry(b / SEG).or_insert_with(empty_seg);
        &mut Rc::make_mut(s)[(b % SEG) as usize]
    }

    fn block_mut(&mut self, b: u64) -> &mut Block {
        Rc::make_mut(self.slot(b).get_or_insert_with(|| Rc::new(ZERO)))
    }

    fn drop_block(&mut self, b: u64) {
        let k = b / SEG;
        if let Some(s) = self.segs.get_mut(&k) {
            if s[(b % SEG) as usize].is_some() {
                Rc::make_mut(s)[(b % SEG) as usize] = None;
                if s.iter().all(|x| x.is_none()) {
                    self.segs.remove(&k);
                }
            }
        }
    }

    /// Present blocks in `[lo_b, hi_b)`, ascending.
    pub fn blocks_in(&self, lo_b: u64, hi_b: u64) -> impl Iterator<Item = (u64, &Block)> + '_ {
        self.segs
            .range(lo_b / SEG..hi_b.div_ceil(SEG))
            .flat_map(move |(k, s)| {
                s.iter().enumerate().filter_map(move |(i, x)| {
                    let b = k * SEG + i as u64;
                    match x {
                        Some(x) if b >= lo_b && b < hi_b => Some((b, &**x)),
                        _ => None,
                    }
                })
            })
    }

    /// Every present block, ascending.
    pub fn blocks(&self) -> impl Iterator<Item = (u64, &Block)> + '_ {
        self.blocks_in(0, u64::MAX / BLOCK)
    }

    /// Bytes `[lo, hi)` (zeros beyond the length).
    pub fn read(&self, lo: u64, hi: u64) -> Vec<u8> {
        let mut out = vec![0u8; hi.saturating_sub(lo) as usize];
        let hi = hi.min(self.len);
        if lo >= hi {
            return out;
        }
        for (b, blk) in self.blocks_in(lo / BLOCK, hi.div_ceil(BLOCK)) {
            let s = lo.max(b * BLOCK);
            let e = hi.min((b + 1) * BLOCK);
            out[(s - lo) as usize..(e - lo) as usize]
                .copy_from_slice(&blk[(s - b * BLOCK) as usize..(e - b * BLOCK) as usize]);
        }
        out
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.read(0, self.len)
    }

    /// Write `bytes` at `off`; the length becomes at least `off + bytes.len()` (also for an
    /// empty write, as `Vec::resize` then copy did).
    pub fn write(&mut self, off: u64, bytes: &[u8]) {
        let end = off + bytes.len() as u64;
        let mut o = off;
        while o < end {
            let b = o / BLOCK;
            let e = end.min((b + 1) * BLOCK);
            let src = &bytes[(o - off) as usize..(e - off) as usize];
            // All-zero data into an absent block stays absent (it reads as zeros already).
            if self.block(b).is_some() || src.iter().any(|x| *x != 0) {
                self.block_mut(b)[(o - b * BLOCK) as usize..(e - b * BLOCK) as usize]
                    .copy_from_slice(src);
            }
            o = e;
        }
        self.len = self.len.max(end);
    }

    pub fn resize(&mut self, n: u64) {
        if n < self.len {
            self.zero_range(n, self.len.min(n.div_ceil(BLOCK) * BLOCK));
            let first = n.div_ceil(BLOCK);
            let drop: Vec<u64> = self
                .blocks_in(first, u64::MAX / BLOCK)
                .map(|(b, _)| b)
                .collect();
            for b in drop {
                self.drop_block(b);
            }
        }
        self.len = n;
    }

    /// Zero `[lo, hi)`, without changing the length (the caller clips to it).
    fn zero_range(&mut self, lo: u64, hi: u64) {
        let present: Vec<u64> = self
            .blocks_in(lo / BLOCK, hi.div_ceil(BLOCK))
            .map(|(b, _)| b)
            .collect();
        for b in present {
            let s = lo.max(b * BLOCK);
            let e = hi.min((b + 1) * BLOCK);
            if s == b * BLOCK && e == (b + 1) * BLOCK {
                self.drop_block(b);
            } else {
                self.block_mut(b)[(s - b * BLOCK) as usize..(e - b * BLOCK) as usize].fill(0);
            }
        }
    }

    /// Zero `[lo, hi)` clipped to the length.
    pub fn zero(&mut self, lo: u64, hi: u64) {
        let (lo, hi) = (lo.min(self.len), hi.min(self.len));
        if lo < hi {
            self.zero_range(lo, hi);
        }
    }

    /// `self[lo..hi] = src[lo..hi]` (src zeros beyond its length); `hi <= self.len()`.
    /// Whole blocks are shared, not copied.
    pub fn copy_from(&mut self, src: &Content, lo: u64, hi: u64) {
        debug_assert!(hi <= self.len);
        let mut o = lo;
        while o < hi {
            let b = o / BLOCK;
            let e = hi.min((b + 1) * BLOCK);
            if o == b * BLOCK && e == (b + 1) * BLOCK && src.len >= e {
                match src.block_rc(b) {
                    Some(r) => *self.slot(b) = Some(r.clone()),
                    None => self.drop_block(b),
                }
            } else {
                let bytes = src.read(o, e);
                if self.block(b).is_some() || bytes.iter().any(|x| *x != 0) {
                    self.block_mut(b)[(o - b * BLOCK) as usize..(e - b * BLOCK) as usize]
                        .copy_from_slice(&bytes);
                }
            }
            o = e;
        }
    }

    /// Is block `b` equal in both (absent = zeros; clipped to each length)?
    pub fn block_eq(&self, other: &Content, b: u64) -> bool {
        match (self.block_rc(b), other.block_rc(b)) {
            (None, None) => true,
            (Some(x), Some(y)) if Rc::ptr_eq(x, y) => true,
            _ => {
                let (lo, hi) = (b * BLOCK, (b + 1) * BLOCK);
                self.read(lo, hi) == other.read(lo, hi)
            }
        }
    }

    /// Indices of blocks holding a non-zero byte, ascending.
    pub fn nonzero_blocks(&self) -> impl Iterator<Item = (u64, &Block)> + '_ {
        self.blocks().filter(|(_, b)| b.iter().any(|x| *x != 0))
    }

    /// Does `[lo, hi)` hold a non-zero byte?
    pub fn any_nonzero(&self, lo: u64, hi: u64) -> bool {
        let hi = hi.min(self.len);
        if lo >= hi {
            return false;
        }
        self.blocks_in(lo / BLOCK, hi.div_ceil(BLOCK))
            .any(|(b, blk)| {
                let s = lo.max(b * BLOCK) - b * BLOCK;
                let e = hi.min((b + 1) * BLOCK) - b * BLOCK;
                blk[s as usize..e as usize].iter().any(|x| *x != 0)
            })
    }

    /// Maximal runs of non-zero blocks as (offset, length), clipped to the length.
    pub fn extent_ranges(&self) -> Vec<(u64, u64)> {
        let mut out: Vec<(u64, u64)> = vec![];
        for (b, _) in self.nonzero_blocks() {
            let lo = b * BLOCK;
            let hi = self.len.min(lo + BLOCK);
            match out.last_mut() {
                Some((o, n)) if *o + *n == lo => *n += hi - lo,
                _ => out.push((lo, hi - lo)),
            }
        }
        out
    }

    /// Append bytes `[lo, hi)` to `out`.
    pub fn append_to(&self, out: &mut Vec<u8>, lo: u64, hi: u64) {
        let start = out.len();
        out.resize(start + (hi - lo) as usize, 0);
        let hi = hi.min(self.len);
        for (b, blk) in self.blocks_in(lo / BLOCK, hi.div_ceil(BLOCK)) {
            let s = lo.max(b * BLOCK);
            let e = hi.min((b + 1) * BLOCK);
            out[start + (s - lo) as usize..start + (e - lo) as usize]
                .copy_from_slice(&blk[(s - b * BLOCK) as usize..(e - b * BLOCK) as usize]);
        }
    }

    /// Maximal runs of non-zero blocks as (offset, bytes), clipped to the length.
    pub fn extents(&self) -> Vec<(u64, Vec<u8>)> {
        self.extent_ranges()
            .into_iter()
            .map(|(o, n)| {
                let mut v = Vec::with_capacity(n as usize);
                self.append_to(&mut v, o, o + n);
                (o, v)
            })
            .collect()
    }

    /// The first offset where the two differ (None: equal bytes and length).
    pub fn first_difference(&self, other: &Content) -> Option<u64> {
        let n = self.len.min(other.len);
        let blocks: std::collections::BTreeSet<u64> = self
            .blocks()
            .map(|(b, _)| b)
            .chain(other.blocks().map(|(b, _)| b))
            .filter(|b| b * BLOCK < n)
            .collect();
        for b in blocks {
            if !self.block_eq(other, b) {
                let (lo, hi) = (b * BLOCK, n.min((b + 1) * BLOCK));
                let (x, y) = (self.read(lo, hi), other.read(lo, hi));
                if let Some(i) = x.iter().zip(&y).position(|(u, v)| u != v) {
                    return Some(lo + i as u64);
                }
            }
        }
        (self.len != other.len).then_some(n)
    }
}

impl PartialEq for Content {
    fn eq(&self, other: &Content) -> bool {
        self.len == other.len && self.first_difference(other).is_none()
    }
}

impl Eq for Content {}

impl PartialEq<[u8]> for Content {
    fn eq(&self, other: &[u8]) -> bool {
        self.len == other.len() as u64 && self.to_vec() == other
    }
}

impl PartialEq<&[u8]> for Content {
    fn eq(&self, other: &&[u8]) -> bool {
        *self == **other
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for Content {
    fn eq(&self, other: &&[u8; N]) -> bool {
        *self == other[..]
    }
}

impl std::fmt::Debug for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.blocks().count();
        if self.len <= 64 {
            write!(f, "Content({:?})", String::from_utf8_lossy(&self.to_vec()))
        } else {
            write!(f, "Content(len {}, {n} blocks)", self.len)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny deterministic generator.
    fn rng(s: &mut u64) -> u64 {
        *s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *s >> 33
    }

    #[test]
    fn content_matches_vec_semantics() {
        for seed in 0..300u64 {
            let mut s = seed;
            let mut v: Vec<u8> = vec![];
            let mut c = Content::new();
            let mut snaps: Vec<(Vec<u8>, Content)> = vec![];
            for _ in 0..60 {
                let span = [100u64, 5000, 300_000][(rng(&mut s) % 3) as usize];
                let off = rng(&mut s) % span;
                match rng(&mut s) % 6 {
                    0 | 1 => {
                        let n = rng(&mut s) % 9000;
                        let fill = (rng(&mut s) % 3) as u8; // 0 sometimes: zero writes
                        let bytes: Vec<u8> = (0..n)
                            .map(|i| if fill == 0 { 0 } else { (i as u8) ^ fill })
                            .collect();
                        let end = off as usize + bytes.len();
                        if v.len() < end {
                            v.resize(end, 0);
                        }
                        v[off as usize..end].copy_from_slice(&bytes);
                        c.write(off, &bytes);
                    }
                    2 => {
                        v.resize(off as usize, 0);
                        c.resize(off);
                    }
                    3 => {
                        let len = rng(&mut s) % 20000;
                        let lo = (off as usize).min(v.len());
                        let hi = ((off + len) as usize).min(v.len());
                        v[lo..hi].fill(0);
                        c.zero(off, off + len);
                    }
                    4 => {
                        // copy_from a snapshot over a range within our length
                        if let Some((sv, sc)) = snaps.last() {
                            let lo = off.min(v.len() as u64);
                            let hi = (lo + rng(&mut s) % 20000).min(v.len() as u64);
                            for i in lo..hi {
                                v[i as usize] = sv.get(i as usize).copied().unwrap_or(0);
                            }
                            c.copy_from(sc, lo, hi);
                        }
                    }
                    _ => snaps.push((v.clone(), c.clone())),
                }
                assert_eq!(c.len(), v.len() as u64);
                assert_eq!(c.to_vec(), v, "seed {seed}");
                for (sv, sc) in &snaps {
                    assert_eq!(&sc.to_vec(), sv, "snapshot changed, seed {seed}");
                }
            }
            let back = Content::from_slice(&v);
            assert!(back == c);
            let mut e = Content::new();
            for (o, b) in c.extents() {
                e.write(o, &b);
            }
            e.resize(c.len());
            assert!(e == c);
        }
    }
}
