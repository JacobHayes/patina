//! What is code, on arm64 (DESIGN 2.2, 2.6). Words are *proven* code when control flow reaches
//! them from a known function start; only proven code is patched. Data inside text is normal
//! here (literal pools, tables of hand-written assembly), so the extent rule of x86_64 is used
//! for the census only: *extent* words are the rest of an unwind entry's or sized symbol's
//! range, decoded linearly up to a word code reads or names; they are counted, never patched.
//! A refusal taints the span between the neighbouring function starts: a word compiled code
//! does not hold, a word code reads (a literal load, an `adrp` pair) or the assembler marked
//! data (`$d`), reached by control flow.

use super::insn::{self, Flow, Ind, PcRel};

/// Per-word flags.
pub const READ: u16 = 1; // a load of decoded code reads this word
pub const ADDR: u16 = 2; // `adr` or an `adrp` pair takes this address
pub const TARGET: u16 = 4; // a direct branch or call lands here, or an anchor
pub const FUNC: u16 = 8; // an anchor or a direct call target: a function start
pub const TAINT: u16 = 16; // never patched
pub const PROVEN: u16 = 32; // reached by control flow
pub const EXTENT: u16 = 64; // decoded by the extent rule (census only)
pub const DATA: u16 = 128; // the assembler's `$d`
pub const PAIR: u16 = 256; // inside an exclusive pair (after its load-exclusive)
pub const RETRY: u16 = 512; // on the way from a failed store-exclusive back to its load

/// How far (in words, along control flow) that way is followed.
pub const RETRY_MAX: usize = 512;

pub struct Region<'a> {
    pub addr: u64,
    pub bytes: &'a [u8],
    fl: Vec<u16>,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct Refusals {
    pub invalid: u64,
    pub data: u64,
    pub read: u64,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct Census {
    pub text: u64,
    pub proven: u64,
    pub extent: u64,
    pub padding: u64,
    pub dark: u64,
    pub tainted: u64,
    pub instructions: u64,
}

pub struct Code<'a> {
    pub regions: Vec<Region<'a>>,
    pub refusals: Refusals,
}

impl<'a> Code<'a> {
    /// The analysis over `text` (address, bytes; sorted, disjoint, word-aligned) from function
    /// starts `anchors`, with function extents `extents` and data ranges `data`.
    pub fn analyze(
        text: &[(u64, &'a [u8])],
        anchors: &[u64],
        extents: &[(u64, u64)],
        data: &[(u64, u64)],
    ) -> Code<'a> {
        let mut c = Code {
            regions: text
                .iter()
                .map(|&(addr, bytes)| Region {
                    addr,
                    bytes,
                    fl: vec![0; bytes.len() / 4],
                })
                .collect(),
            refusals: Refusals::default(),
        };
        for &(lo, hi) in data {
            let mut a = lo & !3;
            while a < hi {
                c.set(a, DATA);
                a += 4;
            }
        }
        let mut work = vec![];
        for &a in anchors.iter().rev() {
            if a % 4 == 0 && c.find(a).is_some() {
                c.set(a, TARGET | FUNC);
                work.push(a);
            }
        }
        let mut bad = vec![];
        c.descend(work, &mut bad);
        c.fill(extents);
        // A word read as data, or marked data, that control flow reached.
        for i in 0..c.regions.len() {
            for k in 0..c.regions[i].fl.len() {
                let f = c.regions[i].fl[k];
                if f & PROVEN != 0 && f & READ != 0 {
                    c.refusals.read += 1;
                    bad.push(c.regions[i].addr + 4 * k as u64);
                }
            }
        }
        c.pairs();
        c.retries();
        c.taint(&bad);
        c
    }

    fn find(&self, a: u64) -> Option<(usize, usize)> {
        let i = self
            .regions
            .partition_point(|r| r.addr <= a)
            .checked_sub(1)?;
        let r = &self.regions[i];
        let o = a.wrapping_sub(r.addr);
        (o.is_multiple_of(4) && (o / 4) < r.fl.len() as u64).then_some((i, (o / 4) as usize))
    }

    fn set(&mut self, a: u64, f: u16) {
        if let Some((i, k)) = self.find(a) {
            self.regions[i].fl[k] |= f;
        }
    }

    pub fn flags(&self, a: u64) -> u16 {
        self.find(a).map_or(0, |(i, k)| self.regions[i].fl[k])
    }

    /// The function starts: anchors and direct calls' targets, in text, in address order.
    pub fn starts(&self) -> Vec<u64> {
        self.regions
            .iter()
            .flat_map(|r| {
                r.fl.iter()
                    .enumerate()
                    .filter(|(_, f)| *f & FUNC != 0)
                    .map(|(k, _)| r.addr + 4 * k as u64)
            })
            .collect()
    }

    /// The word at `a`, if in text.
    pub fn word(&self, a: u64) -> Option<u32> {
        let (i, k) = self.find(a)?;
        let b = &self.regions[i].bytes[4 * k..4 * k + 4];
        Some(u32::from_le_bytes(b.try_into().unwrap()))
    }

    /// Every proven word, in address order.
    pub fn proven(&self) -> impl Iterator<Item = (u64, u32)> + '_ {
        self.regions.iter().flat_map(|r| {
            r.fl.iter()
                .enumerate()
                .filter(|(_, f)| *f & PROVEN != 0)
                .map(|(k, _)| {
                    let a = r.addr + 4 * k as u64;
                    let w = u32::from_le_bytes(r.bytes[4 * k..4 * k + 4].try_into().unwrap());
                    (a, w)
                })
        })
    }

    /// Record what the word `w` at `a` reads or names.
    fn note(&mut self, a: u64, w: u32) {
        match insn::pc_rel(a, w) {
            Some(PcRel::Addr(x)) => self.set(x & !3, ADDR),
            Some(PcRel::Read { at, len }) => self.read(at, len),
            Some(PcRel::Page { page, rd }) => {
                match self.word(a + 4).and_then(|n| insn::paired(page, rd, n)) {
                    Some(PcRel::Addr(x)) => self.set(x & !3, ADDR),
                    Some(PcRel::Read { at, len }) => self.read(at, len),
                    _ => {}
                }
            }
            None => {}
        }
    }

    fn read(&mut self, at: u64, len: u64) {
        let mut x = at & !3;
        while x < at + len {
            self.set(x, READ);
            x += 4;
        }
    }

    /// Follow control flow from every address in `work`.
    fn descend(&mut self, mut work: Vec<u64>, bad: &mut Vec<u64>) {
        while let Some(mut a) = work.pop() {
            while let Some((i, k)) = self.find(a) {
                let f = self.regions[i].fl[k];
                if f & PROVEN != 0 {
                    break;
                }
                let w = self.word(a).unwrap();
                let fl = insn::flow(a, w);
                if f & DATA != 0 || fl == Flow::Refused {
                    if f & DATA != 0 {
                        self.refusals.data += 1;
                    } else {
                        self.refusals.invalid += 1;
                    }
                    bad.push(a);
                    break;
                }
                self.regions[i].fl[k] |= PROVEN;
                self.note(a, w);
                match fl {
                    Flow::Direct { target, link } => {
                        self.set(target, TARGET | if link { FUNC } else { 0 });
                        if self.find(target).is_some() {
                            work.push(target);
                        }
                        if !link {
                            break;
                        }
                    }
                    Flow::Cond { target, .. } => {
                        self.set(target, TARGET);
                        if self.find(target).is_some() {
                            work.push(target);
                        }
                    }
                    // `blr` returns here; `br` and `ret` do not.
                    Flow::Indirect(Ind::Call) => {}
                    Flow::Indirect(_) => break,
                    Flow::Trap | Flow::Refused => break,
                    Flow::Plain => {}
                }
                a += 4;
            }
        }
    }

    /// Extent words, for the census: inside each extent, what proven code left, decoded
    /// linearly up to a word code reads or names, data, or a refused word.
    fn fill(&mut self, extents: &[(u64, u64)]) {
        for &(lo, hi) in extents {
            let mut a = lo;
            while a < hi {
                let f = self.flags(a);
                let Some(w) = self.word(a) else { break };
                if f & PROVEN == 0 {
                    if f & (READ | ADDR | DATA) != 0 || insn::flow(a, w) == Flow::Refused {
                        break;
                    }
                    self.set(a, EXTENT);
                }
                a += 4;
            }
        }
    }

    /// Mark the words inside each exclusive pair: every word on a path from a proven
    /// load-exclusive to a store-exclusive or `clrex` (through fall-through, both ways of a
    /// conditional, `b` and a call's return; not through another load-exclusive or a word that
    /// leaves: `ret`, an indirect branch, `svc`, a trap). A count there could clear the
    /// exclusive monitor before the store. A count after the store (its retry branch) or on a
    /// path that abandons the pair leaves the monitor alone (but see `retries`). The callee of
    /// a call inside a pair is not looked into. Paths are followed for `PAIR_MAX` words
    /// (`proto::step`'s bound, as the stepper's): a store farther than that ends no pair a
    /// program can rely on (the architecture promises no progress for one).
    fn pairs(&mut self) {
        use std::collections::{BTreeMap, BTreeSet};
        let loads: Vec<u64> = self
            .proven()
            .filter(|&(_, w)| insn::is_load_exclusive(w))
            .map(|(a, _)| a)
            .collect();
        for p in loads {
            let mut succ: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
            let mut live: BTreeSet<u64> = BTreeSet::new();
            // Breadth first, so that each word is first seen at its shortest distance.
            let mut work = std::collections::VecDeque::from([(p + 4, 1)]);
            while let Some((a, depth)) = work.pop_front() {
                if succ.contains_key(&a) || live.contains(&a) || depth > proto::step::PAIR_MAX {
                    continue;
                }
                let Some(w) = self.word(a) else { continue };
                if insn::ends_pair(w) {
                    live.insert(a);
                    continue;
                }
                let next = match insn::flow(a, w) {
                    _ if insn::is_load_exclusive(w) => vec![],
                    Flow::Plain if w & 0xffe0_001f != 0xd400_0001 => vec![a + 4],
                    // A call returns into the pair: the call is inside it.
                    Flow::Indirect(Ind::Call) | Flow::Direct { link: true, .. } => vec![a + 4],
                    Flow::Cond { target, .. } => vec![a + 4, target],
                    Flow::Direct {
                        target,
                        link: false,
                    } => vec![target],
                    _ => vec![],
                };
                work.extend(next.iter().map(|&x| (x, depth + 1)));
                succ.insert(a, next);
            }
            // Back from the stores: every word with a successor that reaches one.
            loop {
                let more: Vec<u64> = succ
                    .iter()
                    .filter(|(a, n)| !live.contains(a) && n.iter().any(|x| live.contains(x)))
                    .map(|(&a, _)| a)
                    .collect();
                if more.is_empty() {
                    break;
                }
                live.extend(more);
            }
            for a in live {
                self.set(a, PAIR);
            }
        }
    }

    /// Mark the words a failed store-exclusive runs again on its way back to its load. A
    /// store-exclusive fails now and then with no other writer (the host clears the exclusive
    /// monitor), natively and under Patina, more or less often by run; the program goes round
    /// to the load once more. A count on that way would count that pass: a different number
    /// of events, a different schedule, for the same seed. The way back starts at the store's
    /// failure: where its retry branch (`cbz`/`cbnz` on its status, right after it) goes on
    /// failure, the branch itself marked; else (a weak compare-and-swap, whose status the
    /// program tests later) right after the store. It is every word reached from there
    /// (through fall-through, both ways of a conditional, `b`, and a call's return; within
    /// `RETRY_MAX` words; not through the load) that leads to the load.
    fn retries(&mut self) {
        use std::collections::{BTreeMap, BTreeSet, VecDeque};
        // Every word that encodes one, proven or not: a superset of what any reader finds.
        let loads: Vec<u64> = self
            .regions
            .iter()
            .flat_map(|r| {
                r.bytes
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .enumerate()
                    .filter(|(_, b)| insn::is_load_exclusive(u32::from_le_bytes(**b)))
                    .map(|(k, _)| r.addr + 4 * k as u64)
            })
            .collect();
        let succ = |a: u64, w: u32| match insn::flow(a, w) {
            Flow::Plain | Flow::Indirect(Ind::Call) | Flow::Direct { link: true, .. } => {
                vec![a + 4]
            }
            Flow::Cond { target, .. } => vec![a + 4, target],
            Flow::Direct { target, .. } => vec![target],
            _ => vec![],
        };
        for l in loads {
            // The pair's stores: on a path from the load, within `PAIR_MAX` words.
            let mut stores = vec![];
            let mut seen = BTreeSet::new();
            let mut work = VecDeque::from([(l + 4, 1)]);
            while let Some((a, depth)) = work.pop_front() {
                if depth > proto::step::PAIR_MAX || !seen.insert(a) {
                    continue;
                }
                let Some(w) = self.word(a) else { continue };
                if insn::is_load_exclusive(w) {
                    continue;
                }
                if insn::ends_pair(w) {
                    if let Some(rs) = insn::store_status(w) {
                        stores.push((a, rs));
                    }
                    continue;
                }
                work.extend(succ(a, w).into_iter().map(|n| (n, depth + 1)));
            }
            let mut marks = vec![];
            let mut work = VecDeque::new();
            for (x, rs) in stores {
                match self
                    .word(x + 4)
                    .and_then(|b| insn::on_failure(x + 4, b, rs))
                {
                    Some(f) => {
                        marks.push(x + 4);
                        work.push_back((f, 0));
                    }
                    None => work.push_back((x + 4, 0)),
                }
            }
            // Forward from the failures, not through the load; then back from the load.
            let mut preds: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
            for &(a, _) in &work {
                preds.entry(a).or_default();
            }
            while let Some((a, depth)) = work.pop_front() {
                if a == l {
                    continue;
                }
                let Some(w) = self.word(a) else { continue };
                for n in succ(a, w) {
                    let new = !preds.contains_key(&n);
                    preds.entry(n).or_default().push(a);
                    if new && depth < RETRY_MAX {
                        work.push_back((n, depth + 1));
                    }
                }
            }
            let mut back: Vec<u64> = preds.get(&l).cloned().unwrap_or_default();
            while let Some(a) = back.pop() {
                if marks.contains(&a) || a == l {
                    continue;
                }
                marks.push(a);
                back.extend(preds.get(&a).into_iter().flatten());
            }
            for a in marks {
                self.set(a, RETRY);
            }
        }
    }

    /// Taint the span between the function starts around each refusal.
    fn taint(&mut self, bad: &[u64]) {
        let funcs = self.starts();
        for &a in bad {
            let Some((i, _)) = self.find(a) else { continue };
            let r = &mut self.regions[i];
            let end = r.addr + 4 * r.fl.len() as u64;
            let j = funcs.partition_point(|&f| f <= a);
            let lo = j.checked_sub(1).map_or(r.addr, |j| funcs[j]).max(r.addr);
            let hi = funcs.get(j).copied().unwrap_or(u64::MAX).min(end);
            for f in &mut r.fl[((lo - r.addr) / 4) as usize..((hi - r.addr) / 4) as usize] {
                *f |= TAINT;
            }
        }
    }

    /// Bytes by kind: proven, extent, padding (zero words and `nop`s not decoded), dark.
    pub fn census(&self) -> Census {
        let mut c = Census::default();
        for r in &self.regions {
            c.text += r.bytes.len() as u64;
            for (k, &f) in r.fl.iter().enumerate() {
                let w = u32::from_le_bytes(r.bytes[4 * k..4 * k + 4].try_into().unwrap());
                if f & TAINT != 0 {
                    c.tainted += 4;
                }
                if f & PROVEN != 0 {
                    c.proven += 4;
                    c.instructions += 1;
                } else if f & EXTENT != 0 {
                    c.extent += 4;
                } else if w == 0 || w == 0xd503_201f {
                    c.padding += 4;
                } else {
                    c.dark += 4;
                }
            }
            // A section whose length is not whole words: its tail is dark.
            c.dark += (r.bytes.len() % 4) as u64;
        }
        c
    }
}
