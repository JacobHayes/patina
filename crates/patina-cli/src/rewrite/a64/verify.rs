//! The plan verifier for arm64: an independent check of a plan against its file. It shares the
//! ELF fact reader, the plan reader and the word classifier (`insn`) with the rewriter, and none
//! of its decisions: it finds code its own way (control flow from the anchors, nothing else) and
//! checks that
//!   - the plan is for this file, its cell is the runtime's, its trampolines lie outside the
//!     image (after it, or also before it in a file placed at load time; the span's bytes over
//!     the image are zero), and it has no entry rows (arm64 has no groups and no `cpuid`);
//!   - every word the plan changes is a site's word, and each site's word is code found here,
//!     that no code reads or takes the address of, not marked data, no landing pad, not
//!     between the function starts around a word found that is not code (refused, marked data
//!     or read), outside every exclusive pair (and not a branch into one), and not on the way
//!     from a failed store-exclusive back to its load;
//!   - each site's original word is one its kind may carry (`KIND_JUMP`: `b` or `bl`;
//!     `KIND_COND`: an unhinted conditional branch; `KIND_BEFORE`: an indirect jump or a
//!     single-instruction atomic; `KIND_FAR`: `b` or `bl` to another function's start (an
//!     anchor or a call's target), to a landing pad for `br x16` if the file asks for guarded pages) and is now
//!     `b T` (`bl T` for `bl`) to its own trampoline;
//!   - each trampoline is exactly: (for `KIND_COND`) the same condition aimed 8 bytes on and a
//!     `b` to the next instruction; the count in the runtime's cell with its `cbz` to the
//!     restore before the trap; the row (`b` to the original target, `adrp`, `add` and
//!     `br x16` to it, or the original word and a `b` to the next instruction); the restore,
//!     the trap, a `b` back to the row; and the site row's offsets name those places.
use super::insn::{self, Flow, Ind, PcRel};
use crate::rewrite::elf::Elf;
use crate::rewrite::plan::{Plan, Site, CELL, PAGE};
use proto::plan::{A64_COUNT, A64_TRAP, KIND_BEFORE, KIND_COND, KIND_FAR, KIND_JUMP};
use std::collections::{BTreeMap, BTreeSet};

/// A pair's words, and its store-exclusive with its status register.
type Way = (Vec<u64>, Option<(u64, u32)>);

/// Words found by control flow; what code reads, what it takes the address of, the words
/// where control flow found what is not code, and the function starts (anchors and calls).
struct Found<'a> {
    elf: &'a Elf<'a>,
    code: BTreeMap<u64, u32>,
    read: BTreeSet<u64>,
    addr: BTreeSet<u64>,
    refused: Vec<u64>,
    funcs: BTreeSet<u64>,
    /// `funcs` in order, once found.
    starts: Vec<u64>,
}

impl Found<'_> {
    fn word(&self, a: u64) -> Option<u32> {
        let t = self.elf.text_at(a)?;
        let o = (a - t.addr) as usize;
        let b = self.elf.bytes(t).get(o..o + 4)?;
        a.is_multiple_of(4)
            .then(|| u32::from_le_bytes(b.try_into().unwrap()))
    }

    fn data(&self, a: u64) -> bool {
        self.elf
            .asm_data
            .iter()
            .any(|&(lo, hi)| a + 4 > lo && a < hi)
    }

    fn walk(&mut self) {
        let mut work: Vec<u64> = self.elf.anchors.clone();
        self.funcs.extend(work.iter().copied());
        while let Some(mut a) = work.pop() {
            while !self.code.contains_key(&a) {
                let Some(w) = self.word(a) else { break };
                let f = insn::flow(a, w);
                if f == Flow::Refused || self.data(a) {
                    self.refused.push(a);
                    break;
                }
                self.code.insert(a, w);
                let pc = match insn::pc_rel(a, w) {
                    Some(PcRel::Page { page, rd }) => {
                        self.word(a + 4).and_then(|n| insn::paired(page, rd, n))
                    }
                    x => x,
                };
                match pc {
                    Some(PcRel::Read { at, len }) => {
                        let mut y = at & !3;
                        while y < at + len {
                            self.read.insert(y);
                            y += 4;
                        }
                    }
                    Some(PcRel::Addr(x)) => {
                        self.addr.insert(x & !3);
                    }
                    _ => {}
                }
                match f {
                    Flow::Direct { target, link } => {
                        work.push(target);
                        if link {
                            if self.word(target).is_some() {
                                self.funcs.insert(target);
                            }
                        } else {
                            break;
                        }
                    }
                    Flow::Cond { target, .. } => work.push(target),
                    Flow::Indirect(Ind::Call) | Flow::Plain => {}
                    _ => break,
                }
                a += 4;
            }
        }
        let read: Vec<u64> = self
            .read
            .intersection(&self.code.keys().copied().collect())
            .copied()
            .collect();
        self.refused.extend(read);
        self.starts = self.funcs.iter().copied().collect();
    }

    /// The spans this verifier taints: from the function start at or before each refusal to
    /// the next, within its section.
    fn tainted(&self) -> Vec<(u64, u64)> {
        self.refused
            .iter()
            .filter_map(|&r| {
                let t = self.elf.text_at(r)?;
                let lo = self
                    .funcs
                    .range(..=r)
                    .next_back()
                    .map_or(t.addr, |&f| f.max(t.addr));
                let end = t.addr + t.len as u64;
                let hi = self
                    .funcs
                    .range(r + 1..)
                    .next()
                    .map_or(end, |&f| f.min(end));
                Some((lo, hi))
            })
            .collect()
    }

    /// The way from each found load-exclusive to its store, by this verifier's own rule: in
    /// order from the load, along fall-through, `b` and a call's return (not the taken side
    /// of a conditional), up to a store-exclusive or `clrex` (included), at most 32 words;
    /// none if another load-exclusive or a word that leaves comes first. The words, and the
    /// store with its status register.
    fn pair(&self, l: u64) -> Option<Way> {
        let mut way = vec![];
        let mut a = l + 4;
        for _ in 0..32 {
            let n = self.word(a)?;
            if insn::is_load_exclusive(n) {
                return None;
            }
            way.push(a);
            if insn::ends_pair(n) {
                return Some((way, insn::store_status(n).map(|rs| (a, rs))));
            }
            a = match insn::flow(a, n) {
                Flow::Plain if n & 0xffe0_001f != 0xd400_0001 => a + 4,
                Flow::Cond { .. } | Flow::Indirect(Ind::Call) | Flow::Direct { link: true, .. } => {
                    a + 4
                }
                Flow::Direct {
                    target,
                    link: false,
                } => target,
                _ => return None,
            };
        }
        None
    }

    /// The words inside exclusive pairs.
    fn pairs(&self) -> BTreeSet<u64> {
        let mut out = BTreeSet::new();
        for (&p, &w) in &self.code {
            if insn::is_load_exclusive(w) {
                if let Some((way, _)) = self.pair(p) {
                    out.extend(way);
                }
            }
        }
        out
    }

    /// The words a failed store-exclusive runs again on its way back to its load, by this
    /// verifier's own search: for the store that ends each found load's pair (`pair`), from
    /// where it goes on failure (its `cbz`/`cbnz` retry's way, the branch included, or the next
    /// word), breadth first along fall-through, both ways of a conditional, `b` and a call's
    /// return, at most `RETRY_DEPTH` words, not through the load; then back from the load.
    fn retries(&self) -> BTreeSet<u64> {
        /// No more than the rewriter's bound: a smaller search finds no more words.
        const RETRY_DEPTH: usize = 512;
        let mut out = BTreeSet::new();
        for (&l, &w) in &self.code {
            if !insn::is_load_exclusive(w) {
                continue;
            }
            let Some((_, Some((x, rs)))) = self.pair(l) else {
                continue;
            };
            let start = match self
                .word(x + 4)
                .and_then(|b| insn::on_failure(x + 4, b, rs))
            {
                Some(f) => {
                    out.insert(x + 4);
                    f
                }
                None => x + 4,
            };
            let mut from: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
            let mut found = BTreeSet::from([start]);
            let mut level = vec![start];
            for d in 1..=RETRY_DEPTH + 1 {
                let mut next = vec![];
                for &a in &level {
                    if a == l {
                        continue;
                    }
                    let Some(w) = self.word(a) else { continue };
                    let succ: &[u64] = &match insn::flow(a, w) {
                        Flow::Plain
                        | Flow::Indirect(Ind::Call)
                        | Flow::Direct { link: true, .. } => [a + 4, a + 4],
                        Flow::Cond { target, .. } => [a + 4, target],
                        Flow::Direct {
                            target,
                            link: false,
                        } => [target, target],
                        _ => continue,
                    };
                    for &n in succ {
                        from.entry(n).or_default().push(a);
                        if d <= RETRY_DEPTH && found.insert(n) {
                            next.push(n);
                        }
                    }
                }
                level = next;
            }
            let mut back: Vec<u64> = from.get(&l).cloned().unwrap_or_default();
            while let Some(a) = back.pop() {
                if a != l && found.contains(&a) && out.insert(a) {
                    back.extend(from.get(&a).into_iter().flatten());
                }
            }
        }
        out
    }
}

fn plan_word(plan: &Plan, a: u64) -> Option<u32> {
    let p = plan
        .pages
        .iter()
        .find(|p| a >= p.vaddr && a + 4 <= p.vaddr + p.bytes.len() as u64)?;
    let o = (a - p.vaddr) as usize;
    Some(u32::from_le_bytes(p.bytes[o..o + 4].try_into().unwrap()))
}

pub fn verify(data: &[u8], plan: &Plan) -> Vec<String> {
    let mut bad = vec![];
    let elf = match Elf::parse(data) {
        Ok(e) => e,
        Err(e) => return vec![e],
    };
    if plan.sha256 != elf.sha256 || plan.machine != elf.machine {
        return vec!["the plan is for another file (SHA-256 or machine differs)".into()];
    }
    let in_image = |a: u64, n: u64| {
        elf.loads
            .iter()
            .any(|l| a < l.vaddr + l.memsz && l.vaddr < a.saturating_add(n))
    };
    let span = (plan.tramp_vaddr, plan.tramp.len() as u64);
    // Trampolines below the image wrap below zero in a file placed at load time; a file loaded
    // at its link addresses has them after it only.
    let wraps = span.0.checked_add(span.1).is_none();
    let below = span.0 < elf.image_start() || wraps;
    if !span.0.is_multiple_of(PAGE) || (below && elf.exec) {
        bad.push(format!(
            "trampolines at {:#x} not placed after the image",
            span.0
        ));
    }
    // The span's start as a signed address (below zero before an image linked at zero).
    let s0 = span.0 as i64 as i128;
    for l in &elf.loads {
        let lo = (l.vaddr as i128).max(s0);
        let hi = ((l.vaddr + l.memsz) as i128).min(s0 + span.1 as i128);
        if lo < hi
            && plan.tramp[(lo - s0) as usize..(hi - s0) as usize]
                .iter()
                .any(|&b| b != 0)
        {
            bad.push(format!("trampoline bytes over the image at {:#x}", l.vaddr));
        }
    }
    let over_cell = elf.exec && CELL < span.0.saturating_add(span.1) && span.0 < CELL + 8;
    if plan.cell != CELL || (elf.exec && in_image(CELL, 8)) || over_cell {
        bad.push(format!(
            "cell {:#x} is not the runtime's, or not free",
            plan.cell
        ));
    }
    if !plan.entries.is_empty() {
        bad.push("an arm64 plan with entry rows".into());
    }
    let mut f = Found {
        elf: &elf,
        code: BTreeMap::new(),
        read: BTreeSet::new(),
        addr: BTreeSet::new(),
        refused: vec![],
        funcs: BTreeSet::new(),
        starts: vec![],
    };
    f.walk();
    let pairs = f.pairs();
    let retries = f.retries();
    let tainted = f.tainted();
    let mut sites: Vec<u64> = vec![];
    let mut tramps: Vec<(u64, u64)> = vec![];
    if plan.sites.windows(2).any(|w| w[0].tramp > w[1].tramp) {
        bad.push("the site rows are not in order of their trampolines".into());
    }
    for s in &plan.sites {
        sites.push(s.addr);
        let (t0, t1) = (s.tramp as u64, s.tramp as u64 + s.tramp_len as u64);
        if t1 > span.1 || s.tramp_len % 4 != 0 || t0 % 4 != 0 {
            bad.push(format!("site {:#x}: trampoline outside the span", s.addr));
            continue;
        }
        tramps.push((t0, t1));
        if in_image(plan.tramp_vaddr.wrapping_add(t0), t1 - t0) {
            bad.push(format!("site {:#x}: trampoline over the image", s.addr));
        }
        if tainted.iter().any(|&(lo, hi)| lo <= s.addr && s.addr < hi) {
            bad.push(format!(
                "site {:#x}: between the function starts around a word that is not code",
                s.addr
            ));
        }
        if retries.contains(&s.addr) {
            bad.push(format!(
                "site {:#x}: on the way back from a failed store-exclusive",
                s.addr
            ));
        }
        if let Err(e) = check_site(&f, &pairs, plan, s) {
            bad.push(format!("site {:#x}: {e}", s.addr));
        }
    }
    sites.sort_unstable();
    if sites.windows(2).any(|w| w[0] + 4 > w[1]) {
        bad.push("two patches overlap".into());
    }
    tramps.sort_unstable();
    if tramps.windows(2).any(|w| w[0].1 > w[1].0) {
        bad.push("two trampolines overlap".into());
    }
    // Every changed word is a site's.
    for p in &plan.pages {
        for (k, page) in p.bytes.chunks(PAGE as usize).enumerate() {
            let v = p.vaddr + k as u64 * PAGE;
            let Some(orig) = elf.original_page(v) else {
                bad.push(format!("page {v:#x}: not in an executable segment"));
                continue;
            };
            for (o, (a, b)) in orig.chunks(4).zip(page.chunks(4)).enumerate() {
                let at = v + 4 * o as u64;
                if a != b && sites.binary_search(&at).is_err() {
                    bad.push(format!("word {at:#x}: changed outside every site"));
                    break;
                }
            }
        }
    }
    bad
}

fn check_site(f: &Found, pairs: &BTreeSet<u64>, plan: &Plan, s: &Site) -> Result<(), String> {
    let a = s.addr;
    let orig = *f.code.get(&a).ok_or("not a word found by control flow")?;
    if s.len != 4 || !a.is_multiple_of(4) {
        return Err("not one word".into());
    }
    if f.read.contains(&a) || f.addr.contains(&a) || f.data(a) || insn::landing_pad(orig) {
        return Err(
            "code reads it or takes its address, it is marked data, or it is a landing pad".into(),
        );
    }
    let flow = insn::flow(a, orig);
    let target = match flow {
        Flow::Direct { target, .. } | Flow::Cond { target, .. } => Some(target),
        _ => None,
    };
    if pairs.contains(&a) || target.is_some_and(|t| pairs.contains(&t)) {
        return Err("inside an exclusive pair, or a branch into one".into());
    }
    let fits = match (s.kind, flow) {
        (KIND_JUMP, Flow::Direct { .. }) => true,
        (KIND_FAR, Flow::Direct { target, .. }) => {
            f.funcs.contains(&target)
                && !f.elf.one_function(&f.starts, target, a)
                && (!f.elf.bti || f.word(target).is_some_and(insn::x16_pad))
        }
        (KIND_COND, Flow::Cond { hinted: false, .. }) => true,
        (KIND_BEFORE, Flow::Indirect(Ind::Jump)) => true,
        (KIND_BEFORE, Flow::Plain) => insn::atomic(orig),
        _ => false,
    };
    if !fits {
        return Err(format!("kind {} over a word it may not carry", s.kind));
    }
    let t = plan.tramp_vaddr.wrapping_add(s.tramp as u64);
    let link = matches!(flow, Flow::Direct { link: true, .. });
    let now = plan_word(plan, a).ok_or("patched word not in the plan's pages")?;
    if insn::flow(a, now) != (Flow::Direct { target: t, link }) {
        return Err("the patch is not a branch (with link for a call) to its trampoline".into());
    }
    let tw = |off: u64| -> u32 {
        let o = (s.tramp as u64 + off) as usize;
        plan.tramp
            .get(o..o + 4)
            .map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()))
    };
    // A branch at `off` of the trampoline to `to`.
    let goes = |off: u64, to: u64| {
        insn::flow(t.wrapping_add(off), tw(off))
            == Flow::Direct {
                target: to,
                link: false,
            }
    };
    let c = if s.kind == KIND_COND {
        // The same condition (only its offset field differs), 8 bytes on; else the next word.
        let w = tw(0);
        let field = if orig & 0x7e00_0000 == 0x3600_0000 {
            0x3fff << 5
        } else {
            0x7_ffff << 5
        };
        if w & !field != orig & !field
            || insn::flow(t, w)
                != (Flow::Cond {
                    target: t.wrapping_add(8),
                    hinted: false,
                })
            || !goes(4, a + 4)
        {
            return Err("the trampoline does not test the same condition first".into());
        }
        8
    } else {
        0
    };
    let r = c + A64_COUNT;
    let rs = r + match s.kind {
        KIND_BEFORE => 8,
        KIND_FAR => 12,
        _ => 4,
    };
    // The count, as this verifier spells it: save x16 and x17 32 bytes down, x16 = the cell,
    // x17 = [x16] - 1 stored back, zero to the restore before the trap, restore.
    let words = [
        0xa9be_47f0,
        0xd2a0_0000 | ((CELL >> 16) as u32) << 5 | 16,
        0xf940_0211,
        0xd100_0631,
        0xf900_0211,
    ];
    if CELL & !0xffff_0000 != 0 || (0..5).any(|k| tw(c + 4 * k) != words[k as usize]) {
        return Err("the trampoline does not count in the cell".into());
    }
    let cbz = tw(c + 20);
    if cbz & 0xff00_001f != 0xb400_0011
        || insn::flow(t.wrapping_add(c + 20), cbz)
            != (Flow::Cond {
                target: t.wrapping_add(rs),
                hinted: false,
            })
        || tw(c + 24) != 0xa8c2_47f0
    {
        return Err("the count does not branch to the restore before its trap, or restore".into());
    }
    let row_ok = match s.kind {
        KIND_BEFORE => tw(r) == orig && goes(r + 4, a + 4),
        // adrp x16, target; add x16, x16, #lo12; br x16
        KIND_FAR => {
            let to = target.unwrap();
            let adrp = tw(r);
            adrp & 0x9f00_001f == 0x9000_0010
                && insn::pc_rel(t.wrapping_add(r), adrp)
                    == Some(PcRel::Page {
                        page: to & !0xfff,
                        rd: 16,
                    })
                && tw(r + 4) == 0x9100_0210 | ((to & 0xfff) as u32) << 10
                && tw(r + 8) == 0xd61f_0200
        }
        _ => goes(r, target.unwrap()),
    };
    if !row_ok {
        return Err(
            "the row does not go on to the original target, or copy the word exactly".into(),
        );
    }
    if tw(rs) != 0xa8c2_47f0 || tw(rs + 4) != A64_TRAP || !goes(rs + 8, t.wrapping_add(r)) {
        return Err("the trap is not a restore, `udf`, and a branch back to the row".into());
    }
    if s.copy as u64 != r || s.trap as u64 != rs + 4 || s.tramp_len as u64 != rs + 12 {
        return Err("the site row's offsets are not its trampoline's".into());
    }
    Ok(())
}
