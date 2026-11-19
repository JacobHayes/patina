//! The arm64 rewriter on hand-written word sequences: what is code, which sites get counts and
//! which are refused, the plan and its verifier. Words are spelled out (as an assembler encodes
//! them; each listing is the disassembly).

use super::code::{Code, PAIR, PROVEN, RETRY, TAINT};
use super::points::{self, Class, Outcome, Place};
use super::verify::verify;
use crate::rewrite::plan::{Entry, Plan, PAGE};
use proto::plan::{KIND_BEFORE, KIND_COND, KIND_FAR, KIND_JUMP};

const BASE: u64 = 0x40_1000;

fn bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

fn analyze<'a>(code: &'a [u8], anchors: &[u64], data: &[(u64, u64)]) -> Code<'a> {
    Code::analyze(&[(BASE, code)], anchors, &[], data)
}

/// Trampolines from `after`, none before the image; no far rows.
fn emit(code: &Code, after: u64) -> points::Emitted {
    points::emit(
        code,
        Place {
            after,
            before: None,
        },
        &|_, _| false,
    )
}

/// Each site's class, patch kind and outcome, by address.
fn sites(code: &Code, tramp_vaddr: u64) -> Vec<(u64, Class, Outcome)> {
    emit(code, tramp_vaddr)
        .choices
        .into_iter()
        .map(|c| (c.addr, c.class, c.outcome))
        .collect()
}

/// An ET_EXEC arm64 file: one read+execute segment holding `code` at `BASE`, the entry at its
/// start, no section headers (so the only anchor is the entry).
fn elf(code: &[u8]) -> Vec<u8> {
    elf_typed(code, 2)
}

/// The same as ET_DYN (placed at load time).
fn elf_dyn(code: &[u8]) -> Vec<u8> {
    elf_typed(code, 3)
}

/// A plan of `f` from what `emit` made.
fn plan_of(f: &[u8], em: points::Emitted) -> Plan {
    let e = crate::rewrite::elf::Elf::parse(f).unwrap();
    Plan {
        machine: 183,
        sha256: e.sha256,
        build: "test".into(),
        cell: crate::rewrite::plan::CELL,
        pages: super::pages(&e, &em.patched).unwrap(),
        tramp_vaddr: em.tramp_vaddr,
        tramp: em.tramp,
        sites: em.sites,
        entries: vec![],
        counts: vec![],
    }
}

fn elf_typed(code: &[u8], typ: u16) -> Vec<u8> {
    let mut f = vec![0u8; 0x1000];
    f[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    let put = |f: &mut Vec<u8>, at: usize, v: &[u8]| f[at..at + v.len()].copy_from_slice(v);
    put(&mut f, 0x10, &typ.to_le_bytes());
    put(&mut f, 0x12, &183u16.to_le_bytes());
    put(&mut f, 0x14, &1u32.to_le_bytes());
    put(&mut f, 0x18, &BASE.to_le_bytes());
    put(&mut f, 0x20, &0x40u64.to_le_bytes());
    put(&mut f, 0x34, &64u16.to_le_bytes());
    put(&mut f, 0x36, &56u16.to_le_bytes());
    put(&mut f, 0x38, &1u16.to_le_bytes());
    put(&mut f, 0x3a, &64u16.to_le_bytes());
    put(&mut f, 0x40, &1u32.to_le_bytes());
    put(&mut f, 0x44, &5u32.to_le_bytes());
    let n = code.len() as u64;
    for (k, v) in [0x1000, BASE, BASE, n, n, 0x1000].into_iter().enumerate() {
        put(&mut f, 0x48 + 8 * k, &v.to_le_bytes());
    }
    f.extend_from_slice(code);
    f
}

/// A loop closed by `b.lt`, an atomic, a backward `cbz`, an indirect jump, then words no
/// control flow reaches.
///
/// ```text
/// 00  52800000  mov  w0, #0
/// 04  11000400  L: add w0, w0, #1
/// 08  7100401f  cmp  w0, #16
/// 0c  54ffffcb  b.lt L
/// 10  b8e00041  ldaddal w0, w1, [x2]
/// 14  34ffff80  cbz  w0, L
/// 18  d61f0060  br   x3
/// 1c  12345678  not reached
/// 20  00000000 ... (to 4c)
/// 4c  d65f03c0  ret  (not reached)
/// ```
fn program() -> Vec<u8> {
    let mut w = vec![
        0x5280_0000,
        0x1100_0400,
        0x7100_401f,
        0x54ff_ffcb,
        0xb8e0_0041,
        0x34ff_ff80,
        0xd61f_0060,
        0x1234_5678,
    ];
    w.resize(0x4c / 4, 0);
    w.push(0xd65f_03c0);
    bytes(&w)
}

#[test]
fn a_loop_an_atomic_and_an_indirect_jump_get_counts_in_place() {
    let p = program();
    let code = analyze(&p, &[BASE], &[]);
    let got = sites(&code, 0x80_0000);
    assert_eq!(
        got,
        [
            (BASE + 0x0c, Class::BackBranch, Outcome::InPlace),
            (BASE + 0x10, Class::Atomic, Outcome::InPlace),
            (BASE + 0x14, Class::BackBranch, Outcome::InPlace),
            (BASE + 0x18, Class::IndirectJump, Outcome::InPlace),
        ]
    );
    let kinds: Vec<u8> = emit(&code, 0x80_0000)
        .sites
        .iter()
        .map(|s| s.kind)
        .collect();
    assert_eq!(kinds, [KIND_COND, KIND_BEFORE, KIND_COND, KIND_BEFORE]);
}

#[test]
fn words_no_control_flow_reaches_are_dark_and_not_patched() {
    let p = program();
    let code = analyze(&p, &[BASE], &[]);
    let c = code.census();
    assert_eq!(c.proven, 0x1c);
    // The zero words are padding; the `ret` and the 0x12345678 are dark.
    assert_eq!(c.dark, 8);
    assert!(code.proven().all(|(a, _)| a < BASE + 0x1c));
}

/// ```text
/// 00  885ffc01  P: ldaxr w1, [x0]
/// 04  11000421  R: add   w1, w1, #1
/// 08  34ffffe1  cbz   w1, R          inside the pair
/// 0c  8802fc01  stlxr w2, w1, [x0]
/// 10  35ffff82  cbnz  w2, P          the retry: after the store, on a loop through the load
/// 14  17fffffc  b     R              into the pair
/// ```
#[test]
fn no_count_inside_an_exclusive_pair_or_on_a_branch_into_one() {
    let p = bytes(&[
        0x885f_fc01,
        0x1100_0421,
        0x34ff_ffe1,
        0x8802_fc01,
        0x35ff_ff82,
        0x17ff_fffc,
    ]);
    let code = analyze(&p, &[BASE], &[]);
    assert_eq!(code.flags(BASE) & PAIR, 0);
    assert_ne!(code.flags(BASE + 4) & PAIR, 0);
    assert_eq!(code.flags(BASE + 0x10) & PAIR, 0);
    assert_eq!(
        sites(&code, 0x80_0000),
        [
            (BASE + 0x08, Class::BackBranch, Outcome::Exclusive),
            (BASE + 0x10, Class::BackBranch, Outcome::Exclusive),
            (BASE + 0x14, Class::BackBranch, Outcome::Exclusive),
        ]
    );
}

/// A literal load of a word control flow also reaches taints the span between the function
/// starts around it; the next function is untouched.
///
/// ```text
/// 00  52800000  mov w0, #0
/// 04  11000400  L: add w0, w0, #1
/// 08  18ffffe5  ldr w5, L
/// 0c  34ffffc5  cbz w5, L
/// 10  d65f03c0  ret
/// 14  37000000  G: tbnz w0, #0, G    (another function, an anchor)
/// 18  d65f03c0  ret
/// ```
#[test]
fn a_word_code_reads_taints_its_function() {
    let p = bytes(&[
        0x5280_0000,
        0x1100_0400,
        0x18ff_ffe5,
        0x34ff_ffc5,
        0xd65f_03c0,
        0x3700_0000,
        0xd65f_03c0,
    ]);
    let code = analyze(&p, &[BASE, BASE + 0x14], &[]);
    assert_eq!(code.refusals.read, 1);
    assert_ne!(code.flags(BASE + 4) & TAINT, 0);
    assert_eq!(
        sites(&code, 0x80_0000),
        [
            (BASE + 0x0c, Class::BackBranch, Outcome::Tainted),
            (BASE + 0x14, Class::BackBranch, Outcome::InPlace),
        ]
    );
}

/// The assembler's `$d` over a word control flow reaches: it is not decoded, and its function
/// is tainted.
#[test]
fn words_marked_data_are_never_code() {
    let p = program();
    let code = analyze(&p, &[BASE], &[(BASE + 0x10, BASE + 0x14)]);
    assert_eq!(code.refusals.data, 1);
    assert_eq!(code.flags(BASE + 0x10) & PROVEN, 0);
    assert!(sites(&code, 0x80_0000)
        .iter()
        .all(|&(_, _, o)| o == Outcome::Tainted));
}

/// A backward `tbnz` and `bl` are sites (the call's patch keeps the link); a hinted `bc.ne`
/// and a landing pad are not.
///
/// ```text
/// 00  d65f03c0  F: ret
/// 04  37180000  G: tbnz w0, #3, G
/// 08  97fffffe  bl F
/// 0c  54ffffd1  bc.ne G
/// 10  d503245f  bti c
/// 14  d65f03c0  ret
/// ```
#[test]
fn site_classes() {
    let p = bytes(&[
        0xd65f_03c0,
        0x3718_0000,
        0x97ff_fffe,
        0x54ff_ffd1,
        0xd503_245f,
        0xd65f_03c0,
    ]);
    let code = analyze(&p, &[BASE + 4], &[]);
    assert_eq!(
        sites(&code, 0x80_0000),
        [
            (BASE + 0x04, Class::BackBranch, Outcome::InPlace),
            (BASE + 0x08, Class::BackCall, Outcome::InPlace),
        ]
    );
    let e = emit(&code, 0x80_0000);
    assert_eq!(e.sites[1].kind, KIND_JUMP);
    let (at, patch) = &e.patched[1];
    assert_eq!(*at, BASE + 8);
    // `bl`, not `b`: the call's return address is the program's own.
    assert_eq!(
        u32::from_le_bytes(patch[..].try_into().unwrap()) >> 26,
        0b100101
    );
}

/// Trampolines a `b` cannot reach (±128 MiB) leave their sites alone.
#[test]
fn a_site_out_of_reach_of_its_trampoline_is_not_patched() {
    let p = program();
    let code = analyze(&p, &[BASE], &[]);
    let e = emit(&code, BASE + (1 << 27));
    assert!(e.choices.iter().all(|c| c.outcome == Outcome::Far));
    assert!(e.sites.is_empty() && e.patched.is_empty());
    let e = emit(&code, (BASE + (1 << 27) - PAGE) & !(PAGE - 1));
    assert!(e.choices.iter().all(|c| c.outcome == Outcome::InPlace));
}

/// A call whose trampoline is in reach but whose target is not from it (a `b` reaches
/// ±128 MiB) goes on through `x16`, where `far` allows it; else it is left. The verifier
/// takes it only to another function's start: not to a label inside the caller's own
/// function, where `x16` may be live across the call.
///
/// ```text
/// 00  d65f03c0  F: ret                 00  14000002  G: b  C
/// 04  97ffffff  G: bl F                04  d65f03c0  F: ret
/// 08  d65f03c0  ret                    08  97ffffff  C: bl F
///                                      0c  d65f03c0     ret
/// ```
#[test]
fn a_call_to_a_target_out_of_reach_goes_through_x16() {
    let p = bytes(&[0xd65f_03c0, 0x97ff_ffff, 0xd65f_03c0]);
    let code = analyze(&p, &[BASE + 4], &[]);
    // T 4 bytes inside the reach of the call; its row's `b F`, 28 bytes on, is not.
    let place = Place {
        after: BASE + (1 << 27),
        before: None,
    };
    let e = points::emit(&code, place, &|_, _| false);
    assert_eq!(e.choices[0].outcome, Outcome::Far);
    let e = points::emit(&code, place, &|_, to| to == BASE);
    assert_eq!(e.choices[0].outcome, Outcome::InPlace);
    assert_eq!(e.sites[0].kind, KIND_FAR);
    let mut f = elf(&p);
    f[0x18..0x20].copy_from_slice(&(BASE + 4).to_le_bytes());
    let good = plan_of(&f, e);
    assert_eq!(verify(&f, &good), Vec::<String>::new());
    // The row aimed elsewhere.
    let mut bad = good.clone();
    let o = (bad.sites[0].tramp + bad.sites[0].copy as u32 + 4) as usize;
    bad.tramp[o + 1] ^= 4;
    assert!(!verify(&f, &bad).is_empty());
    // A call to a label inside its own function.
    let p = bytes(&[0x1400_0002, 0xd65f_03c0, 0x97ff_ffff, 0xd65f_03c0]);
    let f = elf(&p);
    let e = crate::rewrite::elf::Elf::parse(&f).unwrap();
    let good = super::make_plan(&e, "test").unwrap();
    assert_eq!(verify(&f, &good), Vec::<String>::new());
    let got = verify(
        &f,
        &one_site(&f, &good, BASE + 8, 0x97ff_ffff, KIND_FAR, BASE + 4),
    );
    assert!(!got.is_empty() && got.iter().all(|g| g.starts_with("site 0x401008")));
}

/// Sites below the split get their trampolines before the image, in a file placed at load
/// time; a file loaded at its link addresses may not have them there.
#[test]
fn trampolines_before_the_image() {
    let p = program();
    let code = analyze(&p, &[BASE], &[]);
    let place = Place {
        after: BASE + 0x1000,
        before: Some((BASE - PAGE, BASE + 0x12)),
    };
    let e = points::emit(&code, place, &|_, _| false);
    assert!(e.choices.iter().all(|c| c.outcome == Outcome::InPlace));
    let at = |a: u64| {
        let s = e.sites.iter().find(|s| s.addr == a).unwrap();
        e.tramp_vaddr + s.tramp as u64
    };
    assert!(at(BASE + 0x0c) < at(BASE + 0x10) && at(BASE + 0x10) < BASE - PAGE);
    assert!(at(BASE + 0x14) >= BASE + 0x1000 && at(BASE + 0x18) > at(BASE + 0x14));
    let f = elf_dyn(&p);
    let plan = plan_of(&f, e);
    assert_eq!(verify(&f, &plan), Vec::<String>::new());
    let mut stand = vec![];
    assert!(crate::rewrite::standalone::apply(&f, &plan, 1 << 40)
        .map(|c| stand = c)
        .is_err());
    assert!(
        stand.is_empty(),
        "a file with no interpreter cannot move them"
    );
    let f = elf(&p);
    let plan = Plan {
        sha256: crate::rewrite::elf::Elf::parse(&f).unwrap().sha256,
        ..plan
    };
    assert!(!verify(&f, &plan).is_empty());
}

#[test]
fn plans_are_deterministic_and_round_trip() {
    let f = elf(&program());
    let a = super::make_plan(&crate::rewrite::elf::Elf::parse(&f).unwrap(), "test")
        .unwrap()
        .to_bytes();
    let b = super::make_plan(&crate::rewrite::elf::Elf::parse(&f).unwrap(), "test")
        .unwrap()
        .to_bytes();
    assert_eq!(a, b);
    let p = Plan::from_bytes(&a).unwrap();
    assert_eq!(p.to_bytes(), a);
    assert_eq!(p.machine, 183);
    assert!(Plan::from_bytes(&a[..a.len() - 1]).is_err());
}

/// Every kind of corruption is a verification failure.
#[test]
fn the_verifier_rejects_corrupted_plans() {
    let f = elf(&program());
    let good = super::make_plan(&crate::rewrite::elf::Elf::parse(&f).unwrap(), "test").unwrap();
    assert_eq!(verify(&f, &good), Vec::<String>::new());
    assert_eq!(good.sites.len(), 4);
    let find = |k: u8| good.sites.iter().position(|s| s.kind == k).unwrap();
    let (cond, before) = (find(KIND_COND), find(KIND_BEFORE));
    fn word(p: &mut Plan, vaddr: u64) -> &mut [u8] {
        let pg = p
            .pages
            .iter_mut()
            .find(|pg| vaddr >= pg.vaddr && vaddr < pg.vaddr + pg.bytes.len() as u64)
            .unwrap();
        let o = (vaddr - pg.vaddr) as usize;
        &mut pg.bytes[o..o + 4]
    }
    fn tword(p: &mut Plan, site: usize, off: u32) -> &mut [u8] {
        let o = (p.sites[site].tramp + off) as usize;
        &mut p.tramp[o..o + 4]
    }
    type Corrupt = Box<dyn Fn(&mut Plan)>;
    let cases: Vec<(&str, Corrupt)> = vec![
        (
            "a changed word outside every site",
            Box::new(|p| word(p, BASE + 4)[0] ^= 1),
        ),
        (
            "a site moved off its word",
            Box::new(move |p| p.sites[cond].addr += 4),
        ),
        (
            "a site moved onto words control flow does not reach",
            Box::new(move |p| p.sites[before].addr = BASE + 0x1c),
        ),
        (
            "a site two words long",
            Box::new(move |p| p.sites[before].len = 8),
        ),
        (
            "a patch aimed elsewhere",
            Box::new(|p| word(p, BASE + 0x10)[0] ^= 1),
        ),
        (
            "a patch with link where the site has none",
            Box::new(|p| word(p, BASE + 0x10)[3] |= 0x80),
        ),
        (
            "a trampoline that tests another condition",
            Box::new(move |p| tword(p, cond, 0)[0] ^= 1),
        ),
        (
            "a trampoline whose fall-through goes elsewhere",
            Box::new(move |p| tword(p, cond, 4)[0] ^= 1),
        ),
        (
            "the count not in the cell",
            Box::new(move |p| tword(p, before, 4)[1] ^= 1),
        ),
        (
            "a count that saves into the frame",
            Box::new(move |p| tword(p, before, 0)[2] ^= 0x10),
        ),
        (
            "a count that adds",
            Box::new(move |p| tword(p, before, 12)[3] ^= 0x40),
        ),
        (
            "a count that branches past its restore",
            Box::new(move |p| tword(p, before, 20)[0] ^= 0x20),
        ),
        (
            "a copy of another instruction",
            Box::new(move |p| {
                let c = p.sites[before].copy as u32;
                tword(p, before, c)[0] ^= 1
            }),
        ),
        (
            "a row that returns to the wrong word",
            Box::new(move |p| {
                let c = p.sites[before].copy as u32;
                tword(p, before, c + 4)[0] ^= 1
            }),
        ),
        (
            "a jump row that goes to the wrong target",
            Box::new(move |p| {
                let c = p.sites[cond].copy as u32;
                tword(p, cond, c)[0] ^= 1
            }),
        ),
        (
            "a trap that is not `udf`",
            Box::new(move |p| {
                let t = p.sites[before].trap as u32;
                tword(p, before, t)[2] = 1
            }),
        ),
        (
            "a trap that does not restore first",
            Box::new(move |p| {
                let t = p.sites[before].trap as u32;
                tword(p, before, t - 4)[0] ^= 1
            }),
        ),
        (
            "a trap offset off its trap",
            Box::new(move |p| p.sites[before].trap += 4),
        ),
        (
            "a trampoline past the span",
            Box::new(move |p| p.sites[before].tramp = p.tramp.len() as u32),
        ),
        (
            "a kind the word may not carry",
            Box::new(move |p| p.sites[before].kind = KIND_JUMP),
        ),
        (
            "trampolines inside the image",
            Box::new(|p| p.tramp_vaddr = BASE),
        ),
        ("the plan of another file", Box::new(|p| p.sha256[0] ^= 1)),
        ("the plan of another machine", Box::new(|p| p.machine = 62)),
        ("a cell not the runtime's", Box::new(|p| p.cell += 8)),
        (
            "an entry row",
            Box::new(|p| {
                p.entries.push(Entry {
                    addr: BASE + 0x0c,
                    to: 0,
                    kind: proto::plan::KIND_CPUID,
                })
            }),
        ),
    ];
    for (what, corrupt) in cases {
        let mut p = good.clone();
        corrupt(&mut p);
        assert!(!verify(&f, &p).is_empty(), "accepted: {what}");
    }
}

/// The verifier finds pairs and the loops through them its own way: a plan whose only site is
/// a well-formed count on a branch inside one, or on its retry, is rejected.
///
/// ```text
/// 00  885ffc01  P: ldaxr w1, [x0]
/// 04  11000421  R: add   w1, w1, #1
/// 08  34ffffe1  cbz   w1, R          inside the pair
/// 0c  8802fc01  stlxr w2, w1, [x0]
/// 10  35ffff82  cbnz  w2, P          the retry
/// 14  d65f03c0  ret
/// ```
#[test]
fn the_verifier_rejects_a_count_inside_an_exclusive_pair_or_on_its_retry() {
    let p = bytes(&[
        0x885f_fc01,
        0x1100_0421,
        0x34ff_ffe1,
        0x8802_fc01,
        0x35ff_ff82,
        0xd65f_03c0,
    ]);
    let f = elf(&p);
    let good = super::make_plan(&crate::rewrite::elf::Elf::parse(&f).unwrap(), "test").unwrap();
    assert_eq!(verify(&f, &good), Vec::<String>::new());
    assert!(good.sites.is_empty());
    // A plan whose one site is the `cbz` inside the pair, or the retry `cbnz`.
    for (a, w, target) in [
        (BASE + 8, 0x34ff_ffe1, BASE + 4),
        (BASE + 0x10, 0x35ff_ff82, BASE),
    ] {
        let got = verify(&f, &one_site(&f, &good, a, w, KIND_COND, target));
        assert!(!got.is_empty());
        assert!(
            got.iter().all(|g| g.starts_with(&format!("site {a:#x}"))),
            "{got:?}"
        );
    }
}

/// `good` with one site: the word `w` at `a`, of `kind`, its own trampoline and patch.
fn one_site(f: &[u8], good: &Plan, a: u64, w: u32, kind: u8, target: u64) -> Plan {
    let mut bad = good.clone();
    let (words, mut site, patch) =
        points::trampoline(a, w, kind, Some(target), bad.tramp_vaddr).unwrap();
    site.tramp = 0;
    bad.sites = vec![site];
    bad.tramp = bytes(&words);
    bad.tramp.resize(PAGE as usize, 0);
    let e = crate::rewrite::elf::Elf::parse(f).unwrap();
    bad.pages = super::pages(&e, &[(a, patch.to_le_bytes().to_vec())]).unwrap();
    bad
}

/// A weak compare-and-swap in a loop: when the store fails (as it may with no other writer),
/// the loop goes round again, and the way back to the load holds no site; the verifier
/// rejects one there. Around a strong one (its retry straight back to the load) only the
/// retry is left: the loop around it runs as often whatever the store does.
///
/// ```text
/// 00  11000424  H: add   w4, w1, #1          00  11000424  H: add   w4, w1, #1
/// 04  885ffc01  L: ldaxr w1, [x0]            04  885ffc01  L: ldaxr w1, [x0]
/// 08  8802fc04     stlxr w2, w4, [x0]        08  8802fc04     stlxr w2, w4, [x0]
/// 0c  34000062     cbz   w2, D               0c  35ffffc2     cbnz  w2, L
/// 10  110004a5     add   w5, w5, #1          10  f10004a5     subs  x5, x5, #1
/// 14  17fffffb     b     H                   14  54ffff61     b.ne  H
/// 18  d65f03c0  D: ret                       18  d65f03c0     ret
/// 1c  17ffffff  E: b     D
/// ```
#[test]
fn no_count_on_the_way_back_from_a_failed_store_exclusive() {
    let p = bytes(&[
        0x1100_0424,
        0x885f_fc01,
        0x8802_fc04,
        0x3400_0062,
        0x1100_04a5,
        0x17ff_fffb,
        0xd65f_03c0,
        0x17ff_ffff,
    ]);
    let code = analyze(&p, &[BASE, BASE + 0x1c], &[]);
    let retry: Vec<u64> = (0..8)
        .map(|k| BASE + 4 * k)
        .filter(|&a| code.flags(a) & RETRY != 0)
        .collect();
    assert_eq!(retry, [BASE, BASE + 0x0c, BASE + 0x10, BASE + 0x14]);
    assert_eq!(
        sites(&code, 0x80_0000),
        [
            (BASE + 0x14, Class::BackBranch, Outcome::Exclusive),
            (BASE + 0x1c, Class::BackBranch, Outcome::InPlace),
        ]
    );
    let f = elf(&p);
    let good = super::make_plan(&crate::rewrite::elf::Elf::parse(&f).unwrap(), "test").unwrap();
    assert_eq!(verify(&f, &good), Vec::<String>::new());
    let got = verify(
        &f,
        &one_site(&f, &good, BASE + 0x14, 0x17ff_fffb, KIND_JUMP, BASE),
    );
    assert_eq!(got.len(), 1, "{got:?}");
    assert!(got[0].starts_with(&format!("site {:#x}", BASE + 0x14)));

    let p = bytes(&[
        0x1100_0424,
        0x885f_fc01,
        0x8802_fc04,
        0x35ff_ffc2,
        0xf100_04a5,
        0x54ff_ff61,
        0xd65f_03c0,
    ]);
    let code = analyze(&p, &[BASE], &[]);
    assert_eq!(
        sites(&code, 0x80_0000),
        [
            (BASE + 0x0c, Class::BackBranch, Outcome::Exclusive),
            (BASE + 0x14, Class::BackBranch, Outcome::InPlace),
        ]
    );
    let f = elf(&p);
    let good = super::make_plan(&crate::rewrite::elf::Elf::parse(&f).unwrap(), "test").unwrap();
    assert_eq!(verify(&f, &good), Vec::<String>::new());
    assert_eq!(good.sites.len(), 1);
}

/// A jump through `x16` is only for a call or a jump from one function into another: the
/// function starts (here only the entry) part the text.
#[test]
fn a_jump_inside_one_function_is_never_far() {
    let p = bytes(&[0xd65f_03c0; 4]);
    let mut f = elf(&p);
    let e = crate::rewrite::elf::Elf::parse(&f).unwrap();
    assert!(e.one_function(&e.anchors, BASE, BASE + 8));
    f[0x18..0x20].copy_from_slice(&(BASE + 4).to_le_bytes());
    let e = crate::rewrite::elf::Elf::parse(&f).unwrap();
    assert!(!e.one_function(&e.anchors, BASE, BASE + 8));
    assert!(e.one_function(&e.anchors, BASE + 4, BASE + 8));
}

/// A call inside an exclusive pair (reached through a `b`), a word whose address code takes,
/// and a site between the function starts around a word that is not code: none is patched,
/// and the verifier rejects a plan with a count on any of them.
///
/// ```text
/// 00  d65f03c0  F: ret                 00  10000060  adr  x0, B       00  d503201f  L: nop
/// 04  885ffc01  L: ldaxr w1, [x0]      04  d503201f  L: nop           04  35ffffe0  cbnz w0, L
/// 08  14000002     b     C             08  d503201f     nop           08  d4000002  hvc  #0
/// 0c  d503201f     nop                 0c  54ffffc1  B: b.ne L
/// 10  97fffffc  C: bl    F             10  d65f03c0     ret
/// 14  8802fc01     stlxr w2, w1, [x0]
/// 18  35ffff62     cbnz  w2, L
/// 1c  d65f03c0     ret
/// ```
#[test]
fn no_count_on_a_call_in_a_pair_a_word_whose_address_is_taken_or_beside_data() {
    let pair = bytes(&[
        0xd65f_03c0,
        0x885f_fc01,
        0x1400_0002,
        0xd503_201f,
        0x97ff_fffc,
        0x8802_fc01,
        0x35ff_ff62,
        0xd65f_03c0,
    ]);
    let adr = bytes(&[
        0x1000_0060,
        0xd503_201f,
        0xd503_201f,
        0x54ff_ffc1,
        0xd65f_03c0,
    ]);
    let hvc = bytes(&[0xd503_201f, 0x35ff_ffe0, 0xd400_0002]);
    for (p, entry, (a, w, kind, target), outcome) in [
        (
            &pair,
            BASE + 4,
            (BASE + 0x10, 0x97ff_fffc, KIND_JUMP, BASE),
            Outcome::Exclusive,
        ),
        (
            &adr,
            BASE,
            (BASE + 0x0c, 0x54ff_ffc1, KIND_COND, BASE + 4),
            Outcome::Tainted,
        ),
        (
            &hvc,
            BASE,
            (BASE + 4, 0x35ff_ffe0, KIND_COND, BASE),
            Outcome::Tainted,
        ),
    ] {
        let code = analyze(p, &[entry], &[]);
        let got = sites(&code, 0x80_0000);
        assert_eq!(got.iter().find(|s| s.0 == a).map(|s| s.2), Some(outcome));
        let mut f = elf(p);
        f[0x18..0x20].copy_from_slice(&entry.to_le_bytes());
        let e = crate::rewrite::elf::Elf::parse(&f).unwrap();
        let good = super::make_plan(&e, "test").unwrap();
        assert_eq!(verify(&f, &good), Vec::<String>::new());
        assert!(good.sites.iter().all(|s| s.addr != a));
        let got = verify(&f, &one_site(&f, &good, a, w, kind, target));
        assert!(!got.is_empty() && got.iter().all(|g| g.starts_with(&format!("site {a:#x}"))));
    }
}
