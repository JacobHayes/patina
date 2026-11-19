//! The rewriter on hand-written instruction sequences: what is code, where counts go, flag
//! liveness, the plan and its verifier. Encodings are spelled out byte by byte.

use super::code::{Code, TAINT};
use super::flags::dead_at;
use super::plan::{Plan, KIND_BEFORE, KIND_JUMP, PAGE};
use super::points::{self, relocatable, Class, Outcome};
use super::verify::verify;
use super::x86::make_plan;

const BASE: u64 = 0x40_1000;

fn analyze<'a>(code: &'a [u8], anchors: &[u64], extents: &[(u64, u64)]) -> Code<'a> {
    Code::analyze(&[(BASE, code)], anchors, extents, true)
}

fn outcome(code: &Code, at: u64) -> Option<Outcome> {
    points::select(code)
        .0
        .into_iter()
        .find(|c| c.addr == at)
        .map(|c| c.outcome)
}

/// An ET_EXEC file: one read+execute segment holding `code` at `BASE`, the entry at its start,
/// no section headers (so the only anchor is the entry).
fn elf(code: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; 0x1000];
    f[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    let put = |f: &mut Vec<u8>, at: usize, v: &[u8]| f[at..at + v.len()].copy_from_slice(v);
    put(&mut f, 0x10, &2u16.to_le_bytes());
    put(&mut f, 0x12, &62u16.to_le_bytes());
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

/// A loop closed by `jl rel32` (flags dead at its head: `add` writes them), a `lock inc` with
/// a RIP-relative operand, then a jump over bytes that are not code.
///
/// ```text
/// 401000  b8 00 00 00 00        mov eax, 0
/// 401005  83 c0 01           L: add eax, 1
/// 401008  3d 10 00 00 00        cmp eax, 16
/// 40100d  0f 8c f2 ff ff ff     jl L
/// 401013  f0 ff 05 17 00 00 00  lock inc dword [rip+0x17]    ; 401031
/// 40101a  e9 21 00 00 00        jmp 401040
/// 40101f  90 b8 11 22 33 44 ..  not code (never reached; a 5-byte `mov` look-alike at 401020)
/// 401040  c3                    ret
/// ```
fn program() -> Vec<u8> {
    let mut c = vec![
        0xb8, 0, 0, 0, 0, 0x83, 0xc0, 0x01, 0x3d, 0x10, 0, 0, 0, 0x0f, 0x8c, 0xf2, 0xff, 0xff, 0xff,
    ];
    c.extend([0xf0, 0xff, 0x05, 0x17, 0, 0, 0, 0xe9, 0x21, 0, 0, 0]);
    c.push(0x90);
    c.extend([0xb8, 0x11, 0x22, 0x33, 0x44]);
    c.resize(0x40, 0x90);
    c.push(0xc3);
    c
}

#[test]
fn a_loop_and_an_atomic_get_counts_in_place() {
    let code = program();
    let c = analyze(&code, &[BASE], &[]);
    assert_eq!(outcome(&c, BASE + 0xd), Some(Outcome::InPlace(BASE + 0xd)));
    assert_eq!(
        outcome(&c, BASE + 0x13),
        Some(Outcome::InPlace(BASE + 0x13))
    );
    let plan = make_plan(&elf(&code), "test").unwrap();
    let kinds: Vec<(u64, u8)> = plan.sites.iter().map(|s| (s.addr, s.kind)).collect();
    assert_eq!(kinds, [(BASE + 0xd, KIND_JUMP), (BASE + 0x13, KIND_BEFORE)]);
    assert_eq!(verify(&elf(&code), &plan), Vec::<String>::new());
}

#[test]
fn bytes_no_control_flow_reaches_are_dark_and_not_patched() {
    let code = program();
    let c = analyze(&code, &[BASE], &[]);
    assert!(c.len_at(BASE + 0x20).is_none());
    assert!(c.census().dark > 0);
    assert!(points::select(&c)
        .0
        .iter()
        .all(|ch| ch.addr < BASE + 0x1f || ch.addr >= BASE + 0x40));
}

/// Inside a function's extent, linear decode covers what control flow did not; it stops at a
/// byte that code reads.
///
/// ```text
/// 401000  48 8b 05 05 00 00 00  mov rax, [rip+5]              ; reads 40100c
/// 401007  e9 0c 00 00 00        jmp 401018
/// 40100c  f0 48 0f c1 05 00..   data that decodes as lock xadd [rip+0], rax
/// 401015  90 90 90
/// 401018  c3                    ret
/// ```
#[test]
fn data_in_text_that_code_reads_ends_extent_decode() {
    let tail = [
        0xe9, 0x0c, 0, 0, 0, 0xf0, 0x48, 0x0f, 0xc1, 0x05, 0, 0, 0, 0, 0x90, 0x90, 0x90, 0xc3,
    ];
    let mut reads = vec![0x48, 0x8b, 0x05, 0x05, 0, 0, 0];
    reads.extend(tail);
    let mut no_read = vec![0xb8, 0, 0, 0, 0, 0x90, 0x90];
    no_read.extend(tail);
    let extent = [(BASE, BASE + reads.len() as u64)];
    let data = BASE + 0xc;
    let c = analyze(&reads, &[BASE], &extent);
    assert!(c.len_at(data).is_none());
    assert_eq!(outcome(&c, data), None);
    // Not PIE: an absolute read of the same bytes (`mov eax, [abs32]`) ends it too.
    let mut abs_read = vec![0x8b, 0x04, 0x25];
    abs_read.extend((data as u32).to_le_bytes());
    abs_read.extend(tail);
    let c = analyze(&abs_read, &[BASE], &extent);
    assert!(c.len_at(data).is_none());
    // The same bytes, not read: the extent rule decodes them, and the look-alike is a site.
    let c = analyze(&no_read, &[BASE], &extent);
    assert_eq!(c.len_at(data), Some(9));
    assert!(outcome(&c, data).is_some());
}

/// Two anchors whose decodes overlap: `mov eax, imm32` at 401000 and `ret` at 401001.
#[test]
fn overlapping_decodes_taint_both_spans() {
    let code = [0xb8, 0xc3, 0x90, 0x90, 0x90, 0xc3];
    let c = analyze(&code, &[BASE, BASE + 1], &[]);
    assert!(c.refusals.conflict > 0);
    assert!(c.flags(BASE) & TAINT != 0);
    assert!(c.flags(BASE + 1) & TAINT != 0);
}

/// A loop whose only 5-byte instruction is entered in its middle by a direct jump:
///
/// ```text
/// 401000  83 c0 01           L: add eax, 1
/// 401003  b9 05 00 00 00        mov ecx, 5
/// 401008  39 d8                 cmp eax, ebx
/// 40100a  7c f4                 jl L
/// 40100c  eb f6                 jmp 401004            ; inside the mov
/// ```
#[test]
fn a_jump_into_a_would_be_patch_taints_it() {
    let code = [
        0x83, 0xc0, 0x01, 0xb9, 0x05, 0, 0, 0, 0x39, 0xd8, 0x7c, 0xf4, 0xeb, 0xf6,
    ];
    let c = analyze(&code, &[BASE], &[]);
    assert!(c.refusals.conflict > 0);
    assert_eq!(outcome(&c, BASE + 0xa), Some(Outcome::Tainted));
    assert!(points::select(&c).1.is_empty());
}

/// Short backward branches: the count moves to a 5-byte instruction of the block, or of the
/// loop head; with none of 5 bytes, there is no room.
#[test]
fn a_short_branch_moves_its_count_or_has_no_room() {
    // L: add eax, 1; cmp eax, 16 (3d imm32); jl L (rel8)
    let code = [0x83, 0xc0, 0x01, 0x3d, 0x10, 0, 0, 0, 0x7c, 0xf6, 0xc3];
    let c = analyze(&code, &[BASE], &[]);
    assert_eq!(outcome(&c, BASE + 8), Some(Outcome::Moved(BASE + 3)));
    // L: mov edx, 7; jmp M; M: add eax, 1; jmp L (rel8): the block that ends at the branch
    // starts at M and has no 5-byte instruction; the loop head has one.
    let code = [
        0xba, 7, 0, 0, 0, 0xeb, 0x00, 0x83, 0xc0, 0x01, 0xeb, 0xf4, 0xc3,
    ];
    let c = analyze(&code, &[BASE], &[]);
    assert_eq!(outcome(&c, BASE + 0xa), Some(Outcome::Moved(BASE)));
    // L: add eax, 1; cmp eax, ebx; jl L: nothing of 5 bytes
    let code = [0x83, 0xc0, 0x01, 0x39, 0xd8, 0x7c, 0xf9, 0xc3];
    let c = analyze(&code, &[BASE], &[]);
    assert_eq!(outcome(&c, BASE + 5), Some(Outcome::NoRoom));
}

/// L: add eax, 1; cmp eax, ebx; mov ecx, 5; jl L — the only 5-byte instruction sits between
/// the `cmp` and the `jl` that reads its flags.
#[test]
fn a_count_is_not_placed_where_flags_are_live() {
    let code = [
        0x83, 0xc0, 0x01, 0x39, 0xd8, 0xb9, 5, 0, 0, 0, 0x7c, 0xf4, 0xc3,
    ];
    let c = analyze(&code, &[BASE], &[]);
    assert_eq!(outcome(&c, BASE + 0xa), Some(Outcome::FlagsLive));
}

fn dead(code: &[u8]) -> bool {
    dead_at(&analyze(code, &[BASE], &[]), BASE)
}

#[test]
fn flag_liveness() {
    // written before read: cmp, then jz
    assert!(dead(&[0x39, 0xd8, 0x74, 0x00, 0xc3]));
    // read first: jz
    assert!(!dead(&[0x74, 0x00, 0xc3]));
    // a return and a call of a function end a path well
    assert!(dead(&[0x90, 0xc3]));
    assert!(dead(&[
        0xe8, 0x01, 0, 0, 0, 0xcc, 0x39, 0xd8, 0x74, 0x00, 0xc3
    ]));
    // a shift by 1 writes them; a shift by cl may write nothing
    assert!(dead(&[0xd1, 0xe0, 0x74, 0x00, 0xc3]));
    assert!(!dead(&[0xd3, 0xe0, 0x74, 0x00, 0xc3]));
    // so may a repeated string compare (rcx = 0)
    assert!(!dead(&[0xf3, 0xa6, 0x74, 0x00, 0xc3]));
    // both sides of a branch that reads no flags (jrcxz): one reads them, or neither does
    assert!(!dead(&[0xe3, 0x03, 0x39, 0xd8, 0xc3, 0x74, 0x00, 0xc3]));
    assert!(dead(&[0xe3, 0x03, 0x39, 0xd8, 0xc3, 0x85, 0xc0, 0xc3]));
    // unknown successors: an indirect jump, a system call, a trap
    assert!(!dead(&[0xff, 0xe0]));
    assert!(!dead(&[0x0f, 0x05, 0x39, 0xd8, 0xc3]));
    assert!(!dead(&[0x0f, 0x0b]));
    // a long path without a write
    assert!(!dead(&[[0x90; 200].as_slice(), &[0xc3]].concat()));
}

#[test]
fn landing_pads_and_traps_are_never_relocated() {
    let i = |b: &[u8]| super::code::decode_at(b, BASE, 0);
    assert!(!relocatable(&i(&[0xf3, 0x0f, 0x1e, 0xfa])));
    assert!(!relocatable(&i(&[0xf4])));
    assert!(!relocatable(&i(&[0xe8, 0, 0, 0, 0])));
    assert!(relocatable(&i(&[0xb8, 0, 0, 0, 0])));
}

#[test]
fn a_copied_rip_relative_operand_addresses_the_same_memory() {
    let code = program();
    let plan = make_plan(&elf(&code), "test").unwrap();
    let s = plan.sites.iter().find(|s| s.kind == KIND_BEFORE).unwrap();
    let at = (s.tramp + s.copy as u32) as usize;
    let copy = super::code::decode_at(&plan.tramp, plan.tramp_vaddr, at);
    let orig = super::code::decode_at(&code, BASE, (s.addr - BASE) as usize);
    assert!(copy.is_ip_rel_memory_operand());
    assert_eq!(copy.ip_rel_memory_address(), orig.ip_rel_memory_address());
    assert_ne!(copy.ip(), orig.ip());
}

/// A patched instruction across a page boundary: both pages are in the plan.
///
/// ```text
/// 401000  90 ...                nops up to the loop
/// 401ffd  b8 01 00 00 00     L: mov eax, 1
/// 402002  39 d8                 cmp eax, ebx
/// 402004  75 f7                 jne L
/// 402006  c3                    ret
/// ```
#[test]
fn a_patch_across_a_page_boundary() {
    let mut code = vec![0x90; 0xffd];
    code.extend([0xb8, 1, 0, 0, 0, 0x39, 0xd8, 0x75, 0xf7, 0xc3]);
    let plan = make_plan(&elf(&code), "test").unwrap();
    let site = plan
        .sites
        .iter()
        .find(|s| s.addr == BASE + 0xffd)
        .expect("the mov is patched");
    assert_eq!(site.kind, KIND_BEFORE);
    let covered: Vec<u64> = plan
        .pages
        .iter()
        .flat_map(|p| (0..p.bytes.len() as u64 / PAGE).map(move |k| p.vaddr + k * PAGE))
        .collect();
    assert_eq!(covered, [BASE, BASE + PAGE]);
    assert_eq!(verify(&elf(&code), &plan), Vec::<String>::new());
}

#[test]
fn plans_are_deterministic_and_round_trip() {
    let f = elf(&program());
    let a = make_plan(&f, "test").unwrap().to_bytes();
    let b = make_plan(&f, "test").unwrap().to_bytes();
    assert_eq!(a, b);
    let p = Plan::from_bytes(&a).unwrap();
    assert_eq!(p.to_bytes(), a);
    assert!(Plan::from_bytes(&a[..a.len() - 1]).is_err());
}

/// Every kind of corruption is a verification failure.
#[test]
fn the_verifier_rejects_corrupted_plans() {
    let f = elf(&program());
    let good = make_plan(&f, "test").unwrap();
    assert_eq!(verify(&f, &good), Vec::<String>::new());
    let jump = good.sites.iter().position(|s| s.kind == KIND_JUMP).unwrap();
    let before = good
        .sites
        .iter()
        .position(|s| s.kind == KIND_BEFORE)
        .unwrap();
    fn byte(p: &mut Plan, vaddr: u64) -> &mut u8 {
        let pg = p
            .pages
            .iter_mut()
            .find(|pg| vaddr >= pg.vaddr && vaddr < pg.vaddr + pg.bytes.len() as u64)
            .unwrap();
        &mut pg.bytes[(vaddr - pg.vaddr) as usize]
    }
    type Corrupt = Box<dyn Fn(&mut Plan)>;
    let cases: Vec<(&str, Corrupt)> = vec![
        (
            "a changed byte outside every site",
            Box::new(|p| *byte(p, BASE + 1) ^= 1),
        ),
        (
            "a site moved off its instruction start",
            Box::new(move |p| p.sites[jump].addr += 1),
        ),
        (
            "a site longer than its instruction",
            Box::new(move |p| p.sites[before].len += 1),
        ),
        (
            "a site moved onto bytes that are not code",
            Box::new(move |p| p.sites[before].addr = BASE + 0x20),
        ),
        (
            "a trampoline that returns to the wrong address",
            Box::new(move |p| {
                let s = &p.sites[before];
                let at = (s.tramp + s.trap as u32) as usize - 4;
                p.tramp[at] = p.tramp[at].wrapping_add(1);
            }),
        ),
        (
            "a jump trampoline that goes to the wrong target",
            Box::new(move |p| {
                let s = &p.sites[jump];
                let at = (s.tramp + s.trap as u32) as usize - 4;
                p.tramp[at] = p.tramp[at].wrapping_sub(1);
            }),
        ),
        (
            "a copy with another displacement",
            Box::new(move |p| {
                let s = &p.sites[before];
                p.tramp[(s.tramp + s.copy as u32) as usize + 3] ^= 4;
            }),
        ),
        (
            "a patch aimed elsewhere",
            Box::new(move |p| *byte(p, BASE + 0x13 + 1) ^= 2),
        ),
        (
            "a trampoline past the blob",
            Box::new(move |p| p.sites[jump].tramp = p.tramp.len() as u32),
        ),
        (
            "a trap outside its trampoline",
            Box::new(move |p| p.sites[jump].trap = p.sites[jump].tramp_len),
        ),
        ("an unknown kind", Box::new(move |p| p.sites[jump].kind = 9)),
        ("the plan of another file", Box::new(|p| p.sha256[0] ^= 1)),
        ("a cell inside the image", Box::new(|p| p.cell = BASE + 8)),
        ("a cell not the runtime's", Box::new(|p| p.cell += 8)),
        (
            "the count not in the cell",
            Box::new(move |p| p.tramp[p.sites[jump].tramp as usize + 4] ^= 8),
        ),
    ];
    for (what, corrupt) in cases {
        let mut p = good.clone();
        corrupt(&mut p);
        assert!(!verify(&f, &p).is_empty(), "accepted: {what}");
    }
    // A second run of the same page (which a loader would map over the first) is unreadable.
    let mut p = good.clone();
    p.pages.push(p.pages[0].clone());
    assert!(Plan::from_bytes(&p.to_bytes()).is_err());
}

#[test]
fn site_classes() {
    let i = |b: &[u8]| super::code::decode_at(b, BASE + 0x10, 0);
    assert_eq!(points::classify(&i(&[0xeb, 0xfe])), Some(Class::BackBranch));
    assert_eq!(points::classify(&i(&[0xeb, 0x00])), None);
    assert_eq!(
        points::classify(&i(&[0xe8, 0xf0, 0xff, 0xff, 0xff])),
        Some(Class::BackCall)
    );
    assert_eq!(
        points::classify(&i(&[0xff, 0xe0])),
        Some(Class::IndirectJump)
    );
    assert_eq!(
        points::classify(&i(&[0xf0, 0x48, 0x0f, 0xb1, 0x0f])),
        Some(Class::Atomic)
    );
    assert_eq!(points::classify(&i(&[0x87, 0x07])), Some(Class::Atomic));
    assert_eq!(points::classify(&i(&[0x87, 0xc3])), None);
    assert_eq!(points::classify(&i(&[0x0f, 0x05])), None);
}
