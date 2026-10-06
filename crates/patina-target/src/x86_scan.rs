//! Boundary-aware x86-64 instruction decoding and forbidden-opcode scanning.

/// Immediate-operand width classes. Widths that depend on the effective
/// operand/address size are resolved from the `0x66`/`0x67`/REX.W prefixes.
#[derive(Clone, Copy)]
enum Imm {
    None,
    /// Exactly N bytes (rel8/rel32 fold in here — near branches are a fixed
    /// width in 64-bit mode; `enter`'s `iw,ib` is a single 3-byte immediate).
    Fixed(u8),
    /// Operand-size immediate: 2 bytes with a `0x66` prefix, else 4.
    Z,
    /// 8 bytes with REX.W, else `Z` (the `mov r64, imm64` family).
    V,
    /// Address-size memory offset: 4 bytes with `0x67`, else 8.
    Moffs,
    /// `f6 /r`: an imm8 only when ModRM.reg selects TEST (0 or 1).
    Group3Byte,
    /// `f7 /r`: an immZ only when ModRM.reg selects TEST (0 or 1).
    Group3Z,
}

/// A classified opcode as `(escape category, decoded mnemonic)`. The mnemonic
/// rides along to the finding so the audit can tell `rdtsc`/`rdtscp` (trap-
/// manageable on x86-64 Linux) from `rdrand`/`rdseed` (never manageable),
/// which share the `cpu-nondeterminism` category.
///
/// Most categories here are refusals; `host-identity` (`cpuid`) is the
/// informational one — the decoder classifies, the audit decides disposition.
type Forbidden = (&'static str, &'static str);

struct OpAttr {
    modrm: bool,
    imm: Imm,
    /// A category fixed by the opcode bytes alone (syscall, rdtsc, cpuid,
    /// pop fs, lfs).
    cat: Option<Forbidden>,
    /// An opcode whose category is decided by its ModRM byte (and, for group
    /// 15, the `f3` prefix), resolved after the ModRM byte is read.
    group: Group,
}

/// The opcode groups whose classification needs the ModRM byte.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Group {
    None,
    /// `0f 01` (group 7): rdtscp is `mod=3, reg=7, rm=1`. The rest of the
    /// group (sgdt/sidt/lgdt/invlpg/swapgs/…) is not forbidden.
    Seven,
    /// `0f c7` (group 9): rdrand (ModRM.reg 6) / rdseed (ModRM.reg 7) vs
    /// cmpxchg8b.
    Nine,
    /// `0f ae` (group 15): with an `f3` prefix and `mod=3`, reg 0..3 are
    /// rdfsbase/rdgsbase/wrfsbase/wrgsbase. Without the prefix the group is
    /// the fences and the memory-form state saves, none of them forbidden.
    Fifteen,
    /// `8e` (`mov Sreg, r/m16`): ModRM.reg names the segment register
    /// loaded, and reg 4 is FS.
    MovSreg,
    /// `ff` (group 5): reg 3 is `lcall m16:xx` and reg 5 is `ljmp m16:xx`,
    /// the far transfers that load CS. The rest (inc/dec/near call/near
    /// jmp/push) is not forbidden.
    Five,
}

enum Step {
    Insn { len: usize, cat: Option<Forbidden> },
    Undecodable,
}

/// Walk one declared code range in `data` (or the whole section when no
/// metadata exists), pushing a finding at each classified boundary and one
/// `undecodable-instruction` finding (then stopping) if the decoder cannot
/// measure an instruction.
pub(super) fn scan(
    data: &[u8],
    range: std::ops::Range<usize>,
    name: &str,
    section_address: u64,
    provenance: &super::NativeProvenanceIndex,
    escapes: &mut Vec<super::NativeEscape>,
) {
    let mut offset = range.start;
    while offset < range.end {
        match decode_one(&data[offset..range.end]) {
            Step::Insn { len, cat } => {
                if let Some((category, mnemonic)) = cat {
                    escapes.push(
                        super::NativeEscape::new(
                            format!("instruction@{name}+0x{offset:x}"),
                            category,
                            vec![
                                provenance.for_address(section_address + offset as u64, Some(name)),
                            ],
                        )
                        .with_mnemonic(mnemonic),
                    );
                }
                // Every instruction consumes at least its opcode byte, so
                // `len >= 1`; the guard only defends the loop invariant.
                if len == 0 {
                    break;
                }
                offset += len;
            }
            Step::Undecodable => {
                escapes.push(super::NativeEscape::new(
                    format!("instruction@{name}+0x{offset:x}"),
                    "undecodable-instruction",
                    vec![provenance.for_address(section_address + offset as u64, Some(name))],
                ));
                break;
            }
        }
    }
}

/// Decode the instruction at `b[0]` into its length and, when it references a
/// fixed address, the displacement encoding that reference. Direct near
/// branches (`call`/`jmp rel32`) and RIP-relative memory operands share one
/// rule — the target is the address of the *next* instruction plus the
/// displacement — so both come back through the same value.
///
/// References are only read at real instruction boundaries. Sliding the same
/// byte patterns over every offset in `.text` instead reads four displacement
/// bytes out of the middle of unrelated instructions, and any of those that
/// happens to land on a GOT slot attributes an import to a function that
/// never referenced it.
pub(super) fn decode_reference(b: &[u8]) -> Option<(usize, Option<i32>)> {
    let len = match decode_one(b) {
        Step::Insn { len, .. } if len > 0 => len,
        _ => return None,
    };
    let insn = b.get(..len)?;

    let mut p = 0usize;
    while matches!(
        insn.get(p).copied(),
        Some(0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65)
    ) {
        p += 1;
    }
    if matches!(insn.get(p).copied(), Some(0x40..=0x4F)) {
        p += 1;
    }

    let displacement = |at: usize| -> Option<i32> {
        insn.get(at..at + 4)
            .map(|bytes| i32::from_le_bytes(bytes.try_into().expect("four bytes")))
    };
    // A ModRM of mod=00, rm=101 is the RIP-relative form, and rm=101 takes no
    // SIB byte, so its disp32 follows the ModRM directly.
    let rip_relative = |modrm: u8| modrm & 0xC7 == 0x05;
    let reference = match insn.get(p).copied() {
        Some(0xE8 | 0xE9) => displacement(p + 1),
        // `call`/`jmp` through a RIP-relative slot: ModRM.reg 2 and 4.
        Some(0xFF) => match insn.get(p + 1).copied() {
            Some(modrm) if rip_relative(modrm) && matches!((modrm >> 3) & 7, 2 | 4) => {
                displacement(p + 2)
            }
            _ => None,
        },
        // `mov reg, [rip+disp]` / `lea reg, [rip+disp]`: the address-taken form.
        Some(0x8B | 0x8D) => match insn.get(p + 1).copied() {
            Some(modrm) if rip_relative(modrm) => displacement(p + 2),
            _ => None,
        },
        _ => None,
    };
    Some((len, reference))
}

/// Decode the length of the single instruction at `b[0]`, and its category
/// if the opcode carries one. Returns `Undecodable` for anything the length
/// rules below do not cover (fail closed).
fn decode_one(b: &[u8]) -> Step {
    let mut p = 0usize;
    let mut o66 = false;
    let mut a67 = false;
    let mut rexw = false;
    let mut f3 = false;
    let mut evex_incompatible_prefix = false;
    // Legacy prefixes, any order. Only `0x66`/`0x67` change a length (via the
    // effective operand/address size); lock/rep/segment do not. `f3` is
    // recorded because it selects the FSGSBASE forms of group 15. It counts
    // wherever it sits in the run, even under a later `f2`: the scan fails
    // toward refusing, never toward passing.
    loop {
        match b.get(p) {
            Some(0x66) => o66 = true,
            Some(0x67) => a67 = true,
            Some(0xF3) => f3 = true,
            Some(0xF0 | 0xF2 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65) => {}
            _ => break,
        }
        evex_incompatible_prefix |= matches!(b[p], 0x66 | 0xF0 | 0xF2 | 0xF3);
        p += 1;
        if p > 14 {
            return Step::Undecodable; // absurd prefix run
        }
    }
    // REX must immediately precede the opcode in 64-bit mode.
    if let Some(&r) = b.get(p)
        && (0x40..=0x4F).contains(&r)
    {
        rexw = r & 0x08 != 0;
        evex_incompatible_prefix = true;
        p += 1;
    }
    let op = match b.get(p) {
        Some(&x) => x,
        None => return Step::Undecodable,
    };
    p += 1;
    let attr = if op == 0x0F {
        let op2 = match b.get(p) {
            Some(&x) => x,
            None => return Step::Undecodable,
        };
        p += 1;
        if op2 == 0x38 || op2 == 0x3A {
            // Legacy three-byte opcode maps (SSSE3/SSE4.1/SSE4.2/SHA-NI): the
            // third byte is the real opcode, always followed by a ModRM.
            // Default codegen *does* emit these — e.g. the `sha2` crate's x86
            // backend uses `pshufb`/`palignr`/`pblendw`/`pinsrd` and the SHA
            // extensions `sha256rnds2`/`sha256msg1`/`sha256msg2` (`0f 38 cb/cc/
            // cd`) — so they must be length-decoded, not declined. No opcode in
            // either map is forbidden: `syscall`/`rdtsc`/`rdrand`/`rdseed` live
            // only in the legacy `0f` (two-byte) map, so measuring these can
            // never hide a forbidden instruction. Length rules mirror the VEX
            // `0f 38`/`0f 3a` maps decoded below: `0f 38` ops carry no
            // immediate, `0f 3a` ops carry an imm8.
            if b.get(p).is_none() {
                return Step::Undecodable; // truncated: no third opcode byte
            }
            p += 1; // consume the third opcode byte
            OpAttr {
                modrm: true,
                imm: if op2 == 0x3A {
                    Imm::Fixed(1)
                } else {
                    Imm::None
                },
                cat: Option::None,
                group: Group::None,
            }
        } else {
            match two_byte(op2) {
                Some(a) => a,
                None => return Step::Undecodable,
            }
        }
    } else if op == 0xC5 {
        // Two-byte VEX: one prefix byte (`R.vvvv.L.pp`), then an opcode in the
        // implied `0f` map.
        if b.get(p).is_none() {
            return Step::Undecodable;
        }
        p += 1;
        let opc = match b.get(p) {
            Some(&x) => x,
            None => return Step::Undecodable,
        };
        p += 1;
        match vex_body(1, opc) {
            Some((modrm, imm)) => OpAttr {
                modrm,
                imm,
                cat: Option::None,
                group: Group::None,
            },
            None => return Step::Undecodable,
        }
    } else if op == 0xC4 {
        // Three-byte VEX: two prefix bytes; the low 5 bits of the first pick
        // the implied opcode map (1=`0f`, 2=`0f 38`, 3=`0f 3a`).
        let b1 = match b.get(p) {
            Some(&x) => x,
            None => return Step::Undecodable,
        };
        p += 1;
        if b.get(p).is_none() {
            return Step::Undecodable;
        }
        p += 1;
        let opc = match b.get(p) {
            Some(&x) => x,
            None => return Step::Undecodable,
        };
        p += 1;
        match vex_body(b1 & 0x1F, opc) {
            Some((modrm, imm)) => OpAttr {
                modrm,
                imm,
                cat: Option::None,
                group: Group::None,
            },
            None => return Step::Undecodable,
        }
    } else if op == 0x62 {
        // EVEX P0/P1/P2, opcode, then a mandatory ModRM. The module comment
        // explains the format-level refusals; operand lengths below are the
        // same as VEX, including compressed displacement's one-byte disp8.
        let Some(&[p0, p1, p2, opc, modrm]) = b.get(p..p + 5) else {
            return Step::Undecodable;
        };
        let map = p0 & 0x0f;
        if evex_incompatible_prefix
            || p0 & 0x08 != 0
            || p1 & 0x04 == 0
            || !matches!(map, 1..=3)
            || (map == 1 && matches!(opc, 0x0F | 0x77 | 0xA4 | 0xAC | 0xBA))
            || (p2 & 0x80 != 0 && p2 & 0x07 == 0)
            || (p2 & 0x60 == 0x60 && (p2 & 0x10 == 0 || modrm >> 6 != 3))
        {
            return Step::Undecodable;
        }
        p += 4; // ModRM is consumed by the common operand decoder.
        match vex_body(map, opc) {
            Some((modrm, imm)) => OpAttr {
                modrm,
                imm,
                cat: Option::None,
                group: Group::None,
            },
            None => return Step::Undecodable,
        }
    } else {
        match one_byte(op) {
            Some(a) => a,
            None => return Step::Undecodable,
        }
    };
    let mut cat = attr.cat;
    // `int imm8` (`cd ib`): vector 0x80 is the kernel's i386 syscall gate,
    // open to 64-bit processes when the kernel has IA32 emulation (Ubuntu's
    // default). Every other vector enters no syscall: it traps or faults
    // (SIGTRAP/SIGSEGV).
    if op == 0xCD && b.get(p) == Some(&0x80) {
        cat = Some(("direct-syscall", "int 0x80"));
    }
    let mut imm = attr.imm;
    if attr.modrm {
        let m = match b.get(p) {
            Some(&x) => x,
            None => return Step::Undecodable,
        };
        p += 1;
        let md = m >> 6;
        let reg = (m >> 3) & 7;
        let rm = m & 7;
        // group 9 (`0f c7`): ModRM.reg 6 is RDRAND, reg 7 is RDSEED. Both are
        // hardware entropy reads — `cpu-nondeterminism` with NO manageability
        // (no mechanism traps them; they stay refusals, unlike the timestamp
        // counter). Neither is guarded on `mod == 3` (the true register-form
        // encoding), keeping the historical reg==6 test's shape: the memory
        // forms of this group are privileged VMX instructions that fault in
        // user mode, so the looser test costs nothing and cannot go blind.
        if attr.group == Group::Nine {
            if reg == 6 {
                cat = Some(("cpu-nondeterminism", "rdrand"));
            } else if reg == 7 {
                cat = Some(("cpu-nondeterminism", "rdseed"));
            }
        }
        // group 7 (`0f 01`): `mod=3, reg=7, rm=1` is RDTSCP — the timestamp
        // counter plus IA32_TSC_AUX. `rm=0` at the same reg is SWAPGS
        // (privileged) and every other encoding is a descriptor-table op, so
        // the exact triple is required.
        if attr.group == Group::Seven && md == 3 && reg == 7 && rm == 1 {
            cat = Some(("cpu-nondeterminism", "rdtscp"));
        }
        // `mod=3, reg=5, rm=6/7` are RDPKRU/WRPKRU: the thread's
        // protection-key rights register, the host CPU's own (a PKU host
        // answers its default PKRU, any other raises SIGILL), where the
        // virtual CPU declares no keys. Host-identity, visible and not
        // refused, as cpuid: the conformance probe itself reads it.
        if attr.group == Group::Seven && md == 3 && reg == 5 && (rm == 6 || rm == 7) {
            cat = Some((
                super::HOST_IDENTITY_CATEGORY,
                if rm == 6 { "rdpkru" } else { "wrpkru" },
            ));
        }
        // group 15 (`f3 [REX.W] 0f ae`, register form): FSGSBASE. Only
        // WRFSBASE (reg 2) moves the thread pointer. The other three are
        // deliberately not findings:
        // - RDFSBASE/RDGSBASE (reg 0/1) read a base, which is what
        //   `arch_prctl(ARCH_GET_FS)` and a `mov rax, fs:0` already hand
        //   the guest;
        // - WRGSBASE (reg 3) moves GS, which neither glibc nor the shim uses
        //   in user space on x86-64 (the same reason the thread/tls design
        //   passes `ARCH_SET_GS` through rather than refusing it).
        if attr.group == Group::Fifteen && f3 && md == 3 && reg == 2 {
            cat = Some((super::THREAD_POINTER_CATEGORY, "wrfsbase"));
        }
        // `mov fs, r/m16` loads FS from a descriptor, and in 64-bit mode a
        // non-null selector replaces the FS base with that descriptor's base
        // (0 for the GDT's user data segment): the thread pointer moves with
        // no FSGSBASE and no syscall. GS (reg 5) is left alone, as above.
        if attr.group == Group::MovSreg && reg == 4 {
            cat = Some((super::THREAD_POINTER_CATEGORY, "mov fs"));
        }
        // Far call/jmp through memory (`ff /3`, `ff /5`) loads CS from the
        // operand's selector, and a 32-bit code selector switches the CPU to
        // compatibility mode, where this 64-bit decoder no longer describes
        // the code that runs. The register form (`mod = 3`) is #UD; it is
        // flagged too, erring toward refusal.
        if attr.group == Group::Five && (reg == 3 || reg == 5) {
            let mnemonic = if reg == 3 { "lcall" } else { "ljmp" };
            cat = Some((super::FAR_TRANSFER_CATEGORY, mnemonic));
        }
        // group 3 (`f6`/`f7`): only TEST (reg 0 or 1) carries an immediate.
        imm = match imm {
            Imm::Group3Byte if reg <= 1 => Imm::Fixed(1),
            Imm::Group3Z if reg <= 1 => Imm::Z,
            Imm::Group3Byte | Imm::Group3Z => Imm::None,
            other => other,
        };
        // ModRM memory forms pull a SIB byte and/or a displacement.
        if md != 3 {
            if rm == 4 {
                let sib = match b.get(p) {
                    Some(&x) => x,
                    None => return Step::Undecodable,
                };
                p += 1;
                if md == 0 && (sib & 7) == 5 {
                    p += 4; // SIB with no base register: disp32
                } else {
                    p += disp_len(md);
                }
            } else if md == 0 && rm == 5 {
                p += 4; // RIP-relative disp32
            } else {
                p += disp_len(md);
            }
        }
    }
    p += imm_len(imm, o66, rexw, a67);
    if p > b.len() || p > 15 {
        return Step::Undecodable; // truncated or exceeds x86's maximum length
    }
    Step::Insn { len: p, cat }
}

fn disp_len(md: u8) -> usize {
    match md {
        1 => 1,
        2 => 4,
        _ => 0,
    }
}

fn imm_len(imm: Imm, o66: bool, rexw: bool, a67: bool) -> usize {
    match imm {
        Imm::None => 0,
        Imm::Fixed(n) => n as usize,
        Imm::Z => {
            if o66 {
                2
            } else {
                4
            }
        }
        Imm::V => {
            if rexw {
                8
            } else if o66 {
                2
            } else {
                4
            }
        }
        Imm::Moffs => {
            if a67 {
                4
            } else {
                8
            }
        }
        // Resolved to a concrete width during ModRM processing; never here.
        Imm::Group3Byte | Imm::Group3Z => 0,
    }
}

fn attr(modrm: bool, imm: Imm) -> Option<OpAttr> {
    Some(OpAttr {
        modrm,
        imm,
        cat: None,
        group: Group::None,
    })
}

/// A ModRM opcode with no immediate whose category its ModRM byte decides.
fn grouped(group: Group) -> Option<OpAttr> {
    Some(OpAttr {
        modrm: true,
        imm: Imm::None,
        cat: None,
        group,
    })
}

/// A no-ModRM opcode whose bytes alone fix its category.
fn classified(imm: Imm, cat: Forbidden) -> Option<OpAttr> {
    Some(OpAttr {
        modrm: false,
        imm,
        cat: Some(cat),
        group: Group::None,
    })
}

/// One-byte opcode attributes. `None` = fail closed (opcodes invalid in
/// 64-bit mode, which valid code never emits). Prefix bytes and `0x0f` are
/// consumed by the caller and never reach here.
fn one_byte(op: u8) -> Option<OpAttr> {
    use Imm::*;
    match op {
        // ALU r/m forms (add/or/adc/sbb/and/sub/xor/cmp), the `xx0..=xx3` rows.
        0x00 | 0x01 | 0x02 | 0x03 | 0x08 | 0x09 | 0x0A | 0x0B | 0x10 | 0x11 | 0x12 | 0x13
        | 0x18 | 0x19 | 0x1A | 0x1B | 0x20 | 0x21 | 0x22 | 0x23 | 0x28 | 0x29 | 0x2A | 0x2B
        | 0x30 | 0x31 | 0x32 | 0x33 | 0x38 | 0x39 | 0x3A | 0x3B => attr(true, None),
        // ALU AL, imm8 / eAX, immZ.
        0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C => attr(false, Fixed(1)),
        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D => attr(false, Z),
        // Invalid in 64-bit mode (push/pop seg, bcd math, pusha/popa, bound,
        // callf/jmpf, aam/aad/salc, into): fail closed.
        0x06 | 0x07 | 0x0E | 0x16 | 0x17 | 0x1E | 0x1F | 0x27 | 0x2F | 0x37 | 0x3F | 0x60
        | 0x61 | 0x82 | 0x9A | 0xCE | 0xD4 | 0xD5 | 0xD6 | 0xEA => Option::None,
        0x50..=0x5F => attr(false, None),     // push/pop r64
        0x63 => attr(true, None),             // movsxd
        0x68 => attr(false, Z),               // push immZ
        0x69 => attr(true, Z),                // imul r, r/m, immZ
        0x6A => attr(false, Fixed(1)),        // push imm8
        0x6B => attr(true, Fixed(1)),         // imul r, r/m, imm8
        0x6C..=0x6F => attr(false, None),     // ins/outs
        0x70..=0x7F => attr(false, Fixed(1)), // Jcc rel8
        0x80 => attr(true, Fixed(1)),         // grp1 Eb, Ib
        0x81 => attr(true, Z),                // grp1 Ev, Iz
        0x83 => attr(true, Fixed(1)),         // grp1 Ev, Ib (sign-extended)
        0x84..=0x87 => attr(true, None),      // test / xchg
        0x88..=0x8D => attr(true, None),      // mov / lea
        0x8E => grouped(Group::MovSreg),      // mov Sreg, r/m16 (reg 4 = FS)
        0x8F => attr(true, None),             // grp1a pop Ev
        0x90..=0x97 => attr(false, None),     // xchg eAX (0x90 nop)
        0x98 | 0x99 | 0x9B | 0x9C | 0x9D | 0x9E | 0x9F => attr(false, None), // cbw..lahf
        0xA0..=0xA3 => attr(false, Moffs),    // mov AL/eAX, moffs
        0xA4..=0xA7 => attr(false, None),     // movs / cmps
        0xA8 => attr(false, Fixed(1)),        // test AL, imm8
        0xA9 => attr(false, Z),               // test eAX, immZ
        0xAA..=0xAF => attr(false, None),     // stos / lods / scas
        0xB0..=0xB7 => attr(false, Fixed(1)), // mov r8, imm8
        0xB8..=0xBF => attr(false, V),        // mov r, immV
        0xC0 | 0xC1 => attr(true, Fixed(1)),  // grp2 shift Eb/Ev, imm8
        0xC2 => attr(false, Fixed(2)),        // ret imm16
        0xC3 => attr(false, None),            // ret
        0xC6 => attr(true, Fixed(1)),         // grp11 mov Eb, Ib
        0xC7 => attr(true, Z),                // grp11 mov Ev, Iz
        0xC8 => attr(false, Fixed(3)),        // enter iw, ib
        0xC9 => attr(false, None),            // leave
        0xCA => classified(Fixed(2), (super::FAR_TRANSFER_CATEGORY, "lret")), // retf imm16
        0xCB => classified(None, (super::FAR_TRANSFER_CATEGORY, "lret")), // retf
        0xCC => attr(false, None),            // int3
        0xCD => attr(false, Fixed(1)),        // int imm8 (0x80 resolved by the caller)
        0xCF => classified(None, (super::FAR_TRANSFER_CATEGORY, "iret")), // iret/iretq
        0xD0..=0xD3 => attr(true, None),      // grp2 shift by 1 / CL
        0xD7 => attr(false, None),            // xlat
        0xD8..=0xDF => attr(true, None),      // x87 (always ModRM, no immediate)
        0xE0..=0xE3 => attr(false, Fixed(1)), // loop / jcxz rel8
        0xE4..=0xE7 => attr(false, Fixed(1)), // in/out imm8
        0xE8 | 0xE9 => attr(false, Fixed(4)), // call / jmp rel32 (fixed in 64-bit)
        0xEB => attr(false, Fixed(1)),        // jmp rel8
        0xEC..=0xEF => attr(false, None),     // in/out DX
        0xF1 | 0xF4 | 0xF5 => attr(false, None), // int1 / hlt / cmc
        0xF6 => attr(true, Group3Byte),       // grp3 Eb
        0xF7 => attr(true, Group3Z),          // grp3 Ev
        0xF8..=0xFD => attr(false, None),     // clc..std
        0xFE => attr(true, None),             // grp4 inc/dec Eb
        0xFF => grouped(Group::Five),         // grp5 (reg 3/5 = lcall/ljmp)
        // Prefixes (consumed by the caller) and any hole: fail closed.
        _ => Option::None,
    }
}

/// Two-byte (`0f xx`) opcode attributes. `None` = fail closed. The forbidden
/// opcodes are `0f 05` (syscall), `0f 34` (sysenter), `0f 31` (rdtsc),
/// `0f 01 f9` (rdtscp, resolved from ModRM by the caller) and `0f c7 /6`,
/// `/7` (rdrand, rdseed, likewise resolved from ModRM.reg); `0f a2` (cpuid)
/// is classified here too, as the informational `host-identity` category
/// rather than a refusal. The thread-pointer writes are `f3 0f ae /2`
/// (wrfsbase, resolved from the prefix and ModRM), `0f a1` (pop fs) and
/// `0f b4` (lfs).
fn two_byte(op2: u8) -> Option<OpAttr> {
    use Imm::*;
    match op2 {
        0x05 => Some(OpAttr {
            modrm: false,
            imm: None,
            cat: Some(("direct-syscall", "syscall")),
            group: Group::None,
        }),
        // SYSENTER: the i386 fast-syscall entry. On Intel it is valid in
        // 64-bit mode and enters the kernel's 32-bit syscall ABI where the
        // kernel has IA32 emulation (on AMD it is #UD → SIGILL). Same
        // length rules as the no-ModRM row below.
        0x34 => Some(OpAttr {
            modrm: false,
            imm: None,
            cat: Some(("direct-syscall", "sysenter")),
            group: Group::None,
        }),
        0x31 => Some(OpAttr {
            modrm: false,
            imm: None,
            cat: Some(("cpu-nondeterminism", "rdtsc")),
            group: Group::None,
        }),
        // Group 7 (`0f 01`): rdtscp is the `mod=3, reg=7, rm=1` form. The
        // group's length rules are unchanged (ModRM, no immediate) — it was
        // already measured correctly by the `0x00..=0x03` arm below; the
        // group7 flag only adds the classification the old table lacked, so
        // an `rdtscp` guest is no longer scanned past as an ordinary
        // instruction.
        0x01 => Some(OpAttr {
            modrm: true,
            imm: None,
            cat: Option::None,
            group: Group::Seven,
        }),
        0xC7 => Some(OpAttr {
            modrm: true,
            imm: None,
            cat: Option::None,
            group: Group::Nine,
        }),
        // CPUID (`0f a2`): the host-identity read. Its length rules were
        // already right (it sat in the no-ModRM/no-immediate row below), so
        // this arm adds only the classification — which is what took the site
        // from silent to reported. `host-identity` is informational, not a
        // refusal (see `HOST_IDENTITY_CATEGORY`).
        0xA2 => Some(OpAttr {
            modrm: false,
            imm: None,
            cat: Some((super::HOST_IDENTITY_CATEGORY, "cpuid")),
            group: Group::None,
        }),
        // Group 15 (`0f ae`): the fences, the memory-form state saves and,
        // under `f3`, FSGSBASE. Same length rules as the ModRM row below;
        // the group adds the wrfsbase classification.
        0xAE => Some(OpAttr {
            modrm: true,
            imm: None,
            cat: Option::None,
            group: Group::Fifteen,
        }),
        // `pop fs` (`0f a1`) and `lfs` (`0f b4`, memory operand) load an FS
        // selector, which replaces the FS base: a thread-pointer write, like
        // `mov fs` in the one-byte map. Their GS twins (`0f a9`, `0f b5`)
        // stay unclassified (GS is unused; see the group 15 resolution).
        0xA1 => Some(OpAttr {
            modrm: false,
            imm: None,
            cat: Some((super::THREAD_POINTER_CATEGORY, "pop fs")),
            group: Group::None,
        }),
        0xB4 => Some(OpAttr {
            modrm: true,
            imm: None,
            cat: Some((super::THREAD_POINTER_CATEGORY, "lfs")),
            group: Group::None,
        }),
        // No ModRM, no immediate (clts/syscall-family/push-pop-seg/bswap/
        // rsm/...; `0f 34` sysenter, `0f a2` cpuid and `0f a1` pop fs are
        // matched above with the same length rules and an added
        // classification).
        0x06
        | 0x07
        | 0x08
        | 0x09
        | 0x0B
        | 0x0E
        | 0x30
        | 0x32
        | 0x33
        | 0x35
        | 0x37
        | 0x77
        | 0xA0
        | 0xA8
        | 0xA9
        | 0xAA
        | 0xC8..=0xCF => attr(false, None),
        // Jcc rel32 (fixed in 64-bit).
        0x80..=0x8F => attr(false, Fixed(4)),
        // ModRM + imm8 (pshuf/shift-group/shld/shrd/bt-group/cmp*/insert/
        // extract/shuf; `0f 0f` 3DNow carries its opcode in the trailing imm8).
        0x0F | 0x70 | 0x71 | 0x72 | 0x73 | 0xA4 | 0xAC | 0xBA | 0xC2 | 0xC4 | 0xC5 | 0xC6 => {
            attr(true, Fixed(1))
        }
        // ModRM, no immediate (the bulk of the 0F map: SSE2/MMX, cmov, setcc,
        // movzx/movsx, bit ops, xadd, cmpxchg, ...).
        // (`0x01` — group 7, which carries rdtscp — `0xae` — group 15, which
        // carries wrfsbase — and `0xb4` — lfs — are matched above with the
        // same length rules and an added classification.)
        0x00
        | 0x02
        | 0x03
        | 0x0D
        | 0x10..=0x1F
        | 0x20..=0x23
        | 0x28..=0x2F
        | 0x40..=0x4F
        | 0x50..=0x6F
        | 0x74..=0x76
        | 0x78
        | 0x79
        | 0x7C..=0x7F
        | 0x90..=0x9F
        | 0xA3
        | 0xA5
        | 0xAB
        | 0xAD
        | 0xAF
        | 0xB0..=0xB3
        | 0xB5..=0xB9
        | 0xBB..=0xBF
        | 0xC0
        | 0xC1
        | 0xC3
        | 0xD0..=0xDF
        | 0xE0..=0xEF
        | 0xF0..=0xFF => attr(true, None),
        // Reserved / invalid 0F opcodes, and the three-byte escapes the caller
        // has already peeled off: fail closed.
        _ => Option::None,
    }
}

/// VEX instruction body attributes `(modrm, imm)` for the implied opcode
/// `map` (1 = `0f`, 2 = `0f 38`, 3 = `0f 3a`) and `op`. VEX opcodes are never
/// forbidden, so no category is returned; this only measures length. Unknown
/// maps fail closed. The immediate rules follow the map: nearly every VEX
/// `0f`-map op is `(modrm, no-imm)`, except `vzeroupper`/`vzeroall` (`0f 77`,
/// no ModRM) and the imm8-bearing shuffle/compare/insert/extract group; `0f
/// 38` ops carry no immediate; `0f 3a` ops carry an imm8.
fn vex_body(map: u8, op: u8) -> Option<(bool, Imm)> {
    match map {
        1 => {
            let modrm = op != 0x77; // vzeroupper / vzeroall take no ModRM
            let imm = match op {
                0x70 | 0x71 | 0x72 | 0x73 | 0xC2 | 0xC4 | 0xC5 | 0xC6 => Imm::Fixed(1),
                _ => Imm::None,
            };
            Some((modrm, imm))
        }
        2 => Some((true, Imm::None)),     // 0f 38: ModRM, no immediate
        3 => Some((true, Imm::Fixed(1))), // 0f 3a: ModRM + imm8
        _ => Option::None,                // reserved VEX map: fail closed
    }
}

#[cfg(test)]
#[path = "x86_scan_tests.rs"]
mod tests;
