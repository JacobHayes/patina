//! arm64: the CPU features a program sees, in the auxiliary vector's feature words
//! (`AT_HWCAP` .. `AT_HWCAP4`) and `/proc/cpuinfo`'s `Features` (the runtime's
//! `arch::aux_value` and `arch::feature_hidden`). Compiled and tested on every host.
//!
//! The host's features pass, as `cpuid` does on x86_64, except those hidden:
//! - `PACG`: the generic key cannot be disabled, so `PACGA` would give a different value in
//!   every run (the scan counts the program's sites, `insn`).
//! - SME, every feature the kernel names `sme*`, in whichever word: with it hidden, libraries
//!   that choose code by the auxiliary vector (glibc, language runtimes) never turn on
//!   streaming mode or the ZA array, whose contents and vector length are the host's.
//! - `CPUID`: the kernel emulates `mrs` of the ID registers, and `MIDR_EL1` answers for
//!   the core the thread runs on, which on a host with two kinds of core changes between runs.
//!
//! A bit not named here passes: a feature a later kernel adds reaches the program. New state
//! that such a feature lets a program enable is saved in a signal-frame record the runtime does
//! not build, which ends the run `unsupported`, stop `signal-context`, at its first delivery
//! (`sigrec`); a new SME feature is added to the masks here. The loader copies only the
//! entries it lists (`loader::COPIED`), so a feature word a later kernel adds is not given.

pub const AT_HWCAP: u64 = 16;
pub const AT_HWCAP2: u64 = 26;
pub const AT_HWCAP3: u64 = 29;
pub const AT_HWCAP4: u64 = 30;

const HWCAP_CPUID: u64 = 1 << 11;
const HWCAP_PACG: u64 = 1 << 31;
/// `AT_HWCAP`'s SME features: SME2P2, SME_SBITPERM, SME_AES, SME_SFEXPA, SME_STMOP, SME_SMOP4.
const HWCAP_SME: u64 = 0x3f << 42;
/// `AT_HWCAP2`'s: bits 23-30 (SME .. SME_FA64), 37-42 (SME2 .. SME_F16F16) and 57-62
/// (SME_LUTV2 .. SME_SF8DP2).
const HWCAP2_SME: u64 = 0xff << 23 | 0x3f << 37 | 0x3f << 57;
/// `AT_HWCAP3`'s: SME_LUT6, SME2P3.
const HWCAP3_SME: u64 = 0x3 << 6;

/// The bits of the feature word `at` (an `AT_HWCAP*` type) the program does not see.
pub const fn hidden(at: u64) -> u64 {
    match at {
        AT_HWCAP => HWCAP_PACG | HWCAP_CPUID | HWCAP_SME,
        AT_HWCAP2 => HWCAP2_SME,
        AT_HWCAP3 => HWCAP3_SME,
        _ => 0,
    }
}

/// Whether `/proc/cpuinfo`'s `Features` line leaves out the word `w`: the features `hidden`
/// hides.
pub fn feature_hidden(w: &[u8]) -> bool {
    w == b"pacg" || w == b"cpuid" || w.starts_with(b"sme")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every feature the kernel names in `/proc/cpuinfo` (`arch/arm64/kernel/cpuinfo.c`), with
    /// its word (1 for `AT_HWCAP` .. 4) and bit (`uapi/asm/hwcap.h`).
    const KERNEL: &[(u64, u32, &str)] = &[
        (1, 0, "fp"),
        (1, 1, "asimd"),
        (1, 2, "evtstrm"),
        (1, 3, "aes"),
        (1, 4, "pmull"),
        (1, 5, "sha1"),
        (1, 6, "sha2"),
        (1, 7, "crc32"),
        (1, 8, "atomics"),
        (1, 9, "fphp"),
        (1, 10, "asimdhp"),
        (1, 11, "cpuid"),
        (1, 12, "asimdrdm"),
        (1, 13, "jscvt"),
        (1, 14, "fcma"),
        (1, 15, "lrcpc"),
        (1, 16, "dcpop"),
        (1, 17, "sha3"),
        (1, 18, "sm3"),
        (1, 19, "sm4"),
        (1, 20, "asimddp"),
        (1, 21, "sha512"),
        (1, 22, "sve"),
        (1, 23, "asimdfhm"),
        (1, 24, "dit"),
        (1, 25, "uscat"),
        (1, 26, "ilrcpc"),
        (1, 27, "flagm"),
        (1, 28, "ssbs"),
        (1, 29, "sb"),
        (1, 30, "paca"),
        (1, 31, "pacg"),
        (1, 32, "gcs"),
        (3, 3, "ls64"),
        (2, 0, "dcpodp"),
        (2, 1, "sve2"),
        (2, 2, "sveaes"),
        (2, 3, "svepmull"),
        (2, 4, "svebitperm"),
        (2, 5, "svesha3"),
        (2, 6, "svesm4"),
        (2, 7, "flagm2"),
        (2, 8, "frint"),
        (2, 9, "svei8mm"),
        (2, 10, "svef32mm"),
        (2, 11, "svef64mm"),
        (2, 12, "svebf16"),
        (2, 13, "i8mm"),
        (2, 14, "bf16"),
        (2, 15, "dgh"),
        (2, 16, "rng"),
        (2, 17, "bti"),
        (2, 18, "mte"),
        (2, 19, "ecv"),
        (2, 20, "afp"),
        (2, 21, "rpres"),
        (2, 22, "mte3"),
        (2, 23, "sme"),
        (2, 24, "smei16i64"),
        (2, 25, "smef64f64"),
        (2, 26, "smei8i32"),
        (2, 27, "smef16f32"),
        (2, 28, "smeb16f32"),
        (2, 29, "smef32f32"),
        (2, 30, "smefa64"),
        (2, 31, "wfxt"),
        (2, 32, "ebf16"),
        (2, 33, "sveebf16"),
        (2, 34, "cssc"),
        (2, 35, "rprfm"),
        (2, 36, "sve2p1"),
        (2, 37, "sme2"),
        (2, 38, "sme2p1"),
        (2, 39, "smei16i32"),
        (2, 40, "smebi32i32"),
        (2, 41, "smeb16b16"),
        (2, 42, "smef16f16"),
        (2, 43, "mops"),
        (2, 44, "hbc"),
        (2, 45, "sveb16b16"),
        (2, 46, "lrcpc3"),
        (2, 47, "lse128"),
        (2, 48, "fpmr"),
        (2, 49, "lut"),
        (2, 50, "faminmax"),
        (2, 51, "f8cvt"),
        (2, 52, "f8fma"),
        (2, 53, "f8dp4"),
        (2, 54, "f8dp2"),
        (2, 55, "f8e4m3"),
        (2, 56, "f8e5m2"),
        (2, 57, "smelutv2"),
        (2, 58, "smef8f16"),
        (2, 59, "smef8f32"),
        (2, 60, "smesf8fma"),
        (2, 61, "smesf8dp4"),
        (2, 62, "smesf8dp2"),
        (2, 63, "poe"),
        (1, 33, "cmpbr"),
        (1, 34, "fprcvt"),
        (1, 35, "f8mm8"),
        (1, 36, "f8mm4"),
        (1, 37, "svef16mm"),
        (1, 38, "sveeltperm"),
        (1, 39, "sveaes2"),
        (1, 40, "svebfscale"),
        (1, 41, "sve2p2"),
        (1, 42, "sme2p2"),
        (1, 43, "smesbitperm"),
        (1, 44, "smeaes"),
        (1, 45, "smesfexpa"),
        (1, 46, "smestmop"),
        (1, 47, "smesmop4"),
        (3, 0, "mtefar"),
        (3, 1, "mtestoreonly"),
        (3, 2, "lsfe"),
        (3, 4, "sveb16mm"),
        (3, 5, "sve2p3"),
        (3, 6, "smelut6"),
        (3, 7, "sme2p3"),
        (3, 8, "f16mm"),
        (3, 9, "f16f32dot"),
        (3, 10, "f16f32mm"),
        (3, 11, "svelut6"),
    ];

    /// The two views agree: a feature is hidden from the feature words exactly when its name
    /// is left out of `/proc/cpuinfo`, in every word.
    #[test]
    fn words_and_names_hide_the_same_features() {
        let at = [AT_HWCAP, AT_HWCAP2, AT_HWCAP3, AT_HWCAP4];
        for &(word, bit, name) in KERNEL {
            let in_word = hidden(at[word as usize - 1]) & 1 << bit != 0;
            assert_eq!(
                in_word,
                feature_hidden(name.as_bytes()),
                "{name} (AT_HWCAP{word} bit {bit})"
            );
        }
    }

    /// Nothing is hidden that the kernel does not name.
    #[test]
    fn only_named_bits_are_hidden() {
        let at = [AT_HWCAP, AT_HWCAP2, AT_HWCAP3, AT_HWCAP4];
        for (i, &t) in at.iter().enumerate() {
            let named = KERNEL
                .iter()
                .filter(|k| k.0 == i as u64 + 1)
                .fold(0u64, |m, k| m | 1 << k.1);
            assert_eq!(hidden(t) & !named, 0, "AT_HWCAP{}", i + 1);
        }
    }
}
