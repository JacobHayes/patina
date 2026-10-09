//! Target metadata and fail-closed import auditing.
//!
//! Internal crate: the analysis behind `cargo patina audit` and the pre-run
//! default-deny gate. It parses native (Mach-O/ELF) and `wasm32-wasip1`
//! artifacts, classifies every externally resolved import against the
//! interposed/known-safe allowlists, and reports the residual effect surface —
//! an unknown import is a refusal, never a silent escape. Adopters drive this
//! through the CLI; see [ARCHITECTURE.md] for the containment story.
//!
//! [ARCHITECTURE.md]: https://github.com/JacobHayes/patina/blob/main/ARCHITECTURE.md

use crate::provenance::normalize_provenance;
use object::{Architecture, BinaryFormat};
use std::fmt;

mod code_ranges;
mod early_init;
mod import_policy;
mod import_xrefs;
mod instruction_scan;
mod native_audit;
mod provenance;
mod report;
mod shim;
mod wasi;
/// x86-64 forbidden-instruction scan, instruction-boundary-aware.
///
/// The aarch64 ISA is fixed-width, so its scan decodes aligned 4-byte words and
/// cannot desync. x86-64 is variable-length: a byte-sliding scan that tested
/// every offset matched the forbidden opcode bytes (`0f 05` syscall, `0f 31`
/// rdtsc, `0f c7 /6` rdrand) *inside* longer instructions' ModRM/SIB/
/// displacement/immediate bytes and flooded the audit with false positives — an
/// ordinary `mov`/`lea`/`movups` whose operand encoding happens to contain those
/// bytes. This module walks real instruction boundaries with a length decoder
/// and only tests the opcode at a genuine boundary, matching the aarch64 scan's
/// precision.
///
/// Scan policy: x86-64 ELF uses the declared function extents from defined
/// STT_FUNC symbols (including dynamic symbols) AND `.eh_frame` FDEs. Each range
/// is decoded independently from its own start to its own end; overlaps are not
/// merged or intersected. Exact duplicates share findings. Defined NOTYPE labels
/// and zero-sized functions establish independent entries, ending at each
/// containing declaration's end, or the next entry/section end in a gap.
/// Malformed/overflowing/out-of-section ranges, unresolved code-entry section
/// indices, indirect FDE addresses
/// and relocations targeting `.eh_frame` refuse: none establishes a code address
/// we can trust, even when another metadata source is valid. REL/RELA tables are
/// read fallibly, including dynamic targets; malformed tables and packed
/// relocation formats (RELR/CREL/Android) refuse rather than guessing their effect
/// on unwind storage. A section without a sized STT_FUNC in .symtab additionally
/// gets a whole-section walk: FDEs and dynamic exports alone cannot justify
/// omitting code, because ordinary toolchains omit unwind records. Stripped
/// code/data mixtures may therefore refuse again. Mach-O retains its whole-
/// section policy. Source builds preserve symbols in the audited/run artifact.
///
/// Where sized .symtab functions exist, bytes outside all declared extents and
/// inferred entry ranges are NOT scanned as x86 instructions. This
/// handles assembly attribution strings/alignment without recognizing any tag,
/// dependency, or byte pattern, and without skipping undecodable bytes inside a
/// range. It assumes compiler/linker metadata describes every executable entry
/// and extent, and that ELF section metadata agrees with the loader's image
/// (contradictory program-header/dynamic tables are not reconciled here).
/// Metadata is NOT a reachability proof: lying or too-short sizes, fallthrough
/// or branches into gaps or operands at undeclared entries, omitted functions
/// in otherwise symbol-bearing sections, and runtime-generated code can evade
/// static discovery. These are residuals, not a contract that such code is safe.
/// A successful scan is a bounded compiler-output check, not certification of
/// arbitrary/adversarial native code. Undecodable bytes inside ANY declared
/// range still refuse the binary, even after a return, with a later range still
/// scanned independently. Import-reference attribution uses the same ranges.
///
/// Runtime backstops are class/platform-specific, not justification for ignoring
/// code: on x86-64 Linux, an active shim SUD trap intercepts raw syscalls (i386
/// entries abort), and PR_SET_TSC traps rdtsc/rdtscp (supported main-image reads
/// are virtualized; out-of-image/generated counter sites stop by name). Neither protects the
/// pre-trap startup window or execution on other platforms. Rdrand/rdseed, TLS-
/// base writes and far transfers have no such backstop: an executed site outside
/// the scan's coverage can escape. Cpuid/PKRU sites are informational only.
/// The vsyscall-address pattern scan still covers the ENTIRE section, including
/// gaps; SUD cannot trap that entry. Aarch64 still scans every aligned word in
/// every text section: no desync, but data can match an opcode and falsely refuse;
/// its entropy/counter/TLS instructions have no runtime trap either. See
/// `ESCAPE-CLASSES.md` for the remaining static-scan boundaries.
///
/// Within this coverage contract, a *false negative* — a real forbidden opcode
/// slipping past — is the dangerous direction. The length decoder fails CLOSED.
/// Any byte sequence it cannot confidently measure — an unmapped/invalid opcode,
/// a truncated tail, or an unsupported vector map — yields an
/// `undecodable-instruction` finding naming the offset and stops the walk, so the
/// binary is refused rather than silently scanned past a length guess. The legacy
/// three-byte maps (`0f 38`/`0f 3a`) *are* length-decoded: default codegen emits
/// them (the `sha2` crate's x86 backend uses `pshufb`/`palignr`/`pblendw` and the
/// SHA extensions `sha256rnds2`/`sha256msg1`/`sha256msg2`), and — like VEX below —
/// none of their opcodes are forbidden (every forbidden opcode lives in the
/// one-byte or the legacy two-byte `0f` map), so measuring them cannot hide a
/// forbidden instruction. VEX (AVX/AVX2, both the two-byte `c5` and three-byte
/// `c4` forms) is length-decoded for the same reason — default codegen emits it
/// (`vmovdqa`/`vzeroupper`/...) and its opcodes are never forbidden, so it is
/// measured only to reach the next real boundary. EVEX (AVX-512, `62 P0 P1 P2`)
/// is measured for maps 1/2/3 (`0f`/`0f 38`/`0f 3a`) by the same rules, except
/// that EVERY EVEX instruction has a ModRM: VEX's map-1 `77` (vzero*) has no EVEX
/// form and is refused. `62` cannot be BOUND in 64-bit mode. Compressed disp8*N
/// is still one encoded byte; masking, vector width and broadcast/rounding do not
/// change the operand lengths. No forbidden instruction lives in these EVEX maps.
///
/// EVEX fails closed on the following rather than extending VEX's length guess:
/// - Maps other than 1/2/3: 0/7 are reserved, 4 is APX, and 5/6 are FP16; none
///   has length rules established here. P0 bit 3 must be zero and P1 bit 2 one:
///   other values are not the supported AVX-512 prefix format (including APX).
/// - Map-1 `0f`, `a4`, `ac`, `ba`: these legacy imm8 opcodes (3DNow!, SHLD,
///   SHRD, group-8 bit operations) have no supported EVEX form. VEX's immediate
///   table does not measure them; refusing avoids dropping an immediate if a
///   future ISA reuses them. This is not a full EVEX opcode-validity allowlist.
/// - Preceding LOCK, 66, F2, F3 or REX: EVEX embeds its mandatory prefix and
///   register extension; those combinations are invalid. Segment/address-size
///   prefixes are allowed and use the ordinary ModRM/SIB/displacement rules.
/// - P2.z with aaa=0: zero-masking requires a mask register. L'L=3 is reserved
///   as a vector length; it is accepted only with b=1 and a register operand,
///   where these bits can instead encode embedded rounding (round toward zero).
/// - Missing prefix/opcode/operand bytes or a length over 15: no complete x86
///   instruction can be measured. As with VEX, this is a length decoder, not an
///   opcode-by-opcode validator of all operand, mask or feature constraints.
///
/// Within each range's linear walk, operand bytes are not tested as opcodes;
/// declared alternate entries are scanned separately. The decoder assumes
/// 64-bit mode throughout, so the instructions
/// that could leave it are refused as `far-transfer` (`lcall`/`ljmp` through
/// memory, `lret`, `iret`); the direct far forms (`9a`/`ea`) are invalid in
/// 64-bit mode and fail closed as undecodable. The length decoder is compared
/// with objdump boundaries over Patina-authored assembly in
/// `x86_decoder_matches_objdump_corpus`, and over optional real binaries in
/// `x86_decoder_matches_objdump_external_corpus`.
mod x86_scan;

#[cfg(test)]
mod tests;

pub use import_policy::native_elf_import_allowed;
#[cfg(test)]
use import_xrefs::collect_import_xref_provenance;
#[cfg(test)]
use instruction_scan::scan_instruction_classes;
pub use instruction_scan::{
    FAR_TRANSFER_CATEGORY, HOST_IDENTITY_CATEGORY, THREAD_POINTER_CATEGORY,
    native_escape_is_host_identity, native_host_identity_sites,
};
pub use native_audit::NativeAudit;
pub use provenance::NativeProvenance;
use provenance::NativeProvenanceIndex;
pub use report::{
    render_compat_mode_note, render_cpu_nondeterminism_note, render_host_identity_note,
    render_inert_weak_imports, render_native_escapes_grouped, render_thread_pointer_note,
    render_tsc_managed_note,
};
pub use shim::{
    NATIVE_LINUX_LIVE_INTERPOSERS, NativeDenyTrap, NativeDenyTrapSymbol,
    native_binary_has_sud_marker, native_binary_has_tsc_marker, native_binary_is_shim_linked,
    native_deny_trap_armed, native_deny_trap_symbols, native_escape_is_sud_manageable,
    native_escape_is_tsc_manageable, native_missing_live_interposers, shim_control_plane_symbols,
    shim_host_alias_violation,
};
pub use wasi::{
    PATINA_SDK_MODULE, SUPPORTED_PATINA_SDK_IMPORTS, SUPPORTED_PREVIEW1_IMPORTS,
    WASI_PREVIEW1_MODULE, WASI_PREVIEW1_TARGET, WasiAudit, WasmImport,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeEscape {
    pub symbol: String,
    pub category: &'static str,
    pub provenance: Vec<NativeProvenance>,
    /// For an *instruction* finding, the decoded mnemonic (`rdtsc`, `rdtscp`,
    /// `rdrand`, `rdseed`, `syscall`, `svc`, `cntvct`, `cntvctss`, `rndr`, `rndrrs`,
    /// `cpuid`, `wrfsbase`, `mov fs`, `pop fs`, `lfs`, `msr tpidr_el0`); `None`
    /// for a symbol, immediate, or undecodable finding.
    ///
    /// The category alone cannot decide manageability: `cpu-nondeterminism`
    /// covers both the timestamp counter (trappable via `PR_SET_TSC` on x86-64
    /// Linux) and the RNG/system-counter reads (`rdrand`/`rdseed`/`mrs CNTVCT`/
    /// `mrs RNDR`),
    /// which no mechanism traps. [`native_escape_is_tsc_manageable`] reads this
    /// field to keep the two apart, so an escape carrying no mnemonic is never
    /// downgraded.
    pub mnemonic: Option<&'static str>,
}

impl NativeEscape {
    fn new(symbol: String, category: &'static str, provenance: Vec<NativeProvenance>) -> Self {
        Self {
            symbol,
            category,
            provenance: normalize_provenance(provenance),
            mnemonic: None,
        }
    }

    /// Attach the decoded mnemonic of an instruction finding (see
    /// [`NativeEscape::mnemonic`]).
    fn with_mnemonic(mut self, mnemonic: &'static str) -> Self {
        self.mnemonic = Some(mnemonic);
        self
    }
}

#[derive(Debug)]
pub enum TargetError {
    Parse(wasmparser::BinaryReaderError),
    NativeParse(object::Error),
    NativeUnwind(gimli::Error),
    InvalidNativeCodeRanges(String),
    UnsupportedImports(Vec<WasmImport>),
    UnsupportedNativeFormat(BinaryFormat),
    RelocatableNativeElf,
    /// A linked ELF whose section headers (or dynamic symbol table) are gone:
    /// the import audit and the instruction scan read them, so nothing could
    /// be certified.
    UnauditableNativeElf,
    UnsupportedNativeArchitecture(Architecture),
    UnsupportedNativeImports(Vec<NativeEscape>),
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(f, "failed to parse WebAssembly module: {error}"),
            Self::NativeParse(error) => write!(f, "failed to parse native object: {error}"),
            Self::NativeUnwind(error) => write!(f, "failed to parse native unwind ranges: {error}"),
            Self::InvalidNativeCodeRanges(reason) => {
                write!(f, "invalid native code ranges: {reason}")
            }
            Self::UnsupportedImports(imports) => {
                write!(f, "unsupported WebAssembly imports:")?;
                for import in imports {
                    write!(f, " {}::{}", import.module, import.name)?;
                }
                Ok(())
            }
            Self::UnsupportedNativeFormat(format) => {
                write!(
                    f,
                    "unsupported native binary format {format:?}; expected Mach-O or ELF"
                )
            }
            Self::RelocatableNativeElf => f.write_str(
                "refusing relocatable ELF (ET_REL): an object file is not a runnable guest; link an executable before audit/run",
            ),
            Self::UnauditableNativeElf => f.write_str(
                "refusing an ELF without section headers or a dynamic symbol table: the import audit and the instruction scan read them, so the binary cannot be certified; link it without stripping its section headers",
            ),
            Self::UnsupportedNativeArchitecture(architecture) => {
                write!(
                    f,
                    "refusing to certify native binary: the forbidden-instruction \
containment scan cannot decode architecture {architecture:?}; supported architectures are Aarch64 \
and X86_64. Passing it would leave every instruction unexamined (a vacuous gate), so the audit/run \
fails closed"
                )
            }
            Self::UnsupportedNativeImports(imports) => {
                f.write_str(&render_native_escapes_grouped(imports))
            }
        }
    }
}

impl std::error::Error for TargetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::NativeParse(error) => Some(error),
            Self::NativeUnwind(error) => Some(error),
            Self::InvalidNativeCodeRanges(_)
            | Self::UnsupportedImports(_)
            | Self::UnsupportedNativeFormat(_)
            | Self::RelocatableNativeElf
            | Self::UnauditableNativeElf
            | Self::UnsupportedNativeArchitecture(_)
            | Self::UnsupportedNativeImports(_) => None,
        }
    }
}
