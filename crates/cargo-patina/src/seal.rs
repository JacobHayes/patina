//! The sealed shim: the two link inputs a guest takes in place of the POSIX
//! object and the shim archive (ARCHITECTURE.md, "The sealed shim"). One
//! pipeline seals ELF and Mach-O alike; only the relocatable link, the
//! rewrite after it (`seal/elf.rs`, `seal/macho.rs`) and the thunks' assembly
//! are the object format's.
//!
//! The **engine** is the archive partially linked into one relocatable object
//! (the shim crate, the runtime crates and their own copy of `std`), garbage
//! collected from the doors and the runtime ABI (on Mach-O, by the guest's
//! final link instead), with every definition but the inventory made local. A
//! door's Rust definition is renamed `patina_impl_<name>`; a door's route
//! alias (the `dlsym` table's answer) is left undefined under the door's name,
//! so it names the façade's address. The **façade** is the C seams (the POSIX
//! object, unchanged) and one generated thunk per Rust door, a tail jump to
//! its implementation.
//!
//! Every other reference engine code makes to a door is the engine's own use
//! of the host, not a guest's call: `std`'s I/O, locks and panic machinery,
//! and anything a workspace crate does through them. The seal binds each one
//! to a **host binding**, a stub it links into the engine that jumps through a
//! slot holding the host's definition of the name, so no engine code re-enters
//! a door. The engine's binder fills every slot (`patina_host_symbol`, the
//! alias table's resolver) when the shim starts, before any guest code runs,
//! so a stub never resolves anything; one whose slot the host left empty is a
//! named fatal. A door's own code naming another door is refused instead: a door
//! shares its model with another through an ordinary function, never through
//! the symbol, which the host binding would take.
//!
//! The engine's `std` is therefore a second copy beside the guest's: its own
//! panic hook, `thread::panicking()` and `io::stderr`, which write to the
//! host.
//!
//! The seal refuses an engine whose exports are not the inventory (the rows of
//! the symbol registry the Rust side defines, and the runtime's `patina_*` ABI)
//! or whose text holds a raw system call or counter read, and workspace code
//! that names a host symbol the import audit classifies as an escape (the
//! host-alias doctrine: the shim reaches the host through its private alias
//! table). It writes the engine's undefined references beside it for review.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use object::read::archive::ArchiveFile;
use object::{BinaryFormat, Object, ObjectSymbol, SymbolKind};
use patina_dst_native_shim::registry::{Os, SYMBOLS, is_control_plane_abi};
use patina_dst_target::{shim_control_plane_symbols, shim_host_alias_violation};

use crate::CliError;
use crate::allocator_routing::AllocatorRouting;

mod elf;
mod macho;

/// The façade object's file name.
pub(super) const FACADE: &str = "patina_facade.o";
/// The engine object's file name.
pub(super) const ENGINE: &str = "patina_engine.o";
/// The engine's undefined references, one `<strong|weak> <name>` per line.
pub(super) const REFERENCES: &str = "patina_engine.references";
/// The prefix of a door's renamed definition.
const IMPL: &str = "patina_impl_";
/// The prefix of a door's route alias.
const ROUTE: &str = "patina_route_";
/// The prefix of a door's host binding.
const HOST: &str = "patina_bound_";
/// The shim's resolver of a door's host definition, which the binder calls,
/// and its fatal for a stub whose slot is empty: the engine's own, never
/// exported.
const HOST_SYMBOL: &str = "patina_host_symbol";
const HOST_UNBOUND: &str = "patina_host_unbound";
/// The binder of every host binding, which the shim calls at startup.
const BIND_HOSTS: &str = "patina_bind_hosts";

/// A digest of the seal's own source and of the linker it runs, which decide
/// its outputs' bytes as much as its inputs do.
pub(super) fn recipe_digest() -> String {
    use sha2::{Digest, Sha256};
    static DIGEST: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DIGEST
        .get_or_init(|| {
            let mut hasher = Sha256::new();
            hasher.update(include_str!("seal.rs"));
            hasher.update(include_str!("seal/elf.rs"));
            hasher.update(include_str!("seal/macho.rs"));
            hasher.update(linker_identity());
            crate::hex(&hasher.finalize())
        })
        .clone()
}

/// The program that partially links: GNU or LLVM `ld`, or Apple's, which
/// the C compiler's driver runs.
const LINKER: &str = "ld";

/// The relocatable linker's resolved path and version report. A linker that
/// cannot be run identifies by its error; the seal then fails to link.
fn linker_identity() -> Vec<u8> {
    let path = std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(LINKER))
            .find(|candidate| candidate.is_file())
    });
    let mut identity = format!("{LINKER} at {path:?}\n").into_bytes();
    let version = if cfg!(target_os = "macos") {
        "-v"
    } else {
        "--version"
    };
    match Command::new(LINKER).arg(version).output() {
        Ok(output) => {
            identity.extend(output.stdout);
            identity.extend(output.stderr);
        }
        Err(error) => identity.extend(error.to_string().into_bytes()),
    }
    identity
}

/// The two objects a sealed guest links.
pub(super) struct Sealed {
    pub(super) facade: PathBuf,
    pub(super) engine: PathBuf,
}

/// Seal `staticlib` with the C seams `posix` into `dir`, or reuse the seal
/// already there once its engine's text passes the current scan. The caller holds
/// `dir`'s lock; outputs are renamed into place, the façade last, so a façade
/// names a complete seal.
pub(super) fn seal(
    staticlib: &Path,
    posix: &Path,
    routing: &AllocatorRouting,
    dir: &Path,
) -> Result<Sealed, CliError> {
    let sealed = Sealed {
        facade: dir.join(FACADE),
        engine: dir.join(ENGINE),
    };
    if sealed.facade.exists() && sealed.engine.exists() {
        // The cache key names the archive, the shim bundle (the registry
        // included) and this seal's source and linker; of the gate, only the
        // instruction scan, another crate's, can judge a reused engine anew.
        check_opcodes(&read(&sealed.engine)?)?;
        return Ok(sealed);
    }
    let posix_bytes = read(posix)?;
    let posix_file = parse(&posix_bytes, posix)?;
    let platform = Platform::of(&posix_file)?;
    let seam_definitions = global_definitions(&posix_file);
    let seams: BTreeSet<String> = seam_definitions.keys().cloned().collect();
    let archive_bytes = read(staticlib)?;
    let mut inventory = Inventory::classify(&archive_bytes, staticlib, &seams, platform)?;
    let rows = rows(platform);
    inventory.seam_doors = seam_definitions
        .into_iter()
        .filter(|(name, kind)| *kind == SymbolKind::Text && rows.contains(name.as_str()))
        .map(|(name, _)| name)
        .collect();
    let allocator = routing.entry_points();
    let scratch = tempfile::Builder::new()
        .prefix(".seal-")
        .tempdir_in(dir)
        .map_err(|error| refuse(format!("creating a scratch directory: {error}")))?;
    let work = scratch.path();

    let engine = work.join(ENGINE);
    platform.link_engine(&inventory, &allocator, staticlib, work, &engine)?;
    let engine_bytes = read(&engine)?;
    let engine_file = parse(&engine_bytes, &engine)?;
    check_exports(&engine_file, &inventory, &allocator)?;
    check_opcodes(&engine_bytes)?;
    fs::write(work.join(REFERENCES), references(&engine_file))
        .map_err(|error| refuse(format!("writing the engine's references: {error}")))?;

    let facade = work.join(FACADE);
    let doors = work.join("patina_doors.s");
    fs::write(&doors, platform.thunks(&inventory.doors))
        .map_err(|error| refuse(format!("writing the façade thunks: {error}")))?;
    let thunks = work.join("patina_doors.o");
    run(
        Command::new(cc())
            .arg("-c")
            .arg(&doors)
            .arg("-o")
            .arg(&thunks),
        "assembling the façade thunks",
    )?;
    run(
        platform
            .relocatable_link()
            .arg(posix)
            .arg(&thunks)
            .arg("-o")
            .arg(&facade),
        "linking the façade",
    )?;
    check_facade(&parse(&read(&facade)?, &facade)?, platform)?;

    for (from, to) in [
        (work.join(REFERENCES), dir.join(REFERENCES)),
        (engine, sealed.engine.clone()),
        (facade, sealed.facade.clone()),
    ] {
        fs::rename(&from, &to)
            .map_err(|error| refuse(format!("publishing {}: {error}", to.display())))?;
    }
    Ok(sealed)
}

/// What the archive's workspace code defines, classified against the registry.
#[derive(Debug, Default)]
struct Inventory {
    /// Registry rows with a Rust function definition: each becomes a façade
    /// thunk over `patina_impl_<name>`.
    doors: BTreeSet<String>,
    /// Registry rows the C seams define as functions: the façade's own
    /// doors, which engine code reaches by an undefined reference.
    seam_doors: BTreeSet<String>,
    /// Registry rows with a Rust data definition, exported under their own
    /// name: data cannot be thunked.
    data: BTreeSet<String>,
    /// The runtime's own ABI (`patina_*`/`PATINA_*`) defined anywhere in the
    /// archive: the C seams and the allocator routing reach the engine
    /// through it, and a guest may call it.
    abi: BTreeSet<String>,
    /// The personality references rustc emits in COMDAT groups
    /// (`DW.ref.*`): the final link keeps one group of each name, the
    /// guest's or the engine's, so the engine's must stay global for its
    /// unwind tables to reach the kept one.
    comdat: BTreeSet<String>,
}

impl Inventory {
    /// Classify every unmangled global the workspace's archive members define.
    /// A name that is neither a registry row nor the runtime ABI, a row also
    /// defined by the C seams, a row defined by neither side, and a host
    /// symbol workspace code names that the import audit classifies as an
    /// escape, each refuse the seal. On Mach-O, a member the merged engine
    /// could not be split at the symbols of refuses it too.
    fn classify(
        archive_bytes: &[u8],
        staticlib: &Path,
        seams: &BTreeSet<String>,
        platform: Platform,
    ) -> Result<Self, CliError> {
        let archive = ArchiveFile::parse(archive_bytes)
            .map_err(|error| refuse(format!("{}: {error}", staticlib.display())))?;
        let rows = rows(platform);
        let mut inventory = Self::default();
        let mut unexplained = BTreeSet::new();
        let mut duplicated = BTreeSet::new();
        let mut unsplittable = BTreeSet::new();
        // Every global the archive or the seams define, and the names
        // workspace code references: those defined by neither are the host's.
        let mut defined = seams.clone();
        let mut referenced = BTreeSet::new();
        for member in archive.members() {
            let member = member.map_err(|error| refuse(error.to_string()))?;
            let workspace = member.name().starts_with(b"patina_dst_");
            let data = member
                .data(archive_bytes)
                .map_err(|error| refuse(error.to_string()))?;
            // Archive members that are not objects (none today) define nothing.
            let Ok(file) = object::File::parse(data) else {
                continue;
            };
            if platform.macho && !macho::splits_at_symbols(data).map_err(refuse)? {
                unsplittable.insert(String::from_utf8_lossy(member.name()).into_owned());
            }
            if workspace {
                referenced.extend(undefined_references(&file).into_keys());
            }
            for (name, kind) in global_definitions(&file) {
                defined.insert(name.clone());
                if is_control_plane_abi(&name) {
                    inventory.abi.insert(name);
                    continue;
                }
                if name.starts_with("DW.ref.") {
                    inventory.comdat.insert(name);
                    continue;
                }
                // Dependencies' and the toolchain's globals are localised
                // unseen; only the workspace's are the shim's to explain.
                if !workspace || toolchain_glue(&name) {
                    continue;
                }
                if !rows.contains(name.as_str()) {
                    unexplained.insert(name);
                } else if seams.contains(&name) {
                    duplicated.insert(name);
                } else if kind == SymbolKind::Data {
                    inventory.data.insert(name);
                } else {
                    inventory.doors.insert(name);
                }
            }
        }
        // A door's route alias is a reference to the door, not ABI, and
        // the binder's resolver is the engine's own.
        for door in &inventory.doors {
            inventory.abi.remove(&route(door));
        }
        inventory.abi.remove(HOST_SYMBOL);
        inventory.abi.remove(HOST_UNBOUND);
        // The shim's weak stand-in for the binder, which the seal's replaces.
        inventory.abi.remove(BIND_HOSTS);
        let undefined: BTreeSet<&str> = rows
            .iter()
            .copied()
            .filter(|row| {
                !seams.contains(*row)
                    && !inventory.doors.contains(*row)
                    && !inventory.data.contains(*row)
            })
            .collect();
        let allow = shim_control_plane_symbols();
        let escapes: BTreeSet<String> = referenced
            .difference(&defined)
            .filter_map(|name| {
                shim_host_alias_violation(&platform.symbol(name), platform.macho, &allow)
                    .map(|category| format!("{name} ({category})"))
            })
            .collect();
        let mut problems = Vec::new();
        if !escapes.is_empty() {
            problems.push(format!(
                "host symbols workspace code names, which only the host-alias table may reach: {escapes:?}"
            ));
        }
        if !unsplittable.is_empty() {
            problems.push(format!(
                "members whose code cannot be split at their symbols: {unsplittable:?}"
            ));
        }
        if !unexplained.is_empty() {
            problems.push(format!(
                "exports that are neither a symbol-registry row nor the patina_* ABI: {unexplained:?}"
            ));
        }
        if !duplicated.is_empty() {
            problems.push(format!(
                "rows defined by both the C seams and the engine: {duplicated:?}"
            ));
        }
        if !undefined.is_empty() {
            problems.push(format!(
                "rows neither the C seams nor the engine define: {undefined:?}"
            ));
        }
        if problems.is_empty() {
            Ok(inventory)
        } else {
            Err(refuse(problems.join("; ")))
        }
    }

    /// The doors engine code reaches the host's definition of instead, the
    /// Rust side's and the C seams' alike: all but the shim's `--wrap`
    /// vehicles (`__wrap_dlsym`), which the host does not define.
    fn bound(&self) -> BTreeSet<String> {
        self.doors
            .iter()
            .chain(&self.seam_doors)
            .filter(|door| !door.starts_with("__wrap_"))
            .cloned()
            .collect()
    }

    /// What the engine exports, by C name.
    fn exports<'a>(&'a self, allocator: &'a [String]) -> impl Iterator<Item = String> + 'a {
        self.doors
            .iter()
            .map(|door| format!("{IMPL}{door}"))
            .chain(self.data.iter().cloned())
            .chain(self.abi.iter().cloned())
            .chain(self.comdat.iter().cloned())
            .chain(allocator.iter().cloned())
    }
}

/// A door's host binding.
fn host(door: &str) -> String {
    format!("{HOST}{door}")
}

/// A door's route alias (the `dlsym` table's hidden address for it), as
/// `build_support.rs` names it.
fn route(door: &str) -> String {
    format!("{ROUTE}{}", door.strip_prefix("__wrap_").unwrap_or(door))
}

/// Unmangled globals rustc emits on its own: Rust symbols, the gdb scripts
/// marker, the allocator glue and constant pools.
fn toolchain_glue(name: &str) -> bool {
    name.starts_with("_R")
        || name.starts_with("_ZN")
        || name.starts_with("__rustc_")
        || name.starts_with("__rust_")
        || name.starts_with("anon.")
}

/// The symbol registry's rows defined on `platform`'s OS.
fn rows(platform: Platform) -> BTreeSet<&'static str> {
    let os = if platform.macho {
        Os::Darwin
    } else {
        Os::Linux
    };
    SYMBOLS
        .iter()
        .filter(|row| row.platform.defines_on(os))
        .map(|row| row.name)
        .collect()
}

/// The façade exports registry rows and the runtime's ABI, whichever of the
/// C seams or the thunks defines them, and nothing else.
fn check_facade(facade: &object::File<'_>, platform: Platform) -> Result<(), CliError> {
    let rows = rows(platform);
    let unexpected: BTreeSet<String> = global_definitions(facade)
        .into_keys()
        .filter(|name| !rows.contains(name.as_str()) && !is_control_plane_abi(name))
        .collect();
    if unexpected.is_empty() {
        return Ok(());
    }
    Err(refuse(format!(
        "façade exports that are neither a symbol-registry row nor the patina_* ABI: {unexpected:?}"
    )))
}

/// The engine's exports must be exactly the inventory: every door's
/// implementation, the data rows, the ABI, the allocator entry points the
/// guest's may override, and the personality references rustc shares by
/// COMDAT.
fn check_exports(
    engine: &object::File<'_>,
    inventory: &Inventory,
    allocator: &[String],
) -> Result<(), CliError> {
    let exported: BTreeSet<String> = global_definitions(engine).into_keys().collect();
    let expected: BTreeSet<String> = inventory.exports(allocator).collect();
    if exported == expected {
        return Ok(());
    }
    Err(refuse(format!(
        "the engine's exports differ from the inventory: unexpected {:?}, missing {:?}",
        exported.difference(&expected).collect::<Vec<_>>(),
        expected.difference(&exported).collect::<Vec<_>>()
    )))
}

/// The engine reaches the kernel only through the host's libc, inside the
/// region system-call dispatch allows: no raw system call, counter or entropy
/// read in its text.
fn check_opcodes(engine: &[u8]) -> Result<(), CliError> {
    let sites = patina_dst_target::relocatable_raw_opcode_sites(engine)
        .map_err(|error| refuse(format!("scanning the engine's text: {error}")))?;
    if sites.is_empty() {
        return Ok(());
    }
    let named: BTreeSet<String> = sites
        .iter()
        .map(|site| {
            let within = site
                .provenance
                .iter()
                .find_map(|provenance| provenance.containing_symbol.as_deref())
                .map(|symbol| format!(" in {symbol}"))
                .unwrap_or_default();
            format!(
                "{}{within} ({})",
                site.symbol,
                site.mnemonic.unwrap_or(site.category)
            )
        })
        .collect();
    Err(refuse(format!(
        "raw system calls or counter reads in the engine's text: {named:?}"
    )))
}

/// The engine's undefined references, for review.
fn references(engine: &object::File<'_>) -> String {
    let mut text = String::new();
    for (name, weak) in undefined_references(engine) {
        let strength = if weak { "weak" } else { "strong" };
        writeln!(text, "{strength} {name}").expect("writing to a string");
    }
    text
}

/// Every global definition in `file`, by C name, with its kind.
fn global_definitions(file: &object::File<'_>) -> BTreeMap<String, SymbolKind> {
    file.symbols()
        .filter(|symbol| symbol.is_definition() && symbol.is_global())
        .filter_map(|symbol| Some((c_name(file, symbol.name().ok()?)?, symbol.kind())))
        .collect()
}

/// Every undefined reference in `file`, by C name, and whether it is weak.
fn undefined_references(file: &object::File<'_>) -> BTreeMap<String, bool> {
    file.symbols()
        .filter(|symbol| symbol.is_undefined())
        .filter_map(|symbol| Some((c_name(file, symbol.name().ok()?)?, symbol.is_weak())))
        .collect()
}

/// The C name of the symbol `name` in `file`: Mach-O prefixes an underscore.
/// A Mach-O name without one (none today) keeps its spelling, so no
/// expected name matches it.
fn c_name(file: &object::File<'_>, name: &str) -> Option<String> {
    if file.format() == BinaryFormat::MachO {
        return Some(name.strip_prefix('_').unwrap_or(name).to_owned());
    }
    Some(name.to_owned())
}

/// The C compiler, which also drives Apple's linker.
fn cc() -> OsString {
    std::env::var_os("CC").unwrap_or_else(|| "cc".into())
}

/// The object format and architecture the seal emits for: ELF on Linux,
/// Mach-O on Darwin, each on x86_64 or aarch64.
#[derive(Clone, Copy, Debug)]
struct Platform {
    macho: bool,
    aarch64: bool,
}

impl Platform {
    fn of(file: &object::File<'_>) -> Result<Self, CliError> {
        let macho = match file.format() {
            BinaryFormat::Elf => false,
            BinaryFormat::MachO => true,
            other => return Err(refuse(format!("no seal for {other:?} objects"))),
        };
        let aarch64 = match file.architecture() {
            object::Architecture::X86_64 => false,
            object::Architecture::Aarch64 => true,
            other => return Err(refuse(format!("no seal for {other:?}"))),
        };
        Ok(Self { macho, aarch64 })
    }

    /// The symbol a C name is in this format's objects.
    fn symbol(self, name: &str) -> String {
        if self.macho {
            format!("_{name}")
        } else {
            name.to_owned()
        }
    }

    /// A relocatable link that keeps hidden globals global, as ELF's does:
    /// Apple's otherwise makes them local, and the façade and the engine
    /// reach each other's.
    fn relocatable_link(self) -> Command {
        if self.macho {
            let mut command = Command::new(cc());
            command.args(["-r", "-nostdlib", "-Wl,-keep_private_externs"]);
            return command;
        }
        let mut command = Command::new(LINKER);
        command.arg("-r");
        command
    }

    /// The façade's thunks: per door, a tail jump, which pushes and signs no
    /// return address, so the door is its implementation to every caller.
    /// On ELF each also starts with a landing pad for indirect calls under
    /// control-flow enforcement.
    fn thunks(self, doors: &BTreeSet<String>) -> String {
        let mut text = String::from("\t.text\n");
        for door in doors {
            let (name, target) = (self.symbol(door), self.symbol(&format!("{IMPL}{door}")));
            let body = match (self.macho, self.aarch64) {
                (false, true) => format!("\thint 34\n\tb {target}\n"),
                (false, false) => format!("\tendbr64\n\tjmp {target}\n"),
                (true, true) => format!("\tb {target}\n"),
                (true, false) => format!("\tjmp {target}\n"),
            };
            if self.macho {
                write!(text, "\t.globl {name}\n\t.p2align 4\n{name}:\n{body}")
            } else {
                write!(
                    text,
                    "\t.globl {name}\n\t.type {name}, %function\n\t.p2align 4\n{name}:\n{body}\t.size {name}, .-{name}\n"
                )
            }
            .expect("writing to a string");
        }
        text.push_str(&self.object_notes());
        text
    }

    /// The notes ending a generated object. On Mach-O, each symbol its own
    /// atom, as the C seams' functions are, so the final link drops what
    /// nothing reaches. On ELF, NT_GNU_PROPERTY_TYPE_0: x86 IBT | SHSTK, or
    /// aarch64 BTI | PAC, so the object keeps the program's control-flow
    /// marking.
    fn object_notes(self) -> String {
        if self.macho {
            return "\t.subsections_via_symbols\n".to_owned();
        }
        let property = if self.aarch64 {
            "0xc0000000"
        } else {
            "0xc0000002"
        };
        format!(
            "\t.section .note.GNU-stack,\"\",%progbits\n\
             \t.section .note.gnu.property,\"a\"\n\t.p2align 3\n\
             \t.long 4\n\t.long 16\n\t.long 5\n\t.asciz \"GNU\"\n\
             \t.long {property}\n\t.long 4\n\t.long 3\n\t.long 0\n"
        )
    }

    /// The engine's host bindings: per bindable door, a stub that jumps
    /// through its slot to the host's definition of the name, and the binder
    /// (`BIND_HOSTS`) that fills every slot through the resolver. The shim
    /// calls the binder first thing at startup, before any guest code or
    /// signal handler runs, so no stub resolves anything: a stub is one load
    /// and a jump, safe in a signal handler and transparent to any signature,
    /// a variadic one's included. A slot stays empty for a name the host does
    /// not define (some doors are the shim's alone), and a stub whose slot is
    /// empty is a named fatal (`HOST_UNBOUND`). The stubs are global so the
    /// rewrite can find them; it makes them local.
    fn host_bindings(self, bound: &BTreeSet<String>) -> String {
        // Local names outside the stubs' `patina_bound_<door>` space.
        let binder = self.symbol(BIND_HOSTS);
        let resolver = self.symbol(HOST_SYMBOL);
        let unbound = self.symbol(HOST_UNBOUND);
        let text_section = |name: &str| {
            if self.macho {
                "__TEXT,__text,regular,pure_instructions".to_owned()
            } else {
                format!(".text.{name},\"ax\",%progbits")
            }
        };
        let typed = |name: &str| {
            if self.macho {
                (String::new(), String::new())
            } else {
                (
                    format!("\t.type {name}, %function\n"),
                    format!("\t.size {name}, .-{name}\n"),
                )
            }
        };
        let mut text = String::new();
        let mut binds = String::new();
        for door in bound {
            let stub = self.symbol(&host(door));
            let slot = self.symbol(&format!("patina_slot_{door}"));
            let name = self.symbol(&format!("patina_name_{door}"));
            let (slot_section, name_section) = if self.macho {
                (
                    "__DATA,__data".to_owned(),
                    "__TEXT,__cstring,cstring_literals".to_owned(),
                )
            } else {
                (
                    format!(".bss.{slot},\"aw\",%nobits"),
                    format!(".rodata.{name},\"a\",%progbits"),
                )
            };
            let (body, bind) = match (self.macho, self.aarch64) {
                (macho, false) => (
                    format!(
                        "{landing}\tmovq {slot}(%rip), %r11\n\ttestq %r11, %r11\n\tjz 1f\n\tjmp *%r11\n\
                         1:\tleaq {name}(%rip), %rdi\n\tjmp {unbound}\n",
                        landing = if macho { "" } else { "\tendbr64\n" },
                    ),
                    format!(
                        "\tleaq {name}(%rip), %rdi\n\tcall {resolver}\n\tmovq %rax, {slot}(%rip)\n"
                    ),
                ),
                (false, true) => (
                    format!(
                        "\thint 34\n\tadrp x16, {slot}\n\tldr x16, [x16, :lo12:{slot}]\n\
                         \tcbz x16, 1f\n\tbr x16\n\
                         1:\tadrp x0, {name}\n\tadd x0, x0, :lo12:{name}\n\tb {unbound}\n"
                    ),
                    format!(
                        "\tadrp x0, {name}\n\tadd x0, x0, :lo12:{name}\n\tbl {resolver}\n\
                         \tadrp x16, {slot}\n\tstr x0, [x16, :lo12:{slot}]\n"
                    ),
                ),
                (true, true) => (
                    format!(
                        "\tadrp x16, {slot}@PAGE\n\tldr x16, [x16, {slot}@PAGEOFF]\n\
                         \tcbz x16, 1f\n\tbr x16\n\
                         1:\tadrp x0, {name}@PAGE\n\tadd x0, x0, {name}@PAGEOFF\n\tb {unbound}\n"
                    ),
                    format!(
                        "\tadrp x0, {name}@PAGE\n\tadd x0, x0, {name}@PAGEOFF\n\tbl {resolver}\n\
                         \tadrp x16, {slot}@PAGE\n\tstr x0, [x16, {slot}@PAGEOFF]\n"
                    ),
                ),
            };
            binds.push_str(&bind);
            let (function, size) = typed(&stub);
            write!(
                text,
                "\t.section {}\n\t.globl {stub}\n{function}\t.p2align 4\n{stub}:\n{body}{size}\
                 \t.section {slot_section}\n\t.p2align 3\n{slot}:\n\t.quad 0\n\
                 \t.section {name_section}\n{name}:\n\t.asciz \"{door}\"\n",
                text_section(&stub)
            )
            .expect("writing to a string");
        }
        // The binder, an ordinary function of no arguments: one resolver call
        // per slot. One push (a frame record on aarch64) aligns the stack for
        // the calls.
        let (prologue, epilogue) = if self.aarch64 {
            (
                "\tstp x29, x30, [sp, #-16]!\n\tmov x29, sp\n",
                "\tldp x29, x30, [sp], #16\n\tret\n",
            )
        } else if self.macho {
            ("\tpushq %rbx\n", "\tpopq %rbx\n\tret\n")
        } else {
            ("\tendbr64\n\tpushq %rbx\n", "\tpopq %rbx\n\tret\n")
        };
        let (function, size) = typed(&binder);
        write!(
            text,
            "\t.section {}\n\t.globl {binder}\n{function}\t.p2align 4\n{binder}:\n\
             {prologue}{binds}{epilogue}{size}",
            text_section(&binder)
        )
        .expect("writing to a string");
        text.push_str(&self.object_notes());
        text
    }

    /// Partially link the archive into `engine`, then split each door into
    /// its implementation and a reference to its public name, and localise
    /// everything but the inventory.
    fn link_engine(
        self,
        inventory: &Inventory,
        allocator: &[String],
        staticlib: &Path,
        work: &Path,
        engine: &Path,
    ) -> Result<(), CliError> {
        let merged = work.join("merged.o");
        let source = work.join("patina_host.s");
        fs::write(&source, self.host_bindings(&inventory.bound()))
            .map_err(|error| refuse(format!("writing the host bindings: {error}")))?;
        let bindings = work.join("patina_host.o");
        run(
            Command::new(cc())
                .arg("-c")
                .arg(&source)
                .arg("-o")
                .arg(&bindings),
            "assembling the host bindings",
        )?;
        if self.macho {
            self.link_macho_engine(inventory, allocator, staticlib, &bindings, &merged)?;
        } else {
            self.link_elf_engine(inventory, allocator, staticlib, &bindings, work, &merged)?;
        }
        fs::rename(&merged, engine)
            .map_err(|error| refuse(format!("localising the engine: {error}")))
    }

    /// ELF: garbage-collect from the inventory and wrap each door so the
    /// other members' references to it stay undefined, then rename the
    /// definitions and bind the references, wrapped or not, to the host.
    fn link_elf_engine(
        self,
        inventory: &Inventory,
        allocator: &[String],
        staticlib: &Path,
        bindings: &Path,
        work: &Path,
        merged: &Path,
    ) -> Result<(), CliError> {
        let mut args = String::new();
        for door in &inventory.doors {
            writeln!(args, "-u {door}\n--wrap={door}").expect("writing to a string");
        }
        // Rooted: nothing references a binding until the rewrite.
        for door in inventory.bound() {
            writeln!(args, "-u {}", host(&door)).expect("writing to a string");
        }
        for name in inventory.data.iter().chain(&inventory.abi) {
            writeln!(args, "-u {name}").expect("writing to a string");
        }
        // The allocator entry points stay routable: the members' calls to them
        // are left as the routing's `__wrap_` names, and the engine's own
        // definitions weaken, so a Rust guest's take precedence.
        for entry in allocator {
            writeln!(args, "-u {entry}\n--wrap={entry}").expect("writing to a string");
        }
        let args_path = work.join("engine.args");
        write(&args_path, &args)?;
        run(
            self.relocatable_link()
                .arg("--gc-sections")
                .arg(at(&args_path))
                .arg(bindings)
                // Whole: a wrapped door's `-u` roots its wrapper, never the
                // member that defines it.
                .arg("--whole-archive")
                .arg(staticlib)
                .arg("--no-whole-archive")
                .arg("-o")
                .arg(merged),
            "partially linking the engine",
        )?;
        let renames: BTreeMap<String, String> = inventory
            .doors
            .iter()
            .flat_map(|door| {
                [
                    (door.clone(), format!("{IMPL}{door}")),
                    (format!("__wrap_{door}"), door.clone()),
                    (route(door), door.clone()),
                ]
            })
            .collect();
        // A route alias names the door the guest links, so `dlsym` answers
        // the same address: one that aliases the definition becomes a
        // reference to the door.
        let undefine: BTreeSet<String> = inventory.doors.iter().map(|door| route(door)).collect();
        // A member's reference to a Rust door is wrapped; the defining
        // member's own names the definition, and a reference to a C seam's
        // door is undefined. All are the engine's, and bind to the host.
        let bind: BTreeMap<String, String> = inventory
            .bound()
            .into_iter()
            .flat_map(|door| {
                [
                    (door.clone(), host(&door)),
                    (format!("__wrap_{door}"), host(&door)),
                ]
            })
            .collect();
        let keep: BTreeSet<String> = inventory.exports(allocator).collect();
        let weaken: BTreeSet<String> = allocator.iter().cloned().collect();
        elf::rewrite(
            merged,
            &elf::Plan {
                renames: &renames,
                keep: &keep,
                weaken: &weaken,
                undefine: &undefine,
                bind: &bind,
                doors: &inventory.doors,
            },
        )
        .map_err(|error| refuse(format!("localising the engine: {error}")))
    }

    /// Mach-O: Apple's relocatable link neither collects garbage nor wraps,
    /// so the whole archive links, and the final link's dead stripping
    /// collects it at the symbols; the rewrite splits the doors and binds
    /// every reference to one to the host. Darwin routes no allocator and
    /// has no route aliases.
    fn link_macho_engine(
        self,
        inventory: &Inventory,
        allocator: &[String],
        staticlib: &Path,
        bindings: &Path,
        merged: &Path,
    ) -> Result<(), CliError> {
        if !allocator.is_empty() {
            return Err(refuse("no Mach-O seal routes the allocator".to_owned()));
        }
        run(
            self.relocatable_link()
                .arg(bindings)
                .arg("-Wl,-all_load")
                .arg(staticlib)
                .arg("-o")
                .arg(merged),
            "partially linking the engine",
        )?;
        let doors: BTreeMap<String, String> = inventory
            .doors
            .iter()
            .map(|door| (self.symbol(door), self.symbol(&format!("{IMPL}{door}"))))
            .collect();
        let bind: BTreeMap<String, String> = inventory
            .bound()
            .iter()
            .map(|door| (self.symbol(door), self.symbol(&host(door))))
            .collect();
        let keep: BTreeSet<String> = inventory
            .exports(allocator)
            .map(|name| self.symbol(&name))
            .collect();
        macho::rewrite(
            merged,
            &macho::Plan {
                doors: &doors,
                bind: &bind,
                keep: &keep,
                // `Inventory::classify` refused any member that could not be.
                subsections: true,
            },
        )
        .map_err(|error| refuse(format!("localising the engine: {error}")))
    }
}

fn at(path: &Path) -> OsString {
    prefixed("@", path)
}

fn prefixed(prefix: &str, path: &Path) -> OsString {
    let mut arg = OsString::from(prefix);
    arg.push(path);
    arg
}

fn run(command: &mut Command, what: &str) -> Result<(), CliError> {
    let output = command
        .output()
        .map_err(|error| refuse(format!("{what}: {error}")))?;
    if output.status.success() {
        return Ok(());
    }
    Err(refuse(format!(
        "{what} failed ({}):\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    )))
}

fn read(path: &Path) -> Result<Vec<u8>, CliError> {
    fs::read(path).map_err(|error| refuse(format!("reading {}: {error}", path.display())))
}

fn write(path: &Path, text: &str) -> Result<(), CliError> {
    fs::write(path, text).map_err(|error| refuse(format!("writing {}: {error}", path.display())))
}

fn parse<'data>(bytes: &'data [u8], path: &Path) -> Result<object::File<'data>, CliError> {
    object::File::parse(bytes).map_err(|error| refuse(format!("{}: {error}", path.display())))
}

fn refuse(reason: String) -> CliError {
    CliError(format!("sealing the native shim: {reason}"))
}
