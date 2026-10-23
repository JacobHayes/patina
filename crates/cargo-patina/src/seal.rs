//! The sealed shim: the two link inputs a Linux guest takes in place of the
//! POSIX object and the shim archive (ARCHITECTURE.md, "The sealed shim").
//! Darwin guests link those two unsealed.
//!
//! The **engine** is the archive partially linked into one relocatable object
//! (the shim crate, the runtime crates and their own copy of `std`), garbage
//! collected from the doors and the runtime ABI, with every definition but the
//! inventory made local. A door's Rust definition is renamed
//! `patina_impl_<name>`; the engine's own references to a door, its route
//! alias included, are left undefined under the door's name, so they bind to
//! the façade exactly as they bound to the shim's definition before. The
//! **façade** is the C seams (the POSIX object, unchanged) and one generated
//! thunk per Rust door, a landing pad and a tail jump to its implementation.
//!
//! The engine's `std` is therefore a second copy beside the guest's: its own
//! panic hook, `thread::panicking()` and `io::stderr`. Nothing rebinds yet: the
//! engine's references still reach the doors, the allocator and the host
//! exactly as they did.
//!
//! The seal refuses an engine whose exports are not the inventory (the rows of
//! the symbol registry the Rust side defines, and the runtime's `patina_*` ABI)
//! or whose text holds a raw system call or counter read, and writes the
//! engine's undefined references beside it for review.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use object::read::archive::ArchiveFile;
use object::{Object, ObjectSymbol, SymbolKind};
use patina_dst_native_shim::registry::{Os, SYMBOLS, is_control_plane_abi};

use crate::CliError;
use crate::allocator_routing::AllocatorRouting;

mod elf;

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
            hasher.update(linker_identity());
            crate::hex(&hasher.finalize())
        })
        .clone()
}

/// The program that partially links, GNU or LLVM `ld`.
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
    match Command::new(LINKER).arg("--version").output() {
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
    let seams: BTreeSet<String> = global_definitions(&posix_file).into_keys().collect();
    let archive_bytes = read(staticlib)?;
    let inventory = Inventory::classify(&archive_bytes, staticlib, &seams)?;
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
        Command::new(std::env::var_os("CC").unwrap_or_else(|| "cc".into()))
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
    check_facade(&parse(&read(&facade)?, &facade)?)?;

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
    /// defined by the C seams, and a row defined by neither side, each refuse
    /// the seal.
    fn classify(
        archive_bytes: &[u8],
        staticlib: &Path,
        seams: &BTreeSet<String>,
    ) -> Result<Self, CliError> {
        let archive = ArchiveFile::parse(archive_bytes)
            .map_err(|error| refuse(format!("{}: {error}", staticlib.display())))?;
        let rows = rows();
        let mut inventory = Self::default();
        let mut unexplained = BTreeSet::new();
        let mut duplicated = BTreeSet::new();
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
            for (name, kind) in global_definitions(&file) {
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
        // A door's route alias is a reference to the door, not ABI.
        for door in &inventory.doors {
            inventory.abi.remove(&route(door));
        }
        let undefined: BTreeSet<&str> = rows
            .iter()
            .copied()
            .filter(|row| {
                !seams.contains(*row)
                    && !inventory.doors.contains(*row)
                    && !inventory.data.contains(*row)
            })
            .collect();
        let mut problems = Vec::new();
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

/// The symbol registry's rows defined on Linux.
fn rows() -> BTreeSet<&'static str> {
    SYMBOLS
        .iter()
        .filter(|row| row.platform.defines_on(Os::Linux))
        .map(|row| row.name)
        .collect()
}

/// The façade exports registry rows and the runtime's ABI, whichever of the
/// C seams or the thunks defines them, and nothing else.
fn check_facade(facade: &object::File<'_>) -> Result<(), CliError> {
    let rows = rows();
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

/// The engine's undefined references, for review: S0 reports them, the
/// binding stage gates them against a checked-in allowlist.
fn references(engine: &object::File<'_>) -> String {
    let mut names = BTreeMap::new();
    for symbol in engine.symbols() {
        if symbol.is_undefined()
            && let Ok(name) = symbol.name()
        {
            names.insert(name.to_owned(), symbol.is_weak());
        }
    }
    let mut text = String::new();
    for (name, weak) in names {
        let strength = if weak { "weak" } else { "strong" };
        writeln!(text, "{strength} {name}").expect("writing to a string");
    }
    text
}

/// Every global definition in `file`, by C name, with its kind.
fn global_definitions(file: &object::File<'_>) -> BTreeMap<String, SymbolKind> {
    file.symbols()
        .filter(|symbol| symbol.is_definition() && symbol.is_global())
        .filter_map(|symbol| {
            let name = symbol.name().ok()?;
            Some((name.to_owned(), symbol.kind()))
        })
        .collect()
}

/// The architecture the seal emits for. The seal links ELF only: Darwin
/// guests link the POSIX object and the archive unsealed (ARCHITECTURE.md,
/// "The sealed shim").
#[derive(Clone, Copy, Debug)]
struct Platform {
    aarch64: bool,
}

impl Platform {
    fn of(file: &object::File<'_>) -> Result<Self, CliError> {
        if file.format() != object::BinaryFormat::Elf {
            return Err(refuse(format!("no seal for {:?} objects", file.format())));
        }
        let aarch64 = match file.architecture() {
            object::Architecture::X86_64 => false,
            object::Architecture::Aarch64 => true,
            other => return Err(refuse(format!("no seal for {other:?}"))),
        };
        Ok(Self { aarch64 })
    }

    fn relocatable_link(self) -> Command {
        let mut command = Command::new(LINKER);
        command.arg("-r");
        command
    }

    /// The façade's thunks: per door, a landing pad for indirect calls under
    /// control-flow enforcement and a tail jump, which pushes and signs no
    /// return address, so the door is its implementation to every caller.
    fn thunks(self, doors: &BTreeSet<String>) -> String {
        let mut text = String::from("\t.text\n");
        for door in doors {
            let (name, target) = (door, format!("{IMPL}{door}"));
            let body = if self.aarch64 {
                format!("\thint 34\n\tb {target}\n")
            } else {
                format!("\tendbr64\n\tjmp {target}\n")
            };
            write!(
                text,
                "\t.globl {name}\n\t.type {name}, %function\n\t.p2align 4\n{name}:\n{body}\t.size {name}, .-{name}\n"
            )
            .expect("writing to a string");
        }
        // NT_GNU_PROPERTY_TYPE_0: x86 IBT | SHSTK, or aarch64 BTI | PAC, so
        // the façade keeps the program's control-flow marking.
        let property = if self.aarch64 {
            "0xc0000000"
        } else {
            "0xc0000002"
        };
        write!(
            text,
            "\t.section .note.GNU-stack,\"\",%progbits\n\
             \t.section .note.gnu.property,\"a\"\n\t.p2align 3\n\
             \t.long 4\n\t.long 16\n\t.long 5\n\t.asciz \"GNU\"\n\
             \t.long {property}\n\t.long 4\n\t.long 3\n\t.long 0\n"
        )
        .expect("writing to a string");
        text
    }

    /// Partially link the archive into `engine`: garbage-collect from the
    /// inventory, wrap each door so the other members' references to it stay
    /// undefined, then rename the definitions and the wrapped references and
    /// localise everything but the inventory.
    fn link_engine(
        self,
        inventory: &Inventory,
        allocator: &[String],
        staticlib: &Path,
        work: &Path,
        engine: &Path,
    ) -> Result<(), CliError> {
        let mut args = String::new();
        for door in &inventory.doors {
            writeln!(args, "-u {door}\n--wrap={door}").expect("writing to a string");
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
        let merged = work.join("merged.o");
        run(
            self.relocatable_link()
                .arg("--gc-sections")
                .arg(at(&args_path))
                // Whole: a wrapped door's `-u` roots its wrapper, never the
                // member that defines it.
                .arg("--whole-archive")
                .arg(staticlib)
                .arg("--no-whole-archive")
                .arg("-o")
                .arg(&merged),
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
        let keep: BTreeSet<String> = inventory.exports(allocator).collect();
        let weaken: BTreeSet<String> = allocator.iter().cloned().collect();
        elf::rewrite(
            &merged,
            &elf::Plan {
                renames: &renames,
                keep: &keep,
                weaken: &weaken,
                undefine: &undefine,
            },
        )
        .map_err(|error| refuse(format!("localising the engine: {error}")))?;
        fs::rename(&merged, engine)
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
