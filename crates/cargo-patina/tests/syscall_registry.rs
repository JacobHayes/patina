//! The syscall registry's object-level, classification, and conformance
//! cross-gates (design §3 tests (c), (d) and (e)):
//!
//! Probe/manifest associations are gated in the pure conformance library's
//! `src/registry_gate.rs`, using typed native associations rather than foreign
//! inventories. This test retains the independent object/symbol surface gates.
//!
//! * (d) every symbol row names a symbol the compiled shim objects define on
//!   this platform, and every defined public symbol has a row (the `patina_*` runtime ABI is excluded
//!   by the prefix rule, and Rust libc definitions obey the same registry);
//! * (e) `patina-target`'s classification lists agree with the rows: the
//!   deny-trap list is exactly the `Deny(class)` rows, which are exactly the
//!   trap-calling definitions in the shim's C, and no interposed symbol is in
//!   the deny-trap list; the load-bearing live interposers are rows the shim
//!   defines;
//! * every group of imports the audit allows says how libc's implementation
//!   reaches the kernel, and the claim agrees with the rows: a group declared
//!   `Interposed` is defined by the shim on its platform, and a symbol the
//!   shim defines is never declared to reach libc's text.
//!
//! The comparisons are pure functions over sets, and the `planted_*` tests
//! feed them doctored inputs so no gate can silently pass.

mod common;

use std::collections::BTreeSet;

use patina_dst_native_shim::registry::SymbolRow;
use patina_dst_native_shim::registry::{Os, Platform, SYMBOLS, SymbolStatus, is_control_plane_abi};
use patina_dst_target::{
    AllowedImports, KernelEntry, NATIVE_LINUX_LIVE_INTERPOSERS, native_deny_trap_symbols,
};

use common::{compile_posix_object, defined_public_symbols, for_each_shim_member, shim_archive};

/// The (d) comparison: what the objects define versus what the rows claim,
/// for one OS. Pure so a planted set can drive it.
#[derive(Debug, Default, PartialEq, Eq)]
struct Gaps {
    /// Defined by the objects, no row (and not the `patina_*` ABI).
    unlisted: Vec<String>,
    /// A row for this OS the objects do not define.
    undefined: Vec<String>,
}

fn gaps(defined: &BTreeSet<String>, os: Os) -> Gaps {
    let rows: BTreeSet<&str> = SYMBOLS
        .iter()
        .filter(|symbol| symbol.platform.defines_on(os))
        .map(|symbol| symbol.name)
        .collect();
    Gaps {
        unlisted: defined
            .iter()
            .filter(|name| !is_control_plane_abi(name) && !rows.contains(name.as_str()))
            .cloned()
            .collect(),
        undefined: rows
            .into_iter()
            .filter(|name| !defined.contains(*name))
            .map(str::to_owned)
            .collect(),
    }
}

fn host_os() -> Os {
    if cfg!(target_os = "macos") {
        Os::Darwin
    } else {
        Os::Linux
    }
}

/// (d) The C object's public definitions are exactly the rows for this OS
/// (minus the runtime ABI).
#[test]
fn every_defined_public_symbol_has_a_row_and_every_row_is_defined() {
    let dir = tempfile::tempdir().unwrap();
    let object_path = compile_posix_object(dir.path());
    let bytes = std::fs::read(&object_path).unwrap();
    let object = object::File::parse(&*bytes).expect("parse the POSIX shim object");
    let mut defined = defined_public_symbols(&object);
    // Rust interposers and C definitions share one registry; neither producer
    // may silently supply a second definition of a public symbol.
    let archive = std::fs::read(shim_archive()).unwrap();
    let mut rust_exports = BTreeSet::new();
    for_each_shim_member(&archive, |member| {
        for name in defined_public_symbols(member) {
            if rustc_demangle::try_demangle(&name).is_err() {
                assert!(
                    rust_exports.insert(name.clone()),
                    "duplicate Rust definition: {name}"
                );
            }
        }
    });
    // rustc emits unmangled globals of its own into the Rust object set: the
    // DWARF EH personality reference, the gdb-scripts section marker, and
    // allocator shims. None is a definition the shim wrote, so none
    // needs a row.
    let toolchain_glue = |name: &str| {
        name.starts_with("DW.ref.")
            || name.starts_with("__rustc_")
            || matches!(
                name,
                "__rust_alloc"
                    | "__rust_alloc_error_handler"
                    | "__rust_alloc_error_handler_should_panic"
                    | "__rust_alloc_zeroed"
                    | "__rust_dealloc"
                    | "__rust_no_alloc_shim_is_unstable"
                    | "__rust_realloc"
            )
    };
    let duplicates = duplicate_libc_definitions(&defined, &rust_exports);
    assert!(
        duplicates.is_empty(),
        "duplicate C/Rust definitions: {duplicates:?}"
    );
    defined.extend(
        rust_exports
            .into_iter()
            .filter(|name| !toolchain_glue(name)),
    );

    // Non-vacuity: a doctored set reports each gap direction, and a
    // definition from both producers is a duplicate (a prefixed bootstrap
    // hook is not).
    let mut planted: BTreeSet<String> = SYMBOLS
        .iter()
        .filter(|symbol| symbol.platform.defines_on(Os::Linux))
        .map(|symbol| symbol.name.to_owned())
        .collect();
    assert_eq!(gaps(&planted, Os::Linux), Gaps::default());
    planted.insert("nonesuch".to_owned()); // defined, no row
    planted.remove("read"); // a row the objects lost
    planted.insert("patina_planted".to_owned()); // runtime ABI: excluded by rule
    let planted_gaps = gaps(&planted, Os::Linux);
    assert_eq!(planted_gaps.unlisted, vec!["nonesuch".to_owned()]);
    assert_eq!(planted_gaps.undefined, vec!["read".to_owned()]);
    let both = BTreeSet::from(["fcntl".to_owned(), "patina_sud_arm_thread".to_owned()]);
    assert_eq!(
        duplicate_libc_definitions(&both, &both),
        vec![&"fcntl".to_owned()]
    );

    let gaps = gaps(&defined, host_os());
    assert_eq!(
        gaps,
        Gaps::default(),
        "the symbol registry and the compiled shim objects disagree on {}:\n  \
         defined but no row (add a SymbolRow): {:?}\n  \
         row but not defined (a stale row, or a definition lost from the link): {:?}",
        host_os().name(),
        gaps.unlisted,
        gaps.undefined
    );
}

// Prefixed bootstrap hooks have intentional weak/strong overrides. Public
// libc entries must have exactly one producer, regardless of implementation.
fn duplicate_libc_definitions<'a>(
    c: &'a BTreeSet<String>,
    rust: &'a BTreeSet<String>,
) -> Vec<&'a String> {
    c.intersection(rust)
        .filter(|name| !is_control_plane_abi(name))
        .collect()
}

/// (e) Registry agreement on the deny-trap surface, and the interposed rows
/// never in it.
#[test]
fn deny_rows_agree_with_patina_target() {
    let rows: BTreeSet<(String, String)> = SYMBOLS
        .iter()
        .filter_map(|symbol| match symbol.status {
            SymbolStatus::Deny(class) => Some((symbol.name.to_owned(), class.to_owned())),
            _ => None,
        })
        .collect();
    let target: BTreeSet<(String, String)> = native_deny_trap_symbols()
        .iter()
        .map(|(symbol, class)| ((*symbol).to_owned(), (*class).to_owned()))
        .collect();
    assert_eq!(
        rows,
        target,
        "registry Deny rows and patina-target's NATIVE_DENY_TRAP_SYMBOLS differ.\n  \
         rows not in patina-target: {:?}\n  patina-target entries with no Deny row: {:?}",
        rows.difference(&target).collect::<Vec<_>>(),
        target.difference(&rows).collect::<Vec<_>>()
    );
    let trap_names: BTreeSet<&str> = target.iter().map(|(name, _)| name.as_str()).collect();
    let interposed_in_deny: Vec<&str> = SYMBOLS
        .iter()
        .filter(|symbol| {
            matches!(
                symbol.status,
                SymbolStatus::Modeled | SymbolStatus::Partial | SymbolStatus::ControlPlane
            )
        })
        .map(|symbol| symbol.name)
        .filter(|name| trap_names.contains(name))
        .collect();
    assert!(
        interposed_in_deny.is_empty(),
        "an interposed symbol is never in the deny-trap list: {interposed_in_deny:?}"
    );
    // The live-interposer set the Linux link must keep is a set of rows the
    // shim defines on Linux.
    let missing: Vec<&str> = NATIVE_LINUX_LIVE_INTERPOSERS
        .iter()
        .copied()
        .filter(|name| {
            !SYMBOLS.iter().any(|symbol| {
                symbol.name == *name
                    && symbol.platform != Platform::Darwin
                    && !matches!(symbol.status, SymbolStatus::Deny(_))
            })
        })
        .collect();
    assert!(
        missing.is_empty(),
        "NATIVE_LINUX_LIVE_INTERPOSERS names symbols the registry does not define on Linux: {missing:?}"
    );
    // Class pairing with the named timer-family refusal: a lost timer door is
    // either caught by the object gate or refused as an import; changing the
    // safe allowlist cannot silently make a timer row host-reaching.
    let timers: Vec<_> = SYMBOLS
        .iter()
        .filter(|row| {
            let name = row.name.trim_start_matches('_');
            matches!(name, "setitimer" | "getitimer" | "alarm" | "ualarm")
                || name.starts_with("timer_")
                || name.starts_with("timerfd_")
        })
        .collect();
    assert!(!timers.is_empty(), "timer contracts must be inventoried");
    for row in timers {
        assert!(
            !patina_dst_target::native_elf_import_allowed(row.name),
            "host-reaching timer import allowed: {}",
            row.name
        );
    }
}

/// Every glibc cancellation point is a compiled shim definition or remains an
/// import the real audit refuses. Paired with registry-derived C AST lints for
/// the contracts of definitions; an import has no C body those lints can inspect.
#[cfg(target_os = "linux")]
#[test]
fn unimplemented_cancellation_points_are_refused_imports() {
    let dir = tempfile::tempdir().unwrap();
    let path = compile_posix_object(dir.path());
    let bytes = std::fs::read(path).unwrap();
    let object = object::File::parse(&*bytes).unwrap();
    let defined = defined_public_symbols(&object);
    let allowed =
        unprotected_cancellation_imports(&defined, patina_dst_target::native_elf_import_allowed);
    assert!(
        allowed.is_empty(),
        "unimplemented glibc cancellation points escape through allowed host imports: {allowed:?}"
    );
    // Non-vacuity: granting an unimplemented cancellation import is a
    // finding even though there is no compiled shim wrapper.
    assert_eq!(
        unprotected_cancellation_imports(&BTreeSet::new(), |name| name == "aio_suspend"),
        vec!["aio_suspend"]
    );
}

#[cfg(target_os = "linux")]
fn unprotected_cancellation_imports(
    defined: &BTreeSet<String>,
    import_allowed: impl Fn(&str) -> bool,
) -> Vec<&'static str> {
    patina_dst_native_shim::registry::cancellation::GLIBC_CANCELLATION_POINTS
        .iter()
        .copied()
        .filter(|name| !defined.contains(*name) && import_allowed(name))
        .collect()
}

/// The allowlist claims that disagree with the rows for `os`: an
/// `Interposed` name no row defines there under that exact name (the
/// interposer binds its own linker name, never an alias that normalizes onto
/// it), or a `Never`/`HostPassthrough` name the shim defines under any
/// spelling the audit admits for it (its import would bind to the
/// interposer, so the claim describes code that never runs).
fn misdeclared_allowlist<'a>(
    groups: impl IntoIterator<Item = &'a AllowedImports>,
    rows: &[SymbolRow],
    os: Os,
) -> Vec<String> {
    let defined = |group: &AllowedImports| -> BTreeSet<&'static str> {
        rows.iter()
            .filter(|row| row.platform.defines_on(os))
            .filter(|row| !matches!(row.status, SymbolStatus::Deny(_)))
            .filter_map(|row| match group.entry {
                KernelEntry::Interposed => Some(row.name).filter(|name| group.lists(name)),
                KernelEntry::Never | KernelEntry::HostPassthrough(_) => {
                    [row.name, row.name.trim_start_matches('_')]
                        .into_iter()
                        .find(|name| group.lists(name))
                }
            })
            .collect()
    };
    let mut misdeclared = Vec::new();
    for group in groups {
        let defined = defined(group);
        match group.entry {
            KernelEntry::Interposed => misdeclared.extend(
                group
                    .names
                    .iter()
                    .filter(|name| !defined.contains(*name))
                    .map(|name| {
                        format!("{name}: declared interposed, not defined on {}", os.name())
                    }),
            ),
            KernelEntry::Never | KernelEntry::HostPassthrough(_) => {
                misdeclared.extend(defined.iter().map(|name| {
                    format!("{name}: defined on {}, declared to reach libc", os.name())
                }))
            }
        }
    }
    misdeclared
}

/// Every allowlisted import group's kernel entry agrees with the registry on
/// both platforms.
#[test]
fn allowlisted_imports_declare_how_they_reach_the_kernel() {
    for (os, groups) in [
        (
            Os::Linux,
            patina_dst_target::elf_import_allowlist().collect::<Vec<_>>(),
        ),
        (
            Os::Darwin,
            patina_dst_target::macho_import_allowlist().collect(),
        ),
    ] {
        let misdeclared = misdeclared_allowlist(groups, SYMBOLS, os);
        assert!(
            misdeclared.is_empty(),
            "allowlisted imports whose kernel entry disagrees with the registry: {misdeclared:?}"
        );
    }
    // Non-vacuity: a lost interposer behind an `Interposed` group, and a shim
    // definition behind a group that claims libc's text, are each reported.
    let interposed = [AllowedImports {
        names: &["read"],
        prefix: false,
        entry: KernelEntry::Interposed,
    }];
    let passthrough = [AllowedImports {
        names: &["read"],
        prefix: false,
        entry: KernelEntry::HostPassthrough("planted"),
    }];
    let pure = [AllowedImports {
        names: &["re"],
        prefix: true,
        entry: KernelEntry::Never,
    }];
    assert!(misdeclared_allowlist(&interposed, SYMBOLS, Os::Linux).is_empty());
    let without_read: Vec<SymbolRow> = SYMBOLS
        .iter()
        .copied()
        .filter(|row| row.name.trim_start_matches('_') != "read")
        .collect();
    assert_eq!(
        misdeclared_allowlist(&interposed, &without_read, Os::Linux).len(),
        1
    );
    assert_eq!(
        misdeclared_allowlist(&passthrough, SYMBOLS, Os::Linux).len(),
        1
    );
    assert!(!misdeclared_allowlist(&pure, SYMBOLS, Os::Linux).is_empty());
    // Interposition is proved by the exact linker name: the shim defines
    // `__libc_start_main`, so a claim spelled as its normalized form names a
    // symbol the shim does not define, and is reported.
    let normalized = [AllowedImports {
        names: &["libc_start_main"],
        prefix: false,
        entry: KernelEntry::Interposed,
    }];
    assert_eq!(
        misdeclared_allowlist(&normalized, SYMBOLS, Os::Linux).len(),
        1
    );
    assert!(misdeclared_allowlist(&passthrough, &without_read, Os::Linux).is_empty());
    // A name listed as itself is judged as itself: a shim that defined
    // `_exit` would contradict the allowlist's passthrough claim for it.
    let exit = SYMBOLS.iter().find(|row| row.name == "exit").unwrap();
    let with_immediate_exit: Vec<SymbolRow> = SYMBOLS
        .iter()
        .copied()
        .chain([SymbolRow {
            name: "_exit",
            ..*exit
        }])
        .collect();
    for (os, groups) in [
        (
            Os::Linux,
            patina_dst_target::elf_import_allowlist().collect::<Vec<_>>(),
        ),
        (
            Os::Darwin,
            patina_dst_target::macho_import_allowlist().collect(),
        ),
    ] {
        assert_eq!(
            misdeclared_allowlist(groups, &with_immediate_exit, os).len(),
            1,
            "{}",
            os.name()
        );
    }
}

/// The seal's gate over the engine and the façade `cargo patina build`
/// links: the shim archive seals, and each plant is refused, naming it: an
/// engine export that is neither a registry row nor the runtime ABI, a raw
/// system call in the engine's text, workspace code calling a host symbol
/// the import audit classifies as an escape rather than its host alias, and
/// a C seam exporting a name that is neither.
#[test]
fn the_seal_refuses_an_unlisted_export_a_raw_system_call_and_a_host_call() {
    let dir = tempfile::tempdir().unwrap();
    let seams = dir.path().join("seams");
    std::fs::create_dir_all(&seams).unwrap();
    let posix = compile_posix_object(&seams);
    let archive = shim_archive();
    cargo_patina::seal_shim(&archive, &posix, &dir.path().join("pristine"))
        .unwrap_or_else(|error| panic!("the shim archive does not seal: {error}"));
    let trap = match (cfg!(target_arch = "x86_64"), cfg!(target_os = "macos")) {
        (true, _) => "syscall",
        (false, false) => "svc #0",
        (false, true) => "svc #0x80",
    };
    for (plant, source, in_seams) in [
        (
            "planted_unlisted_export",
            "int planted_unlisted_export(void) { return 1; }\n".to_owned(),
            false,
        ),
        (
            "patina_planted_raw_syscall",
            format!("void patina_planted_raw_syscall(void) {{ __asm__ volatile(\"{trap}\"); }}\n"),
            false,
        ),
        (
            // A vehicle the pre-doctrine shim named directly.
            "semaphore_wait",
            "int semaphore_wait(unsigned);\n\
             int patina_planted_host_call(void) { return semaphore_wait(0); }\n"
                .to_owned(),
            false,
        ),
        (
            "planted_unlisted_seam",
            "int planted_unlisted_seam(void) { return 1; }\n".to_owned(),
            true,
        ),
    ] {
        let work = dir.path().join(plant);
        std::fs::create_dir_all(&work).unwrap();
        // A workspace crate's member name, so the gate holds it to the inventory.
        let object = compile_plant(&work, "patina_dst_planted", &source);
        let refused = if in_seams {
            let planted = work.join("patina_posix.o");
            let mut link = common::c_compiler();
            link.args(["-r", "-nostdlib"]);
            if cfg!(target_os = "macos") {
                link.arg("-Wl,-keep_private_externs");
            }
            run_tool(link.arg(&posix).arg(&object).arg("-o").arg(&planted));
            cargo_patina::seal_shim(&archive, &planted, &work.join("sealed"))
        } else {
            cargo_patina::seal_shim(
                &plant_member(&archive, &work, &object),
                &posix,
                &work.join("sealed"),
            )
        }
        .expect_err("the seal accepted a plant");
        assert!(refused.to_string().contains(plant), "{refused}");
    }
}

/// A shared definition the engine localised is the engine's alone: a guest
/// defining one of the same name links beside it, and each side calls its
/// own. On ELF the definitions are COMDAT groups, on Mach-O weak ones.
#[test]
fn an_engine_comdat_group_survives_a_guests_group_of_the_same_name() {
    let dir = tempfile::tempdir().unwrap();
    let posix = compile_posix_object(dir.path());
    let archive = shim_archive();
    let returns = |value: u32| {
        if cfg!(target_os = "macos") {
            return format!(
                "__attribute__((weak)) int planted_comdat(void) {{ return {value}; }}\n"
            );
        }
        let body = if cfg!(target_arch = "x86_64") {
            format!("movl ${value}, %eax\\n ret")
        } else {
            format!("mov w0, #{value}\\n ret")
        };
        format!(
            "__asm__(\".section .text.planted_comdat,\\\"axG\\\",%progbits,planted_comdat,comdat\\n\"\n\
             \".globl planted_comdat\\n.type planted_comdat, %function\\nplanted_comdat:\\n {body}\\n.text\");\n\
             int planted_comdat(void);\n"
        )
    };
    // A dependency's member: its globals are localised unseen.
    let dependency = compile_plant(
        dir.path(),
        "planted_dependency",
        &format!(
            "{}int patina_planted_comdat_user(void) {{ return planted_comdat(); }}\n",
            returns(1)
        ),
    );
    let planted = plant_member(&archive, dir.path(), &dependency);
    let sealed = cargo_patina::seal_shim(&planted, &posix, &dir.path().join("sealed"))
        .unwrap_or_else(|error| panic!("{error}"));
    let guest = dir.path().join("guest.c");
    std::fs::write(
        &guest,
        format!(
            "{}int patina_planted_comdat_user(void);\n\
             int main(void) {{ return planted_comdat() * 10 + patina_planted_comdat_user(); }}\n",
            returns(2)
        ),
    )
    .unwrap();
    // The guest's group first, as the guest's objects precede the shim's.
    run_tool(
        common::c_compiler()
            .arg(&guest)
            .args(sealed)
            .args(common::shim_linker_args(&planted, dir.path()))
            .arg("-o")
            .arg(dir.path().join("guest")),
    );
}

/// Engine code that calls one of the shim's own doors, as `std`'s I/O, locks
/// and panic machinery do, is the engine's use of the host, never a guest
/// call: the seal binds it to the host's definition. A planted engine call
/// to `getpid` answers the process's own id while the guest's call of the
/// same name answers the virtual one.
#[test]
fn an_engine_call_to_a_door_reaches_the_host_not_the_door() {
    let dir = tempfile::tempdir().unwrap();
    let posix = compile_posix_object(dir.path());
    let archive = shim_archive();
    // A workspace crate's member, so its call is engine code like any other.
    let plant = compile_plant(
        dir.path(),
        "patina_dst_planted",
        "int getpid(void);\nint patina_planted_engine_getpid(void) { return getpid(); }\n",
    );
    let planted = plant_member(&archive, dir.path(), &plant);
    let sealed = cargo_patina::seal_shim(&planted, &posix, &dir.path().join("sealed"))
        .unwrap_or_else(|error| panic!("{error}"));
    let guest = dir.path().join("guest.c");
    std::fs::write(
        &guest,
        "#include <stdio.h>\n#include <unistd.h>\n\
         int patina_planted_engine_getpid(void);\n\
         int main(void) {\n\
             printf(\"guest=%d engine=%d\\n\", (int)getpid(), patina_planted_engine_getpid());\n\
             return 0;\n\
         }\n",
    )
    .unwrap();
    let binary = dir.path().join("guest");
    run_tool(
        common::c_compiler()
            .arg(&guest)
            .args(sealed)
            .args(common::shim_linker_args(&planted, dir.path()))
            .arg("-o")
            .arg(&binary),
    );
    let child = std::process::Command::new(&binary)
        .env_clear()
        .envs([("PATINA_RT_MODE", "seeded"), ("PATINA_RT_SEED", "1")])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id().to_string();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let field = |key: &str| {
        stdout
            .split_whitespace()
            .find_map(|word| word.strip_prefix(key))
            .unwrap_or_else(|| panic!("no {key} in {output:?}"))
            .to_owned()
    };
    assert_eq!(field("engine="), pid, "{output:?}");
    assert_ne!(field("guest="), pid, "{output:?}");
}

/// Compile the C `source` to `<dir>/<member>.o`.
fn compile_plant(dir: &std::path::Path, member: &str, source: &str) -> std::path::PathBuf {
    let c = dir.join(format!("{member}.c"));
    std::fs::write(&c, source).unwrap();
    let object = dir.join(format!("{member}.o"));
    run_tool(
        common::c_compiler()
            .arg("-c")
            .arg(&c)
            .arg("-o")
            .arg(&object),
    );
    object
}

/// A copy of `archive` in `dir` with `object` added as a member.
fn plant_member(
    archive: &std::path::Path,
    dir: &std::path::Path,
    object: &std::path::Path,
) -> std::path::PathBuf {
    let planted = dir.join("libpatina_dst_native_shim.a");
    std::fs::copy(archive, &planted).unwrap();
    // Cargo writes its artifacts read-only; `ar` rewrites the copy.
    std::fs::set_permissions(
        &planted,
        std::os::unix::fs::PermissionsExt::from_mode(0o644),
    )
    .unwrap();
    run_tool(
        std::process::Command::new("ar")
            .arg("rs")
            .arg(&planted)
            .arg(object),
    );
    planted
}

fn run_tool(command: &mut std::process::Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
