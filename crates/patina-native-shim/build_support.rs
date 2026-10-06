//! Generate the staged C translation unit and its routing table from owned data.
use std::fmt::Write;
use std::path::Path;

use crate::symbol_metadata::Symbol;

// This inventory owns both staging and compilation. Order is significant:
// the slices share static helpers in one translation unit.
const FAMILIES: &[&str] = &[
    "core",
    "init",
    "time",
    "sched_identity",
    "fs",
    "fd_io",
    "thread_sync",
    "signal_process",
    "privileged",
    "net",
    "readiness",
    "stdio",
    "darwin",
    "dlsym",
];

pub fn generate(out: &Path, symbols: &[Symbol]) {
    let mut umbrella = String::from("/* Generated from build_support.rs. */\n");
    let mut sources = String::from(
        "/// Staged family slices and generated routing metadata.\npub const POSIX_C_FAMILY_SOURCES: &[(&str, &str)] = &[\n",
    );
    for family in FAMILIES {
        if *family == "dlsym" {
            umbrella.push_str("#include \"posix/dlsym_routes.h\"\n");
            sources.push_str("(\"posix/dlsym_routes.h\", include_str!(concat!(env!(\"OUT_DIR\"), \"/dlsym_routes.h\"))),\n");
        }
        writeln!(umbrella, "#include \"posix/{family}.c\"").unwrap();
        writeln!(sources, "(\"posix/{family}.c\", include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/c/posix/{family}.c\"))),").unwrap();
        println!("cargo:rerun-if-changed=c/posix/{family}.c");
    }
    sources.push_str("(\"posix/darwin_traps.h\", include_str!(concat!(env!(\"OUT_DIR\"), \"/darwin_traps.h\"))),\n");
    sources.push_str("];\n");
    let mut darwin_traps =
        String::from("/* Deny wrappers generated from the symbol inventory. */\n");
    for row in symbols {
        let macro_name = match row.deny_class.as_deref() {
            Some("macos-framework") => "PATINA_FRAMEWORK_TRAP",
            Some("host-introspection") => "PATINA_INTROSPECTION_TRAP",
            _ => continue,
        };
        writeln!(darwin_traps, "{macro_name}({})", row.name).unwrap();
    }
    std::fs::write(out.join("darwin_traps.h"), darwin_traps).unwrap();
    let mut ordinary = Vec::new();
    let mut x86 = Vec::new();
    let mut assembly = Vec::new();
    for row in symbols {
        if !row.linux || !row.routed || row.name == "__wrap_dlsym" {
            continue;
        }
        if matches!(
            row.name.as_str(),
            "mmap"
                | "mmap64"
                | "munmap"
                | "msync"
                | "mprotect"
                | "mlock"
                | "mlock2"
                | "munlock"
                | "mlockall"
                | "munlockall"
                | "memfd_create"
                | "getentropy"
                | "getrandom"
                | "getenv"
                | "setenv"
                | "unsetenv"
                | "clearenv"
                | "putenv"
                | "secure_getenv"
                | "syscall"
                | "fcntl"
                | "fcntl64"
                | "mremap"
                | "ioctl"
                | "ptrace"
                | "prctl"
                | "printf"
                | "fprintf"
                | "open"
                | "openat"
                | "open64"
                | "openat64"
                | "__open"
                | "__open64"
        ) {
            assembly.push(row.name.as_str());
        } else if row.only_x86 {
            x86.push(row.name.as_str());
        } else {
            ordinary.push(row.name.as_str());
        }
    }
    let mut routing = String::from("/* Generated from the symbol registry. */\n#ifdef __linux__\n");
    for (name, mut rows) in [
        ("PATINA_ROUTED", ordinary),
        ("PATINA_ROUTED_X86_64", x86),
        ("PATINA_ROUTED_ASM", assembly),
    ] {
        rows.sort_unstable();
        write!(routing, "#define {name}(X)").unwrap();
        for row in rows {
            write!(routing, " \\\n    X({row})").unwrap();
        }
        routing.push('\n');
    }
    routing.push_str("#endif\n");
    std::fs::write(out.join("patina_posix.c"), umbrella).unwrap();
    std::fs::write(out.join("posix_sources.rs"), sources).unwrap();
    std::fs::write(out.join("dlsym_routes.h"), routing).unwrap();
}
