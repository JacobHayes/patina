//! Generate retained C staging, hidden aliases and Rust routes from owned data.
use std::fmt::Write;
use std::path::Path;

use crate::symbol_metadata::Symbol;

// This inventory owns both staging and compilation. Order is significant:
// the slices share static helpers in one translation unit.
const FAMILIES: &[&str] = &[
    "core",
    "init",
    "time",
    "thread_sync",
    "signal_process",
    "stdio",
    "dlsym",
];

// Linux routed definitions that remain C. Each gets a same-object GNU alias;
// every other routed definition is Rust and carries its own assembly alias.
const C_ROUTED: &[&str] = &[
    "__assert_fail",
    "__clock_gettime",
    "__gettimeofday",
    "abort",
    "clock_getres",
    "clock_gettime",
    "clock_nanosleep",
    "gettimeofday",
    "nanosleep",
    "pthread_cancel",
    "pthread_exit",
    "pthread_once",
    "pthread_setcancelstate",
    "pthread_setcanceltype",
    "pthread_testcancel",
    "sleep",
    "time",
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
    sources.push_str("];\n");
    let mut darwin_traps = String::from("// Deny wrappers generated from the symbol registry.\n");
    for row in symbols {
        let class = match row.deny_class.as_deref() {
            Some(class @ ("macos-framework" | "host-introspection")) => class,
            _ => continue,
        };
        writeln!(darwin_traps,
            "#[unsafe(no_mangle)]\npub extern \"C\" fn {}() -> ! {{\n    let _panic_scope = crate::panic_boundary::PanicScope::enter();\n    native_trap(c\"{class}\", c\"{}\")\n}}", row.name, row.name).unwrap();
    }
    std::fs::write(out.join("darwin_traps.rs"), darwin_traps).unwrap();
    let mut ordinary = Vec::new();
    let mut x86 = Vec::new();
    for row in symbols {
        if !row.linux || !row.routed || row.name == "__wrap_dlsym" {
            continue;
        }
        if !C_ROUTED.contains(&row.name.as_str()) {
            continue;
        }
        if row.only_x86 {
            x86.push(row.name.as_str());
        } else {
            ordinary.push(row.name.as_str());
        }
    }
    assert_eq!(
        ordinary.len() + x86.len(),
        C_ROUTED.len(),
        "every retained C route names a routed Linux symbol row"
    );
    let mut routing =
        String::from("/* Same-object C aliases from the symbol registry. */\n#ifdef __linux__\n");
    for (name, mut rows) in [("PATINA_ROUTED", ordinary), ("PATINA_ROUTED_X86_64", x86)] {
        rows.sort_unstable();
        write!(routing, "#define {name}(X)").unwrap();
        for row in rows {
            write!(routing, " \\\n    X({row})").unwrap();
        }
        routing.push('\n');
    }
    let mut rust_routes = String::from(
        "// Hidden addresses generated from the symbol registry.\nunsafe extern \"C\" {\n",
    );
    for row in symbols {
        if !row.linux || !row.routed || row.name == "__wrap_dlsym" {
            continue;
        }
        if row.only_x86 {
            rust_routes.push_str("#[cfg(target_arch = \"x86_64\")]\n");
        }
        writeln!(rust_routes, "static patina_route_{}: u8;", row.name).unwrap();
    }
    rust_routes.push_str("static patina_route_dlsym: u8;\n}\npub(super) fn route(name: &CStr) -> *mut c_void {\n    match name.to_bytes() {\n");
    for row in symbols {
        if !row.linux || !row.routed || row.name == "__wrap_dlsym" {
            continue;
        }
        if row.only_x86 {
            rust_routes.push_str("#[cfg(target_arch = \"x86_64\")]\n");
        }
        writeln!(
            rust_routes,
            "b\"{}\" => (&raw const patina_route_{}).cast_mut().cast(),",
            row.name, row.name
        )
        .unwrap();
    }
    rust_routes.push_str("b\"dlsym\" => (&raw const patina_route_dlsym).cast_mut().cast(),\n_ => core::ptr::null_mut(),\n}\n}\n");
    std::fs::write(out.join("dlsym_routes.rs"), rust_routes).unwrap();
    routing.push_str("#endif\n");
    std::fs::write(out.join("patina_posix.c"), umbrella).unwrap();
    std::fs::write(out.join("posix_sources.rs"), sources).unwrap();
    std::fs::write(out.join("dlsym_routes.h"), routing).unwrap();
}
