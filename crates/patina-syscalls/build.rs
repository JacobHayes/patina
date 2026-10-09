//! Export source location and small host-independent symbol metadata. This
//! compiles the owned symbol table, never the target-specific syscall registry.
use std::fmt::Write;

#[allow(dead_code)] // Runtime render/association helpers share these owned types.
#[path = "src/symbol_types.rs"]
mod symbol_types;
use symbol_types::{Platform, Serves, SymbolRow, SymbolStatus};
#[allow(dead_code)] // Metadata deliberately includes every architecture.
#[path = "src/symbols.rs"]
mod symbols;

fn main() {
    for source in [
        "build.rs",
        "src/symbol_types.rs",
        "src/symbols.rs",
        "src/symbol_inventory.rs",
        "src/symbol_time.rs",
        "src/symbol_stdio.rs",
    ] {
        println!("cargo:rerun-if-changed={source}");
    }
    println!("cargo:src_dir={}", env!("CARGO_MANIFEST_DIR"));
    let mut metadata = String::from("patina.symbols/v1\n");
    for (row, architecture) in symbols::ALL_SYMBOLS_WITH_ARCH {
        writeln!(
            metadata,
            "{}\t{}\t{}\t{}",
            row.name,
            row.platform.name(),
            row.status.render(),
            architecture.unwrap_or("all")
        )
        .unwrap();
    }
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let path = out.join("symbols.tsv");
    std::fs::write(&path, metadata).unwrap();
    println!("cargo:symbol_metadata={}", path.display());
}
