// Publish the embedded source location and generate native C staging inputs.
mod build_support;
mod symbol_metadata;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(patina_posix_exports)");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_support.rs");
    let out = std::env::var_os("OUT_DIR").unwrap();
    let metadata = std::env::var_os("DEP_PATINA_DST_SYSCALLS_SYMBOL_METADATA")
        .expect("syscalls normal dependency must export generated symbol metadata");
    println!(
        "cargo:rerun-if-changed={}",
        std::path::Path::new(&metadata).display()
    );
    println!("cargo:rerun-if-changed=symbol_metadata.rs");
    let symbols = symbol_metadata::read(std::path::Path::new(&metadata));
    build_support::generate(std::path::Path::new(&out), &symbols);
    println!(
        "cargo:src_dir={}",
        std::env::var("CARGO_MANIFEST_DIR").unwrap()
    );
}
