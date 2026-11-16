fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rerun-if-changed=link.ld");
    println!("cargo:rustc-link-arg-bins=--no-pie");
    println!("cargo:rustc-link-arg-bins=-T{dir}/link.ld");
    println!("cargo:rustc-link-arg-bins=--build-id=none");
}
