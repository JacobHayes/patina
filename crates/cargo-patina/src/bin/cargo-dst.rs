fn main() {
    match cargo_patina::entrypoint() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("cargo-dst: {error}");
            std::process::exit(2);
        }
    }
}
