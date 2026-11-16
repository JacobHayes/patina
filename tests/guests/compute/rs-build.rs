// A build script with a loop and a store in it: built with the coverage flags it would need
// the hooks, which a build script does not link.
fn main() {
    let n = std::env::var("PROFILE").map(|p| p.len()).unwrap_or(0);
    println!("cargo:rustc-env=COMPUTE_RS_PROFILE_LEN={n}");
}
