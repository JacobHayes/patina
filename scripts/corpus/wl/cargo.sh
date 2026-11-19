#!/bin/bash
# cargo build (offline, no dependencies) of a 3-module crate, debug and release, then run it and its tests.
# programs: rust
set -euo pipefail; shopt -s inherit_errexit
T=$PROGS/rust
export CARGO_HOME=$PWD/.cargo RUSTC=$T/bin/rustc PATH=$T/bin:$PATH
mkdir -p tiny/src; cd tiny
printf '[package]\nname = "tiny"\nversion = "0.1.0"\nedition = "2021"\n' > Cargo.toml
printf 'pub fn f(x: u64) -> u64 { (0..x).map(|i| i * i).sum() }\n#[cfg(test)] mod t { #[test] fn ok() { assert_eq!(super::f(3), 5); } }\n' > src/a.rs
printf 'pub fn g(s: &str) -> usize { s.split_whitespace().count() }\n' > src/b.rs
printf 'mod a; mod b;\nfn main() { let h: Vec<_> = (0..4).map(|i| std::thread::spawn(move || a::f(1000 * i))).collect(); for x in h { println!("{}", x.join().unwrap()); } println!("{}", b::g("a b c")); }\n' > src/main.rs
cargo build --offline -q
cargo build --offline -q --release
./target/release/tiny
cargo test --offline -q 2>&1 | grep -E 'test result'
