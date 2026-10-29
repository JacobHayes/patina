//! Stock proptest under the native shim: case generation is seeded.

#[cfg(test)]
mod tests {
    use super::super::*;
    use common::native::{Guest, assert_success};

    // An unmodified proptest program: a default `TestRunner` draws its RNG
    // seed from OS entropy, which the shim interposes and seeds from the run
    // seed. The guest prints a fold-digest of every generated case; with no
    // failure proptest never shrinks, so the digest is a pure function of the
    // run seed.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const PROPTEST_MAIN: &str = r#"
use std::cell::Cell;

use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};

fn main() {
    let mut runner = TestRunner::new(Config::default());
    let digest = Cell::new(0xcbf2_9ce4_8422_2325_u64);
    runner
        .run(&(any::<u64>(), 0i64..1_000_000i64), |(a, b)| {
            let mixed = a ^ (b as u64).rotate_left(21);
            digest.set(
                (digest.get() ^ mixed)
                    .wrapping_mul(0x0000_0100_0000_01b3)
                    .rotate_left(13),
            );
            Ok(())
        })
        .expect("the property holds for every generated case");
    println!("PROPTEST_DIGEST digest={:016x}", digest.get());
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn proptest_guest() -> Guest {
        let dir = tempdir().unwrap();
        let root = dir.path().join("pkg");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"stock-proptest-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\nproptest = { version = \"=1.11.0\", default-features = false, features = [\"std\", \"bit-set\"] }\n",
        )
        .unwrap();
        fs::write(root.join("src/main.rs"), PROPTEST_MAIN).unwrap();
        let binary = dir.path().join("proptest-guest");
        invoke(
            native_workspace(),
            &[
                "build",
                root.to_str().unwrap(),
                "--output",
                binary.to_str().unwrap(),
            ],
        );
        Guest { dir, binary }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn digest_line(output: &Output) -> String {
        std::str::from_utf8(&output.stdout)
            .unwrap()
            .lines()
            .find(|line| line.starts_with("PROPTEST_DIGEST"))
            .unwrap_or_else(|| {
                panic!(
                    "missing digest in stdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            })
            .to_owned()
    }

    /// The same seed generates the same cases (the shared run check runs,
    /// records and replays it), and a different seed generates different ones.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn stock_proptest_generates_cases_from_the_run_seed() {
        let guest = proptest_guest();
        let seeded = guest.assert_run_success(5, &[]);
        let again = assert_success(guest.command("run", &["--seed", "5"]));
        let other = assert_success(guest.command("run", &["--seed", "6"]));
        assert_eq!(digest_line(&seeded), digest_line(&again));
        assert_ne!(
            digest_line(&seeded),
            digest_line(&other),
            "a different seed must generate a different case digest"
        );
    }
}
