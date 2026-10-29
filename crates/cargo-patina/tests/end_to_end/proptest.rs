//! Stock proptest under the native shim: case generation and shrinking are
//! seeded.

#[cfg(test)]
mod tests {
    use super::super::*;
    use common::native::{Guest, assert_success};

    // An unmodified proptest program: a default `TestRunner` draws its RNG
    // seed from OS entropy, which the shim interposes and seeds from the run
    // seed. The guest prints a fold-digest of every generated case; with no
    // failure proptest never shrinks, so the digest is a pure function of the
    // run seed.
    //
    // With `shrink` as its argument the guest instead runs a property that
    // fails, and prints what proptest's stock shrinker reduced it to, along
    // with the first failing case and the number of cases tried. Every one of
    // those is drawn from the seeded RNG, so the whole search is a function of
    // the run seed.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const PROPTEST_MAIN: &str = r#"
use std::cell::{Cell, RefCell};

use proptest::prelude::*;
use proptest::test_runner::{Config, TestError, TestRunner};

fn shrink() {
    let mut runner = TestRunner::new(Config::default());
    let first = RefCell::new(None);
    let calls = Cell::new(0_u64);
    let strategy = (any::<u32>(), proptest::collection::vec(any::<u8>(), 0..16));
    let result = runner.run(&strategy, |(a, v)| {
        calls.set(calls.get() + 1);
        if a >= 1000 && v.len() >= 3 {
            first.borrow_mut().get_or_insert_with(|| format!("{a}:{v:?}"));
            return Err(TestCaseError::fail("too big"));
        }
        Ok(())
    });
    match result {
        Err(TestError::Fail(_, (a, v))) => println!(
            "PROPTEST_SHRUNK minimal={a}:{v:?} first={} calls={}",
            first.borrow().as_deref().unwrap_or("none"),
            calls.get()
        ),
        other => panic!("expected a shrunk failure, got {other:?}"),
    }
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("shrink") {
        return shrink();
    }
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
        marker_line(output, "PROPTEST_DIGEST")
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn marker_line(output: &Output, marker: &str) -> String {
        std::str::from_utf8(&output.stdout)
            .unwrap()
            .lines()
            .find(|line| line.starts_with(marker))
            .unwrap_or_else(|| {
                panic!(
                    "missing {marker} in stdout:\n{}\nstderr:\n{}",
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

    /// Stock shrinking works under the shim: a failing property shrinks to its
    /// minimal case, and the whole search (first failure, cases tried, result)
    /// is identical across a seeded run, a recorded run and its replay.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn stock_proptest_shrinks_deterministically() {
        let guest = proptest_guest();
        let seeded = guest.assert_run_success(5, &["--", "shrink"]);
        let shrunk = marker_line(&seeded, "PROPTEST_SHRUNK");
        assert!(
            shrunk.contains("minimal=1000:[0, 0, 0] "),
            "proptest did not shrink to the minimal failing case: {shrunk}"
        );
        let other = assert_success(guest.command("run", &["--seed", "6", "--", "shrink"]));
        assert!(
            marker_line(&other, "PROPTEST_SHRUNK").contains("minimal=1000:[0, 0, 0] "),
            "another seed shrank somewhere else"
        );
    }
}
