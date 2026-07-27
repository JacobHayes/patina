//! Low-friction [`proptest`](https://docs.rs/proptest) compatibility under Patina.
//!
//! # The model: the patina seed is the universe
//!
//! An ordinary proptest run draws its randomness from OS entropy, so two runs of
//! the same property explore different cases and a failure is only reproducible
//! through proptest's own regression files. Under Patina the whole run is already
//! a deterministic function of a single root seed: [`patina::rng()`] bridges to
//! that seed inside simulation (and to a plainly-seeded fallback outside it). This
//! crate wires proptest's case generation onto that hook, so **under simulation
//! the entire sequence of generated cases — and therefore any failure — is a pure
//! function of the Patina run seed.** Re-run with the same `--seed` (or replay the
//! recorded trace) and you get byte-identical cases; there is nothing else to
//! persist.
//!
//! ```no_run
//! use patina_proptest::prelude::*;
//!
//! proptest! {
//!     #[test]
//!     fn addition_commutes(a in 0i32..1000, b in 0i32..1000) {
//!         prop_assert_eq!(a + b, b + a);
//!     }
//! }
//! ```
//!
//! Adopting the crate is a one-line change: swap `use proptest::prelude::*;` for
//! `use patina_proptest::prelude::*;`. The [`proptest!`] macro re-exported here is
//! a drop-in wrapper that runs the property against a [`TestRunner`] seeded from
//! [`patina::rng()`]; everything else (strategies, `prop_assert*`, `prop_oneof!`,
//! shrinking) is proptest's own. A plain `cargo test` of an adopter still works —
//! outside simulation `patina::rng()` falls back to OS-independent entropy, so the
//! property still runs, just without a Patina universe pinning the cases.
//!
//! # Why ChaCha, and NOT `PassThrough` (do not "simplify" this back)
//!
//! It is tempting to feed patina's bytes straight through proptest's
//! `RngAlgorithm::PassThrough`. **That does not work for a multi-case run and must
//! not be reintroduced.** proptest derives a *fresh RNG per case* by splitting its
//! seed RNG (`TestRunner::run_in_process` calls `TestRng::gen_get_seed` for every
//! case). For `PassThrough`, splitting bisects a *fixed byte buffer*
//! (`TestRng::new_rng_seed`, proptest 1.11.0 `src/test_runner/rng.rs:558-571`):
//! each case takes the far half of the remaining region, so the region halves
//! every case. Reaching proptest's default 256 cases with distinct bytes would
//! need a 2^256-byte buffer. Once a region is exhausted, `fill_bytes`
//! (`rng.rs:168-175`) fills the remainder with **zeros**, so every later case
//! degenerates to the same all-zero-derived input. The run is still deterministic,
//! but case *diversity* collapses to a constant — a vacuous property test that
//! passes while exercising almost nothing. (`PassThrough` also panics outright in
//! `gen_rng`/`deterministic_rng`, `rng.rs:402-403,474-475,510-511`.) It exists to
//! replay a *single* persisted/forked case, not to drive a run.
//!
//! So we instead seed proptest's ChaCha RNG ([`RngAlgorithm::ChaCha`]) from 32
//! bytes drawn from [`patina::rng()`] (see [`seed`]). ChaCha is a full-quality
//! PRNG whose per-case splits (`rng.random()`) never degenerate, and because the
//! 32-byte seed is a pure function of the Patina seed, the run stays fully
//! deterministic and replayable. **ChaCha-seeded-from-`patina::rng()` is the
//! determinism boundary of this crate.** The [`seed`] draw and its byte order are
//! the load-bearing detail; both the internal-stability and case-diversity
//! properties are pinned by this crate's unit tests.
//!
//! # Persistence and fork are intentionally off
//!
//! - **Failure persistence is disabled** ([`config()`] sets
//!   `failure_persistence = None`). A failing case is reproduced by re-running the
//!   program with the same Patina seed, or by replaying its recorded trace — not by
//!   a `proptest-regressions` file, which would be redundant and would not capture
//!   the surrounding non-deterministic-looking (but actually seed-determined) I/O.
//! - **Forking is compiled out.** This crate depends on proptest without its
//!   `fork`/`timeout` features, so proptest cannot fork a child process — which
//!   would escape Patina's single deterministic scheduler and virtual clock.
//!
//! # Reproducing a failure
//!
//! When a property fails under `cargo patina native-run`, the failing run is
//! identified by its `--seed`. Re-run the same binary with that seed to reproduce
//! the exact case sequence and the shrunk counterexample; record the run with
//! `--record` and replay it with `--replay` for a byte-identical re-execution. To
//! reproduce a specific case sequence directly in a unit test, build a runner from
//! an explicit 32-byte seed with [`rng_from_seed`].

pub use proptest::test_runner::{Config, RngAlgorithm, TestCaseError, TestRng, TestRunner};

pub mod state;

/// A commonly-needed set of imports for writing properties under Patina.
///
/// Wildcard-import this (`use patina_proptest::prelude::*;`) in place of
/// `proptest::prelude::*`. It re-exports proptest's prelude (strategies,
/// `prop_assert*`, `prop_oneof!`, the `prop` module, …) but with the
/// Patina-seeded [`proptest!`](crate::proptest) macro shadowing proptest's own, so
/// the macro invocations in an adopter's tests transparently run against the
/// deterministic runner.
pub mod prelude {
    pub use proptest::prelude::*;

    // These shadow the same-named glob re-exports above with the Patina-aware
    // variants. An explicit re-export wins over a glob one, so adopters get the
    // seeded macro and the persistence-off config without any ambiguity error.
    pub use crate::config;
    pub use crate::proptest;
}

/// A ready-to-use [`Config`] for running properties under Patina.
///
/// Failure persistence is disabled (`failure_persistence = None`) — failures are
/// reproduced by re-running with the same Patina seed or replaying the trace, not
/// by regression files. Forking is not available (compiled out). All other fields
/// keep proptest's defaults, including honoring the standard `PROPTEST_*`
/// environment variables via proptest's `contextualize_config`.
pub fn config() -> Config {
    prepare(Config::default())
}

/// The 32 seed bytes for a run's [`TestRng`], drawn from [`patina::rng()`].
///
/// This is the crate's single seed-draw site with a fixed, stable draw order:
/// exactly four consecutive [`patina::rng()`] draws, each written little-endian
/// into the next 8 bytes (draw 0 → bytes `0..8`, draw 1 → `8..16`, …). Given the
/// same `patina::rng()` stream state the result is identical, so — inside
/// simulation, where `patina::rng()` is the run's seeded deterministic entropy —
/// the returned bytes, and every case generated from them, are a pure function of
/// the Patina run seed. Outside simulation they come from `patina::rng()`'s
/// fallback stream. This draw order is load-bearing (see the crate docs on the
/// determinism boundary) and is pinned by a unit test; do not reorder it.
pub fn seed() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_exact_mut(8) {
        chunk.copy_from_slice(&patina::rng().to_le_bytes());
    }
    bytes
}

/// A [`TestRng`] seeded for this run from [`patina::rng()`] (via [`seed`]).
pub fn rng() -> TestRng {
    rng_from_seed(seed())
}

/// A [`TestRng`] seeded from an explicit 32-byte seed.
///
/// Uses [`RngAlgorithm::ChaCha`], so the RNG — and the whole case sequence derived
/// from it — is a deterministic function of `seed`. Use this to reproduce a
/// specific case sequence in a unit test without going through `patina::rng()`.
pub fn rng_from_seed(seed: [u8; 32]) -> TestRng {
    TestRng::from_seed(RngAlgorithm::ChaCha, &seed)
}

/// A [`TestRunner`] with the default Patina [`config()`], seeded from
/// [`patina::rng()`].
pub fn runner() -> TestRunner {
    runner_with_config(Config::default())
}

/// A [`TestRunner`] with a caller-supplied config, seeded from [`patina::rng()`].
///
/// The config is normalized the same way [`config()`] normalizes the default
/// (failure persistence forced off, `PROPTEST_*` env honored), then the runner is
/// built with an RNG from [`rng()`].
pub fn runner_with_config(config: Config) -> TestRunner {
    TestRunner::new_with_rng(prepare(config), rng())
}

/// Apply Patina's config policy to a proptest [`Config`]: run proptest's own
/// environment contextualization, then force failure persistence off.
fn prepare(config: Config) -> Config {
    let mut config = proptest::test_runner::contextualize_config(config);
    config.failure_persistence = None;
    config
}

/// Implementation detail re-exports the [`proptest!`] macro expands into. Not a
/// stable API — invoke the macro, do not name these.
#[doc(hidden)]
pub mod __rt {
    pub use proptest::proptest_helper;
    pub use proptest::strategy::Strategy;
    pub use proptest::sugar::NamedArguments;
}

/// A drop-in wrapper for proptest's [`proptest!`](proptest::proptest) macro that
/// runs each property against a [`TestRunner`] seeded from [`patina::rng()`].
///
/// It accepts the same forms as proptest's macro — the `fn`-item form
/// (`proptest! { #[test] fn prop(x in strat) { .. } }`), the closure form
/// (`proptest!(|(x in strat)| { .. })`), and an explicit leading `Config`
/// expression — but constructs the runner via [`runner_with_config`] so case
/// generation is deterministic from the Patina seed and failure persistence is
/// off.
#[macro_export]
macro_rules! proptest {
    // ---- `fn`-item forms with an explicit config attribute ----
    (#![proptest_config($config:expr)]
     $(
        $(#[$meta:meta])*
        fn $test_name:ident($($parm:pat in $strategy:expr),+ $(,)?) $body:block
     )*) => {
        $(
            $(#[$meta])*
            fn $test_name() {
                $crate::proptest!($config, |($($parm in $strategy),+)| $body);
            }
        )*
    };
    (#![proptest_config($config:expr)]
     $(
        $(#[$meta:meta])*
        fn $test_name:ident($($arg:tt)+) $body:block
     )*) => {
        $(
            $(#[$meta])*
            fn $test_name() {
                $crate::proptest!($config, |($($arg)+)| $body);
            }
        )*
    };

    // ---- `fn`-item forms with the default Patina config ----
    ($(
        $(#[$meta:meta])*
        fn $test_name:ident($($parm:pat in $strategy:expr),+ $(,)?) $body:block
    )*) => {
        $crate::proptest! {
            #![proptest_config($crate::config())]
            $($(#[$meta])* fn $test_name($($parm in $strategy),+) $body)*
        }
    };
    ($(
        $(#[$meta:meta])*
        fn $test_name:ident($($arg:tt)+) $body:block
    )*) => {
        $crate::proptest! {
            #![proptest_config($crate::config())]
            $($(#[$meta])* fn $test_name($($arg)+) $body)*
        }
    };

    // ---- closure forms with the default Patina config ----
    (|($($parm:pat in $strategy:expr),+ $(,)?)| $body:expr) => {
        $crate::proptest!($crate::config(), |($($parm in $strategy),+)| $body)
    };
    (move |($($parm:pat in $strategy:expr),+ $(,)?)| $body:expr) => {
        $crate::proptest!($crate::config(), move |($($parm in $strategy),+)| $body)
    };
    (|($($arg:tt)+)| $body:expr) => {
        $crate::proptest!($crate::config(), |($($arg)+)| $body)
    };
    (move |($($arg:tt)+)| $body:expr) => {
        $crate::proptest!($crate::config(), move |($($arg)+)| $body)
    };

    // ---- closure forms with an explicit config: the real runner build ----
    ($config:expr, |($($parm:pat in $strategy:expr),+ $(,)?)| $body:expr) => {
        $crate::__patina_proptest_run!($config, ($($parm in $strategy),+) [] $body)
    };
    ($config:expr, move |($($parm:pat in $strategy:expr),+ $(,)?)| $body:expr) => {
        $crate::__patina_proptest_run!($config, ($($parm in $strategy),+) [move] $body)
    };
    ($config:expr, |($($arg:tt)+)| $body:expr) => {
        $crate::__patina_proptest_run2!($config, ($($arg)+) [] $body)
    };
    ($config:expr, move |($($arg:tt)+)| $body:expr) => {
        $crate::__patina_proptest_run2!($config, ($($arg)+) [move] $body)
    };
}

/// Internal: build and run a property from the `pat in strategy` form. Mirrors
/// proptest's own `@_BODY` but swaps in the Patina-seeded runner.
#[doc(hidden)]
#[macro_export]
macro_rules! __patina_proptest_run {
    ($config:expr, ($($parm:pat in $strategy:expr),+) [$($mod:tt)*] $body:expr) => {{
        let mut runner = $crate::runner_with_config($config);
        let names = $crate::__rt::proptest_helper!(@_WRAPSTR ($($parm),*));
        match runner.run(
            &$crate::__rt::Strategy::prop_map(
                $crate::__rt::proptest_helper!(@_WRAP ($($strategy)*)),
                |values| $crate::__rt::NamedArguments(names, values)),
            $($mod)* |$crate::__rt::NamedArguments(
                _, $crate::__rt::proptest_helper!(@_WRAPPAT ($($parm),*)))|
            {
                let (): () = $body;
                ::core::result::Result::Ok(())
            })
        {
            ::core::result::Result::Ok(()) => (),
            ::core::result::Result::Err(e) => ::core::panic!("{}\n{}", e, runner),
        }
    }};
}

/// Internal: build and run a property from the `pat: type` / mixed form. Mirrors
/// proptest's own `@_BODY2` but swaps in the Patina-seeded runner.
#[doc(hidden)]
#[macro_export]
macro_rules! __patina_proptest_run2 {
    ($config:expr, ($($arg:tt)+) [$($mod:tt)*] $body:expr) => {{
        let mut runner = $crate::runner_with_config($config);
        let names = $crate::__rt::proptest_helper!(@_EXT _STR ($($arg)*));
        match runner.run(
            &$crate::__rt::Strategy::prop_map(
                $crate::__rt::proptest_helper!(@_EXT _STRAT ($($arg)*)),
                |values| $crate::__rt::NamedArguments(names, values)),
            $($mod)* |$crate::__rt::NamedArguments(
                _, $crate::__rt::proptest_helper!(@_EXT _PAT ($($arg)*)))|
            {
                let (): () = $body;
                ::core::result::Result::Ok(())
            })
        {
            ::core::result::Result::Ok(()) => (),
            ::core::result::Result::Err(e) => ::core::panic!("{}\n{}", e, runner),
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::TestError;

    #[test]
    fn config_disables_failure_persistence() {
        assert!(
            config().failure_persistence.is_none(),
            "failure persistence must be off: reproduce via the Patina seed / trace, not regression files"
        );
    }

    #[test]
    fn config_has_no_fork() {
        // The `fork`/`timeout` features are compiled out, so proptest reports a
        // configuration that never forks.
        assert!(!config().fork(), "forking must be unavailable under Patina");
    }

    #[test]
    fn runner_uses_the_chacha_algorithm() {
        assert_eq!(config().rng_algorithm, RngAlgorithm::ChaCha);
    }

    // Digest the sequence of generated cases a runner produces for a *passing*
    // property. With no failure there is no shrinking, so the closure is invoked
    // exactly `cases` times with freshly generated inputs, and the fold is a pure
    // function of the runner's RNG seed.
    fn case_digest(seed: [u8; 32], cases: u32) -> u64 {
        let mut config = config();
        config.cases = cases;
        let mut runner = TestRunner::new_with_rng(config, rng_from_seed(seed));
        let digest = std::cell::Cell::new(0xcbf2_9ce4_8422_2325_u64);
        runner
            .run(&(any::<u64>(), any::<i32>()), |(a, b)| {
                let mixed = a ^ ((b as u64) << 17);
                digest.set(
                    (digest.get() ^ mixed)
                        .wrapping_mul(0x0000_0100_0000_01b3)
                        .rotate_left(13),
                );
                Ok(())
            })
            .expect("passing property must not fail");
        digest.get()
    }

    // The single seed-draw site is internally stable: with the same
    // `patina::rng()` stream state it returns the same 32 bytes. A freshly spawned
    // thread resets `patina::rng()`'s fallback stream to its fixed start, so two
    // fresh threads observe identical stream state and must produce identical
    // seeds — pinning both the draw order and its little-endian composition.
    #[test]
    fn seed_draw_is_stable_for_equal_stream_state() {
        let first = std::thread::spawn(seed).join().unwrap();
        let second = std::thread::spawn(seed).join().unwrap();
        assert_eq!(
            first, second,
            "seed() must be a pure function of the patina::rng() stream state"
        );
    }

    // Regression for the PassThrough bisect-then-zero-fill collapse: the cases a
    // single runner generates must not degenerate to a constant. Collect the
    // inputs of 64 generated cases and assert they are not all identical — this
    // would FAIL under PassThrough (later cases all zero-derived) and passes under
    // the ChaCha seeding.
    #[test]
    fn generated_cases_are_diverse_not_collapsed() {
        let mut config = config();
        config.cases = 64;
        let mut runner = TestRunner::new_with_rng(config, rng_from_seed([9u8; 32]));
        let seen = std::cell::RefCell::new(Vec::new());
        runner
            .run(&any::<u64>(), |value| {
                seen.borrow_mut().push(value);
                Ok(())
            })
            .expect("passing property must not fail");
        let seen = seen.into_inner();
        assert_eq!(seen.len(), 64, "every generated case should be observed");
        let distinct: std::collections::BTreeSet<u64> = seen.iter().copied().collect();
        assert!(
            distinct.len() > 32,
            "generated cases degenerated ({} distinct of 64) — the PassThrough failure mode",
            distinct.len()
        );
    }

    #[test]
    fn same_seed_generates_identical_cases() {
        let seed = [7u8; 32];
        assert_eq!(case_digest(seed, 128), case_digest(seed, 128));
    }

    #[test]
    fn different_seeds_generate_different_cases() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[0] = 1;
        b[0] = 2;
        assert_ne!(case_digest(a, 128), case_digest(b, 128));
    }

    // Shrinking is driven by the strategy tree, so a deterministic case sequence
    // yields a deterministic shrunk counterexample. A property that fails whenever
    // `n >= 100` must shrink to exactly 100, stably, across seeds and repeats.
    fn shrink_to_minimal(seed: [u8; 32]) -> i64 {
        let mut runner = TestRunner::new_with_rng(config(), rng_from_seed(seed));
        let error = runner
            .run(&(0i64..10_000i64), |n| {
                prop_assert!(n < 100, "n reached the failing region");
                Ok(())
            })
            .expect_err("property must fail so it can shrink");
        match error {
            TestError::Fail(_, value) => value,
            other => panic!("expected a failing case, got {other:?}"),
        }
    }

    #[test]
    fn shrinking_is_stable_and_minimal() {
        assert_eq!(shrink_to_minimal([1u8; 32]), 100);
        assert_eq!(shrink_to_minimal([1u8; 32]), 100);
        assert_eq!(shrink_to_minimal([42u8; 32]), 100);
    }

    // The re-exported macro compiles and runs against the seeded runner in all its
    // common shapes.
    #[test]
    fn macro_closure_form_runs() {
        crate::proptest!(|(a in 0u32..1000, b in 0u32..1000)| {
            prop_assert_eq!(a.wrapping_add(b), b.wrapping_add(a));
        });
    }

    crate::proptest! {
        #[test]
        fn macro_fn_form_runs(x in 0i32..1000, y in 0i32..1000) {
            prop_assert_eq!(x + y, y + x);
        }
    }
}
