//! The [Patina] SDK: cooperative fault injection and test oracles, in the style
//! of FoundationDB's `BUGGIFY` and Antithesis assertions.
//!
//! Patina is a deterministic simulation testing (DST) runtime that runs ordinary
//! `std` programs under a seeded virtual OS personality — same seed, same run,
//! byte for byte. This crate is the one Patina crate an application depends on
//! directly: it marks the fault sites and invariants that the runtime cannot
//! know about from outside ("what if this batch path ran?", "this must *always*
//! hold"). It has **zero dependencies and no feature flags**, and every entry
//! point is a no-op or a plain fallback outside a Patina build, so you ship it
//! unconditionally — no `cfg(patina)`, no test-only dependency graph, no cost in
//! production:
//!
//! ```
//! fn flush(batch: &[u64]) -> usize {
//!     // A rare path, taken only under Patina on seed-chosen runs. Under a
//!     // plain `cargo build` this is a constant `false`.
//!     if patina_dst::buggify!("flush-early-drop") {
//!         return 0;
//!     }
//!     patina_dst::always!(batch.len() <= 1_000_000, "batch-bounded"); // fatal if false
//!     patina_dst::sometimes!(batch.len() > 100, "large-batch-seen"); // coverage oracle
//!     batch.len()
//! }
//!
//! assert_eq!(flush(&[1, 2, 3]), 3); // outside Patina: buggify! never fires
//! ```
//!
//! Instrumented programs run under the deterministic runtime with
//! `cargo patina build` / `cargo patina run`; fault sites arm with
//! `cargo patina run --buggify`, and every decision is a pure function of
//! `--seed`. See the repository [README] and [TUTORIAL] for the ten-minute
//! version.
//!
//! # The SDK surface
//!
//! - [`buggify!`] / [`buggify_with_prob!`] — a probabilistic fault trigger at a
//!   labeled site. Under Patina, an activated site fires deterministically from
//!   the run seed; outside Patina it is always `false`.
//! - [`buggify_delay!`] — inject a deterministic delay through the virtual clock
//!   (never a real sleep).
//! - [`buggify_knob!`] — a per-run perturbed value within a range.
//! - [`always!`] — a fatal invariant: under Patina a violation emits a
//!   `PATINA_ALWAYS_VIOLATION` marker and aborts; outside it is a `debug_assert`.
//! - [`sometimes!`] / [`reachable!`] — coverage oracles.
//! - [`is_simulated`] / [`rng`] and the [`lifecycle`] module.
//!
//! Site labels are explicit strings and must be unique across the program;
//! a label reused at a different call site is a fatal error at first evaluation.
//!
//! # No vacuous "all clean"
//!
//! A fault site that never fires proves nothing. Under `--buggify` the runtime
//! prints a `PATINA_SDK_REPORT` line at the end of the run showing how many
//! sites registered, activated, and actually fired. Each per-site row carries
//! the macro/import `file:line`, so `cargo patina sites --exercised <stderr-file>`
//! can join runtime counters back to the static inventory. A green run with
//! inert instrumentation is visible instead of silently reassuring.
//!
//! ## Determinism and the never-reached-site blind spot
//!
//! Sites register lazily, at first evaluation. A compile-time site inventory
//! (`ctor`/`linkme`-style) was considered and rejected: it would add a
//! dependency to the dependency-light default and constructor run-order is not a
//! determinism guarantee across platforms. The consequence is that a site the
//! run never reaches is invisible to the `PATINA_SDK_REPORT` — the campaign layer
//! closes this by accumulating coverage across many generations rather than
//! within one run.
//!
//! ## Lifecycle gating (honest limitation)
//!
//! [`lifecycle::setup_complete`] marks the boundary between setup and workload.
//! Patina cannot causally make sites "inert until setup" without lookahead, so
//! buggify is armed from the start and `setup_complete()` is a boundary/coverage
//! marker; place workload sites after it to keep setup buggify-free.
//!
//! # Where this crate sits (the SDK / runtime split)
//!
//! This crate is a pure SDK: it does not run applications, and it never links
//! the simulator. Under `cargo patina build`/`run` the native shim or WASI host
//! supplies the deterministic runtime below ordinary
//! `std::fs`/`std::net`/clock/thread calls, so SDK-instrumented production code
//! needs no explicit runtime dependency (usage mode 1 of [USAGE-MODES.md]).
//! The `cfg(patina)`/`cfg(patina_shim)` markers this crate compiles against are
//! injected by `cargo patina build` — an adopter never sets them.
//!
//! - To configure Patina in code and then drive normal application code through
//!   the same shims, use the shim-backed harness crate `patina-dst-harness`
//!   (mode 2).
//! - For the low-level explicit-`Context` API — `run`/`run_with`, `Context`,
//!   `RuntimeBuilder`, `RuntimeConfig`, and ABI types — depend on
//!   [`patina-dst-runtime`] directly (mode 3); the deterministic async surface
//!   lives in `patina-dst-async` over that same `Context`. This API creates an
//!   explicit context and does not control unrelated `std` calls.
//! - For proptest properties whose case generation is a pure function of the
//!   Patina seed, see `patina-dst-proptest`, which builds on this crate's
//!   [`rng`].
//!
//! [Patina]: https://github.com/JacobHayes/patina
//! [README]: https://github.com/JacobHayes/patina/blob/main/README.md
//! [TUTORIAL]: https://github.com/JacobHayes/patina/blob/main/TUTORIAL.md
//! [USAGE-MODES.md]: https://github.com/JacobHayes/patina/blob/main/USAGE-MODES.md
//! [`patina-dst-runtime`]: https://docs.rs/patina-dst-runtime

// ---- Cooperative-SUT SDK ------------------------------------------------------

/// Whether execution is under Patina's deterministic simulator.
///
/// Analogous to FoundationDB's `g_network->isSimulated()`. `true` inside any
/// Patina build, `false` in an ordinary build. Prefer keeping code identical in
/// and out of simulation; reserve this for the rare simulation-only affordance
/// (extra validation, a simulation-visible log line).
///
/// ```
/// // Under a plain `cargo build`/`cargo test` this is always false.
/// assert!(!patina_dst::is_simulated());
/// ```
#[inline]
pub fn is_simulated() -> bool {
    #[cfg(patina_shim)]
    {
        // Authoritative: ask the linked shim whether the runtime is installed.
        unsafe { ffi::patina_is_simulated() != 0 }
    }
    #[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
    {
        // Authoritative: ask the WASI host through the `patina_sdk` import. Under
        // a foreign (non-Patina) wasip1 runtime this import is unresolved and the
        // module cannot instantiate, so a `true` here always reflects a real host.
        unsafe { wasm_ffi::is_simulated() != 0 }
    }
    #[cfg(all(patina, not(patina_shim), not(target_arch = "wasm32")))]
    {
        true
    }
    #[cfg(not(patina))]
    {
        false
    }
}

/// A deterministic 64-bit draw. Under Patina it is bridged to the run's root
/// seed (through the native shim, or the WASI `patina_sdk` host import), so the
/// stream — and everything derived from it — is a pure function of `--seed`.
/// Outside Patina it is a plainly-seeded per-thread fallback stream, so callers
/// still get reproducible values without touching OS entropy.
///
/// This is the hook `patina-dst-proptest` builds on to make property-test case
/// generation a pure function of the run seed.
///
/// ```
/// let a = patina_dst::rng();
/// let b = patina_dst::rng();
/// // Consecutive draws advance the stream.
/// assert_ne!(a, b);
/// ```
#[inline]
pub fn rng() -> u64 {
    #[cfg(patina_shim)]
    {
        unsafe { ffi::patina_rng() }
    }
    #[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
    {
        unsafe { wasm_ffi::rng() }
    }
    #[cfg(all(not(patina_shim), not(all(patina, target_arch = "wasm32"))))]
    {
        fallback::next()
    }
}

/// Lifecycle markers for cooperating with the simulator's run phases.
///
/// ```
/// // Build fixtures, open stores, spawn workers ... then:
/// patina_dst::lifecycle::setup_complete();
/// patina_dst::lifecycle::event!("workload-started");
/// // Both are no-ops outside Patina.
/// ```
pub mod lifecycle {
    pub use crate::lifecycle_event as event;

    /// Mark the boundary between setup and the workload under test. Emits a
    /// `PATINA_LIFECYCLE setup_complete` marker under Patina; a no-op outside.
    ///
    /// Pair with `cargo patina run --buggify --buggify-after-setup`, which gates
    /// fault injection off until this call (and fails the run loudly if the
    /// guest never makes it). See the crate docs for the honest limits of
    /// lifecycle gating.
    #[inline]
    pub fn setup_complete() {
        crate::__rt::lifecycle_setup_complete();
    }
}

/// Implementation shims the SDK macros expand into. Not a stable public API;
/// call the macros, not these functions.
#[doc(hidden)]
pub mod __rt {
    /// `buggify!` / `buggify_with_prob!`: whether the site fires. `prob_permille`
    /// is `-1` for the run default.
    #[inline]
    pub fn buggify(label: &str, site: &str, prob_permille: i32) -> bool {
        #[cfg(patina_shim)]
        {
            unsafe {
                super::ffi::patina_buggify(
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                    prob_permille,
                ) != 0
            }
        }
        #[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
        {
            unsafe {
                super::wasm_ffi::buggify(
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                    prob_permille,
                ) != 0
            }
        }
        #[cfg(all(not(patina_shim), not(all(patina, target_arch = "wasm32"))))]
        {
            let _ = (label, site, prob_permille);
            false
        }
    }

    /// `buggify_delay!`: whether a deterministic delay was injected.
    #[inline]
    pub fn buggify_delay(label: &str, site: &str) -> bool {
        #[cfg(patina_shim)]
        {
            unsafe {
                super::ffi::patina_buggify_delay(
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                ) != 0
            }
        }
        #[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
        {
            unsafe {
                super::wasm_ffi::buggify_delay(
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                ) != 0
            }
        }
        #[cfg(all(not(patina_shim), not(all(patina, target_arch = "wasm32"))))]
        {
            let _ = (label, site);
            false
        }
    }

    /// `buggify_knob!`: a per-run perturbed value in `[lo, hi]`, else `default`.
    #[inline]
    pub fn buggify_knob(label: &str, site: &str, default: i64, lo: i64, hi: i64) -> i64 {
        #[cfg(patina_shim)]
        {
            unsafe {
                super::ffi::patina_buggify_knob(
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                    default,
                    lo,
                    hi,
                )
            }
        }
        #[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
        {
            unsafe {
                super::wasm_ffi::buggify_knob(
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                    default,
                    lo,
                    hi,
                )
            }
        }
        #[cfg(all(not(patina_shim), not(all(patina, target_arch = "wasm32"))))]
        {
            let _ = (label, site, lo, hi);
            default
        }
    }

    /// `always!`: a fatal invariant under Patina (marker + abort), a
    /// `debug_assert` outside.
    #[inline]
    #[track_caller]
    pub fn always(condition: bool, label: &str, site: &str) {
        #[cfg(patina_shim)]
        {
            unsafe {
                super::ffi::patina_always(
                    i32::from(condition),
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                );
            }
        }
        #[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
        {
            // Host-authoritative: on a violation the WASI host emits the
            // `PATINA_ALWAYS_VIOLATION` marker and traps the guest, so this import
            // does not return when `condition` is false.
            unsafe {
                super::wasm_ffi::always(
                    i32::from(condition),
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                );
            }
        }
        #[cfg(all(patina, not(patina_shim), not(target_arch = "wasm32")))]
        {
            let _ = site;
            assert!(condition, "patina always! invariant violated: {label}");
        }
        #[cfg(not(patina))]
        {
            let _ = site;
            debug_assert!(condition, "always! invariant violated: {label}");
        }
    }

    /// `sometimes!`: a coverage oracle. No effect on control flow.
    #[inline]
    pub fn sometimes(condition: bool, label: &str, site: &str) {
        #[cfg(patina_shim)]
        {
            unsafe {
                super::ffi::patina_sometimes(
                    i32::from(condition),
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                );
            }
        }
        #[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
        {
            unsafe {
                super::wasm_ffi::sometimes(
                    i32::from(condition),
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                );
            }
        }
        #[cfg(all(not(patina_shim), not(all(patina, target_arch = "wasm32"))))]
        {
            let _ = (condition, label, site);
        }
    }

    /// `reachable!`: a coverage oracle noting the site was reached.
    #[inline]
    pub fn reachable(label: &str, site: &str) {
        #[cfg(patina_shim)]
        {
            unsafe {
                super::ffi::patina_reachable(
                    label.as_ptr(),
                    label.len(),
                    site.as_ptr(),
                    site.len(),
                );
            }
        }
        #[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
        {
            unsafe {
                super::wasm_ffi::reachable(label.as_ptr(), label.len(), site.as_ptr(), site.len());
            }
        }
        #[cfg(all(not(patina_shim), not(all(patina, target_arch = "wasm32"))))]
        {
            let _ = (label, site);
        }
    }

    /// `patina_dst::lifecycle::event!`.
    #[inline]
    pub fn lifecycle_event(label: &str) {
        #[cfg(patina_shim)]
        {
            unsafe {
                super::ffi::patina_lifecycle_event(label.as_ptr(), label.len());
            }
        }
        #[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
        {
            unsafe {
                super::wasm_ffi::lifecycle_event(label.as_ptr(), label.len());
            }
        }
        #[cfg(all(not(patina_shim), not(all(patina, target_arch = "wasm32"))))]
        {
            let _ = label;
        }
    }

    /// `patina_dst::lifecycle::setup_complete`.
    #[inline]
    pub fn lifecycle_setup_complete() {
        #[cfg(patina_shim)]
        {
            unsafe {
                super::ffi::patina_lifecycle_setup_complete();
            }
        }
        #[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
        {
            unsafe {
                super::wasm_ffi::lifecycle_setup_complete();
            }
        }
    }

    /// Convert a `0.0..=1.0` probability to a `0..=1000` per-mille integer.
    #[inline]
    pub fn prob_to_permille(probability: f64) -> i32 {
        (probability.clamp(0.0, 1.0) * 1000.0).round() as i32
    }
}

/// FFI into the native shim. Present only when the shim is actually linked
/// (`cfg(patina_shim)`, injected by `cargo patina build`). Under a plain
/// `cargo build`, a WASI build, or `cargo patina run`, these symbols are never
/// referenced, so nothing is left unresolved at link time.
#[cfg(patina_shim)]
mod ffi {
    unsafe extern "C" {
        pub fn patina_is_simulated() -> i32;
        pub fn patina_buggify(
            label: *const u8,
            label_len: usize,
            site: *const u8,
            site_len: usize,
            prob_permille: i32,
        ) -> i32;
        pub fn patina_buggify_delay(
            label: *const u8,
            label_len: usize,
            site: *const u8,
            site_len: usize,
        ) -> i32;
        pub fn patina_buggify_knob(
            label: *const u8,
            label_len: usize,
            site: *const u8,
            site_len: usize,
            default_value: i64,
            lo: i64,
            hi: i64,
        ) -> i64;
        pub fn patina_always(
            condition: i32,
            label: *const u8,
            label_len: usize,
            site: *const u8,
            site_len: usize,
        ) -> i32;
        pub fn patina_sometimes(
            condition: i32,
            label: *const u8,
            label_len: usize,
            site: *const u8,
            site_len: usize,
        ) -> i32;
        pub fn patina_reachable(
            label: *const u8,
            label_len: usize,
            site: *const u8,
            site_len: usize,
        ) -> i32;
        pub fn patina_rng() -> u64;
        pub fn patina_lifecycle_setup_complete() -> i32;
        pub fn patina_lifecycle_event(label: *const u8, label_len: usize) -> i32;
    }
}

/// WASI import surface for the SDK, mirroring the native shim's C ABI. Present
/// only under a Patina wasm build (`cfg(patina)` without the native shim), so a
/// plain `cargo build --target wasm32-wasip1` of an adopter references none of
/// these symbols and its import table stays free of `patina_sdk`. The host side
/// (`patina-dst-wasi-host`) defines the `patina_sdk` module against the same
/// deterministic runtime the shim uses; `patina-dst-target`'s WASI audit allowlists
/// exactly these ten names. `usize`/`*const u8` lower to wasm `i32`, matching the
/// host's `func_wrap` signatures.
#[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
mod wasm_ffi {
    #[link(wasm_import_module = "patina_sdk")]
    unsafe extern "C" {
        pub fn is_simulated() -> i32;
        pub fn buggify(
            label: *const u8,
            label_len: usize,
            site: *const u8,
            site_len: usize,
            prob_permille: i32,
        ) -> i32;
        pub fn buggify_delay(
            label: *const u8,
            label_len: usize,
            site: *const u8,
            site_len: usize,
        ) -> i32;
        pub fn buggify_knob(
            label: *const u8,
            label_len: usize,
            site: *const u8,
            site_len: usize,
            default_value: i64,
            lo: i64,
            hi: i64,
        ) -> i64;
        pub fn always(
            condition: i32,
            label: *const u8,
            label_len: usize,
            site: *const u8,
            site_len: usize,
        ) -> i32;
        pub fn sometimes(
            condition: i32,
            label: *const u8,
            label_len: usize,
            site: *const u8,
            site_len: usize,
        ) -> i32;
        pub fn reachable(
            label: *const u8,
            label_len: usize,
            site: *const u8,
            site_len: usize,
        ) -> i32;
        pub fn rng() -> u64;
        pub fn lifecycle_setup_complete() -> i32;
        pub fn lifecycle_event(label: *const u8, label_len: usize) -> i32;
    }
}

/// Plainly-seeded fallback entropy for [`rng`] outside a Patina build (and for a
/// non-wasm Patina build without the shim). A process-local SplitMix64 with a
/// fixed seed, so it is reproducible without contacting any host source.
#[cfg(all(not(patina_shim), not(all(patina, target_arch = "wasm32"))))]
mod fallback {
    use std::cell::Cell;

    thread_local! {
        static STATE: Cell<u64> = const { Cell::new(0x9e37_79b9_7f4a_7c15) };
    }

    pub fn next() -> u64 {
        STATE.with(|state| {
            let mut value = state.get().wrapping_add(0x9e37_79b9_7f4a_7c15);
            state.set(value);
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            value ^ (value >> 31)
        })
    }
}

/// Trigger a probabilistic fault at a labeled site. Under Patina an activated
/// site fires deterministically from the run seed; outside Patina always `false`.
///
/// Use it to make rare paths — retries, evictions, early returns, error
/// branches — reachable on seed-chosen runs. Enable with
/// `cargo patina run --buggify`; without that flag (and always outside Patina)
/// every site is inert.
///
/// ```
/// fn commit(dirty: bool) -> Result<(), &'static str> {
///     if patina_dst::buggify!("commit-conflict") {
///         return Err("simulated commit conflict");
///     }
///     let _ = dirty;
///     Ok(())
/// }
///
/// // Outside a Patina build the site never fires.
/// assert_eq!(commit(true), Ok(()));
/// ```
#[macro_export]
macro_rules! buggify {
    ($label:expr) => {
        $crate::__rt::buggify(
            $label,
            ::core::concat!(::core::file!(), ":", ::core::line!()),
            -1,
        )
    };
}

/// Like [`buggify!`] but with an explicit per-evaluation probability in `0.0..=1.0`,
/// overriding the run-default firing probability for this site.
///
/// ```
/// // Outside Patina this is always false, even at probability 1.0.
/// assert!(!patina_dst::buggify_with_prob!("aggressive-retry", 1.0));
/// ```
#[macro_export]
macro_rules! buggify_with_prob {
    ($label:expr, $probability:expr) => {
        $crate::__rt::buggify(
            $label,
            ::core::concat!(::core::file!(), ":", ::core::line!()),
            $crate::__rt::prob_to_permille($probability),
        )
    };
}

/// Inject a deterministic delay at a labeled site through the virtual clock
/// (never a real sleep). Returns whether a delay was injected.
///
/// Under Patina the delay advances virtual time, so it costs no wall-clock time
/// while still perturbing timers, timeouts, and interleavings. Outside Patina it
/// does nothing and returns `false`.
///
/// ```
/// // Outside a Patina build: no delay, and no real time passes.
/// assert!(!patina_dst::buggify_delay!("pre-heartbeat-stall"));
/// ```
#[macro_export]
macro_rules! buggify_delay {
    ($label:expr) => {
        $crate::__rt::buggify_delay(
            $label,
            ::core::concat!(::core::file!(), ":", ::core::line!()),
        )
    };
}

/// A per-run perturbed value within `[lo, hi]` (deterministic from the seed and
/// label) under Patina; `default` outside. Values are `i64`.
///
/// Use it for tunables whose extremes hide bugs — buffer sizes, batch limits,
/// timeouts — so each seed explores a different configuration:
///
/// ```
/// let batch_size = patina_dst::buggify_knob!("batch-size", 64_i64, 1, 1024);
/// // Outside Patina the default is returned unchanged.
/// assert_eq!(batch_size, 64);
/// ```
#[macro_export]
macro_rules! buggify_knob {
    ($label:expr, $default:expr, $lo:expr, $hi:expr) => {
        $crate::__rt::buggify_knob(
            $label,
            ::core::concat!(::core::file!(), ":", ::core::line!()),
            $default,
            $lo,
            $hi,
        )
    };
}

/// Assert an invariant. Under Patina a violation emits a
/// `PATINA_ALWAYS_VIOLATION label=<label>` marker and aborts the run — the
/// violation classifies the seed as a failure a campaign can dedup and a replay
/// can reproduce. Outside Patina it is a `debug_assert` (checked in debug and
/// test builds, free in release).
///
/// ```
/// let ledger = [1, 5, 9];
/// patina_dst::always!(ledger.windows(2).all(|w| w[0] <= w[1]), "ledger-sorted");
/// ```
#[macro_export]
macro_rules! always {
    ($condition:expr, $label:expr) => {
        $crate::__rt::always(
            $condition,
            $label,
            ::core::concat!(::core::file!(), ":", ::core::line!()),
        )
    };
}

/// Coverage oracle: record that `condition` was true at least once at this site.
///
/// The inverse of [`always!`]: instead of "this must never be false", it claims
/// "this should be true on at least some runs" — a cache hit observed, a retry
/// path taken, a conflict actually detected. It never affects control flow; on
/// a `--buggify` run the end-of-run `PATINA_SDK_REPORT` shows which
/// `sometimes!` claims were satisfied, and outside Patina it is a no-op.
///
/// ```
/// fn lookup(cache: &[u32], key: u32) -> bool {
///     let hit = cache.contains(&key);
///     patina_dst::sometimes!(hit, "cache-hit-seen");
///     hit
/// }
/// assert!(lookup(&[7], 7));
/// ```
#[macro_export]
macro_rules! sometimes {
    ($condition:expr, $label:expr) => {
        $crate::__rt::sometimes(
            $condition,
            $label,
            ::core::concat!(::core::file!(), ":", ::core::line!()),
        )
    };
}

/// Coverage oracle: record that this site was reached. The companion of
/// [`sometimes!`] for paths ("recovery ran", "compaction triggered") whose
/// mere execution is the interesting fact — no condition to evaluate.
/// No effect on control flow; a no-op outside Patina.
///
/// ```
/// patina_dst::reachable!("startup-recovery-path");
/// ```
#[macro_export]
macro_rules! reachable {
    ($label:expr) => {
        $crate::__rt::reachable(
            $label,
            ::core::concat!(::core::file!(), ":", ::core::line!()),
        )
    };
}

/// Emit a named lifecycle marker (`PATINA_LIFECYCLE_EVENT label=<label>`) under
/// Patina; a no-op outside. Invoke as [`lifecycle::event!`](crate::lifecycle::event).
#[macro_export]
macro_rules! lifecycle_event {
    ($label:expr) => {
        $crate::__rt::lifecycle_event($label)
    };
}

#[cfg(test)]
mod sdk_tests {
    // Built WITHOUT `cfg(patina)`/`cfg(patina_shim)`, so this exercises the
    // fallback behavior an ordinary `cargo build` of an adopter gets.
    #[test]
    fn macros_are_inert_outside_patina() {
        assert!(!super::is_simulated());
        assert!(!buggify!("outside-fault"));
        assert!(!buggify_with_prob!("outside-fault-prob", 0.9));
        assert!(!buggify_delay!("outside-delay"));
        assert_eq!(buggify_knob!("outside-knob", 7_i64, 1, 100), 7);
        // always! with a true condition is a no-op; sometimes/reachable no-op.
        always!(true, "outside-invariant");
        sometimes!(true, "outside-sometimes");
        reachable!("outside-reachable");
        super::lifecycle::setup_complete();
        super::lifecycle::event!("outside-event");
    }

    #[test]
    fn fallback_rng_is_deterministic_per_thread() {
        // Fresh threads share the fixed seed, so their streams agree.
        let first = std::thread::spawn(|| (0..4).map(|_| super::rng()).collect::<Vec<_>>())
            .join()
            .unwrap();
        let second = std::thread::spawn(|| (0..4).map(|_| super::rng()).collect::<Vec<_>>())
            .join()
            .unwrap();
        assert_eq!(first, second);
    }
}
