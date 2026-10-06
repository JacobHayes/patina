//! The [Patina] SDK: cooperative fault injection and test oracles, in the style
//! of FoundationDB's `BUGGIFY` and Antithesis assertions.
//!
//! Patina is a deterministic simulation testing (DST) runtime that runs ordinary
//! `std` programs under a seeded virtual OS personality — same seed, same run,
//! byte for byte. This crate is the one Patina crate an application depends on
//! directly: it marks the fault sites and invariants that the runtime cannot
//! know about from outside ("what if this batch path ran?", "this must *always*
//! hold"). Its default feature set has **zero dependencies**, and every entry
//! point is a no-op or a plain fallback outside a Patina build, so you ship it
//! unconditionally — no `cfg(patina)`, no runtime dependency graph, no cost in
//! production. The default-off `macros` feature adds only the test-time
//! `#[patina_dst::test]` attribute for point-solution DST tests under plain
//! `cargo test`:
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
//! - [`always!`] — a fatal invariant: under Patina a violation reports a
//!   `violation` verdict and aborts; outside it is a `debug_assert`.
//! - [`sometimes!`] / [`reachable!`] — coverage oracles.
//! - [`verdict`] — report a structured outcome ([`VerdictKind`]) about the run:
//!   recorded as a trace event and surfaced in the result envelope's
//!   `verdicts[]`. An `always!` violation reports one automatically.
//! - [`custom_op_bytes`] — wrap an effect Patina does not model so it is
//!   recorded on the record pass and reproduced from the recording on replay.
//!   [`custom_op_bytes_faultable`] additionally declares what failure means for
//!   the operation, which is what `--custom-op-fail-permille` acts on. With the
//!   default-off `custom-ops` feature, `custom_op` and `custom_op_faultable` are
//!   the same two with serde-typed keys and results.
//! - [`is_simulated`] / [`rng`] and the [`lifecycle`] module.
//! - With the default-off `macros` feature, `#[patina_dst::test]` rebuilds the
//!   same libtest harness shim-linked and sweeps the annotated test under plain
//!   `cargo test`.
//!
//! Site labels are explicit strings and must be unique across the program; a
//! label reused at a different call site is fatal. For literal labels the
//! link-time site table (below) catches the reuse before the guest runs, even
//! when neither site is ever evaluated; a computed label is caught at its first
//! evaluation. Either way the embedder emits `PATINA_BUGGIFY_DUPLICATE_LABEL`
//! and aborts.
//!
//! [`verdict`] and [`custom_op_bytes`] labels share that namespace — the same
//! string names the same thing in `sites.json`, in a run's `verdicts[]`, and in
//! a trace's custom-op events — but neither is a site: they register nothing, so
//! the duplicate-label rule does not apply to them, and reporting one label
//! repeatedly in a run is exactly how verdicts aggregate and how a custom-op
//! label names an operation *class* rather than a call. Reusing an oracle's
//! label for either is therefore legal and deliberate: it joins the coverage
//! view and the outcome view of one invariant.
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
//! ## Determinism and never-reached sites
//!
//! Literal-label SDK macro calls also emit a dependency-free link-time site
//! table under `cfg(patina)`. The native shim and WASI host enumerate that table
//! before the guest runs and surface `declared_site=` rows in `PATINA_SDK_REPORT`,
//! so a `sometimes!` or `reachable!` site that no generation ever reaches still
//! appears in campaign `sites.json` with `registered_gens=0`. The table uses no
//! constructors and does not compute activation or firing decisions, so replay
//! fingerprints and buggify decisions remain driven only by the runtime config,
//! seed, and actually evaluated sites.
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
//! This crate is a pure SDK by default: it does not run applications, and it
//! never links the simulator. The `macros` feature adds a test orchestrator that
//! shells out to `cargo-patina`; the guest still enters through the same native
//! shim path. Under `cargo patina build`/`run` the native shim or WASI host
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

#[cfg(feature = "macros")]
pub use patina_dst_macros::test;

// ---- Cooperative-SUT SDK ------------------------------------------------------

mod custom_ops;
mod simulation;
mod static_sites;
mod test_harness;
mod verdict;

#[cfg(feature = "custom-ops")]
pub use custom_ops::{custom_op, custom_op_faultable};
pub use custom_ops::{custom_op_bytes, custom_op_bytes_faultable};
pub use simulation::{is_simulated, rng};
pub use verdict::{VerdictKind, verdict};

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
pub mod __rt;

/// FFI into the native shim. Present only when the shim is actually linked
/// (`cfg(patina_shim)`, injected by `cargo patina build`). Under a plain
/// `cargo build`, a WASI build, or `cargo patina run`, these symbols are never
/// referenced, so nothing is left unresolved at link time.
#[cfg(patina_shim)]
mod ffi;

/// WASI import surface for the SDK, mirroring the native shim's C ABI. Present
/// only under a Patina wasm build (`cfg(patina)` without the native shim), so a
/// plain `cargo build --target wasm32-wasip1` of an adopter references none of
/// these symbols and its import table stays free of `patina_sdk`. The host side
/// (`patina-dst-wasi-host`) defines the `patina_sdk` module against the same
/// deterministic runtime the shim uses; `patina-dst-target`'s WASI audit allowlists
/// exactly these fourteen names. `usize`/`*const u8` lower to wasm `i32`, matching
/// the host's `func_wrap` signatures.
#[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
mod wasm_ffi;

#[doc(hidden)]
#[macro_export]
macro_rules! __patina_static_site {
    ($label:literal, $site:expr, $kind:expr) => {
        #[allow(unexpected_cfgs)]
        const _: () = {
            #[cfg(all(patina, target_arch = "wasm32"))]
            #[used]
            #[unsafe(link_section = "patina_sites")]
            static __PATINA_SITE: [u8; { $crate::__rt::wasm_static_site_len($label, $site) }] =
                $crate::__rt::encode_wasm_static_site::<
                    { $crate::__rt::wasm_static_site_len($label, $site) },
                >($kind, $label, $site);

            #[cfg(all(patina, not(target_arch = "wasm32")))]
            #[used]
            #[cfg_attr(target_os = "macos", unsafe(link_section = "__DATA,__patina_sites"))]
            #[cfg_attr(not(target_os = "macos"), unsafe(link_section = "patina_sites"))]
            static __PATINA_SITE: $crate::__rt::StaticSiteDescriptor =
                $crate::__rt::StaticSiteDescriptor::new($label, $site, $kind);
        };
    };
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
    ($label:literal) => {{
        $crate::__patina_static_site!(
            $label,
            ::core::concat!(::core::file!(), ":", ::core::line!()),
            $crate::__rt::STATIC_SITE_KIND_FAULT
        );
        $crate::__rt::buggify(
            $label,
            ::core::concat!(::core::file!(), ":", ::core::line!()),
            -1,
        )
    }};
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
    ($label:literal, $probability:expr) => {{
        $crate::__patina_static_site!(
            $label,
            ::core::concat!(::core::file!(), ":", ::core::line!()),
            $crate::__rt::STATIC_SITE_KIND_FAULT
        );
        $crate::__rt::buggify(
            $label,
            ::core::concat!(::core::file!(), ":", ::core::line!()),
            $crate::__rt::prob_to_permille($probability),
        )
    }};
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
    ($label:literal) => {{
        $crate::__patina_static_site!(
            $label,
            ::core::concat!(::core::file!(), ":", ::core::line!()),
            $crate::__rt::STATIC_SITE_KIND_DELAY
        );
        $crate::__rt::buggify_delay(
            $label,
            ::core::concat!(::core::file!(), ":", ::core::line!()),
        )
    }};
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
    ($label:literal, $default:expr, $lo:expr, $hi:expr) => {{
        $crate::__patina_static_site!(
            $label,
            ::core::concat!(::core::file!(), ":", ::core::line!()),
            $crate::__rt::STATIC_SITE_KIND_KNOB
        );
        $crate::__rt::buggify_knob(
            $label,
            ::core::concat!(::core::file!(), ":", ::core::line!()),
            $default,
            $lo,
            $hi,
        )
    }};
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

/// Assert an invariant. Under Patina a violation reports a `violation`
/// [`VerdictKind`] under the site's label and aborts the run — the verdict
/// classifies the seed as a failure a campaign can dedup and a replay can
/// reproduce. Outside Patina it is a `debug_assert` (checked in debug and
/// test builds, free in release).
///
/// ```
/// let ledger = [1, 5, 9];
/// patina_dst::always!(ledger.windows(2).all(|w| w[0] <= w[1]), "ledger-sorted");
/// ```
#[macro_export]
macro_rules! always {
    ($condition:expr, $label:literal) => {{
        $crate::__patina_static_site!(
            $label,
            ::core::concat!(::core::file!(), ":", ::core::line!()),
            $crate::__rt::STATIC_SITE_KIND_ALWAYS
        );
        $crate::__rt::always(
            $condition,
            $label,
            ::core::concat!(::core::file!(), ":", ::core::line!()),
        )
    }};
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
    ($condition:expr, $label:literal) => {{
        $crate::__patina_static_site!(
            $label,
            ::core::concat!(::core::file!(), ":", ::core::line!()),
            $crate::__rt::STATIC_SITE_KIND_SOMETIMES
        );
        $crate::__rt::sometimes(
            $condition,
            $label,
            ::core::concat!(::core::file!(), ":", ::core::line!()),
        )
    }};
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
    ($label:literal) => {{
        $crate::__patina_static_site!(
            $label,
            ::core::concat!(::core::file!(), ":", ::core::line!()),
            $crate::__rt::STATIC_SITE_KIND_REACHABLE
        );
        $crate::__rt::reachable(
            $label,
            ::core::concat!(::core::file!(), ":", ::core::line!()),
        )
    }};
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
mod tests;
