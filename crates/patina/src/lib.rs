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

#[macro_use]
mod site_macros;

#[doc(hidden)]
pub use site_macros::{SDK_SITE_MACROS, SdkSiteMacro};

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
