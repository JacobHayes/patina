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

/// What a guest asserts about its own run, for [`verdict`].
///
/// A closed enum: kinds are data on one ABI verb, never a symbol per kind. The
/// numeric values mirror the native shim's `patina_native.h` and are pinned by
/// `patina_dst_abi::VerdictKind::as_abi`; this crate restates them rather than
/// depending on the ABI crate so the SDK keeps its zero-dependency default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerdictKind {
    /// The guest detected a violation of its own invariant.
    Violation,
    /// The guest confirmed a property held.
    Pass,
    /// The guest is about to abort deliberately, on its own invariant — so the
    /// resulting SIGABRT is attributable to the guest, not to a Patina refusal.
    AbortIntent,
}

impl VerdictKind {
    /// The `u32` this kind travels as across the shim / WASI ABI. Public so a
    /// guest that calls `patina_verdict` directly (a non-Rust guest, or one
    /// hand-rolling the FFI) can name the same constants the SDK uses.
    #[inline]
    pub const fn as_abi(self) -> u32 {
        match self {
            VerdictKind::Violation => 1,
            VerdictKind::Pass => 2,
            VerdictKind::AbortIntent => 3,
        }
    }
}

/// Report a structured verdict about this run: what the guest concluded, under a
/// `label` that aggregates across runs, with optional `detail` (UTF-8, JSON by
/// convention) recorded verbatim for triage.
///
/// Under Patina the call is recorded as a trace event — replay reproduces the
/// verdict stream byte-identically, and a divergent one fails closed like any
/// other operation mismatch — and surfaces in the run's `patina.result/v1`
/// envelope as a `verdicts[]` entry. Outside Patina it is a no-op, so it is safe
/// to leave in production code.
///
/// A verdict never changes control flow: `Violation` does not abort, and
/// `AbortIntent` does not abort either — it *attributes* an abort the guest is
/// about to perform itself, so the resulting SIGABRT is not mistaken for a Patina
/// fail-closed refusal.
///
/// `label` shares the site-label namespace of [`sometimes!`]/[`buggify!`], but a
/// verdict is not a fault site: it registers nothing, the duplicate-label rule
/// does not apply, and reporting the same label many times in one run is the
/// point (that is what aggregation means).
///
/// ```
/// // Outside Patina this compiles to nothing.
/// patina_dst::verdict(patina_dst::VerdictKind::Pass, "queue-drained", "");
/// ```
///
/// In the cargo family (a package that links `patina-dst-runtime` and drives its
/// own `Context`) this function has no runtime handle to call, exactly like
/// [`buggify!`]; report through `patina_dst_runtime::Context::verdict` there.
#[inline]
pub fn verdict(kind: VerdictKind, label: &str, detail: &str) {
    #[cfg(patina_shim)]
    {
        unsafe {
            ffi::patina_verdict(
                kind.as_abi(),
                label.as_ptr(),
                label.len(),
                detail.as_ptr(),
                detail.len(),
            );
        }
    }
    #[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
    {
        unsafe {
            wasm_ffi::verdict(
                kind.as_abi(),
                label.as_ptr(),
                label.len(),
                detail.as_ptr(),
                detail.len(),
            );
        }
    }
    #[cfg(all(not(patina_shim), not(all(patina, target_arch = "wasm32"))))]
    {
        let _ = (kind, label, detail);
    }
}

/// Perform one **custom operation**: an effect Patina does not model, wrapped at
/// a boundary the guest controls so Patina can mediate it — raw bytes in, raw
/// bytes out.
///
/// On the record pass `perform` runs and its bytes are recorded under `label`.
/// On replay `perform` is **not** run: the recorded bytes are returned. That is
/// what makes a custom op deterministic by construction — the guest does not
/// decide which pass it is on, the runtime does.
///
/// - `label` names the operation *class* (`"s3.get_object"`), not the call. It
///   shares the site-label namespace of [`sometimes!`]/[`buggify!`] and
///   aggregates like a [`verdict`] label, but a custom op registers no fault
///   site, so the duplicate-label rule does not apply and one label naming many
///   calls in a run is exactly the point.
/// - `key` is the operation's logical input. It is recorded with the result and
///   checked on replay, so a guest that asks a *different* question under the
///   same label is refused rather than handed a stale answer.
///
/// This is the untyped surface: it lowers directly to the shim/WASI ABI with no
/// encoding of its own. With the default-off `custom-ops` feature, `custom_op`
/// adds serde-typed keys and results over exactly this call.
///
/// # Honest limits
///
/// A custom op does **not** exempt the wrapped effect from interposition. On the
/// record pass `perform` runs for real, so an un-modeled raw effect inside it
/// still refuses or audits exactly as it would outside a custom op — recording
/// is not the determinism-guaranteed mode, replay is. And `perform` must not
/// perform effects Patina *does* model: replay skips `perform`, so those
/// operations could never be reproduced, and the runtime refuses at record time
/// rather than writing a trace that cannot replay.
///
/// Outside Patina — and in the cargo family, which has no shim to call — this is
/// just `perform()`; report through `patina_dst_runtime::Context::custom_op`
/// there.
///
/// ```
/// // Outside Patina the closure simply runs and its bytes come straight back.
/// let bytes = patina_dst::custom_op_bytes("clock.host", b"utc", || vec![1, 2, 3]);
/// assert_eq!(bytes, vec![1, 2, 3]);
/// ```
pub fn custom_op_bytes(label: &str, key: &[u8], perform: impl FnOnce() -> Vec<u8>) -> Vec<u8> {
    custom_op_bytes_inner(label, key, None::<fn() -> Vec<u8>>, perform)
}

/// A [`custom_op_bytes`] that **declares a failure shape**, so the seeded
/// `--custom-op-fail-permille` knob can fail it.
///
/// `on_fault` produces the bytes the guest receives when a fault fires; it is
/// the guest's own answer to "what does this operation failing look like", and
/// the runtime never invents one, because only the guest knows a value its
/// caller can handle. When a fault fires, `perform` does **not** run and the
/// fault is recorded, so a replay reproduces it exactly — without re-consulting
/// eligibility, because the trace is the authority.
///
/// Declaring a failure shape injects nothing on its own: with the knob off (the
/// default) this behaves exactly like [`custom_op_bytes`]. What it buys is that
/// a campaign can now exercise the guest's error path for an effect Patina does
/// not model, which is the whole reason a custom op is worth wrapping.
///
/// Outside Patina this is just `perform()`; `on_fault` is never called.
///
/// ```
/// // Outside Patina the real closure runs and the declared failure is unused.
/// let bytes = patina_dst::custom_op_bytes_faultable(
///     "s3.get_object",
///     b"bucket/key",
///     || b"TIMEOUT".to_vec(),
///     || b"etag-7".to_vec(),
/// );
/// assert_eq!(bytes, b"etag-7".to_vec());
/// ```
pub fn custom_op_bytes_faultable(
    label: &str,
    key: &[u8],
    on_fault: impl FnOnce() -> Vec<u8>,
    perform: impl FnOnce() -> Vec<u8>,
) -> Vec<u8> {
    custom_op_bytes_inner(label, key, Some(on_fault), perform)
}

/// The one place the custom-op protocol is written down: `on_fault` present is
/// the eligibility declaration the ABI carries, so the faultable and plain
/// surfaces differ in exactly that bit and can never drift apart in any other.
fn custom_op_bytes_inner(
    label: &str,
    key: &[u8],
    on_fault: Option<impl FnOnce() -> Vec<u8>>,
    perform: impl FnOnce() -> Vec<u8>,
) -> Vec<u8> {
    #[cfg(any(patina_shim, all(patina, target_arch = "wasm32")))]
    {
        let mut len: usize = 0;
        let mode = unsafe {
            custom_op_ffi::begin(
                label.as_ptr(),
                label.len(),
                key.as_ptr(),
                key.len(),
                i32::from(on_fault.is_some()),
                &raw mut len,
            )
        };
        match mode {
            0 => {
                let result = perform();
                let code = unsafe { custom_op_ffi::record(result.as_ptr(), result.len()) };
                assert!(
                    code >= 0,
                    "patina custom op {label:?}: the runtime refused the recorded result"
                );
                result
            }
            1 => {
                let mut buffer = vec![0u8; len];
                let written =
                    unsafe { custom_op_ffi::replay_result(buffer.as_mut_ptr(), buffer.len()) };
                assert!(
                    written >= 0 && written as usize == len,
                    "patina custom op {label:?}: the runtime returned {written} bytes of a \
{len}-byte recorded result"
                );
                buffer
            }
            // A seeded (or recorded) fault. The runtime only answers this to a
            // call that declared a failure shape, so the `expect` is the ABI
            // contract being upheld, not a hope.
            2 => on_fault.expect("a custom-op fault needs a declared failure shape")(),
            // Only a malformed call reaches here: every runtime-level refusal is
            // fatal on the embedder side. Fail loudly rather than silently
            // performing an effect replay was supposed to reproduce.
            other => panic!(
                "patina custom op {label:?}: the runtime refused the call (code {other}); the \
label or key argument is malformed"
            ),
        }
    }
    #[cfg(not(any(patina_shim, all(patina, target_arch = "wasm32"))))]
    {
        let _ = (label, key, on_fault);
        perform()
    }
}

/// The two ABI mirrors of the custom-op verbs behind one name, so
/// [`custom_op_bytes`] states the protocol once instead of twice.
#[cfg(any(patina_shim, all(patina, target_arch = "wasm32")))]
mod custom_op_ffi {
    #[inline]
    pub unsafe fn begin(
        label: *const u8,
        label_len: usize,
        key: *const u8,
        key_len: usize,
        fault_eligible: i32,
        out_len: *mut usize,
    ) -> i32 {
        #[cfg(patina_shim)]
        // SAFETY: forwarded from `custom_op_bytes`, which passes live slices.
        unsafe {
            super::ffi::patina_custom_op_begin(
                label,
                label_len,
                key,
                key_len,
                fault_eligible,
                out_len,
            )
        }
        #[cfg(not(patina_shim))]
        // SAFETY: as above.
        unsafe {
            super::wasm_ffi::custom_op_begin(
                label,
                label_len,
                key,
                key_len,
                fault_eligible,
                out_len,
            )
        }
    }

    #[inline]
    pub unsafe fn replay_result(out: *mut u8, out_cap: usize) -> isize {
        #[cfg(patina_shim)]
        // SAFETY: forwarded from `custom_op_bytes`, which passes a live buffer.
        unsafe {
            super::ffi::patina_custom_op_replay_result(out, out_cap)
        }
        #[cfg(not(patina_shim))]
        // SAFETY: as above.
        unsafe {
            super::wasm_ffi::custom_op_replay_result(out, out_cap) as isize
        }
    }

    #[inline]
    pub unsafe fn record(result: *const u8, result_len: usize) -> i32 {
        #[cfg(patina_shim)]
        // SAFETY: forwarded from `custom_op_bytes`, which passes a live slice.
        unsafe {
            super::ffi::patina_custom_op_record(result, result_len)
        }
        #[cfg(not(patina_shim))]
        // SAFETY: as above.
        unsafe {
            super::wasm_ffi::custom_op_record(result, result_len)
        }
    }
}

/// A typed [`custom_op_bytes`]: the same record/replay contract with the key and
/// the result carried as ordinary Rust values.
///
/// Requires the default-off `custom-ops` feature, which is the only thing in this
/// crate that pulls in a dependency (`serde` + `serde_json`); the untyped
/// [`custom_op_bytes`] is always available and needs nothing extra.
///
/// ```ignore
/// #[derive(serde::Serialize, serde::Deserialize)]
/// struct Object { etag: String, body: Vec<u8> }
///
/// let object: Object = patina_dst::custom_op("s3.get_object", &request_key, || {
///     real_s3_client.get(&request_key) // runs on record only
/// });
/// ```
///
/// # The encoding is build-owned, not ABI-owned
///
/// Values are encoded with `serde_json`. The shim ABI and the trace carry opaque
/// bytes precisely so no serialization format is pinned into the boundary
/// contract, and a recorded trace only ever replays against the guest binary
/// that produced it — which the run fingerprint already enforces. So the choice
/// lives here, in the guest's build. JSON rather than a denser binary format
/// because a custom op's value is triage: the key and result stay legible in
/// `cargo patina trace`, which a non-self-describing encoding would reduce to a
/// blob. It is also already in the workspace, so it adds no third-party crate
/// and no MSRV risk to a 1.86 build.
///
/// # Panics
///
/// If the value cannot be encoded, or a recorded result cannot be decoded into
/// `T` — the latter means the trace was recorded by a guest whose result type no
/// longer matches this one, which is a fail-closed refusal, not a value to guess
/// at.
#[cfg(feature = "custom-ops")]
pub fn custom_op<T, K>(label: &str, key: &K, perform: impl FnOnce() -> T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
    K: serde::Serialize + ?Sized,
{
    let key = serde_json::to_vec(key)
        .unwrap_or_else(|error| panic!("patina custom op {label:?}: cannot encode key: {error}"));
    // `performed` carries the record pass's value out of the closure so the
    // caller gets exactly what `perform` returned, not a re-decoded copy of it.
    let mut performed = None;
    let bytes = custom_op_bytes(label, &key, || {
        let value = perform();
        let bytes = serde_json::to_vec(&value).unwrap_or_else(|error| {
            panic!("patina custom op {label:?}: cannot encode result: {error}")
        });
        performed = Some(value);
        bytes
    });
    match performed {
        Some(value) => value,
        None => serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!(
                "patina custom op {label:?}: cannot decode the recorded result: {error}; the \
recording was produced by a guest whose result type no longer matches this one"
            )
        }),
    }
}

/// A typed [`custom_op_bytes_faultable`]: [`custom_op`] plus a declared failure
/// shape, so `--custom-op-fail-permille` can fail the operation and the guest
/// exercises its own error path.
///
/// `on_fault` returns the value a failure produces — for a `Result`-shaped `T`,
/// the `Err` variant the caller already handles. It runs *instead of* `perform`
/// when a seeded fault fires, and never otherwise.
///
/// ```ignore
/// let object: Result<Object, FetchError> = patina_dst::custom_op_faultable(
///     "s3.get_object",
///     &request_key,
///     || Err(FetchError::Timeout),        // what failure means here
///     || real_s3_client.get(&request_key), // runs on record only
/// );
/// ```
///
/// # Panics
///
/// As [`custom_op`]: an unencodable value or an undecodable recorded result.
#[cfg(feature = "custom-ops")]
pub fn custom_op_faultable<T, K>(
    label: &str,
    key: &K,
    on_fault: impl FnOnce() -> T,
    perform: impl FnOnce() -> T,
) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
    K: serde::Serialize + ?Sized,
{
    let key = serde_json::to_vec(key)
        .unwrap_or_else(|error| panic!("patina custom op {label:?}: cannot encode key: {error}"));
    // A `RefCell` rather than `custom_op`'s plain `&mut`: both closures are
    // handed over at once and exactly one of them runs, so they must share the
    // slot the produced value comes back through.
    let produced: core::cell::RefCell<Option<T>> = core::cell::RefCell::new(None);
    let encode = |value: T| -> Vec<u8> {
        let bytes = serde_json::to_vec(&value).unwrap_or_else(|error| {
            panic!("patina custom op {label:?}: cannot encode result: {error}")
        });
        *produced.borrow_mut() = Some(value);
        bytes
    };
    let bytes = custom_op_bytes_faultable(label, &key, || encode(on_fault()), || encode(perform()));
    match produced.into_inner() {
        Some(value) => value,
        None => serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!(
                "patina custom op {label:?}: cannot decode the recorded result: {error}; the \
recording was produced by a guest whose result type no longer matches this one"
            )
        }),
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
    /// Link-time SDK site descriptor emitted by literal-label SDK macro calls in
    /// native Patina builds. Embedders enumerate the `patina_sites` linker
    /// section before the guest runs, so never-reached sites can still appear in
    /// runtime-joined reports without constructors or external dependencies.
    #[repr(C)]
    pub struct StaticSiteDescriptor {
        pub label_ptr: *const u8,
        pub label_len: usize,
        pub site_ptr: *const u8,
        pub site_len: usize,
        pub kind: u8,
        pub _reserved: [u8; 7],
    }

    // SAFETY: descriptors point at immutable string literals and are never
    // mutated; sharing them between threads is safe.
    unsafe impl Sync for StaticSiteDescriptor {}

    impl StaticSiteDescriptor {
        pub const fn new(label: &'static str, site: &'static str, kind: u8) -> Self {
            Self {
                label_ptr: label.as_ptr(),
                label_len: label.len(),
                site_ptr: site.as_ptr(),
                site_len: site.len(),
                kind,
                _reserved: [0; 7],
            }
        }
    }

    pub const STATIC_SITE_KIND_FAULT: u8 = 1;
    pub const STATIC_SITE_KIND_DELAY: u8 = 2;
    pub const STATIC_SITE_KIND_KNOB: u8 = 3;
    pub const STATIC_SITE_KIND_ALWAYS: u8 = 4;
    pub const STATIC_SITE_KIND_SOMETIMES: u8 = 5;
    pub const STATIC_SITE_KIND_REACHABLE: u8 = 6;

    pub const WASM_STATIC_SITE_RECORD_HEADER_LEN: usize = 14;

    pub const fn wasm_static_site_len(label: &str, site: &str) -> usize {
        WASM_STATIC_SITE_RECORD_HEADER_LEN + label.len() + site.len()
    }

    /// Encode one WASM `patina_sites` custom-section record. The wasm target
    /// rejects custom-section statics with relocations, so wasm descriptors are
    /// self-contained bytes rather than native pointer records.
    pub const fn encode_wasm_static_site<const N: usize>(
        kind: u8,
        label: &str,
        site: &str,
    ) -> [u8; N] {
        let label_bytes = label.as_bytes();
        let site_bytes = site.as_bytes();
        let label_len = label_bytes.len() as u32;
        let site_len = site_bytes.len() as u32;
        let mut out = [0_u8; N];
        out[0] = b'P';
        out[1] = b'T';
        out[2] = b'S';
        out[3] = b'1';
        out[4] = kind;
        out[5] = 0;
        out[6] = (label_len & 0xff) as u8;
        out[7] = ((label_len >> 8) & 0xff) as u8;
        out[8] = ((label_len >> 16) & 0xff) as u8;
        out[9] = ((label_len >> 24) & 0xff) as u8;
        out[10] = (site_len & 0xff) as u8;
        out[11] = ((site_len >> 8) & 0xff) as u8;
        out[12] = ((site_len >> 16) & 0xff) as u8;
        out[13] = ((site_len >> 24) & 0xff) as u8;

        let mut cursor = WASM_STATIC_SITE_RECORD_HEADER_LEN;
        let mut i = 0;
        while i < label_bytes.len() {
            out[cursor] = label_bytes[i];
            cursor += 1;
            i += 1;
        }
        i = 0;
        while i < site_bytes.len() {
            out[cursor] = site_bytes[i];
            cursor += 1;
            i += 1;
        }
        out
    }

    /// Runtime data emitted by `#[patina_dst::test]`.
    #[cfg(feature = "macros")]
    #[doc(hidden)]
    pub struct DstTest {
        pub manifest_dir: &'static str,
        pub harness_target: &'static str,
        pub test_path: &'static str,
        pub cli_args: &'static [&'static str],
    }

    /// Return types accepted by `#[patina_dst::test]` bodies.
    #[cfg(feature = "macros")]
    #[doc(hidden)]
    pub trait DstTestReturn {
        fn assert_ok(self);
    }

    #[cfg(feature = "macros")]
    impl DstTestReturn for () {
        fn assert_ok(self) {}
    }

    #[cfg(feature = "macros")]
    impl<E: core::fmt::Debug> DstTestReturn for Result<(), E> {
        fn assert_ok(self) {
            if let Err(error) = self {
                panic!("patina dst test body returned error: {error:?}");
            }
        }
    }

    /// Assert a guest-side `#[patina_dst::test]` body return value.
    #[cfg(feature = "macros")]
    #[doc(hidden)]
    pub fn assert_test_return<T: DstTestReturn>(value: T) {
        value.assert_ok();
    }

    /// Orchestrate a point-solution DST test from a plain `cargo test` process.
    ///
    /// The shim-linked guest calls the same wrapper, but `is_simulated()` is true
    /// there, so only the body executes. This function is therefore host-side
    /// only: discover `cargo-patina`, ask it to rebuild the same libtest target
    /// under the native shim, and panic loudly on any failure.
    #[cfg(feature = "macros")]
    #[doc(hidden)]
    #[track_caller]
    pub fn orchestrate(test: &DstTest) {
        if let Err(message) = orchestrate_inner(test) {
            panic!("{message}");
        }
    }

    #[cfg(feature = "macros")]
    fn orchestrate_inner(test: &DstTest) -> Result<(), String> {
        let cli = resolve_cargo_patina(test)?;
        let exact = libtest_exact_name(test);
        let mut command = std::process::Command::new(&cli);
        command
            .arg("test")
            .arg(test.manifest_dir)
            .arg("--harness-target")
            .arg(test.harness_target)
            .arg("--exact")
            .arg(&exact)
            .args(test.cli_args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let rendered = render_command(&cli, command.get_args());
        let output = command.output().map_err(|error| {
            format!(
                "patina dst test could not launch cargo-patina for {}: {error}\n  command: {rendered}",
                test.test_path
            )
        })?;
        if output.status.success() {
            return Ok(());
        }
        let exit = match output.status.code() {
            Some(code) => code.to_string(),
            None => "terminated by signal".to_string(),
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let mut message = format!(
            "patina dst test orchestration failed: {}\n  command: {rendered}\n  exit: {exit}",
            test.test_path
        );
        if !stdout.trim().is_empty() {
            message.push_str("\n  stdout:\n");
            message.push_str(&indent_block(&stdout));
        }
        if !stderr.trim().is_empty() {
            message.push_str("\n  stderr:\n");
            message.push_str(&indent_block(&stderr));
        }
        Err(message)
    }

    #[cfg(feature = "macros")]
    fn libtest_exact_name(test: &DstTest) -> String {
        if let Some(rest) = test.test_path.strip_prefix(test.harness_target) {
            if let Some(rest) = rest.strip_prefix("::") {
                if !rest.is_empty() {
                    return rest.to_string();
                }
            }
        }
        test.test_path.to_string()
    }

    #[cfg(feature = "macros")]
    fn resolve_cargo_patina(test: &DstTest) -> Result<std::path::PathBuf, String> {
        if let Some(raw) = std::env::var_os("PATINA_CLI") {
            if raw.as_os_str().is_empty() {
                return Err(missing_cli_message(test, "PATINA_CLI is set but empty"));
            }
            let path = std::path::PathBuf::from(raw);
            if !path.is_absolute() {
                return Err(missing_cli_message(
                    test,
                    &format!(
                        "PATINA_CLI must be an absolute path to cargo-patina, got {}",
                        path.display()
                    ),
                ));
            }
            if !is_executable(&path) {
                return Err(missing_cli_message(
                    test,
                    &format!(
                        "PATINA_CLI points at {}, but it is not an executable file",
                        path.display()
                    ),
                ));
            }
            return Ok(path);
        }

        let path = std::env::var_os("PATH").unwrap_or_default();
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(executable_name("cargo-patina"));
            if is_executable(&candidate) {
                return Ok(candidate);
            }
        }
        Err(missing_cli_message(
            test,
            "PATINA_CLI is not set and cargo-patina was not found on PATH",
        ))
    }

    #[cfg(feature = "macros")]
    fn missing_cli_message(test: &DstTest, reason: &str) -> String {
        format!(
            "patina dst test could not find cargo-patina for {}\n  reason: {reason}\n  remedies:\n    set PATINA_CLI to the absolute path of a cargo-patina binary\n    or put cargo-patina on PATH\n  DST tests never skip when the CLI is missing; absence is a test failure.",
            test.test_path
        )
    }

    #[cfg(all(feature = "macros", windows))]
    fn executable_name(name: &str) -> String {
        format!("{name}.exe")
    }

    #[cfg(all(feature = "macros", not(windows)))]
    fn executable_name(name: &str) -> &str {
        name
    }

    #[cfg(all(feature = "macros", unix))]
    fn is_executable(path: &std::path::Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(metadata) => metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
            Err(_) => false,
        }
    }

    #[cfg(all(feature = "macros", windows))]
    fn is_executable(path: &std::path::Path) -> bool {
        std::fs::metadata(path)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false)
    }

    #[cfg(all(feature = "macros", not(any(unix, windows))))]
    fn is_executable(path: &std::path::Path) -> bool {
        std::fs::metadata(path)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false)
    }

    #[cfg(feature = "macros")]
    fn render_command<'a>(
        program: &std::path::Path,
        args: impl Iterator<Item = &'a std::ffi::OsStr>,
    ) -> String {
        let mut rendered = shell_quote(program.as_os_str());
        for arg in args {
            rendered.push(' ');
            rendered.push_str(&shell_quote(arg));
        }
        rendered
    }

    #[cfg(feature = "macros")]
    fn shell_quote(value: &std::ffi::OsStr) -> String {
        let text = value.to_string_lossy();
        if !text.is_empty()
            && text.chars().all(|ch| {
                ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | ':' | '=')
            })
        {
            return text.into_owned();
        }
        let mut quoted = String::from("'");
        for ch in text.chars() {
            if ch == '\'' {
                quoted.push_str("'\\''");
            } else {
                quoted.push(ch);
            }
        }
        quoted.push('\'');
        quoted
    }

    #[cfg(feature = "macros")]
    fn indent_block(text: &str) -> String {
        text.lines()
            .map(|line| format!("    {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[cfg(all(test, feature = "macros"))]
    mod macro_tests {
        use super::*;

        const TEST: DstTest = DstTest {
            manifest_dir: "/repo/crate",
            harness_target: "macro_adopter",
            test_path: "macro_adopter::nested::case",
            cli_args: &[],
        };

        #[test]
        fn libtest_exact_strips_the_harness_crate_segment() {
            assert_eq!(libtest_exact_name(&TEST), "nested::case");
        }

        #[test]
        fn missing_cli_message_is_a_loud_failure_not_a_skip() {
            let message = missing_cli_message(
                &TEST,
                "PATINA_CLI is not set and cargo-patina was not found on PATH",
            );
            assert!(message.contains("could not find cargo-patina"));
            assert!(message.contains("set PATINA_CLI"));
            assert!(message.contains("put cargo-patina on PATH"));
            assert!(message.contains("never skip"));
        }

        #[test]
        fn shell_quote_preserves_copy_pasteable_commands() {
            assert_eq!(
                shell_quote(std::ffi::OsStr::new("simple/path")),
                "simple/path"
            );
            assert_eq!(
                shell_quote(std::ffi::OsStr::new("two words")),
                "'two words'"
            );
        }
    }

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
            // Host-authoritative: on a violation the WASI host records the
            // `violation` verdict and traps the guest, so this import does not
            // return when `condition` is false.
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
        pub fn patina_verdict(
            kind: u32,
            label: *const u8,
            label_len: usize,
            detail: *const u8,
            detail_len: usize,
        ) -> i32;
        pub fn patina_custom_op_begin(
            label: *const u8,
            label_len: usize,
            key: *const u8,
            key_len: usize,
            fault_eligible: i32,
            out_len: *mut usize,
        ) -> i32;
        pub fn patina_custom_op_replay_result(out: *mut u8, out_cap: usize) -> isize;
        pub fn patina_custom_op_record(result: *const u8, result_len: usize) -> i32;
    }
}

/// WASI import surface for the SDK, mirroring the native shim's C ABI. Present
/// only under a Patina wasm build (`cfg(patina)` without the native shim), so a
/// plain `cargo build --target wasm32-wasip1` of an adopter references none of
/// these symbols and its import table stays free of `patina_sdk`. The host side
/// (`patina-dst-wasi-host`) defines the `patina_sdk` module against the same
/// deterministic runtime the shim uses; `patina-dst-target`'s WASI audit allowlists
/// exactly these fourteen names. `usize`/`*const u8` lower to wasm `i32`, matching
/// the host's `func_wrap` signatures.
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
        pub fn verdict(
            kind: u32,
            label: *const u8,
            label_len: usize,
            detail: *const u8,
            detail_len: usize,
        ) -> i32;
        pub fn custom_op_begin(
            label: *const u8,
            label_len: usize,
            key: *const u8,
            key_len: usize,
            fault_eligible: i32,
            out_len: *mut usize,
        ) -> i32;
        pub fn custom_op_replay_result(out: *mut u8, out_cap: usize) -> i32;
        pub fn custom_op_record(result: *const u8, result_len: usize) -> i32;
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

    // The SDK restates the verdict ABI numbering instead of depending on
    // `patina-dst-abi` (zero-dependency default), so pin the values here too:
    // this test and `patina_dst_abi`'s twin fail together if either side drifts.
    #[test]
    fn verdict_kind_abi_numbering_matches_the_shim_header() {
        assert_eq!(super::VerdictKind::Violation.as_abi(), 1);
        assert_eq!(super::VerdictKind::Pass.as_abi(), 2);
        assert_eq!(super::VerdictKind::AbortIntent.as_abi(), 3);
    }

    #[test]
    fn verdict_is_a_no_op_outside_patina() {
        super::verdict(super::VerdictKind::Violation, "outside-verdict", "{}");
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
