//! One declaration generates the SDK site macros and their recognition metadata.

/// Internal metadata shared with cargo-patina's source recognizer.
#[doc(hidden)]
pub struct SdkSiteMacro {
    pub name: &'static str,
    pub kind: &'static str,
    pub runtime: &'static str,
    pub label_index: usize,
    /// A valid literal-label guest invocation for product checks.
    pub fixture: &'static str,
}

// The dollar token lets this generator declare the inner macros' metavariables
// on stable Rust. Literal-label arms always emit a descriptor before the call;
// expression-label arms keep the existing runtime-only registration behavior.
macro_rules! declare_site_macros {
    ($d:tt; $(
        $(#[$doc:meta])*
        $name:ident ($descriptor:ident, $kind:literal, $runtime:literal)
        [$($before:ident = $before_sample:expr),*]
        [$($after:ident = $after_sample:expr => $convert:ident),*]
        => $call:ident [$($tail:expr),*];
    )*) => {
        #[doc(hidden)]
        pub const SDK_SITE_MACROS: &[SdkSiteMacro] = &[
            $(SdkSiteMacro {
                name: stringify!($name),
                kind: $kind,
                runtime: $runtime,
                label_index: (&[$(stringify!($before)),*] as &[&str]).len(),
                fixture: concat!(
                    stringify!($name), "!(",
                    $(stringify!($before_sample), ",",)*
                    "\"registry-", stringify!($name), "\"",
                    $(",", stringify!($after_sample),)* ")"
                ),
            },)*
        ];
        $(
            $(#[$doc])*
            #[macro_export]
            macro_rules! $name {
                ($($d $before:expr,)* $d label:literal $(, $d $after:expr)*) => {{
                    $d crate::__patina_static_site!(
                        $d label,
                        ::core::concat!(::core::file!(), ":", ::core::line!()),
                        $d crate::__rt::$descriptor
                    );
                    $d crate::__rt::$call(
                        $($d $before,)* $d label,
                        ::core::concat!(::core::file!(), ":", ::core::line!()),
                        $($d crate::__rt::$convert($d $after),)* $($tail),*
                    )
                }};
                ($($d $before:expr,)* $d label:expr $(, $d $after:expr)*) => {
                    $d crate::__rt::$call(
                        $($d $before,)* $d label,
                        ::core::concat!(::core::file!(), ":", ::core::line!()),
                        $($d crate::__rt::$convert($d $after),)* $($tail),*
                    )
                };
            }
        )*
    };
}

declare_site_macros! { $;
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
buggify (STATIC_SITE_KIND_FAULT, "fault", "driven")
    [] [] => buggify [-1];

/// Like [`buggify!`] but with an explicit per-evaluation probability in `0.0..=1.0`,
/// overriding the run-default firing probability for this site.
///
/// ```
/// // Outside Patina this is always false, even at probability 1.0.
/// assert!(!patina_dst::buggify_with_prob!("aggressive-retry", 1.0));
/// ```
buggify_with_prob (STATIC_SITE_KIND_FAULT, "fault", "driven")
    [] [probability = 0.5 => prob_to_permille] => buggify [];

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
buggify_delay (STATIC_SITE_KIND_DELAY, "delay", "driven")
    [] [] => buggify_delay [];

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
buggify_knob (STATIC_SITE_KIND_KNOB, "knob", "driven")
    [] [default = 7_i64 => identity, lo = 1 => identity, hi = 10 => identity]
    => buggify_knob [];

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
always (STATIC_SITE_KIND_ALWAYS, "always", "observed")
    [condition = true] [] => always [];

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
sometimes (STATIC_SITE_KIND_SOMETIMES, "sometimes", "observed")
    [condition = true] [] => sometimes [];

/// Coverage oracle: record that this site was reached. The companion of
/// [`sometimes!`] for paths ("recovery ran", "compaction triggered") whose
/// mere execution is the interesting fact — no condition to evaluate.
/// No effect on control flow; a no-op outside Patina.
///
/// ```
/// patina_dst::reachable!("startup-recovery-path");
/// ```
reachable (STATIC_SITE_KIND_REACHABLE, "reachable", "observed")
    [] [] => reachable [];
}
