//! Patina's SDK for Rust: state invariants, mark rare paths, and expose fault points to a
//! [Patina] run.
//!
//! Every call goes through one reserved system call that the Patina runtime answers. Outside
//! Patina the kernel answers `ENOSYS`; the first call learns that, and from then on every macro
//! is a load and a branch. There are no dependencies and no build flags, and on any target but
//! Linux x86_64 and aarch64 the crate compiles to the inert path, so code ships it
//! unconditionally. It works in `no_std`. The feature `compute` (off by default) adds the
//! hooks of compute points: see the module `compute`.
//!
//! ```
//! fn commit(ledger: &mut Vec<u64>, entry: u64) {
//!     // A rare path, taken on seed-chosen evaluations under `patina run --buggify`.
//!     if patina_dst::buggify!("batch-commit") && !ledger.is_empty() {
//!         ledger.insert(ledger.len() - 1, entry);
//!     } else {
//!         ledger.push(entry);
//!     }
//!     patina_dst::always!(ledger.is_sorted(), "ledger-sorted", "after {entry}");
//!     patina_dst::sometimes!(ledger.len() > 4, "ledger-grew");
//! }
//! let mut l = vec![];
//! for e in 0..8 {
//!     commit(&mut l, e);
//! }
//! assert!(!patina_dst::is_simulated());
//! ```
//!
//! - [`always!`]: an invariant. Under Patina a failure ends the run with outcome `violation`
//!   and the message `label: detail`; the detail is formatted only on failure.
//!   [`unreachable!`] marks a point that must not be reached: reaching it is a violation,
//!   and a sweep does not list it as unmet when no run reaches it. [`violation`] is a failed
//!   `always` with a label computed at run time.
//! - [`sometimes!`], [`reachable!`]: coverage oracles, reported per run and folded by a sweep.
//! - [`buggify!`]: a fault point. False unless the run has
//!   `--buggify`; then a point is active in a quarter of runs and an active point fires on a
//!   quarter of its evaluations, decided from the seed and the label alone. `--fault
//!   buggify:LABEL=PERMILLE` forces one point's rate (`0`: off).
//! - [`buggify_knob!`]: a seed-chosen integer in a range; [`buggify_delay!`]: maybe sleep a
//!   seeded virtual time.
//! - [`mark!`] names a point in the run's log; [`setup_complete`] marks the end of setup (with
//!   `faults-after-setup`, no fault fires before it). [`is_simulated`].
//!
//! # Labels and sites
//!
//! A macro's label is a compile-time `&str` (a literal, a `const`, `concat!`). Each expansion
//! is a site: it keeps one static byte, so a passing assertion traps only the first time it is
//! evaluated (a `sometimes!` also the first time it holds), and it places a record in the ELF
//! section `patina_sites`, which the runtime reads before the program starts, so a site that
//! is never reached is still reported. Sites with one label and kind are one row of the run's
//! table, however many expansions share it. A check that runs for many dynamic instances keeps
//! one label and puts the instance in the detail ([`always_family!`]).
//!
//! [Patina]: https://github.com/JacobHayes/patina
#![no_std]

#[doc(hidden)]
pub mod __rt {
    pub use crate::sys::*;
}
mod sys;

#[cfg(feature = "compute")]
pub mod compute;

pub use sys::{is_simulated, mark as mark_label};

/// A control call in a run with several machines, e.g. `control("net cut a b")`: `Err` holds
/// the errno Patina answered (`EPERM` outside the driver's node, `ENOENT` for an unknown node,
/// `EINVAL` for other words, `EALREADY` or `EAGAIN` for a node in the wrong state), or `ENOSYS`
/// outside Patina.
/// The words are those of `patina ctl` (`sdk/c/patina.h` in the Patina repository).
pub fn control(words: &str) -> Result<(), i32> {
    sys::control(words)
}

/// Mark the end of setup: with `faults-after-setup`, no fault fires before this call.
pub fn setup_complete() {
    sys::mark("setup-complete");
}

/// Report a failed invariant under a label computed at run time. The label is not declared
/// ahead, so prefer [`always!`] with a literal label.
pub fn violation(label: &str, detail: &str) {
    sys::violation(label, detail);
}

#[doc(hidden)]
#[macro_export]
macro_rules! __site {
    ($kind:expr, $label:expr) => {
        const __PATINA_LABEL: &str = $label;
        const __PATINA_LOC: &str = ::core::concat!(::core::file!(), ":", ::core::line!());
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        const _: () = {
            #[used]
            #[unsafe(link_section = "patina_sites")]
            static __PATINA_REC: $crate::__rt::Rec<
                { __PATINA_LABEL.len() },
                { $crate::__rt::loc_len(__PATINA_LOC) },
            > = $crate::__rt::Rec::new($kind, __PATINA_LABEL, __PATINA_LOC);
        };
    };
}

/// Assert an invariant: `always!(cond, "label")` or `always!(cond, "label", "fmt", args..)`.
/// Under Patina a false `cond` ends the run as `violation` with `label: detail`.
///
/// ```
/// let balance = 10;
/// patina_dst::always!(balance >= 0, "balance-non-negative", "balance {balance}");
/// ```
#[macro_export]
macro_rules! always {
    ($cond:expr, $label:expr $(,)?) => {
        $crate::always!($cond, $label, "")
    };
    ($cond:expr, $label:expr, $($detail:tt)+) => {{
        $crate::__site!($crate::__rt::KIND_ALWAYS, $label);
        static __PATINA_SITE: $crate::__rt::Site = $crate::__rt::Site::new();
        __PATINA_SITE.always($cond, __PATINA_LABEL, |w| {
            let _ = ::core::fmt::Write::write_fmt(w, ::core::format_args!($($detail)+));
        })
    }};
}

/// This point must not be reached: reaching it ends the run as `violation` with
/// `label: detail`, as a failed [`always!`] does. Unlike an `always` that no run evaluates, an
/// `unreachable` that no run reaches is not reported as unmet.
///
/// ```
/// fn parse(b: u8) -> u8 {
///     match b {
///         0..=127 => b,
///         _ => {
///             patina_dst::unreachable!("high-byte", "byte {b}");
///             0
///         }
///     }
/// }
/// assert_eq!(parse(5), 5);
/// ```
#[macro_export]
macro_rules! unreachable {
    ($label:expr $(,)?) => {
        $crate::unreachable!($label, "")
    };
    ($label:expr, $($detail:tt)+) => {{
        $crate::__site!($crate::__rt::KIND_UNREACHABLE, $label);
        static __PATINA_SITE: $crate::__rt::Site = $crate::__rt::Site::new();
        __PATINA_SITE.unreachable(__PATINA_LABEL, |w| {
            let _ = ::core::fmt::Write::write_fmt(w, ::core::format_args!($($detail)+));
        })
    }};
}

/// Coverage: `cond` should hold on some runs.
///
/// ```
/// let hit = [7].contains(&7);
/// patina_dst::sometimes!(hit, "cache-hit");
/// ```
#[macro_export]
macro_rules! sometimes {
    ($cond:expr, $label:expr $(,)?) => {{
        $crate::__site!($crate::__rt::KIND_SOMETIMES, $label);
        static __PATINA_SITE: $crate::__rt::Site = $crate::__rt::Site::new();
        __PATINA_SITE.sometimes($cond, __PATINA_LABEL)
    }};
}

/// Coverage: this point should be reached on some runs.
///
/// ```
/// patina_dst::reachable!("recovery-ran");
/// ```
#[macro_export]
macro_rules! reachable {
    ($label:expr $(,)?) => {{
        $crate::__site!($crate::__rt::KIND_REACHABLE, $label);
        static __PATINA_SITE: $crate::__rt::Site = $crate::__rt::Site::new();
        __PATINA_SITE.reachable(__PATINA_LABEL)
    }};
}

/// A fault point: true on seed-chosen evaluations of a run with `--buggify`, else false. It
/// takes a path the real system can take there (a short write, an error, an early flush).
///
/// ```
/// let n = if patina_dst::buggify!("short-write") { 1 } else { 3 };
/// assert_eq!(n, 3);
/// ```
#[macro_export]
macro_rules! buggify {
    ($label:expr $(,)?) => {{
        $crate::__site!($crate::__rt::KIND_BUGGIFY, $label);
        static __PATINA_SITE: $crate::__rt::Site = $crate::__rt::Site::new();
        __PATINA_SITE.point(false, __PATINA_LABEL, -1)
    }};
}

/// A tunable: `default` outside Patina or without `--buggify`; with it, an active point's value
/// is a seed-chosen `i64` in `[lo, hi]`, fixed for the run.
///
/// ```
/// let batch = patina_dst::buggify_knob!("batch-size", 64, 1, 1024);
/// assert_eq!(batch, 64);
/// ```
#[macro_export]
macro_rules! buggify_knob {
    ($label:expr, $default:expr, $lo:expr, $hi:expr $(,)?) => {{
        $crate::__site!($crate::__rt::KIND_KNOB, $label);
        $crate::__rt::knob(__PATINA_LABEL, $default, $lo, $hi)
    }};
}

/// Maybe sleep a seeded virtual time (never a real one): between 1 ms and 5 s, or up to `max`
/// (a `Duration`). Returns whether it slept.
///
/// ```
/// assert!(!patina_dst::buggify_delay!("pre-heartbeat-stall"));
/// ```
#[macro_export]
macro_rules! buggify_delay {
    ($label:expr $(,)?) => {
        $crate::buggify_delay!(@ $label, 0)
    };
    ($label:expr, $max:expr $(,)?) => {
        $crate::buggify_delay!(@ $label, $crate::__rt::nanos($max))
    };
    (@ $label:expr, $ns:expr) => {{
        $crate::__site!($crate::__rt::KIND_DELAY, $label);
        static __PATINA_SITE: $crate::__rt::Site = $crate::__rt::Site::new();
        __PATINA_SITE.point(true, __PATINA_LABEL, $ns)
    }};
}

/// A named point in the run's log (any `&str`, not declared ahead).
///
/// ```
/// patina_dst::mark!("workload-started");
/// ```
#[macro_export]
macro_rules! mark {
    ($label:expr $(,)?) => {
        $crate::mark_label($label)
    };
}

/// A declared `always!` site that many callers share; see [`always_family!`].
pub struct AlwaysFamily {
    label: &'static str,
    site: sys::Site,
}

/// A declared `sometimes!` site that many callers share; see [`sometimes_family!`].
pub struct SometimesFamily {
    label: &'static str,
    site: sys::Site,
}

/// A declared `reachable!` site that many callers share; see [`reachable_family!`].
pub struct ReachableFamily {
    label: &'static str,
    site: sys::Site,
}

impl AlwaysFamily {
    #[doc(hidden)]
    pub const fn new(label: &'static str) -> Self {
        Self {
            label,
            site: sys::Site::new(),
        }
    }
    /// Assert `cond` for one instance; `detail` names it and is formatted only on failure.
    pub fn check(&self, cond: bool, detail: impl core::fmt::Display) {
        self.site.always(cond, self.label, |w| {
            let _ = core::fmt::Write::write_fmt(w, format_args!("{detail}"));
        });
    }
}

impl SometimesFamily {
    #[doc(hidden)]
    pub const fn new(label: &'static str) -> Self {
        Self {
            label,
            site: sys::Site::new(),
        }
    }
    pub fn check(&self, cond: bool) {
        self.site.sometimes(cond, self.label);
    }
}

impl ReachableFamily {
    #[doc(hidden)]
    pub const fn new(label: &'static str) -> Self {
        Self {
            label,
            site: sys::Site::new(),
        }
    }
    pub fn hit(&self) {
        self.site.reachable(self.label);
    }
}

macro_rules! family_macros {
    ($d:tt; $($name:ident, $ty:ident, $kind:ident;)*) => {$(
        #[doc = concat!("Declare a [`", stringify!($ty), "`]: one literal-label site for any number of callers.")]
        ///
        /// ```
        /// patina_dst::always_family!(SHARD_BALANCED, "shard-balanced");
        /// SHARD_BALANCED.check(10 >= 0, format_args!("shard={}", 3));
        /// ```
        #[macro_export]
        macro_rules! $name {
            ($d vis:vis $d id:ident, $d label:expr $d(,)?) => {
                $d vis static $d id: $d crate::$ty = {
                    $d crate::__site!($d crate::__rt::$kind, $d label);
                    $d crate::$ty::new(__PATINA_LABEL)
                };
            };
        }
    )*};
}

family_macros! { $;
    always_family, AlwaysFamily, KIND_ALWAYS;
    sometimes_family, SometimesFamily, KIND_SOMETIMES;
    reachable_family, ReachableFamily, KIND_REACHABLE;
}
