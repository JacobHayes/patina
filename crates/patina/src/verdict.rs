//! Structured guest verdicts and their ABI numbering.

#[cfg(patina_shim)]
use crate::ffi;
#[cfg(all(patina, not(patina_shim), target_arch = "wasm32"))]
use crate::wasm_ffi;
#[cfg(doc)]
use crate::{buggify, sometimes};

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

#[cfg(test)]
mod tests {
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
}
