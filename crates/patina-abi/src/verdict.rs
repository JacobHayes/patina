//! Guest verdict kinds and their stable ABI and trace names.

use serde::{Deserialize, Serialize};

/// What a guest asserts about its own run through the verdict ABI — the single
/// verb `patina_verdict` (native shim) / the `patina_sdk` `verdict` import
/// (WASI) / `Context::verdict` (in-process).
///
/// A **closed** enum owned by the runtime: kinds are data, never new symbols, so
/// a new kind is one enum value the compiler walks to every consumer. The `u32`
/// wire values are the ABI and are pinned by test; the C header
/// (`patina_native.h`) and the SDK's mirror of it must agree with
/// [`VerdictKind::as_abi`].
///
/// A verdict `label` shares the `sites.json` label namespace with the SDK's
/// `sometimes!`/`buggify!` site labels and aggregates the same way, but a
/// verdict is *not* a buggify site: it registers no site, so the duplicate-label
/// gate does not apply to it and the same label may be reported many times in
/// one run (that is what aggregation means). Reusing a *site's* label for a
/// verdict is legal and deliberate — it joins the two views of one invariant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictKind {
    /// The guest detected a violation of its own invariant.
    Violation,
    /// The guest confirmed a property held.
    Pass,
    /// The guest is about to abort deliberately, on its own invariant — so the
    /// resulting SIGABRT is attributable to the guest and not to a Patina
    /// fail-closed refusal.
    AbortIntent,
}

impl VerdictKind {
    /// Every kind, in wire order. Exhaustive by construction: a new variant that
    /// is not added here fails [`VerdictKind::as_abi`]'s round-trip test.
    pub const ALL: &'static [VerdictKind] = &[
        VerdictKind::Violation,
        VerdictKind::Pass,
        VerdictKind::AbortIntent,
    ];

    /// The `u32` this kind travels as across the C / WASI ABI. Numbering starts
    /// at 1 so a zeroed argument is never a valid kind and fails closed.
    pub const fn as_abi(self) -> u32 {
        match self {
            VerdictKind::Violation => 1,
            VerdictKind::Pass => 2,
            VerdictKind::AbortIntent => 3,
        }
    }

    /// Decode an ABI `u32`. `None` for any unknown value — the embedder refuses
    /// the call rather than guessing a kind.
    pub const fn from_abi(value: u32) -> Option<Self> {
        match value {
            1 => Some(VerdictKind::Violation),
            2 => Some(VerdictKind::Pass),
            3 => Some(VerdictKind::AbortIntent),
            _ => None,
        }
    }

    /// The stable snake_case name used in the trace, the `PATINA_VERDICT` marker
    /// line, and the result envelope.
    pub const fn as_str(self) -> &'static str {
        match self {
            VerdictKind::Violation => "violation",
            VerdictKind::Pass => "pass",
            VerdictKind::AbortIntent => "abort_intent",
        }
    }

    /// Parse the name [`VerdictKind::as_str`] renders. `None` is a hard parse
    /// failure for the caller, never a default kind.
    pub fn from_name(text: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.as_str() == text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The ABI numbering is the contract three independent mirrors compile
    // against (the C header, the SDK's `extern "C"` block, the WASI import), so
    // pin the exact values: a renumber here silently misclassifies every verdict
    // a shim-linked guest reports.
    #[test]
    fn verdict_kind_abi_values_are_pinned_and_round_trip() {
        assert_eq!(VerdictKind::Violation.as_abi(), 1);
        assert_eq!(VerdictKind::Pass.as_abi(), 2);
        assert_eq!(VerdictKind::AbortIntent.as_abi(), 3);
        assert_eq!(VerdictKind::from_abi(0), None);
        assert_eq!(VerdictKind::from_abi(4), None);
        for kind in VerdictKind::ALL {
            assert_eq!(VerdictKind::from_abi(kind.as_abi()), Some(*kind));
            assert_eq!(VerdictKind::from_name(kind.as_str()), Some(*kind));
        }
        assert_eq!(VerdictKind::from_name("violation!"), None);
    }
}
