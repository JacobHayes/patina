//! Shared campaign auxiliary-store resume contract.
//!
//! Campaign-owned auxiliary stores (`sites.json` and `coverage/`) persist folds
//! that are intentionally outside `campaign-state.json`. They all expose a
//! monotonically increasing generation watermark. On resume, the watermark may be
//! exactly the campaign cursor or one generation ahead when a checkpoint tear
//! happened after the aux store was written but before `campaign-state.json` was
//! renamed. Anything else is an inconsistent out-dir.

use crate::CliError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuxFoldDecision {
    Apply,
    SkipAlreadyApplied,
}

/// How an auxiliary store's watermark disagrees with the campaign cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WatermarkMismatch {
    /// The store lost folds the campaign state already counts.
    Behind,
    /// The store is more than one checkpoint-tear generation ahead.
    TooFarAhead,
}

/// The watermark rule: exactly the cursor, or one generation ahead.
pub(crate) fn check_watermark(
    watermark: u64,
    campaign_cursor: u64,
) -> Result<(), WatermarkMismatch> {
    if watermark < campaign_cursor {
        return Err(WatermarkMismatch::Behind);
    }
    if watermark > campaign_cursor.saturating_add(1) {
        return Err(WatermarkMismatch::TooFarAhead);
    }
    Ok(())
}

/// Validate an auxiliary store's persisted generation watermark against the
/// campaign-state cursor loaded for a resume/extend invocation.
pub(crate) fn validate_resume_watermark(
    store_label: &str,
    watermark_label: &str,
    watermark: u64,
    campaign_cursor: u64,
    behind_detail: &str,
) -> Result<(), CliError> {
    check_watermark(watermark, campaign_cursor).map_err(|mismatch| match mismatch {
        WatermarkMismatch::Behind => CliError(format!(
            "{store_label} {watermark_label} is {watermark} but campaign-state cursor is {campaign_cursor}; {behind_detail}"
        )),
        WatermarkMismatch::TooFarAhead => CliError(format!(
            "{store_label} {watermark_label} is {watermark} but campaign-state cursor is {campaign_cursor}; expected the cursor or at most one checkpoint-tear generation ahead; refusing inconsistent out-dir"
        )),
    })
}

/// Decide whether a generation's contribution should be folded into an aux
/// store whose current watermark is `watermark`.
///
/// The helper is intentionally the only place that implements the skip rule: a
/// generation below the watermark was already folded by an interrupted writer and
/// must not be folded again, the generation equal to the watermark is next in the
/// sequence, and a generation beyond the watermark is a non-sequential gap.
pub(crate) fn fold_decision(
    store_label: &str,
    watermark_label: &str,
    watermark: u64,
    generation: u64,
) -> Result<AuxFoldDecision, CliError> {
    if generation < watermark {
        return Ok(AuxFoldDecision::SkipAlreadyApplied);
    }
    if generation == watermark {
        return Ok(AuxFoldDecision::Apply);
    }
    Err(CliError(format!(
        "{store_label} fold gap: generation {generation} is beyond {watermark_label} {watermark}; refusing non-sequential accumulation"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_watermark_may_equal_or_lead_the_cursor_by_one_generation() {
        assert_eq!(check_watermark(3, 3), Ok(()));
        assert_eq!(check_watermark(4, 3), Ok(()));
        assert_eq!(check_watermark(2, 3), Err(WatermarkMismatch::Behind));
        assert_eq!(check_watermark(5, 3), Err(WatermarkMismatch::TooFarAhead));
        assert_eq!(check_watermark(u64::MAX, u64::MAX), Ok(()));
    }
}
