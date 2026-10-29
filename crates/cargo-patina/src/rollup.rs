//! Shared hierarchical rollups for inventory-style reports.
//!
//! The rollup contract is intentionally independent of `sites`: callers provide
//! attributed leaves (crate/module plus a bucket name such as `driven` or
//! `covered`) and receive deterministic crate→module summaries. Coverage-depth reuses this module with edge buckets rather than
//! growing a parallel grouping implementation.

use std::collections::BTreeMap;

/// One leaf that can be grouped into the shared hierarchy.
pub(crate) trait RollupLeaf {
    /// Cargo package / crate display name.
    fn crate_name(&self) -> &str;
    /// Rust module path used for drill-down (`crate::module::path`).
    fn module(&self) -> &str;
    /// Bucket name counted in every summary (for sites this is runtime class).
    fn bucket(&self) -> &str;
    /// Whether this leaf contributes to the caller's gap counter.
    fn is_gap(&self) -> bool {
        false
    }
}

/// A deterministic, summary-first hierarchy over a set of leaves.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Rollup {
    pub(crate) total: usize,
    pub(crate) by_bucket: BTreeMap<String, usize>,
    pub(crate) gaps: usize,
    pub(crate) crates: Vec<CrateRollup>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CrateRollup {
    pub(crate) name: String,
    pub(crate) total: usize,
    pub(crate) by_bucket: BTreeMap<String, usize>,
    pub(crate) gaps: usize,
    pub(crate) modules: Vec<ModuleRollup>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ModuleRollup {
    pub(crate) module: String,
    pub(crate) total: usize,
    pub(crate) by_bucket: BTreeMap<String, usize>,
    pub(crate) gaps: usize,
}

#[derive(Default)]
struct Counts {
    total: usize,
    by_bucket: BTreeMap<String, usize>,
    gaps: usize,
}

impl Counts {
    fn add(&mut self, bucket: &str, gap: bool) {
        self.total += 1;
        *self.by_bucket.entry(bucket.to_string()).or_insert(0) += 1;
        if gap {
            self.gaps += 1;
        }
    }

    fn with_all_buckets(mut self, bucket_order: &[&str]) -> Self {
        for bucket in bucket_order {
            self.by_bucket.entry((*bucket).to_string()).or_insert(0);
        }
        self
    }
}

/// Build the crate→module hierarchy. `bucket_order` names buckets that
/// should appear with zero counts even when absent, keeping JSON and human tables
/// stable across small scopes.
pub(crate) fn build_rollup<T: RollupLeaf>(leaves: &[T], bucket_order: &[&str]) -> Rollup {
    let mut totals = Counts::default();
    let mut crates: BTreeMap<String, Counts> = BTreeMap::new();
    let mut modules: BTreeMap<(String, String), Counts> = BTreeMap::new();

    for leaf in leaves {
        let bucket = leaf.bucket();
        let gap = leaf.is_gap();
        totals.add(bucket, gap);
        crates
            .entry(leaf.crate_name().to_string())
            .or_default()
            .add(bucket, gap);
        modules
            .entry((leaf.crate_name().to_string(), leaf.module().to_string()))
            .or_default()
            .add(bucket, gap);
    }

    let mut modules_by_crate: BTreeMap<String, Vec<ModuleRollup>> = BTreeMap::new();
    for ((crate_name, module), counts) in modules {
        let counts = counts.with_all_buckets(bucket_order);
        modules_by_crate
            .entry(crate_name)
            .or_default()
            .push(ModuleRollup {
                module,
                total: counts.total,
                by_bucket: counts.by_bucket,
                gaps: counts.gaps,
            });
    }

    let crates = crates
        .into_iter()
        .map(|(name, counts)| {
            let counts = counts.with_all_buckets(bucket_order);
            let mut modules = modules_by_crate.remove(&name).unwrap_or_default();
            modules.sort_by(|left, right| left.module.cmp(&right.module));
            CrateRollup {
                name,
                total: counts.total,
                by_bucket: counts.by_bucket,
                gaps: counts.gaps,
                modules,
            }
        })
        .collect();

    let totals = totals.with_all_buckets(bucket_order);
    Rollup {
        total: totals.total,
        by_bucket: totals.by_bucket,
        gaps: totals.gaps,
        crates,
    }
}
