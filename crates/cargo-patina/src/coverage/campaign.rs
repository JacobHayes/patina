//! Campaign coverage accumulation and persistence.

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoverageArtifact {
    pub(crate) path: String,
    pub(crate) sha256: String,
}

impl CoverageArtifact {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "path": self.path.clone(),
            "sha256": self.sha256.clone(),
        })
    }

    pub(crate) fn from_json(value: &Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "coverage artifact must be an object".to_string())?;
        let artifact = Self {
            path: json_required_str(object, "path")?.to_string(),
            sha256: json_required_str(object, "sha256")?.to_string(),
        };
        if artifact.to_json() != *value {
            return Err("coverage artifact is not in canonical lossless form".to_string());
        }
        Ok(artifact)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CampaignCoverageMeta {
    pub(crate) artifact: CoverageArtifact,
    pub(crate) fingerprint: String,
    pub(crate) edges_total: u64,
    pub(crate) ranges: Vec<CovmapRange>,
    pub(crate) edges_covered: u64,
    pub(crate) generations_applied: u64,
    pub(crate) last_new_edge_gen: Option<u64>,
    pub(crate) plateau_window: u64,
    pub(crate) plateaued: bool,
    pub(crate) new_edge_log: Vec<(u64, u64)>,
}

impl CampaignCoverageMeta {
    fn new(
        artifact: CoverageArtifact,
        fingerprint: String,
        covmap: &Covmap,
        plateau_window: u64,
    ) -> Self {
        Self {
            artifact,
            fingerprint,
            edges_total: covmap.guard_count,
            ranges: covmap.ranges.clone(),
            edges_covered: 0,
            generations_applied: 0,
            last_new_edge_gen: None,
            plateau_window,
            plateaued: false,
            new_edge_log: Vec::new(),
        }
    }

    pub(crate) fn covered_permille(&self) -> u64 {
        permille(self.edges_covered, self.edges_total)
    }

    fn update_plateau(&mut self, generation: u64) {
        self.plateaued = self.plateau_window != 0
            && self
                .last_new_edge_gen
                .is_some_and(|last| generation.saturating_sub(last) >= self.plateau_window);
    }

    pub(crate) fn to_json(&self) -> Value {
        json!({
            "schema": CAMPAIGN_COVERAGE_SCHEMA,
            "artifact": self.artifact.to_json(),
            "fingerprint": self.fingerprint.clone(),
            "edges_total": self.edges_total,
            "ranges": self.ranges.iter().map(CovmapRange::to_json).collect::<Vec<_>>(),
            "edges_covered": self.edges_covered,
            "covered_permille": self.covered_permille(),
            "generations_applied": self.generations_applied,
            "last_new_edge_gen": self.last_new_edge_gen,
            "plateau_window": self.plateau_window,
            "plateaued": self.plateaued,
            "new_edge_log": self.new_edge_log.iter().map(|(generation, new_edges)| json!([generation, new_edges])).collect::<Vec<_>>(),
        })
    }

    fn from_json(value: &Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "campaign coverage meta must be an object".to_string())?;
        let schema = json_required_str(object, "schema")?;
        if schema != CAMPAIGN_COVERAGE_SCHEMA {
            return Err(format!("unsupported schema {schema:?}"));
        }
        let ranges = object
            .get("ranges")
            .and_then(Value::as_array)
            .ok_or_else(|| "ranges must be an array".to_string())?
            .iter()
            .map(CovmapRange::from_json)
            .collect::<Result<Vec<_>, _>>()?;
        let new_edge_log = object
            .get("new_edge_log")
            .and_then(Value::as_array)
            .ok_or_else(|| "new_edge_log must be an array".to_string())?
            .iter()
            .map(|entry| {
                let values = entry
                    .as_array()
                    .ok_or_else(|| "new_edge_log entries must be arrays".to_string())?;
                if values.len() != 2 {
                    return Err("new_edge_log entries must have two elements".to_string());
                }
                Ok((
                    values[0].as_u64().ok_or_else(|| {
                        "new_edge_log generation must be an unsigned integer".to_string()
                    })?,
                    values[1].as_u64().ok_or_else(|| {
                        "new_edge_log new_edges must be an unsigned integer".to_string()
                    })?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let meta = Self {
            artifact: CoverageArtifact::from_json(
                object
                    .get("artifact")
                    .ok_or_else(|| "campaign coverage meta missing artifact".to_string())?,
            )?,
            fingerprint: json_required_str(object, "fingerprint")?.to_string(),
            edges_total: json_required_u64(object, "edges_total")?,
            ranges,
            edges_covered: json_required_u64(object, "edges_covered")?,
            generations_applied: json_required_u64(object, "generations_applied")?,
            last_new_edge_gen: json_optional_u64(object, "last_new_edge_gen")?,
            plateau_window: json_required_u64(object, "plateau_window")?,
            plateaued: json_required_bool(object, "plateaued")?,
            new_edge_log,
        };
        meta.validate()?;
        if meta.to_json() != *value {
            return Err("campaign coverage meta is not in canonical lossless form".to_string());
        }
        Ok(meta)
    }

    fn validate(&self) -> Result<(), String> {
        if self.edges_covered > self.edges_total {
            return Err(format!(
                "edges_covered={} exceeds edges_total={}",
                self.edges_covered, self.edges_total
            ));
        }
        let mut guard_offset = 0u64;
        let mut pc_offset = 0u64;
        for range in &self.ranges {
            if range.guard_offset != guard_offset || range.pc_offset != pc_offset {
                return Err(format!(
                    "coverage range table is not contiguous at guard_offset={} pc_offset={}; expected guards={} pcs={}",
                    range.guard_offset, range.pc_offset, guard_offset, pc_offset
                ));
            }
            if range.guard_count != range.pc_count {
                return Err(format!(
                    "coverage range table has guard_count={} but pc_count={}",
                    range.guard_count, range.pc_count
                ));
            }
            guard_offset = guard_offset
                .checked_add(range.guard_count)
                .ok_or_else(|| "coverage range guard count overflows u64".to_string())?;
            pc_offset = pc_offset
                .checked_add(range.pc_count)
                .ok_or_else(|| "coverage range pc count overflows u64".to_string())?;
        }
        if guard_offset != self.edges_total || pc_offset != self.edges_total {
            return Err(format!(
                "coverage range table covers guards={guard_offset} pcs={pc_offset}, expected edges_total={}",
                self.edges_total
            ));
        }
        if let Some(last) = self.last_new_edge_gen
            && last >= self.generations_applied
        {
            return Err(format!(
                "last_new_edge_gen={last} is not below generations_applied={}",
                self.generations_applied
            ));
        }
        let mut previous = None;
        for (generation, new_edges) in &self.new_edge_log {
            if *new_edges == 0 {
                return Err(format!(
                    "new_edge_log generation {generation} records zero new edges"
                ));
            }
            if *generation >= self.generations_applied {
                return Err(format!(
                    "new_edge_log generation {generation} is beyond generations_applied={}",
                    self.generations_applied
                ));
            }
            if previous.is_some_and(|old| *generation <= old) {
                return Err("new_edge_log generations must be strictly increasing".to_string());
            }
            previous = Some(*generation);
        }
        if self.new_edge_log.last().map(|(generation, _)| *generation) != self.last_new_edge_gen {
            return Err(
                "last_new_edge_gen must match the final new_edge_log generation".to_string(),
            );
        }
        let expected_plateaued = self.plateau_window != 0
            && self.last_new_edge_gen.is_some_and(|last| {
                self.generations_applied
                    .saturating_sub(1)
                    .saturating_sub(last)
                    >= self.plateau_window
            });
        if self.generations_applied == 0 {
            if self.plateaued {
                return Err("empty coverage state cannot be plateaued".to_string());
            }
        } else if self.plateaued != expected_plateaued {
            return Err(format!(
                "plateaued={} does not match plateau_window={} last_new_edge_gen={:?} generations_applied={}",
                self.plateaued,
                self.plateau_window,
                self.last_new_edge_gen,
                self.generations_applied
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FoldOutcome {
    pub(crate) generation: u64,
    pub(crate) new_edges: u64,
    /// Hit-count features this generation reached first (see [`hit_bucket`]).
    /// A newly covered edge is always a new feature too.
    pub(crate) new_features: u64,
    pub(crate) skipped_by_watermark: bool,
}

/// The AFL hit-count bucket of an edge counter: 1, 2, 3, 4-7, 8-15, 16-31,
/// 32-127, 128+ map to 0..=7, and an unhit edge has none.
///
/// A (edge, bucket) pair is one coverage FEATURE. Novelty is reaching a feature
/// for the first time, so a run that takes a covered loop or retry path more
/// often than any run before it is novel even though it covers no new edge:
/// threshold logic (count >= N, the k-th retry) gets a gradient instead of a
/// single step.
pub(crate) fn hit_bucket(count: u32) -> Option<u8> {
    match count {
        0 => None,
        1 => Some(0),
        2 => Some(1),
        3 => Some(2),
        4..=7 => Some(3),
        8..=15 => Some(4),
        16..=31 => Some(5),
        32..=127 => Some(6),
        _ => Some(7),
    }
}

/// The buckets per edge, and so the stride of a feature id (`edge * 8 + bucket`).
const BUCKETS: u64 = 8;

/// A feature and the generation that first reached it. The store keeps these
/// in generation order, so the coverage state as of any generation boundary
/// is a prefix: that is what keeps guidance rewindable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FeatureRecord {
    pub(crate) generation: u64,
    pub(crate) feature: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct CampaignCoverageStore {
    dir: PathBuf,
    artifact: CoverageArtifact,
    fingerprint: String,
    plateau_window: u64,
    meta: Option<CampaignCoverageMeta>,
    union_bits: Vec<u8>,
    /// Per edge, a bitmask of the hit-count buckets any generation reached.
    /// Derived from `features`, which is what is persisted.
    reached: Vec<u8>,
    /// Every feature ever reached, in first-reached order.
    features: Vec<FeatureRecord>,
    pub(super) hits: Vec<u64>,
    sites: Vec<i64>,
    /// Watermark floor contributed by generations that produced NO coverage map
    /// before the store had ever seen one (see
    /// [`Self::note_generation_without_covmap`]). In-memory only: once any
    /// generation folds a real map the floor is absorbed into the persisted
    /// `generations_applied`, and a `--resume` reads the watermark from there.
    skipped_watermark: u64,
}

impl CampaignCoverageStore {
    pub(crate) fn fresh(
        dir: PathBuf,
        artifact: CoverageArtifact,
        fingerprint: String,
        plateau_window: u64,
    ) -> Self {
        Self {
            dir,
            artifact,
            fingerprint,
            plateau_window,
            meta: None,
            union_bits: Vec::new(),
            reached: Vec::new(),
            features: Vec::new(),
            hits: Vec::new(),
            sites: Vec::new(),
            skipped_watermark: 0,
        }
    }

    pub(crate) fn load(
        dir: PathBuf,
        artifact: CoverageArtifact,
        fingerprint: String,
        plateau_window: u64,
        campaign_generations_done: u64,
    ) -> Result<Self, CliError> {
        let meta_path = dir.join("meta.json");
        if !meta_path.exists() {
            if campaign_generations_done == 0 {
                return Ok(Self::fresh(dir, artifact, fingerprint, plateau_window));
            }
            return Err(CliError(format!(
                "campaign out-dir is missing native coverage store {} for {} already-recorded generations; refusing to resume partially",
                meta_path.display(),
                campaign_generations_done
            )));
        }
        let meta = read_campaign_meta(&meta_path)?;
        if meta.artifact != artifact {
            return Err(CliError(format!(
                "coverage state artifact identity mismatch: meta records {} sha256 {}, campaign records {} sha256 {}; start a new out-dir for the new build",
                meta.artifact.path, meta.artifact.sha256, artifact.path, artifact.sha256,
            )));
        }
        if meta.fingerprint != fingerprint {
            return Err(CliError(format!(
                "coverage state fingerprint mismatch: meta records {} but this campaign expects {}; coverage bitsets from different binaries/policies cannot be unioned",
                meta.fingerprint, fingerprint
            )));
        }
        if meta.plateau_window != plateau_window {
            return Err(CliError(format!(
                "coverage state plateau_window {} does not match campaign spec {}; start a new out-dir to change --plateau-after",
                meta.plateau_window, plateau_window
            )));
        }
        validate_resume_watermark(
            "coverage state",
            "generations_applied",
            meta.generations_applied,
            campaign_generations_done,
            "per-generation covmaps are transient, so refusing to resume with missing coverage folds",
        )?;
        let edge_count = usize::try_from(meta.edges_total).map_err(|_| {
            CliError(format!(
                "coverage state edge count {} does not fit this host",
                meta.edges_total
            ))
        })?;
        let union_bits = read_exact_len(
            &dir.join("union.bits"),
            bit_len(edge_count),
            "coverage union bitset",
        )?;
        let hits_bytes = read_exact_len(
            &dir.join("hits.u64le"),
            edge_count.checked_mul(8).ok_or_else(|| {
                CliError("coverage hit-sum array is too large for this host".into())
            })?,
            "coverage hit-sum array",
        )?;
        let sites_bytes = read_exact_len(
            &dir.join("sites.i64le"),
            edge_count.checked_mul(8).ok_or_else(|| {
                CliError("coverage site-delta array is too large for this host".into())
            })?,
            "coverage site-delta array",
        )?;
        let hits = decode_u64_vec(&hits_bytes);
        let sites = decode_i64_vec(&sites_bytes);
        let covered = count_bits(&union_bits, edge_count) as u64;
        if covered != meta.edges_covered {
            return Err(CliError(format!(
                "coverage state union.bits covers {covered} edges but meta.json records {}; refusing corrupt out-dir",
                meta.edges_covered
            )));
        }
        let features_path = dir.join("features.u64le");
        let features_bytes = fs::read(&features_path).map_err(|error| {
            CliError(format!(
                "failed to read coverage feature log {}: {error}",
                features_path.display()
            ))
        })?;
        let (features, reached) = decode_features(&features_bytes, &meta, &union_bits, edge_count)
            .map_err(|error| {
                CliError(format!(
                    "coverage feature log {} is corrupt: {error}; refusing corrupt out-dir",
                    features_path.display()
                ))
            })?;
        Ok(Self {
            dir,
            artifact,
            fingerprint,
            plateau_window,
            meta: Some(meta),
            union_bits,
            reached,
            features,
            hits,
            sites,
            skipped_watermark: 0,
        })
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    pub(crate) fn meta(&self) -> Option<&CampaignCoverageMeta> {
        self.meta.as_ref()
    }

    /// The novelty log as guidance ancestors: each generation that reached at
    /// least one feature first, weighted by how many it reached.
    pub(crate) fn novelty_log(&self) -> Vec<crate::guided::NoveltyEntry> {
        let mut log: Vec<crate::guided::NoveltyEntry> = Vec::new();
        for record in &self.features {
            match log.last_mut() {
                Some(entry) if entry.generation == record.generation => entry.weight += 1,
                _ => log.push(crate::guided::NoveltyEntry {
                    generation: record.generation,
                    weight: 1,
                }),
            }
        }
        log
    }

    /// The features first reached by generations below `generation`: the
    /// store's reach state rewound to that generation boundary.
    #[cfg(test)]
    pub(crate) fn features_below(&self, generation: u64) -> &[FeatureRecord] {
        let cut = self
            .features
            .partition_point(|record| record.generation < generation);
        &self.features[..cut]
    }

    pub(crate) fn generation_covmap_path(&self, generation: u64) -> PathBuf {
        self.dir.join(format!("gen-{generation}.covmap"))
    }

    pub(crate) fn fold_decision(&self, generation: u64) -> Result<AuxFoldDecision, CliError> {
        fold_decision(
            "coverage state",
            "generations_applied",
            self.watermark(),
            generation,
        )
    }

    /// How many generations this store has processed: the persisted count, or —
    /// before any real map has been folded — the floor left by generations that
    /// were killed before they could write one.
    fn watermark(&self) -> u64 {
        self.meta
            .as_ref()
            .map_or(0, |meta| meta.generations_applied)
            .max(self.skipped_watermark)
    }

    pub(crate) fn fold_covmap(
        &mut self,
        generation: u64,
        covmap: &Covmap,
    ) -> Result<FoldOutcome, CliError> {
        if self.meta.is_none() {
            self.initialize(covmap)?;
            // Generations that were killed before they could write a map still
            // count as processed; absorb their floor so the very first REAL fold
            // is not read as a non-sequential gap.
            let floor = self.skipped_watermark;
            let meta = self.meta.as_mut().expect("initialized above");
            meta.generations_applied = meta.generations_applied.max(floor);
            // The floor is now persisted; do not double-count it.
            self.skipped_watermark = 0;
        }
        if self.fold_decision(generation)? == AuxFoldDecision::SkipAlreadyApplied {
            return Ok(FoldOutcome {
                generation,
                new_edges: 0,
                new_features: 0,
                skipped_by_watermark: true,
            });
        }
        let meta = self.meta.as_mut().expect("initialized above");
        validate_covmap_compatible(meta, &self.sites, covmap)?;
        let mut new_edges = 0u64;
        let mut new_features = 0u64;
        for (index, &counter) in covmap.counters.iter().enumerate() {
            self.hits[index] = self.hits[index].saturating_add(u64::from(counter));
            let Some(bucket) = hit_bucket(counter) else {
                continue;
            };
            if !bit_is_set(&self.union_bits, index) {
                set_bit(&mut self.union_bits, index);
                new_edges += 1;
            }
            let mask = 1u8 << bucket;
            if self.reached[index] & mask == 0 {
                self.reached[index] |= mask;
                self.features.push(FeatureRecord {
                    generation,
                    feature: index as u64 * BUCKETS + u64::from(bucket),
                });
                new_features += 1;
            }
        }
        if new_edges > 0 {
            meta.edges_covered += new_edges;
            meta.last_new_edge_gen = Some(generation);
            meta.new_edge_log.push((generation, new_edges));
        }
        meta.generations_applied = generation + 1;
        meta.update_plateau(generation);
        Ok(FoldOutcome {
            generation,
            new_edges,
            new_features,
            skipped_by_watermark: false,
        })
    }

    pub(crate) fn write_checkpoint(&self) -> Result<(), CliError> {
        let Some(meta) = &self.meta else {
            return Ok(());
        };
        meta.validate().map_err(|error| {
            CliError(format!("refusing to write invalid coverage meta: {error}"))
        })?;
        atomic_write(
            &self.dir.join("union.bits"),
            &self.union_bits,
            "coverage union bitset",
        )?;
        atomic_write(
            &self.dir.join("features.u64le"),
            &encode_features(&self.features),
            "coverage feature log",
        )?;
        atomic_write(
            &self.dir.join("hits.u64le"),
            &encode_u64_vec(&self.hits),
            "coverage hit-sum array",
        )?;
        atomic_write(
            &self.dir.join("sites.i64le"),
            &encode_i64_vec(&self.sites),
            "coverage site-delta array",
        )?;
        atomic_write_json(
            &self.dir.join("meta.json"),
            &meta.to_json(),
            "coverage meta",
        )
    }

    /// Record that `generation` contributed no coverage map, advancing the
    /// watermark so the store's sequential-accumulation invariant still holds.
    ///
    /// A generation the supervisor KILLED — a `--timeout-secs` kill, a
    /// guest that died on a signal — never reaches
    /// the shim's shutdown dump, so it has no map and never will. Without this
    /// the next generation's fold reads as a gap and fails the whole campaign,
    /// which would make coverage and a timed-out generation mutually exclusive in
    /// practice.
    /// Skipping is not the same as folding nothing: no edge is claimed and the
    /// plateau window still advances, so a long run of killed generations is
    /// correctly reported as a plateau rather than as progress.
    pub(crate) fn note_generation_without_covmap(&mut self, generation: u64) {
        let next = generation.saturating_add(1);
        match self.meta.as_mut() {
            Some(meta) => {
                if next > meta.generations_applied {
                    meta.generations_applied = next;
                    meta.update_plateau(generation);
                }
            }
            // No map has ever been folded, so there is no meta to advance yet;
            // remember the floor for the first real fold to absorb.
            None => self.skipped_watermark = self.skipped_watermark.max(next),
        }
    }

    fn initialize(&mut self, covmap: &Covmap) -> Result<(), CliError> {
        let edge_count = usize::try_from(covmap.guard_count).map_err(|_| {
            CliError(format!(
                "coverage map edge count {} does not fit this host",
                covmap.guard_count
            ))
        })?;
        self.meta = Some(CampaignCoverageMeta::new(
            self.artifact.clone(),
            self.fingerprint.clone(),
            covmap,
            self.plateau_window,
        ));
        self.union_bits = vec![0; bit_len(edge_count)];
        self.reached = vec![0; edge_count];
        self.features = Vec::new();
        self.hits = vec![0; edge_count];
        self.sites = covmap.deltas.clone();
        Ok(())
    }

    pub(super) fn as_coverage_data(&self) -> Option<CoverageData> {
        let meta = self.meta.as_ref()?;
        Some(CoverageData {
            input_kind: "campaign",
            artifact: Some(meta.artifact.clone()),
            edges_total: meta.edges_total,
            edges_covered: meta.edges_covered,
            covered_permille: meta.covered_permille(),
            hits_total: self
                .hits
                .iter()
                .fold(0u64, |total, hits| total.saturating_add(*hits)),
            hits_max: self.hits.iter().copied().max().unwrap_or(0),
            saturated: self.hits.iter().filter(|&&hits| hits == u64::MAX).count() as u64,
            ranges: meta.ranges.clone(),
            hits: self.hits.clone(),
            deltas: self.sites.clone(),
            generations_applied: Some(meta.generations_applied),
            last_new_edge_gen: meta.last_new_edge_gen,
            plateau_window: Some(meta.plateau_window),
            plateaued: Some(meta.plateaued),
            new_edge_log: meta.new_edge_log.clone(),
        })
    }
}

fn validate_covmap_compatible(
    meta: &CampaignCoverageMeta,
    sites: &[i64],
    covmap: &Covmap,
) -> Result<(), CliError> {
    if covmap.guard_count != meta.edges_total {
        return Err(CliError(format!(
            "coverage map edge count {} does not match campaign coverage state {}; refusing to accumulate different binaries",
            covmap.guard_count, meta.edges_total
        )));
    }
    if covmap.ranges != meta.ranges {
        return Err(CliError(
            "coverage map guard-range table does not match campaign coverage state; refusing to accumulate different binaries".into(),
        ));
    }
    if covmap.deltas != sites {
        return Err(CliError(
            "coverage map site-delta table does not match campaign coverage state; refusing to accumulate different binaries".into(),
        ));
    }
    Ok(())
}

pub(super) fn read_campaign_meta(path: &Path) -> Result<CampaignCoverageMeta, CliError> {
    let text = fs::read_to_string(path).map_err(|error| {
        CliError(format!(
            "failed to read campaign coverage meta {}: {error}",
            path.display()
        ))
    })?;
    let json: Value = serde_json::from_str(&text).map_err(|error| {
        CliError(format!(
            "campaign coverage meta {} is invalid JSON: {error}",
            path.display()
        ))
    })?;
    CampaignCoverageMeta::from_json(&json).map_err(|error| {
        CliError(format!(
            "campaign coverage meta {} is corrupt: {error}; refusing to resume partially",
            path.display()
        ))
    })
}

fn encode_features(features: &[FeatureRecord]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(features.len() * 16);
    for record in features {
        bytes.extend_from_slice(&record.generation.to_le_bytes());
        bytes.extend_from_slice(&record.feature.to_le_bytes());
    }
    bytes
}

/// Decode the feature log and rebuild the per-edge reached masks, checking it
/// against the rest of the store: generation order, no repeats, every
/// generation already applied, and the edges it covers matching `union.bits`
/// and the meta's per-generation new-edge log.
fn decode_features(
    bytes: &[u8],
    meta: &CampaignCoverageMeta,
    union_bits: &[u8],
    edge_count: usize,
) -> Result<(Vec<FeatureRecord>, Vec<u8>), String> {
    if bytes.len() % 16 != 0 {
        return Err(format!(
            "{} bytes is not a whole number of records",
            bytes.len()
        ));
    }
    let words = decode_u64_vec(bytes);
    let mut reached = vec![0u8; edge_count];
    let mut features = Vec::with_capacity(words.len() / 2);
    let mut first_reach: BTreeMap<u64, u64> = BTreeMap::new();
    for pair in words.chunks_exact(2) {
        let record = FeatureRecord {
            generation: pair[0],
            feature: pair[1],
        };
        if features
            .last()
            .is_some_and(|last: &FeatureRecord| record.generation < last.generation)
        {
            return Err("records are not in generation order".to_string());
        }
        if record.generation >= meta.generations_applied {
            return Err(format!(
                "generation {} is beyond generations_applied={}",
                record.generation, meta.generations_applied
            ));
        }
        let edge = usize::try_from(record.feature / BUCKETS)
            .ok()
            .filter(|&edge| edge < edge_count)
            .ok_or_else(|| format!("feature {} is outside the edge table", record.feature))?;
        let mask = 1u8 << (record.feature % BUCKETS);
        if reached[edge] & mask != 0 {
            return Err(format!("feature {} is recorded twice", record.feature));
        }
        if reached[edge] == 0 {
            *first_reach.entry(record.generation).or_default() += 1;
        }
        reached[edge] |= mask;
        features.push(record);
    }
    if (0..edge_count).any(|edge| (reached[edge] != 0) != bit_is_set(union_bits, edge)) {
        return Err("the edges it covers do not match union.bits".to_string());
    }
    if first_reach.into_iter().collect::<Vec<_>>() != meta.new_edge_log {
        return Err("its first-covered edges do not match new_edge_log".to_string());
    }
    Ok((features, reached))
}

pub(super) fn read_exact_len(
    path: &Path,
    expected_len: usize,
    label: &str,
) -> Result<Vec<u8>, CliError> {
    let bytes = fs::read(path).map_err(|error| {
        CliError(format!(
            "failed to read {label} {}: {error}",
            path.display()
        ))
    })?;
    if bytes.len() != expected_len {
        return Err(CliError(format!(
            "{label} {} has {} bytes; expected {expected_len}",
            path.display(),
            bytes.len()
        )));
    }
    Ok(bytes)
}

pub(super) fn bit_len(bits: usize) -> usize {
    bits.div_ceil(8)
}

fn bit_is_set(bytes: &[u8], index: usize) -> bool {
    let byte = bytes[index / 8];
    let mask = 1u8 << (index % 8);
    byte & mask != 0
}

fn set_bit(bytes: &mut [u8], index: usize) {
    let mask = 1u8 << (index % 8);
    bytes[index / 8] |= mask;
}

pub(super) fn count_bits(bytes: &[u8], edge_count: usize) -> usize {
    (0..edge_count)
        .filter(|&index| bit_is_set(bytes, index))
        .count()
}

pub(super) fn decode_u64_vec(bytes: &[u8]) -> Vec<u64> {
    bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|chunk| u64::from_le_bytes(*chunk))
        .collect()
}

pub(super) fn decode_i64_vec(bytes: &[u8]) -> Vec<i64> {
    bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|chunk| i64::from_le_bytes(*chunk))
        .collect()
}

fn encode_u64_vec(values: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(values.len() * 8);
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn encode_i64_vec(values: &[i64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(values.len() * 8);
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

pub(crate) fn atomic_write_json(path: &Path, value: &Value, label: &str) -> Result<(), CliError> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|error| CliError(format!("failed to serialize {label}: {error}")))?;
    atomic_write(path, text.as_bytes(), label)
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8], label: &str) -> Result<(), CliError> {
    let parent = path
        .parent()
        .ok_or_else(|| CliError(format!("{label} path {} has no parent", path.display())))?;
    fs::create_dir_all(parent).map_err(|error| {
        CliError(format!(
            "failed to create {label} dir {}: {error}",
            parent.display()
        ))
    })?;
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("bin")
    ));
    {
        let mut file = File::create(&tmp).map_err(|error| {
            CliError(format!(
                "failed to create temporary {label} {}: {error}",
                tmp.display()
            ))
        })?;
        file.write_all(bytes).map_err(|error| {
            CliError(format!(
                "failed to write temporary {label} {}: {error}",
                tmp.display()
            ))
        })?;
        file.sync_all().map_err(|error| {
            CliError(format!(
                "failed to sync temporary {label} {}: {error}",
                tmp.display()
            ))
        })?;
    }
    fs::rename(&tmp, path).map_err(|error| {
        CliError(format!(
            "failed to atomically replace {label} {}: {error}",
            path.display()
        ))
    })
}

pub(crate) fn json_required_str<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} must be a string"))
}

pub(crate) fn json_required_u64(object: &Map<String, Value>, key: &str) -> Result<u64, String> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{key} must be an unsigned integer"))
}

pub(crate) fn json_optional_u64(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<u64>, String> {
    match object.get(key) {
        Some(Value::Null) | None => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("{key} must be an unsigned integer or null")),
    }
}

pub(crate) fn json_required_bool(object: &Map<String, Value>, key: &str) -> Result<bool, String> {
    object
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{key} must be a boolean"))
}

#[cfg(test)]
mod tests;
