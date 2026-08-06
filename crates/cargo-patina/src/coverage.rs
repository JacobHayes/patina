//! Native yield-point coverage map parsing, campaign accumulation, and the
//! `cargo patina coverage` offline report verb.
//!
//! This is the single parser for `patina.covmap/v1`. `run --coverage-out`, the
//! campaign accumulator, and the read-only coverage verb all come through this
//! module so the binary format has one validation path.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use object::{Object, ObjectSymbol, SymbolKind};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::CliError;
use crate::aux_store::{AuxFoldDecision, fold_decision, validate_resume_watermark};
use crate::cli;
use crate::help;
use crate::output;
use crate::rollup::{Rollup, RollupLeaf, build_rollup};

const COVERAGE_MAP_MAGIC: &[u8; 16] = b"patina.covmap/v1";
const COVERAGE_MAP_VERSION: u32 = 1;

pub(crate) const CAMPAIGN_COVERAGE_SCHEMA: &str = "patina.coverage.campaign/v1";
const COVERAGE_ENVELOPE_SCHEMA: &str = "patina.coverage/v1";
const COVERED_BUCKETS: &[&str] = &["covered", "uncovered"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CovmapRange {
    pub(crate) guard_offset: u64,
    pub(crate) guard_count: u64,
    pub(crate) pc_offset: u64,
    pub(crate) pc_count: u64,
}

impl CovmapRange {
    fn to_json(&self) -> Value {
        json!({
            "guard_offset": self.guard_offset,
            "guard_count": self.guard_count,
            "pc_offset": self.pc_offset,
            "pc_count": self.pc_count,
        })
    }

    fn from_json(value: &Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "coverage range must be an object".to_string())?;
        let range = Self {
            guard_offset: json_required_u64(object, "guard_offset")?,
            guard_count: json_required_u64(object, "guard_count")?,
            pc_offset: json_required_u64(object, "pc_offset")?,
            pc_count: json_required_u64(object, "pc_count")?,
        };
        if range.to_json() != *value {
            return Err("coverage range is not in canonical lossless form".to_string());
        }
        Ok(range)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Covmap {
    pub(crate) guard_count: u64,
    pub(crate) ranges: Vec<CovmapRange>,
    pub(crate) counters: Vec<u32>,
    pub(crate) deltas: Vec<i64>,
}

impl Covmap {
    pub(crate) fn summary(&self, map_path: Option<PathBuf>) -> output::CoverageReport {
        let mut edges_covered = 0u64;
        let mut hits_total = 0u64;
        let mut hits_max = 0u32;
        let mut saturated = 0u64;
        for &hits in &self.counters {
            if hits != 0 {
                edges_covered += 1;
            }
            hits_total = hits_total.saturating_add(hits as u64);
            hits_max = hits_max.max(hits);
            if hits == u32::MAX {
                saturated += 1;
            }
        }
        let covered_permille = permille(edges_covered, self.guard_count);
        output::CoverageReport {
            edges_total: self.guard_count,
            edges_covered,
            covered_permille,
            hits_total,
            hits_max,
            saturated,
            map_path,
        }
    }

    fn as_coverage_data(&self, input_kind: &'static str) -> CoverageData {
        let summary = self.summary(None);
        CoverageData {
            input_kind,
            artifact: None,
            edges_total: summary.edges_total,
            edges_covered: summary.edges_covered,
            covered_permille: summary.covered_permille,
            hits_total: summary.hits_total,
            hits_max: u64::from(summary.hits_max),
            saturated: summary.saturated,
            ranges: self.ranges.clone(),
            hits: self.counters.iter().map(|&hits| u64::from(hits)).collect(),
            deltas: self.deltas.clone(),
            generations_applied: None,
            last_new_edge_gen: None,
            plateau_window: None,
            plateaued: None,
            new_edge_log: Vec::new(),
        }
    }
}

fn read_le_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, CliError> {
    let end = offset.saturating_add(4);
    let chunk = bytes
        .get(*offset..end)
        .ok_or_else(|| CliError("truncated patina.covmap/v1 u32 field".into()))?;
    *offset = end;
    Ok(u32::from_le_bytes(chunk.try_into().unwrap()))
}

fn read_le_i64(bytes: &[u8], offset: &mut usize) -> Result<i64, CliError> {
    let end = offset.saturating_add(8);
    let chunk = bytes
        .get(*offset..end)
        .ok_or_else(|| CliError("truncated patina.covmap/v1 i64 field".into()))?;
    *offset = end;
    Ok(i64::from_le_bytes(chunk.try_into().unwrap()))
}

fn read_le_u64(bytes: &[u8], offset: &mut usize) -> Result<u64, CliError> {
    let end = offset.saturating_add(8);
    let chunk = bytes
        .get(*offset..end)
        .ok_or_else(|| CliError("truncated patina.covmap/v1 u64 field".into()))?;
    *offset = end;
    Ok(u64::from_le_bytes(chunk.try_into().unwrap()))
}

fn checked_covmap_len(guard_count: usize, range_count: usize) -> Result<usize, CliError> {
    let header = COVERAGE_MAP_MAGIC.len() + 4 + 8 + 8;
    let ranges = range_count
        .checked_mul(32)
        .ok_or_else(|| CliError("patina.covmap/v1 range table is too large".into()))?;
    let counters = guard_count
        .checked_mul(4)
        .ok_or_else(|| CliError("patina.covmap/v1 counter array is too large".into()))?;
    let deltas = guard_count
        .checked_mul(8)
        .ok_or_else(|| CliError("patina.covmap/v1 pc-delta array is too large".into()))?;
    header
        .checked_add(ranges)
        .and_then(|len| len.checked_add(counters))
        .and_then(|len| len.checked_add(deltas))
        .ok_or_else(|| CliError("patina.covmap/v1 is too large".into()))
}

/// Read and validate a `patina.covmap/v1` file.
pub(crate) fn read_covmap(path: &Path) -> Result<Covmap, CliError> {
    let bytes = fs::read(path).map_err(|error| {
        CliError(format!(
            "failed to read coverage map {}: {error}",
            path.display()
        ))
    })?;
    parse_covmap_bytes(&bytes, path)
}

fn parse_covmap_bytes(bytes: &[u8], path: &Path) -> Result<Covmap, CliError> {
    let magic_end = COVERAGE_MAP_MAGIC.len();
    if bytes.get(..magic_end) != Some(COVERAGE_MAP_MAGIC.as_slice()) {
        return Err(CliError(format!(
            "coverage map {} is not patina.covmap/v1 (bad magic)",
            path.display()
        )));
    }
    let mut offset = magic_end;
    let version = read_le_u32(bytes, &mut offset)?;
    if version != COVERAGE_MAP_VERSION {
        return Err(CliError(format!(
            "coverage map {} has unsupported version {version}",
            path.display()
        )));
    }
    let guard_count_u64 = read_le_u64(bytes, &mut offset)?;
    let range_count_u64 = read_le_u64(bytes, &mut offset)?;
    let guard_count = usize::try_from(guard_count_u64).map_err(|_| {
        CliError(format!(
            "coverage map {} guard count {guard_count_u64} does not fit this host",
            path.display()
        ))
    })?;
    let range_count = usize::try_from(range_count_u64).map_err(|_| {
        CliError(format!(
            "coverage map {} range count {range_count_u64} does not fit this host",
            path.display()
        ))
    })?;
    let expected_len = checked_covmap_len(guard_count, range_count)?;
    if bytes.len() != expected_len {
        return Err(CliError(format!(
            "coverage map {} has {} bytes; expected {expected_len} for {guard_count} guards and {range_count} ranges",
            path.display(),
            bytes.len(),
        )));
    }

    let mut guard_offset = 0u64;
    let mut pc_offset = 0u64;
    let mut ranges = Vec::with_capacity(range_count);
    for index in 0..range_count {
        let range_guard_offset = read_le_u64(bytes, &mut offset)?;
        let range_guard_count = read_le_u64(bytes, &mut offset)?;
        let range_pc_offset = read_le_u64(bytes, &mut offset)?;
        let range_pc_count = read_le_u64(bytes, &mut offset)?;
        if range_guard_offset != guard_offset
            || range_pc_offset != pc_offset
            || range_guard_count != range_pc_count
        {
            return Err(CliError(format!(
                "coverage map {} range {index} is inconsistent: guard_offset={range_guard_offset} guard_count={range_guard_count} pc_offset={range_pc_offset} pc_count={range_pc_count}",
                path.display(),
            )));
        }
        ranges.push(CovmapRange {
            guard_offset: range_guard_offset,
            guard_count: range_guard_count,
            pc_offset: range_pc_offset,
            pc_count: range_pc_count,
        });
        guard_offset = guard_offset.saturating_add(range_guard_count);
        pc_offset = pc_offset.saturating_add(range_pc_count);
    }
    if guard_offset != guard_count_u64 || pc_offset != guard_count_u64 {
        return Err(CliError(format!(
            "coverage map {} range table covers guards={guard_offset} pcs={pc_offset}, expected {guard_count_u64}",
            path.display(),
        )));
    }

    let mut counters = Vec::with_capacity(guard_count);
    for _ in 0..guard_count {
        counters.push(read_le_u32(bytes, &mut offset)?);
    }
    let mut deltas = Vec::with_capacity(guard_count);
    for _ in 0..guard_count {
        deltas.push(read_le_i64(bytes, &mut offset)?);
    }
    if offset != bytes.len() {
        return Err(CliError(format!(
            "coverage map {} has trailing bytes after pc-delta array",
            path.display()
        )));
    }
    Ok(Covmap {
        guard_count: guard_count_u64,
        ranges,
        counters,
        deltas,
    })
}

pub(crate) fn coverage_summary_from_map(path: &Path) -> Result<output::CoverageReport, CliError> {
    Ok(read_covmap(path)?.summary(Some(path.to_path_buf())))
}

fn permille(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        ((numerator as u128 * 1000) / denominator as u128) as u64
    }
}

fn percent_string_permille(permille: u64) -> String {
    format!("{}.{:01}%", permille / 10, permille % 10)
}

fn percent_string(numerator: u64, denominator: u64) -> String {
    percent_string_permille(permille(numerator, denominator))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoverageArtifact {
    pub(crate) path: String,
    pub(crate) sha256: String,
    pub(crate) family: String,
}

impl CoverageArtifact {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "path": self.path.clone(),
            "sha256": self.sha256.clone(),
            "family": self.family.clone(),
        })
    }

    pub(crate) fn from_json(value: &Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "coverage artifact must be an object".to_string())?;
        let artifact = Self {
            path: json_required_str(object, "path")?.to_string(),
            sha256: json_required_str(object, "sha256")?.to_string(),
            family: json_required_str(object, "family")?.to_string(),
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
        if let Some(last) = self.last_new_edge_gen {
            if last >= self.generations_applied {
                return Err(format!(
                    "last_new_edge_gen={last} is not below generations_applied={}",
                    self.generations_applied
                ));
            }
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
    pub(crate) skipped_by_watermark: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct CampaignCoverageStore {
    dir: PathBuf,
    artifact: CoverageArtifact,
    fingerprint: String,
    plateau_window: u64,
    meta: Option<CampaignCoverageMeta>,
    union_bits: Vec<u8>,
    hits: Vec<u64>,
    sites: Vec<i64>,
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
            hits: Vec::new(),
            sites: Vec::new(),
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
                "coverage state artifact identity mismatch: meta records {} sha256 {} family {}, campaign records {} sha256 {} family {}; start a new out-dir for the new build",
                meta.artifact.path,
                meta.artifact.sha256,
                meta.artifact.family,
                artifact.path,
                artifact.sha256,
                artifact.family,
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
        Ok(Self {
            dir,
            artifact,
            fingerprint,
            plateau_window,
            meta: Some(meta),
            union_bits,
            hits,
            sites,
        })
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    pub(crate) fn meta(&self) -> Option<&CampaignCoverageMeta> {
        self.meta.as_ref()
    }

    /// The novelty log as guidance ancestors: each generation that turned at
    /// least one guard from unseen to seen, weighted by how many it opened.
    pub(crate) fn novelty_log(&self) -> Vec<crate::guided::NoveltyEntry> {
        self.meta
            .as_ref()
            .map(|meta| {
                meta.new_edge_log
                    .iter()
                    .map(|(generation, new_edges)| crate::guided::NoveltyEntry {
                        generation: *generation,
                        weight: *new_edges,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn generation_covmap_path(&self, generation: u64) -> PathBuf {
        self.dir.join(format!("gen-{generation}.covmap"))
    }

    pub(crate) fn fold_decision(&self, generation: u64) -> Result<AuxFoldDecision, CliError> {
        fold_decision(
            "coverage state",
            "generations_applied",
            self.meta
                .as_ref()
                .map_or(0, |meta| meta.generations_applied),
            generation,
        )
    }

    pub(crate) fn fold_covmap(
        &mut self,
        generation: u64,
        covmap: &Covmap,
    ) -> Result<FoldOutcome, CliError> {
        if self.meta.is_none() {
            self.initialize(covmap)?;
        }
        if self.fold_decision(generation)? == AuxFoldDecision::SkipAlreadyApplied {
            return Ok(FoldOutcome {
                generation,
                new_edges: 0,
                skipped_by_watermark: true,
            });
        }
        let meta = self.meta.as_mut().expect("initialized above");
        validate_covmap_compatible(meta, &self.sites, covmap)?;
        let mut new_edges = 0u64;
        for (index, &counter) in covmap.counters.iter().enumerate() {
            if counter != 0 && !bit_is_set(&self.union_bits, index) {
                set_bit(&mut self.union_bits, index);
                new_edges += 1;
            }
            self.hits[index] = self.hits[index].saturating_add(u64::from(counter));
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
        self.hits = vec![0; edge_count];
        self.sites = covmap.deltas.clone();
        Ok(())
    }

    fn as_coverage_data(&self) -> Option<CoverageData> {
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

fn read_campaign_meta(path: &Path) -> Result<CampaignCoverageMeta, CliError> {
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

fn read_exact_len(path: &Path, expected_len: usize, label: &str) -> Result<Vec<u8>, CliError> {
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

fn bit_len(bits: usize) -> usize {
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

fn count_bits(bytes: &[u8], edge_count: usize) -> usize {
    (0..edge_count)
        .filter(|&index| bit_is_set(bytes, index))
        .count()
}

fn decode_u64_vec(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
        .collect()
}

fn decode_i64_vec(bytes: &[u8]) -> Vec<i64> {
    bytes
        .chunks_exact(8)
        .map(|chunk| i64::from_le_bytes(chunk.try_into().unwrap()))
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CoverageOptions {
    focus: Option<String>,
    top: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoverageInvocation {
    binary: PathBuf,
    input: PathBuf,
    options: CoverageOptions,
}

/// Parse `coverage <BINARY> <MAP|CAMPAIGN-OUT-DIR> [--focus PATH] [--top N]`.
pub(crate) fn parse(arguments: Vec<OsString>) -> Result<CoverageInvocation, CliError> {
    let scan = crate::locate_positionals("coverage", &arguments, 2);
    if scan.positionals.len() != 2 {
        return Err(CliError::usage(
            "coverage requires a binary path and a coverage map or campaign out-dir",
        ));
    }
    let args = cli::parse("coverage", help::Family::Sole, scan.rest)?;
    Ok(CoverageInvocation {
        binary: PathBuf::from(&scan.positionals[0]),
        input: PathBuf::from(&scan.positionals[1]),
        options: CoverageOptions {
            focus: args.string("--focus"),
            top: args.usize("--top"),
        },
    })
}

pub(crate) fn execute(invocation: CoverageInvocation) -> Result<i32, CliError> {
    let data = load_coverage_input(&invocation.input)?;
    validate_coverage_binary(&invocation.binary, &data)?;
    let report = symbolize_coverage(&invocation.binary, &data)?;
    if output::options().is_json() {
        println!(
            "{}",
            serde_json::to_string_pretty(&coverage_json(&invocation, &data, &report))
                .map_err(|error| CliError(format!("failed to encode coverage JSON: {error}")))?
        );
    } else {
        print_coverage_human(&invocation, &data, &report);
    }
    Ok(0)
}

#[derive(Clone, Debug)]
struct CoverageData {
    input_kind: &'static str,
    artifact: Option<CoverageArtifact>,
    edges_total: u64,
    edges_covered: u64,
    covered_permille: u64,
    hits_total: u64,
    hits_max: u64,
    saturated: u64,
    ranges: Vec<CovmapRange>,
    hits: Vec<u64>,
    deltas: Vec<i64>,
    generations_applied: Option<u64>,
    last_new_edge_gen: Option<u64>,
    plateau_window: Option<u64>,
    plateaued: Option<bool>,
    new_edge_log: Vec<(u64, u64)>,
}

fn load_coverage_input(input: &Path) -> Result<CoverageData, CliError> {
    if input.is_file() {
        return Ok(read_covmap(input)?.as_coverage_data("covmap"));
    }
    if input.is_dir() {
        let coverage_dir = if input.join("meta.json").is_file() {
            input.to_path_buf()
        } else {
            input.join("coverage")
        };
        return load_campaign_coverage_data(&coverage_dir);
    }
    Err(CliError(format!(
        "coverage input {} is neither a covmap file nor a campaign out-dir",
        input.display()
    )))
}

fn validate_coverage_binary(binary: &Path, data: &CoverageData) -> Result<(), CliError> {
    let Some(artifact) = data.artifact.as_ref() else {
        return Ok(());
    };
    if artifact.family != "native" {
        return Err(CliError(format!(
            "coverage store records artifact family {} for {}; offline native coverage can only symbolize native artifacts",
            artifact.family, artifact.path
        )));
    }
    let bytes = fs::read(binary).map_err(|error| {
        CliError(format!(
            "failed to read coverage binary {} for campaign artifact identity check: {error}",
            binary.display()
        ))
    })?;
    let actual = sha256_hex(&bytes);
    if actual != artifact.sha256 {
        return Err(CliError(format!(
            "coverage store records artifact {} sha256 {} but coverage binary {} hashes {}; pass the same binary that produced the campaign coverage store",
            artifact.path,
            artifact.sha256,
            binary.display(),
            actual
        )));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn load_campaign_coverage_data(coverage_dir: &Path) -> Result<CoverageData, CliError> {
    let meta = read_campaign_meta(&coverage_dir.join("meta.json"))?;
    let edge_count = usize::try_from(meta.edges_total).map_err(|_| {
        CliError(format!(
            "coverage state edge count {} does not fit this host",
            meta.edges_total
        ))
    })?;
    let union_bits = read_exact_len(
        &coverage_dir.join("union.bits"),
        bit_len(edge_count),
        "coverage union bitset",
    )?;
    let hits_bytes = read_exact_len(
        &coverage_dir.join("hits.u64le"),
        edge_count
            .checked_mul(8)
            .ok_or_else(|| CliError("coverage hit-sum array is too large".into()))?,
        "coverage hit-sum array",
    )?;
    let sites_bytes = read_exact_len(
        &coverage_dir.join("sites.i64le"),
        edge_count
            .checked_mul(8)
            .ok_or_else(|| CliError("coverage site-delta array is too large".into()))?,
        "coverage site-delta array",
    )?;
    let hits = decode_u64_vec(&hits_bytes);
    let deltas = decode_i64_vec(&sites_bytes);
    let covered = count_bits(&union_bits, edge_count) as u64;
    if covered != meta.edges_covered {
        return Err(CliError(format!(
            "coverage union.bits covers {covered} edges but meta.json records {}; refusing corrupt coverage store",
            meta.edges_covered
        )));
    }
    Ok(CoverageData {
        input_kind: "campaign",
        artifact: Some(meta.artifact.clone()),
        edges_total: meta.edges_total,
        edges_covered: meta.edges_covered,
        covered_permille: meta.covered_permille(),
        hits_total: hits
            .iter()
            .fold(0u64, |total, hits| total.saturating_add(*hits)),
        hits_max: hits.iter().copied().max().unwrap_or(0),
        saturated: hits.iter().filter(|&&hits| hits == u64::MAX).count() as u64,
        ranges: meta.ranges,
        hits,
        deltas,
        generations_applied: Some(meta.generations_applied),
        last_new_edge_gen: meta.last_new_edge_gen,
        plateau_window: Some(meta.plateau_window),
        plateaued: Some(meta.plateaued),
        new_edge_log: meta.new_edge_log,
    })
}

#[derive(Clone, Debug)]
struct FunctionSymbol {
    address: u64,
    end: u64,
    symbol: String,
    demangled: String,
}

#[derive(Clone, Debug)]
struct SymbolTable {
    anchor: u64,
    functions: Vec<FunctionSymbol>,
}

fn read_symbol_table(binary: &Path) -> Result<SymbolTable, CliError> {
    let bytes = fs::read(binary).map_err(|error| {
        CliError(format!(
            "failed to read binary {} for coverage symbolization: {error}",
            binary.display()
        ))
    })?;
    let file = object::File::parse(&*bytes).map_err(|error| {
        CliError(format!(
            "failed to parse binary {} for coverage symbolization: {error}",
            binary.display()
        ))
    })?;
    let mut anchor = None;
    let mut functions = BTreeMap::<u64, FunctionSymbol>::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        let Ok(name) = symbol.name() else {
            continue;
        };
        let normalized = name.trim_start_matches('_');
        if normalized == "patina_yield_point" {
            anchor = Some(symbol.address());
        }
        if symbol.is_undefined() || symbol.kind() != SymbolKind::Text || symbol.address() == 0 {
            continue;
        }
        let demangled = demangle_symbol(name);
        let size = symbol.size();
        let address = symbol.address();
        let end = if size == 0 {
            address
        } else {
            address.saturating_add(size)
        };
        functions.entry(address).or_insert(FunctionSymbol {
            address,
            end,
            symbol: name.to_string(),
            demangled,
        });
    }
    let anchor = anchor.ok_or_else(|| {
        CliError(format!(
            "coverage symbolization could not find nm anchor symbol patina_yield_point in {}; is this a native --yield-points binary?",
            binary.display()
        ))
    })?;
    let mut functions: Vec<_> = functions.into_values().collect();
    functions.sort_by_key(|function| function.address);
    let addresses: Vec<u64> = functions.iter().map(|function| function.address).collect();
    for (index, function) in functions.iter_mut().enumerate() {
        if function.end <= function.address {
            if let Some(next) = addresses.get(index + 1).copied() {
                function.end = next;
            } else {
                function.end = u64::MAX;
            }
        }
    }
    Ok(SymbolTable { anchor, functions })
}

fn demangle_symbol(name: &str) -> String {
    if let Ok(demangled) = rustc_demangle::try_demangle(name) {
        return format!("{demangled:#}");
    }
    if let Some(stripped) = name.strip_prefix('_') {
        if let Ok(demangled) = rustc_demangle::try_demangle(stripped) {
            return format!("{demangled:#}");
        }
    }
    name.trim_start_matches('_').to_string()
}

impl SymbolTable {
    fn function_for_pc(&self, pc: u64) -> Option<&FunctionSymbol> {
        let index = self
            .functions
            .partition_point(|function| function.address <= pc);
        let function = self.functions.get(index.checked_sub(1)?)?;
        (pc < function.end).then_some(function)
    }
}

#[derive(Clone, Debug)]
struct EdgeAttribution {
    crate_name: String,
    module: String,
    covered: bool,
    groups: Vec<String>,
}

impl RollupLeaf for EdgeAttribution {
    fn crate_name(&self) -> &str {
        &self.crate_name
    }

    fn module(&self) -> &str {
        &self.module
    }

    fn groups(&self) -> &[String] {
        &self.groups
    }

    fn bucket(&self) -> &str {
        if self.covered { "covered" } else { "uncovered" }
    }

    fn is_gap(&self) -> bool {
        !self.covered
    }
}

#[derive(Clone, Debug, Default)]
struct CoverageStats {
    edges_total: u64,
    edges_covered: u64,
    hits_total: u64,
}

impl CoverageStats {
    fn add(&mut self, covered: bool, hits: u64) {
        self.edges_total += 1;
        if covered {
            self.edges_covered += 1;
        }
        self.hits_total = self.hits_total.saturating_add(hits);
    }

    fn covered_permille(&self) -> u64 {
        permille(self.edges_covered, self.edges_total)
    }
}

#[derive(Clone, Debug)]
struct CoverageReportTree {
    rollup: Rollup,
    crates: BTreeMap<String, CoverageStats>,
    modules: BTreeMap<(String, String), CoverageStats>,
    functions: BTreeMap<String, CoverageStats>,
}

fn symbolize_coverage(binary: &Path, data: &CoverageData) -> Result<CoverageReportTree, CliError> {
    if data.hits.len() != data.deltas.len() {
        return Err(CliError(format!(
            "coverage input has {} hit counters but {} site deltas",
            data.hits.len(),
            data.deltas.len()
        )));
    }
    let symbols = read_symbol_table(binary)?;
    let mut edges = Vec::with_capacity(data.hits.len());
    let mut crates = BTreeMap::<String, CoverageStats>::new();
    let mut modules = BTreeMap::<(String, String), CoverageStats>::new();
    let mut functions = BTreeMap::<String, CoverageStats>::new();
    for (index, (&hits, &delta)) in data.hits.iter().zip(&data.deltas).enumerate() {
        let covered = hits != 0;
        let (static_pc, function) = if delta == 0 && !covered {
            (None, None)
        } else {
            let pc_i128 = i128::from(symbols.anchor) + i128::from(delta);
            if !(0..=i128::from(u64::MAX)).contains(&pc_i128) {
                return Err(CliError(format!(
                    "coverage edge {index} static pc is out of range: anchor={} delta={delta}",
                    symbols.anchor
                )));
            }
            let pc = pc_i128 as u64;
            (Some(pc), symbols.function_for_pc(pc))
        };
        let (crate_name, module, function_path, symbol_name) = function.map_or_else(
            || {
                (
                    "<unknown>".to_string(),
                    "<unknown>".to_string(),
                    "<unknown>".to_string(),
                    "<unknown>".to_string(),
                )
            },
            |function| {
                let parsed = parse_symbol_path(&function.demangled);
                (
                    parsed.crate_name,
                    parsed.module,
                    parsed.function_path,
                    function.symbol.clone(),
                )
            },
        );
        crates
            .entry(crate_name.clone())
            .or_default()
            .add(covered, hits);
        modules
            .entry((crate_name.clone(), module.clone()))
            .or_default()
            .add(covered, hits);
        functions
            .entry(function_path.clone())
            .or_default()
            .add(covered, hits);
        let _ = (symbol_name, static_pc);
        edges.push(EdgeAttribution {
            crate_name,
            module,
            covered,
            groups: Vec::new(),
        });
    }
    let rollup = build_rollup(&edges, COVERED_BUCKETS);
    Ok(CoverageReportTree {
        rollup,
        crates,
        modules,
        functions,
    })
}

struct ParsedSymbolPath {
    crate_name: String,
    module: String,
    function_path: String,
}

fn parse_symbol_path(demangled: &str) -> ParsedSymbolPath {
    let cleaned = demangled
        .split("::h")
        .next()
        .unwrap_or(demangled)
        .trim()
        .to_string();
    let grouping_path = grouping_path_for_symbol(&cleaned);
    let parts: Vec<&str> = grouping_path
        .split("::")
        .map(|part| part.trim_matches(|c| c == '<' || c == '>' || c == '&' || c == '[' || c == ']'))
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        return ParsedSymbolPath {
            crate_name: "<unknown>".to_string(),
            module: "<unknown>".to_string(),
            function_path: cleaned,
        };
    }
    let crate_name = if parts.len() == 1 && primitive_type(parts[0]) {
        "core".to_string()
    } else {
        parts[0].to_string()
    };
    let module = if parts.len() <= 1 {
        crate_name.clone()
    } else {
        parts[..parts.len() - 1].join("::")
    };
    ParsedSymbolPath {
        crate_name,
        module,
        function_path: cleaned,
    }
}

fn primitive_type(part: &str) -> bool {
    matches!(
        part,
        "bool"
            | "char"
            | "str"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
    )
}

fn grouping_path_for_symbol(symbol: &str) -> &str {
    let symbol = symbol
        .trim_start_matches("&mut ")
        .trim_start_matches("mut ")
        .trim_start_matches("const ");
    if symbol.starts_with('[') || symbol.starts_with('*') {
        return "core";
    }
    let Some(inner) = symbol
        .strip_prefix('<')
        .and_then(|rest| rest.split('>').next())
    else {
        return symbol;
    };
    let inner = inner.trim();
    if let Some((left, right)) = inner.split_once(" as ") {
        let left = left.trim();
        if left.contains("::") && !left.starts_with('*') && left != "()" {
            return normalize_grouping_path(left);
        }
        return normalize_grouping_path(right.trim());
    }
    normalize_grouping_path(inner)
}

fn normalize_grouping_path(path: &str) -> &str {
    let path = path
        .trim_start_matches("&mut ")
        .trim_start_matches("mut ")
        .trim_start_matches("const ")
        .trim_start_matches('<')
        .trim_start();
    if path.starts_with('*') {
        return "core";
    }
    if let Some(stripped) = path.strip_prefix('[') {
        let stripped = stripped.trim_start_matches('&');
        if stripped.contains("::") {
            return stripped;
        }
        return "core";
    }
    path
}

fn coverage_json(
    invocation: &CoverageInvocation,
    data: &CoverageData,
    report: &CoverageReportTree,
) -> Value {
    json!({
        "schema": COVERAGE_ENVELOPE_SCHEMA,
        "verb": "coverage",
        "artifact": invocation.binary.display().to_string(),
        "input": invocation.input.display().to_string(),
        "input_kind": data.input_kind,
        "summary": coverage_summary_json(data),
        "rollup": rollup_json(report, data),
        "functions": functions_json(report, data),
        "focus": invocation.options.focus,
    })
}

fn coverage_summary_json(data: &CoverageData) -> Value {
    let mut object = Map::new();
    object.insert("edges_total".into(), data.edges_total.into());
    object.insert("edges_covered".into(), data.edges_covered.into());
    object.insert("covered_permille".into(), data.covered_permille.into());
    object.insert("hits_total".into(), data.hits_total.into());
    object.insert("hits_max".into(), data.hits_max.into());
    object.insert("saturated".into(), data.saturated.into());
    object.insert("range_count".into(), (data.ranges.len() as u64).into());
    if let Some(value) = data.generations_applied {
        object.insert("generations_applied".into(), value.into());
    }
    if let Some(value) = data.last_new_edge_gen {
        object.insert("last_new_edge_gen".into(), value.into());
    }
    if let Some(value) = data.plateau_window {
        object.insert("plateau_window".into(), value.into());
    }
    if let Some(value) = data.plateaued {
        object.insert("plateaued".into(), value.into());
    }
    if !data.new_edge_log.is_empty() {
        object.insert(
            "new_edge_log".into(),
            data.new_edge_log
                .iter()
                .map(|(generation, new_edges)| json!([generation, new_edges]))
                .collect::<Vec<_>>()
                .into(),
        );
    }
    Value::Object(object)
}

fn rollup_json(report: &CoverageReportTree, data: &CoverageData) -> Value {
    let crates = report
        .rollup
        .crates
        .iter()
        .map(|krate| {
            let stats = report.crates.get(&krate.name).cloned().unwrap_or_default();
            let modules = krate
                .modules
                .iter()
                .map(|module| {
                    let stats = report
                        .modules
                        .get(&(krate.name.clone(), module.module.clone()))
                        .cloned()
                        .unwrap_or_default();
                    json!({
                        "module": module.module,
                        "edges_total": stats.edges_total,
                        "edges_covered": stats.edges_covered,
                        "covered_permille": stats.covered_permille(),
                        "hits_total": stats.hits_total,
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "name": krate.name,
                "edges_total": stats.edges_total,
                "edges_covered": stats.edges_covered,
                "covered_permille": stats.covered_permille(),
                "hits_total": stats.hits_total,
                "hits_share_permille": permille(stats.hits_total, data.hits_total),
                "over_rep_permille": over_rep_permille(stats.edges_total, stats.hits_total, data.edges_total, data.hits_total),
                "by_edge_state": krate.by_bucket,
                "modules": modules,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "edges_total": data.edges_total,
        "by_edge_state": report.rollup.by_bucket,
        "crates": crates,
    })
}

fn functions_json(report: &CoverageReportTree, data: &CoverageData) -> Value {
    report
        .functions
        .iter()
        .map(|(function, stats)| {
            json!({
                "function": function,
                "edges_total": stats.edges_total,
                "edges_covered": stats.edges_covered,
                "covered_permille": stats.covered_permille(),
                "hits_total": stats.hits_total,
                "hits_share_permille": permille(stats.hits_total, data.hits_total),
            })
        })
        .collect::<Vec<_>>()
        .into()
}

fn over_rep_permille(edges: u64, hits: u64, total_edges: u64, total_hits: u64) -> u64 {
    if edges == 0 || total_edges == 0 || total_hits == 0 {
        return 0;
    }
    // (hits / total_hits) / (edges / total_edges) scaled by 1000.
    ((hits as u128 * total_edges as u128 * 1000) / (total_hits as u128 * edges as u128)) as u64
}

fn print_coverage_human(
    invocation: &CoverageInvocation,
    data: &CoverageData,
    report: &CoverageReportTree,
) {
    println!("== coverage ==");
    println!(
        "artifact={} input={} kind={}",
        invocation.binary.display(),
        invocation.input.display(),
        data.input_kind
    );
    println!(
        "edges={}/{} covered={} hits_total={} hits_max={} saturated={}",
        data.edges_covered,
        data.edges_total,
        percent_string_permille(data.covered_permille),
        data.hits_total,
        data.hits_max,
        data.saturated
    );
    if let Some(generations) = data.generations_applied {
        println!(
            "campaign_generations_applied={} last_new_edge_gen={} plateau_after={} plateaued={}",
            generations,
            data.last_new_edge_gen
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_string()),
            data.plateau_window.unwrap_or(0),
            data.plateaued.unwrap_or(false) as u8,
        );
    }
    println!("-- crates --");
    println!("crate edges pct hits_share over_rep");
    for krate in &report.rollup.crates {
        let stats = report.crates.get(&krate.name).cloned().unwrap_or_default();
        println!(
            "{} {}/{} {} {} {}x",
            krate.name,
            stats.edges_covered,
            stats.edges_total,
            percent_string_permille(stats.covered_permille()),
            percent_string(stats.hits_total, data.hits_total),
            ratio_string(over_rep_permille(
                stats.edges_total,
                stats.hits_total,
                data.edges_total,
                data.hits_total,
            )),
        );
    }
    if let Some(focus) = &invocation.options.focus {
        print_focus(focus, report);
    }
    if let Some(top) = invocation.options.top {
        print_top(top, report);
    }
}

fn ratio_string(permille: u64) -> String {
    format!("{}.{:03}", permille / 1000, permille % 1000)
}

fn print_focus(focus: &str, report: &CoverageReportTree) {
    println!("-- focus {focus} --");
    println!("path edges pct hits");
    for ((_, module), stats) in report
        .modules
        .iter()
        .filter(|((krate, module), _)| krate == focus || module.starts_with(focus))
    {
        println!(
            "{} {}/{} {} {}",
            module,
            stats.edges_covered,
            stats.edges_total,
            percent_string_permille(stats.covered_permille()),
            stats.hits_total,
        );
    }
    for (function, stats) in report
        .functions
        .iter()
        .filter(|(function, _)| function.starts_with(focus))
    {
        println!(
            "{} {}/{} {} {}",
            function,
            stats.edges_covered,
            stats.edges_total,
            percent_string_permille(stats.covered_permille()),
            stats.hits_total,
        );
    }
}

fn print_top(top: usize, report: &CoverageReportTree) {
    if top == 0 {
        return;
    }
    let mut functions: Vec<_> = report.functions.iter().collect();
    functions.sort_by(|(left_name, left), (right_name, right)| {
        right
            .hits_total
            .cmp(&left.hits_total)
            .then_with(|| right.edges_covered.cmp(&left.edges_covered))
            .then_with(|| left_name.cmp(right_name))
    });
    println!("-- top hot functions --");
    for (function, stats) in functions.iter().take(top) {
        println!(
            "{} hits={} edges={}/{} pct={}",
            function,
            stats.hits_total,
            stats.edges_covered,
            stats.edges_total,
            percent_string_permille(stats.covered_permille()),
        );
    }
    functions.sort_by(|(left_name, left), (right_name, right)| {
        left.edges_covered
            .cmp(&right.edges_covered)
            .then_with(|| right.edges_total.cmp(&left.edges_total))
            .then_with(|| left_name.cmp(right_name))
    });
    println!("-- top cold functions --");
    for (function, stats) in functions.iter().take(top) {
        println!(
            "{} hits={} edges={}/{} pct={}",
            function,
            stats.hits_total,
            stats.edges_covered,
            stats.edges_total,
            percent_string_permille(stats.covered_permille()),
        );
    }
}

pub(crate) fn top_uncovered_crates(
    binary: &Path,
    store: &CampaignCoverageStore,
    limit: usize,
) -> Result<Vec<(String, u64, u64)>, CliError> {
    let Some(data) = store.as_coverage_data() else {
        return Ok(Vec::new());
    };
    let report = symbolize_coverage(binary, &data)?;
    let mut rows: Vec<_> = report
        .crates
        .iter()
        .map(|(name, stats)| {
            (
                name.clone(),
                stats.edges_total.saturating_sub(stats.edges_covered),
                stats.edges_total,
            )
        })
        .filter(|(_, uncovered, _)| *uncovered > 0)
        .collect();
    rows.sort_by(|left, right| {
        right
            .1
            .cmp(&left.1)
            .then_with(|| right.2.cmp(&left.2))
            .then_with(|| left.0.cmp(&right.0))
    });
    rows.truncate(limit);
    Ok(rows)
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

pub(crate) fn campaign_detector_selftest() -> Vec<(&'static str, bool, String)> {
    vec![
        detector_fingerprint_mismatch(),
        detector_plateau_exactness(),
        detector_watermark_idempotency(),
    ]
}

fn synthetic_covmap(counters: &[u32], deltas: &[i64]) -> Covmap {
    assert_eq!(counters.len(), deltas.len());
    Covmap {
        guard_count: counters.len() as u64,
        ranges: vec![CovmapRange {
            guard_offset: 0,
            guard_count: counters.len() as u64,
            pc_offset: 0,
            pc_count: deltas.len() as u64,
        }],
        counters: counters.to_vec(),
        deltas: deltas.to_vec(),
    }
}

fn detector_fingerprint_mismatch() -> (&'static str, bool, String) {
    let result = (|| -> Result<String, CliError> {
        let temp = tempfile::tempdir()
            .map_err(|error| CliError(format!("failed to create tempdir: {error}")))?;
        let dir = temp.path().join("coverage");
        let artifact = CoverageArtifact {
            path: "guest".into(),
            sha256: "abc".into(),
            family: "native".into(),
        };
        let mut store = CampaignCoverageStore::fresh(
            dir.clone(),
            artifact.clone(),
            "patina-native+yieldpoints".into(),
            200,
        );
        store.fold_covmap(0, &synthetic_covmap(&[1], &[10]))?;
        store.write_checkpoint()?;
        let mut meta: Value = serde_json::from_str(
            &fs::read_to_string(dir.join("meta.json"))
                .map_err(|error| CliError(format!("failed to read meta: {error}")))?,
        )
        .map_err(|error| CliError(format!("failed to parse meta: {error}")))?;
        meta["fingerprint"] = "other".into();
        fs::write(
            dir.join("meta.json"),
            serde_json::to_string_pretty(&meta)
                .map_err(|error| CliError(format!("failed to encode meta: {error}")))?,
        )
        .map_err(|error| CliError(format!("failed to rewrite meta: {error}")))?;
        let error =
            CampaignCoverageStore::load(dir, artifact, "patina-native+yieldpoints".into(), 200, 1)
                .unwrap_err();
        Ok(error.0)
    })();
    match result {
        Ok(message) if message.contains("coverage state fingerprint mismatch") => (
            "coverage-fingerprint-mismatch-refuses",
            true,
            "loud mismatch".to_string(),
        ),
        Ok(message) => (
            "coverage-fingerprint-mismatch-refuses",
            false,
            format!("wrong error: {message}"),
        ),
        Err(error) => (
            "coverage-fingerprint-mismatch-refuses",
            false,
            error.to_string(),
        ),
    }
}

fn detector_plateau_exactness() -> (&'static str, bool, String) {
    let artifact = CoverageArtifact {
        path: "guest".into(),
        sha256: "abc".into(),
        family: "native".into(),
    };
    let first = synthetic_covmap(&[1, 0], &[10, 20]);
    let repeat = synthetic_covmap(&[1, 0], &[10, 20]);
    let mut store = CampaignCoverageStore::fresh(
        PathBuf::from("out/coverage"),
        artifact.clone(),
        "patina-native+yieldpoints".into(),
        2,
    );
    let ok = store.fold_covmap(0, &first).is_ok()
        && !store.meta().unwrap().plateaued
        && store.fold_covmap(1, &repeat).is_ok()
        && !store.meta().unwrap().plateaued
        && store.fold_covmap(2, &repeat).is_ok()
        && store.meta().unwrap().plateaued;
    let mut disabled = CampaignCoverageStore::fresh(
        PathBuf::from("out/coverage"),
        artifact,
        "patina-native+yieldpoints".into(),
        0,
    );
    let disabled_ok = disabled.fold_covmap(0, &first).is_ok()
        && disabled.fold_covmap(1, &repeat).is_ok()
        && disabled.fold_covmap(2, &repeat).is_ok()
        && !disabled.meta().unwrap().plateaued;
    (
        "coverage-plateau-exactness",
        ok && disabled_ok,
        "fires at N, not N-1; zero disables".to_string(),
    )
}

fn detector_watermark_idempotency() -> (&'static str, bool, String) {
    let mut store = CampaignCoverageStore::fresh(
        PathBuf::from("out/coverage"),
        CoverageArtifact {
            path: "guest".into(),
            sha256: "abc".into(),
            family: "native".into(),
        },
        "patina-native+yieldpoints".into(),
        200,
    );
    let covmap = synthetic_covmap(&[1, 2], &[10, 20]);
    let ok = store.fold_covmap(0, &covmap).is_ok();
    let hits = store.hits.clone();
    let skipped = store
        .fold_covmap(0, &covmap)
        .map(|outcome| outcome.skipped_by_watermark)
        .unwrap_or(false);
    (
        "coverage-watermark-idempotency",
        ok && skipped && store.hits == hits,
        "second fold skipped without hit double-count".to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_i64(bytes: &mut Vec<u8>, value: i64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn covmap_bytes(counters: &[u32], deltas: &[i64]) -> Vec<u8> {
        assert_eq!(counters.len(), deltas.len());
        let mut bytes = Vec::new();
        bytes.extend_from_slice(COVERAGE_MAP_MAGIC);
        push_u32(&mut bytes, COVERAGE_MAP_VERSION);
        push_u64(&mut bytes, counters.len() as u64);
        push_u64(&mut bytes, 1);
        push_u64(&mut bytes, 0);
        push_u64(&mut bytes, counters.len() as u64);
        push_u64(&mut bytes, 0);
        push_u64(&mut bytes, deltas.len() as u64);
        for counter in counters {
            push_u32(&mut bytes, *counter);
        }
        for delta in deltas {
            push_i64(&mut bytes, *delta);
        }
        bytes
    }

    #[test]
    fn covmap_parser_preserves_counters_and_deltas() {
        let path = Path::new("fixture.covmap");
        let map = parse_covmap_bytes(&covmap_bytes(&[0, 3, u32::MAX], &[-4, 8, 12]), path)
            .expect("valid covmap parses");
        assert_eq!(map.guard_count, 3);
        assert_eq!(map.counters, vec![0, 3, u32::MAX]);
        assert_eq!(map.deltas, vec![-4, 8, 12]);
        let summary = map.summary(None);
        assert_eq!(summary.edges_total, 3);
        assert_eq!(summary.edges_covered, 2);
        assert_eq!(summary.hits_total, u64::from(u32::MAX) + 3);
        assert_eq!(summary.saturated, 1);
    }

    #[test]
    fn covmap_parser_rejects_range_mismatch() {
        let mut bytes = covmap_bytes(&[1, 2], &[10, 20]);
        // Corrupt pc_count in the single range.
        let pc_count_offset = COVERAGE_MAP_MAGIC.len() + 4 + 8 + 8 + 8 + 8 + 8;
        bytes[pc_count_offset..pc_count_offset + 8].copy_from_slice(&1u64.to_le_bytes());
        let error = parse_covmap_bytes(&bytes, Path::new("bad.covmap")).unwrap_err();
        assert!(
            error.0.contains("range 0 is inconsistent"),
            "unexpected error: {}",
            error.0
        );
    }

    #[test]
    fn campaign_fold_is_watermark_idempotent() {
        let covmap = parse_covmap_bytes(&covmap_bytes(&[1, 2], &[10, 20]), Path::new("a"))
            .expect("valid covmap");
        let mut store = CampaignCoverageStore::fresh(
            PathBuf::from("out/coverage"),
            CoverageArtifact {
                path: "guest".into(),
                sha256: "abc".into(),
                family: "native".into(),
            },
            "patina-native+yieldpoints".into(),
            200,
        );
        let first = store.fold_covmap(0, &covmap).expect("first fold");
        assert_eq!(first.new_edges, 2);
        let hits_after_first = store.hits.clone();
        let second = store.fold_covmap(0, &covmap).expect("watermark skip");
        assert!(second.skipped_by_watermark);
        assert_eq!(
            store.hits, hits_after_first,
            "duplicate fold must not double-count hits"
        );
    }

    #[test]
    fn campaign_load_validates_resume_watermark() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("coverage");
        let artifact = CoverageArtifact {
            path: "guest".into(),
            sha256: "abc".into(),
            family: "native".into(),
        };
        let covmap = parse_covmap_bytes(&covmap_bytes(&[1], &[10]), Path::new("a")).unwrap();
        let mut store = CampaignCoverageStore::fresh(
            dir.clone(),
            artifact.clone(),
            "patina-native+yieldpoints".into(),
            200,
        );
        store.fold_covmap(0, &covmap).unwrap();
        store.write_checkpoint().unwrap();

        CampaignCoverageStore::load(
            dir.clone(),
            artifact.clone(),
            "patina-native+yieldpoints".into(),
            200,
            0,
        )
        .expect("one-generation tear ahead is resumable");
        let behind = CampaignCoverageStore::load(
            dir.clone(),
            artifact.clone(),
            "patina-native+yieldpoints".into(),
            200,
            2,
        )
        .unwrap_err();
        assert!(
            behind.0.contains("missing coverage folds"),
            "unexpected error: {behind}"
        );

        let meta_path = dir.join("meta.json");
        let mut meta: Value =
            serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
        meta["generations_applied"] = 3.into();
        fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();
        let ahead =
            CampaignCoverageStore::load(dir, artifact, "patina-native+yieldpoints".into(), 200, 1)
                .unwrap_err();
        assert!(
            ahead
                .0
                .contains("at most one checkpoint-tear generation ahead"),
            "unexpected error: {ahead}"
        );
    }

    #[test]
    fn campaign_meta_rejects_schema_and_edges_total_mismatch() {
        let covmap = parse_covmap_bytes(&covmap_bytes(&[1], &[10]), Path::new("a")).unwrap();
        let meta = CampaignCoverageMeta::new(
            CoverageArtifact {
                path: "guest".into(),
                sha256: "abc".into(),
                family: "native".into(),
            },
            "patina-native+yieldpoints".into(),
            &covmap,
            200,
        )
        .to_json();

        let mut bad_schema = meta.clone();
        bad_schema["schema"] = "patina.coverage.campaign/v999".into();
        assert!(
            CampaignCoverageMeta::from_json(&bad_schema)
                .unwrap_err()
                .contains("unsupported schema")
        );

        let mut bad_edges = meta;
        bad_edges["edges_total"] = 2.into();
        let error = CampaignCoverageMeta::from_json(&bad_edges).unwrap_err();
        assert!(
            error.contains("expected edges_total=2"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn plateau_rule_is_exact_and_zero_disables() {
        let covmap = parse_covmap_bytes(&covmap_bytes(&[1, 0], &[10, 20]), Path::new("a"))
            .expect("valid covmap");
        let no_new = parse_covmap_bytes(&covmap_bytes(&[1, 0], &[10, 20]), Path::new("b"))
            .expect("valid covmap");
        let artifact = CoverageArtifact {
            path: "guest".into(),
            sha256: "abc".into(),
            family: "native".into(),
        };
        let mut store = CampaignCoverageStore::fresh(
            PathBuf::from("out/coverage"),
            artifact.clone(),
            "patina-native+yieldpoints".into(),
            2,
        );
        store.fold_covmap(0, &covmap).unwrap();
        assert!(!store.meta().unwrap().plateaued);
        store.fold_covmap(1, &no_new).unwrap();
        assert!(!store.meta().unwrap().plateaued, "N-1 must not plateau");
        store.fold_covmap(2, &no_new).unwrap();
        assert!(store.meta().unwrap().plateaued, "N must plateau");

        let mut disabled = CampaignCoverageStore::fresh(
            PathBuf::from("out/coverage"),
            artifact,
            "patina-native+yieldpoints".into(),
            0,
        );
        disabled.fold_covmap(0, &covmap).unwrap();
        disabled.fold_covmap(1, &no_new).unwrap();
        disabled.fold_covmap(2, &no_new).unwrap();
        assert!(!disabled.meta().unwrap().plateaued);
    }

    #[test]
    fn offline_campaign_coverage_rejects_wrong_binary_hash() {
        let temp = tempfile::tempdir().unwrap();
        let good = temp.path().join("good-bin");
        let bad = temp.path().join("bad-bin");
        fs::write(&good, b"expected binary").unwrap();
        fs::write(&bad, b"wrong binary").unwrap();
        let mut data = synthetic_covmap(&[1], &[10]).as_coverage_data("campaign");
        data.artifact = Some(CoverageArtifact {
            path: "recorded-bin".into(),
            sha256: sha256_hex(b"expected binary"),
            family: "native".into(),
        });

        validate_coverage_binary(&good, &data).unwrap();
        let error = validate_coverage_binary(&bad, &data).unwrap_err();
        assert!(
            error
                .0
                .contains("coverage store records artifact recorded-bin sha256"),
            "unexpected error: {}",
            error.0
        );
    }

    #[test]
    fn campaign_meta_rejects_fingerprint_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("coverage");
        let covmap = parse_covmap_bytes(&covmap_bytes(&[1], &[10]), Path::new("a")).unwrap();
        let artifact = CoverageArtifact {
            path: "guest".into(),
            sha256: "abc".into(),
            family: "native".into(),
        };
        let mut store = CampaignCoverageStore::fresh(
            dir.clone(),
            artifact.clone(),
            "patina-native+yieldpoints".into(),
            200,
        );
        store.fold_covmap(0, &covmap).unwrap();
        store.write_checkpoint().unwrap();
        let mut meta: Value =
            serde_json::from_str(&fs::read_to_string(dir.join("meta.json")).unwrap()).unwrap();
        meta["fingerprint"] = "other".into();
        fs::write(
            dir.join("meta.json"),
            serde_json::to_string_pretty(&meta).unwrap(),
        )
        .unwrap();
        let error =
            CampaignCoverageStore::load(dir, artifact, "patina-native+yieldpoints".into(), 200, 1)
                .unwrap_err();
        assert!(
            error.0.contains("coverage state fingerprint mismatch"),
            "unexpected error: {}",
            error.0
        );
    }
}
