//! Offline coverage input loading and binary validation.

use super::*;

#[derive(Clone, Debug)]
pub(super) struct CoverageData {
    pub(super) input_kind: &'static str,
    pub(super) artifact: Option<CoverageArtifact>,
    pub(super) edges_total: u64,
    pub(super) edges_covered: u64,
    pub(super) covered_permille: u64,
    pub(super) hits_total: u64,
    pub(super) hits_max: u64,
    pub(super) saturated: u64,
    pub(super) ranges: Vec<CovmapRange>,
    pub(super) hits: Vec<u64>,
    pub(super) deltas: Vec<i64>,
    pub(super) generations_applied: Option<u64>,
    pub(super) last_new_edge_gen: Option<u64>,
    pub(super) plateau_window: Option<u64>,
    pub(super) plateaued: Option<bool>,
    pub(super) new_edge_log: Vec<(u64, u64)>,
}

pub(super) fn load_coverage_input(input: &Path) -> Result<CoverageData, CliError> {
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

pub(super) fn validate_coverage_binary(binary: &Path, data: &CoverageData) -> Result<(), CliError> {
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

#[cfg(test)]
mod tests;
