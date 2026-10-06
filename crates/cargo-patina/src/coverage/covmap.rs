//! Native coverage-map layout and parsing.

use super::*;

pub(super) const COVERAGE_MAP_MAGIC: &[u8; 16] = b"patina.covmap/v1";
pub(super) const COVERAGE_MAP_VERSION: u32 = 1;

pub(crate) const CAMPAIGN_COVERAGE_SCHEMA: &str = "patina.coverage.campaign/v1";
pub(super) const COVERAGE_ENVELOPE_SCHEMA: &str = "patina.coverage/v1";
pub(super) const COVERED_BUCKETS: &[&str] = &["covered", "uncovered"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CovmapRange {
    pub(crate) guard_offset: u64,
    pub(crate) guard_count: u64,
    pub(crate) pc_offset: u64,
    pub(crate) pc_count: u64,
}

impl CovmapRange {
    pub(super) fn to_json(&self) -> Value {
        json!({
            "guard_offset": self.guard_offset,
            "guard_count": self.guard_count,
            "pc_offset": self.pc_offset,
            "pc_count": self.pc_count,
        })
    }

    pub(super) fn from_json(value: &Value) -> Result<Self, String> {
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

    pub(super) fn as_coverage_data(&self, input_kind: &'static str) -> CoverageData {
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

pub(super) fn parse_covmap_bytes(bytes: &[u8], path: &Path) -> Result<Covmap, CliError> {
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

#[cfg(test)]
mod tests;
