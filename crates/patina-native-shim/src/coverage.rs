//! Sanitizer coverage registration, validation, and report output.

use super::*;

pub(crate) const COVERAGE_MAGIC: &[u8; 16] = b"patina.covmap/v1";
const COVERAGE_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoverageRange {
    pub(crate) start: usize,
    pub(crate) len: usize,
}

#[derive(Default)]
struct CoverageState {
    guard_ranges: Vec<CoverageRange>,
    pc_ranges: Vec<CoverageRange>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CoverageSummary {
    pub(crate) edges_total: u64,
    pub(crate) edges_covered: u64,
    pub(crate) covered_permille: u64,
    pub(crate) hits_total: u64,
    pub(crate) hits_max: u32,
    pub(crate) saturated: u64,
}

#[derive(Debug)]
pub(crate) struct PreparedCoverage {
    summary: CoverageSummary,
    map: Option<Vec<u8>>,
}

static COVERAGE_STATE: OnceLock<SpinMutex<CoverageState>> = OnceLock::new();

fn coverage_state() -> &'static SpinMutex<CoverageState> {
    COVERAGE_STATE.get_or_init(|| SpinMutex::new(CoverageState::default()))
}

fn coverage_len<T>(start: *const T, stop: *const T) -> usize {
    if start.is_null() || stop.is_null() {
        return 0;
    }
    let start = start as usize;
    let stop = stop as usize;
    if stop <= start {
        return 0;
    }
    (stop - start) / std::mem::size_of::<T>()
}

fn register_coverage_range(ranges: &mut Vec<CoverageRange>, start: usize, len: usize) {
    if len == 0 {
        return;
    }
    if ranges
        .iter()
        .any(|range| range.start == start && range.len == len)
    {
        return;
    }
    ranges.push(CoverageRange { start, len });
}

#[unsafe(no_mangle)]
/// Register one SanitizerCoverage guard-counter range. Called by the C hook's
/// `__sanitizer_cov_trace_pc_guard_init` once per codegen unit. The guard words
/// are the counters themselves, so registration records only the live range.
pub extern "C" fn patina_coverage_register(start: *mut u32, stop: *mut u32) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let len = coverage_len(start.cast_const(), stop.cast_const());
    let mut state = coverage_state().lock();
    register_coverage_range(&mut state.guard_ranges, start as usize, len);
}

#[unsafe(no_mangle)]
/// Register one SanitizerCoverage pc-table range. LLVM gives a flat uintptr_t
/// array of `(pc, flags)` pairs; the coverage map persists one anchor-relative
/// pc delta per guard. The flags are intentionally not serialized in wave A's
/// `patina.covmap/v1` format (12 bytes per edge: u32 count + i64 delta).
pub extern "C" fn patina_coverage_register_pcs(start: *const usize, stop: *const usize) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let words = coverage_len(start, stop);
    let entries = words / 2;
    let mut state = coverage_state().lock();
    register_coverage_range(&mut state.pc_ranges, start as usize, entries);
}

fn coverage_snapshot() -> (Vec<CoverageRange>, Vec<CoverageRange>) {
    let state = coverage_state().lock();
    (state.guard_ranges.clone(), state.pc_ranges.clone())
}

fn coverage_count(ranges: &[CoverageRange]) -> Result<usize, String> {
    ranges.iter().try_fold(0usize, |total, range| {
        total.checked_add(range.len).ok_or_else(|| {
            "registered coverage ranges exceed this platform's addressable size".to_string()
        })
    })
}

fn validate_coverage_ranges(
    guard_ranges: &[CoverageRange],
    pc_ranges: &[CoverageRange],
) -> Result<usize, String> {
    let guard_count = coverage_count(guard_ranges)?;
    let pc_count = coverage_count(pc_ranges)?;
    if guard_count != pc_count {
        return Err(format!(
            "guard/pc-table count mismatch: guards={guard_count} pcs={pc_count}"
        ));
    }
    if guard_ranges.len() != pc_ranges.len() {
        return Err(format!(
            "guard/pc-table range count mismatch: guard_ranges={} pc_ranges={} guards={} pcs={}",
            guard_ranges.len(),
            pc_ranges.len(),
            guard_count,
            pc_count,
        ));
    }
    for (index, (guards, pcs)) in guard_ranges.iter().zip(pc_ranges).enumerate() {
        if guards.len != pcs.len {
            return Err(format!(
                "guard/pc-table range {index} count mismatch: guards={} pcs={} total_guards={} total_pcs={}",
                guards.len, pcs.len, guard_count, pc_count,
            ));
        }
    }
    Ok(guard_count)
}

pub(crate) fn coverage_summary(guard_ranges: &[CoverageRange]) -> CoverageSummary {
    let mut edges_total = 0u64;
    let mut edges_covered = 0u64;
    let mut hits_total = 0u64;
    let mut hits_max = 0u32;
    let mut saturated = 0u64;
    for range in guard_ranges {
        // SAFETY: SanitizerCoverage guard arrays are process-lifetime static
        // storage. Registration only records the compiler-provided `[start, stop)`
        // subranges, and finalization runs after managed execution is stopped.
        let counters = unsafe { slice::from_raw_parts(range.start as *const u32, range.len) };
        edges_total += counters.len() as u64;
        for &hits in counters {
            if hits != 0 {
                edges_covered += 1;
            }
            hits_total = hits_total.saturating_add(hits as u64);
            hits_max = hits_max.max(hits);
            if hits == u32::MAX {
                saturated += 1;
            }
        }
    }
    let covered_permille = if edges_total == 0 {
        0
    } else {
        ((edges_covered as u128 * 1000) / edges_total as u128) as u64
    };
    CoverageSummary {
        edges_total,
        edges_covered,
        covered_permille,
        hits_total,
        hits_max,
        saturated,
    }
}

fn push_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64_le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_i64_le(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(crate) fn build_coverage_map(
    guard_ranges: &[CoverageRange],
    pc_ranges: &[CoverageRange],
) -> Result<Vec<u8>, String> {
    let guard_count = validate_coverage_ranges(guard_ranges, pc_ranges)?;
    let range_count = guard_ranges.len();
    let mut bytes = Vec::with_capacity(
        COVERAGE_MAGIC.len()
            + 4
            + 8
            + 8
            + range_count.saturating_mul(32)
            + guard_count.saturating_mul(12),
    );
    bytes.extend_from_slice(COVERAGE_MAGIC);
    push_u32_le(&mut bytes, COVERAGE_VERSION);
    push_u64_le(&mut bytes, guard_count as u64);
    push_u64_le(&mut bytes, range_count as u64);

    let mut guard_offset = 0u64;
    let mut pc_offset = 0u64;
    for (guards, pcs) in guard_ranges.iter().zip(pc_ranges) {
        push_u64_le(&mut bytes, guard_offset);
        push_u64_le(&mut bytes, guards.len as u64);
        push_u64_le(&mut bytes, pc_offset);
        push_u64_le(&mut bytes, pcs.len as u64);
        guard_offset += guards.len as u64;
        pc_offset += pcs.len as u64;
    }

    let mut counters_flat = Vec::with_capacity(guard_count);
    for range in guard_ranges {
        // SAFETY: see `coverage_summary`.
        let counters = unsafe { slice::from_raw_parts(range.start as *const u32, range.len) };
        for &counter in counters {
            counters_flat.push(counter);
            push_u32_le(&mut bytes, counter);
        }
    }

    let anchor = patina_yield_point as *const () as i128;
    let mut guard_index = 0usize;
    for range in pc_ranges {
        // SAFETY: pc-table arrays are process-lifetime static storage. `len` is
        // the number of `(pc, flags)` pairs, so the raw word slice is `len * 2`.
        let words = unsafe { slice::from_raw_parts(range.start as *const usize, range.len * 2) };
        for pair in words.as_chunks::<2>().0.iter() {
            let raw_pc = pair[0];
            let delta = if raw_pc <= 1 {
                // On current Darwin/LLVM builds a handful of unexecuted guard
                // slots can carry a null/function-entry sentinel (`0`/`1`) in
                // the pc-table rather than a load-addressed code pointer. The
                // literal sentinel is already stable; subtracting the ASLR-slid
                // anchor would manufacture nondeterministic bytes. Keep unhit
                // sentinels as the stable zero delta, but fail closed if such a
                // guard ever reports coverage — a covered edge without a real PC
                // cannot be symbolized honestly.
                if counters_flat[guard_index] != 0 {
                    return Err(format!(
                        "coverage pc-table entry {guard_index} has sentinel pc={raw_pc} for a covered guard"
                    ));
                }
                0
            } else {
                let pc = raw_pc as i128;
                let delta = pc - anchor;
                i64::try_from(delta).map_err(|_| {
                    format!(
                        "coverage pc delta {delta} does not fit in patina.covmap/v1 i64 encoding"
                    )
                })?
            };
            push_i64_le(&mut bytes, delta);
            guard_index += 1;
        }
    }
    Ok(bytes)
}

fn control_coverage_fd() -> Result<Option<c_int>, RuntimeError> {
    control_env(patina_dst_runtime::ENV_COVERAGE_FD)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value.parse().map_err(|_| {
                RuntimeError::Config(format!(
                    "{} must be a non-negative descriptor number",
                    patina_dst_runtime::ENV_COVERAGE_FD
                ))
            })
        })
        .transpose()
}

/// The run's end-of-run report-suppression preferences, parsed ONCE from the
/// constructor's pre-scrub control-plane snapshot and cached.
///
/// Cached because both consumers need the same answer at different times: the
/// runtime config takes it at install, and coverage finalization takes it at
/// shutdown — after the context has left the slot, where a `std::env` read would
/// route through the interposed `getenv` and come back empty. The control plane
/// is the only view of the operator's environment that outlives the scrub, so it
/// is the only one either consumer may use.
pub(crate) fn control_reports() -> patina_dst_runtime::ReportConfig {
    *REPORTS.get_or_init(|| patina_dst_runtime::ReportConfig::default().applied(control_env))
}

static REPORTS: OnceLock<patina_dst_runtime::ReportConfig> = OnceLock::new();

pub(crate) fn prepare_coverage_output(
    requested: bool,
    guard_ranges: &[CoverageRange],
    pc_ranges: &[CoverageRange],
) -> Result<Option<PreparedCoverage>, String> {
    let guard_count = coverage_count(guard_ranges)?;
    if requested && guard_count == 0 {
        return Err(
            "requested coverage is unavailable: the binary registered zero SanitizerCoverage guard ranges; rebuild with `cargo patina build --yield-points`"
                .to_string(),
        );
    }
    if guard_count == 0 {
        return Ok(None);
    }
    // Validate before reading counters or emitting a report so the fail-closed
    // guard/pc-table invariant always wins over any derived observation.
    validate_coverage_ranges(guard_ranges, pc_ranges)?;
    let summary = coverage_summary(guard_ranges);
    if requested && summary.edges_covered == 0 {
        return Err(format!(
            "requested coverage is empty: edges_total={} edges_covered=0; the yield-point hook did not count any executed guard",
            summary.edges_total,
        ));
    }
    let map = requested
        .then(|| build_coverage_map(guard_ranges, pc_ranges))
        .transpose()?;
    Ok(Some(PreparedCoverage { summary, map }))
}

pub(crate) fn finalize_coverage() -> Result<(), String> {
    let coverage_fd = control_coverage_fd().map_err(|error| error.to_string())?;
    let requested = coverage_fd.is_some();
    let (guard_ranges, pc_ranges) = coverage_snapshot();
    let Some(prepared) = prepare_coverage_output(requested, &guard_ranges, &pc_ranges)? else {
        return Ok(());
    };
    if control_reports().enabled(patina_dst_runtime::Report::Coverage) {
        capture_stderr_line(&format!(
            "PATINA_COVERAGE_REPORT edges_total={} edges_covered={} covered_permille={} hits_total={} hits_max={} saturated={}",
            prepared.summary.edges_total,
            prepared.summary.edges_covered,
            prepared.summary.covered_permille,
            prepared.summary.hits_total,
            prepared.summary.hits_max,
            prepared.summary.saturated,
        ));
    }
    if let (Some(fd), Some(map)) = (coverage_fd, prepared.map) {
        host_write_all(fd, &map).map_err(|error| {
            format!(
                "failed to write {} coverage map to descriptor {fd}: {error}",
                patina_dst_runtime::ENV_COVERAGE_FD,
            )
        })?;
    }
    Ok(())
}

thread_local! {
    pub(crate) static LAST_ERRNO: Cell<c_int> = const { Cell::new(0) };
}

pub(crate) fn slot() -> &'static SpinMutex<Option<Context>> {
    CONTEXT.get_or_init(|| SpinMutex::new(None))
}
