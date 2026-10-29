//! Sanitizer coverage registration, validation, and report output.

use super::*;

pub(crate) const COVERAGE_MAGIC: &[u8; 16] = b"patina.covmap/v1";
const COVERAGE_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoverageRange {
    pub(crate) start: usize,
    pub(crate) len: usize,
}

/// Every counter range the guest registered, read at finalization.
///
/// Two counter kinds feed one map. An `--instrument` build's trace-pc-guard
/// words are `u32` hit counters that saturate, each with a pc-table entry. A Go
/// guest's libFuzzer instrumentation keeps one `u8` counter per block instead
/// (Go's `-d=libfuzzer`, over the linker's `.go.fuzzcntrs` section): the
/// compiler's increment never lands on zero (it wraps 255 to 1), so "covered"
/// is exact but the count is a hit count modulo that wrap, and Go registers no
/// pcs (its pc table is a zero-filled heap buffer), so a byte counter's site is
/// unknown.
#[derive(Clone, Debug, Default)]
pub(crate) struct CoverageRanges {
    /// Trace-pc-guard counter words (`u32`), one range per codegen unit.
    pub(crate) guards: Vec<CoverageRange>,
    /// The pc tables of `guards`, one `(pc, flags)` pair per guard.
    pub(crate) pcs: Vec<CoverageRange>,
    /// Go's 8-bit counters (`u8`), which have no pc table.
    pub(crate) bytes: Vec<CoverageRange>,
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

static COVERAGE_STATE: OnceLock<SpinMutex<CoverageRanges>> = OnceLock::new();

fn coverage_state() -> &'static SpinMutex<CoverageRanges> {
    COVERAGE_STATE.get_or_init(|| SpinMutex::new(CoverageRanges::default()))
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
    let _panic_scope = crate::panic_boundary::PanicScope::enter_glue();
    let len = coverage_len(start.cast_const(), stop.cast_const());
    let mut state = coverage_state().lock();
    register_coverage_range(&mut state.guards, start as usize, len);
}

#[unsafe(no_mangle)]
/// Register one range of 8-bit edge counters, which carries no pc table. Called
/// by a Go guest's meter object from `__sanitizer_cov_8bit_counters_init`, which
/// the Go runtime calls once at start-up over the `.go.fuzzcntrs` section.
pub extern "C" fn patina_coverage_register_u8(start: *mut u8, stop: *mut u8) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter_glue();
    let len = coverage_len(start.cast_const(), stop.cast_const());
    let mut state = coverage_state().lock();
    register_coverage_range(&mut state.bytes, start as usize, len);
}

#[unsafe(no_mangle)]
/// Register one SanitizerCoverage pc-table range. LLVM gives a flat uintptr_t
/// array of `(pc, flags)` pairs; the coverage map persists one anchor-relative
/// pc delta per guard. The flags are intentionally not serialized in wave A's
/// `patina.covmap/v1` format (12 bytes per edge: u32 count + i64 delta).
pub extern "C" fn patina_coverage_register_pcs(start: *const usize, stop: *const usize) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter_glue();
    let words = coverage_len(start, stop);
    let entries = words / 2;
    let mut state = coverage_state().lock();
    register_coverage_range(&mut state.pcs, start as usize, entries);
}

fn coverage_snapshot() -> CoverageRanges {
    coverage_state().lock().clone()
}

/// Why requested coverage could not be prepared or encoded. Every variant is
/// fatal for the coverage request; the split lets the tests (and the report
/// text) tell the failure classes apart.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CoverageError {
    /// The binary registered no edge counters: it was not built instrumented.
    Unavailable,
    /// Edge counters are registered but none was ever hit.
    Empty { edges_total: u64 },
    /// The guard and pc tables disagree in total size.
    TableMismatch { guards: usize, pcs: usize },
    /// Any other malformed range table or unencodable entry.
    Malformed(String),
}

impl core::fmt::Display for CoverageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unavailable => f.write_str(
                "requested coverage is unavailable: the binary registered no edge counters; rebuild with `cargo patina build --instrument` (or `--go`)",
            ),
            Self::Empty { edges_total } => write!(
                f,
                "requested coverage is empty: edges_total={edges_total} edges_covered=0; no edge counter recorded an executed edge"
            ),
            Self::TableMismatch { guards, pcs } => {
                write!(f, "guard/pc-table count mismatch: guards={guards} pcs={pcs}")
            }
            Self::Malformed(reason) => f.write_str(reason),
        }
    }
}

fn coverage_count(ranges: &[CoverageRange]) -> Result<usize, CoverageError> {
    ranges.iter().try_fold(0usize, |total, range| {
        total.checked_add(range.len).ok_or_else(|| {
            CoverageError::Malformed(
                "registered coverage ranges exceed this platform's addressable size".to_string(),
            )
        })
    })
}

fn validate_coverage_ranges(
    guard_ranges: &[CoverageRange],
    pc_ranges: &[CoverageRange],
) -> Result<usize, CoverageError> {
    let guard_count = coverage_count(guard_ranges)?;
    let pc_count = coverage_count(pc_ranges)?;
    if guard_count != pc_count {
        return Err(CoverageError::TableMismatch {
            guards: guard_count,
            pcs: pc_count,
        });
    }
    if guard_ranges.len() != pc_ranges.len() {
        return Err(CoverageError::Malformed(format!(
            "guard/pc-table range count mismatch: guard_ranges={} pc_ranges={} guards={} pcs={}",
            guard_ranges.len(),
            pc_ranges.len(),
            guard_count,
            pc_count,
        )));
    }
    for (index, (guards, pcs)) in guard_ranges.iter().zip(pc_ranges).enumerate() {
        if guards.len != pcs.len {
            return Err(CoverageError::Malformed(format!(
                "guard/pc-table range {index} count mismatch: guards={} pcs={} total_guards={} total_pcs={}",
                guards.len, pcs.len, guard_count, pc_count,
            )));
        }
    }
    Ok(guard_count)
}

impl CoverageRanges {
    /// Every registered edge counter: the guard words, then the byte counters
    /// widened, in registration order — the map's edge order.
    fn counters(&self) -> impl Iterator<Item = u32> + '_ {
        let guards = self.guards.iter().flat_map(|range| {
            // SAFETY: SanitizerCoverage guard arrays are process-lifetime static
            // storage. Registration only records the compiler-provided
            // `[start, stop)` subranges, and finalization runs after managed
            // execution is stopped.
            unsafe { slice::from_raw_parts(range.start as *const u32, range.len) }
                .iter()
                .copied()
        });
        let bytes = self.bytes.iter().flat_map(|range| {
            // SAFETY: Go's counter section is process-lifetime static storage,
            // registered as the `[start, stop)` the runtime passed.
            unsafe { slice::from_raw_parts(range.start as *const u8, range.len) }
                .iter()
                .map(|&hits| u32::from(hits))
        });
        guards.chain(bytes)
    }

    /// The map's ranges: the guard ranges, then the byte ranges.
    fn counter_ranges(&self) -> impl Iterator<Item = &CoverageRange> {
        self.guards.iter().chain(&self.bytes)
    }

    fn edge_count(&self) -> Result<usize, CoverageError> {
        coverage_count(&self.guards)?
            .checked_add(coverage_count(&self.bytes)?)
            .ok_or_else(|| {
                CoverageError::Malformed(
                    "registered coverage ranges exceed this platform's addressable size"
                        .to_string(),
                )
            })
    }
}

pub(crate) fn coverage_summary(ranges: &CoverageRanges) -> CoverageSummary {
    let mut edges_total = 0u64;
    let mut edges_covered = 0u64;
    let mut hits_total = 0u64;
    let mut hits_max = 0u32;
    let mut saturated = 0u64;
    for hits in ranges.counters() {
        edges_total += 1;
        if hits != 0 {
            edges_covered += 1;
        }
        hits_total = hits_total.saturating_add(hits as u64);
        hits_max = hits_max.max(hits);
        // Only a guard word saturates; a byte counter wraps and never reads
        // `u32::MAX` widened.
        if hits == u32::MAX {
            saturated += 1;
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

pub(crate) fn build_coverage_map(ranges: &CoverageRanges) -> Result<Vec<u8>, CoverageError> {
    validate_coverage_ranges(&ranges.guards, &ranges.pcs)?;
    let guard_count = ranges.edge_count()?;
    let range_count = ranges.guards.len() + ranges.bytes.len();
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

    // Every range has one site delta per counter: a guard range's from its pc
    // table (validated equal in length above), a byte range's all zero.
    let mut offset = 0u64;
    for range in ranges.counter_ranges() {
        push_u64_le(&mut bytes, offset);
        push_u64_le(&mut bytes, range.len as u64);
        push_u64_le(&mut bytes, offset);
        push_u64_le(&mut bytes, range.len as u64);
        offset += range.len as u64;
    }

    for counter in ranges.counters() {
        push_u32_le(&mut bytes, counter);
    }

    let anchor = patina_yield_point as *const () as i128;
    for range in &ranges.pcs {
        // SAFETY: pc-table arrays are process-lifetime static storage. `len` is
        // the number of `(pc, flags)` pairs, so the raw word slice is `len * 2`.
        let words = unsafe { slice::from_raw_parts(range.start as *const usize, range.len * 2) };
        for pair in words.as_chunks::<2>().0.iter() {
            let raw_pc = pair[0];
            let delta = if raw_pc <= 1 {
                // A pc-table slot holding the literal `0`/`1` names no code:
                // LLVM emits a `blockaddress` per instrumented block and, when a
                // later pass deletes or folds that block, zaps the dangling
                // address to `inttoptr 1`, while the guard bump survives in the
                // block it was folded into. Such a guard is hit like any other
                // (on Linux a `BTreeSet` dedup path in std's
                // `DedupSortedIter::next` is one), so its count is real coverage
                // and is kept; only its site is unknown. The literal sentinel is
                // stable, so it maps to the stable zero delta — subtracting the
                // ASLR-slid anchor would manufacture nondeterministic bytes —
                // which the reader treats as an unattributable site.
                0
            } else {
                let pc = raw_pc as i128;
                let delta = pc - anchor;
                i64::try_from(delta).map_err(|_| {
                    CoverageError::Malformed(format!(
                        "coverage pc delta {delta} does not fit in patina.covmap/v1 i64 encoding"
                    ))
                })?
            };
            push_i64_le(&mut bytes, delta);
        }
    }
    // A byte counter has no pc: Go registers none. Its site is the zero delta,
    // the same unattributable site a guard's pc-table sentinel gets, so the
    // readers count it as an edge by its index and name no function for it.
    for range in &ranges.bytes {
        for _ in 0..range.len {
            push_i64_le(&mut bytes, 0);
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
    ranges: &CoverageRanges,
) -> Result<Option<PreparedCoverage>, CoverageError> {
    let edge_count = ranges.edge_count()?;
    if requested && edge_count == 0 {
        return Err(CoverageError::Unavailable);
    }
    if edge_count == 0 {
        return Ok(None);
    }
    // Validate before reading counters or emitting a report so the fail-closed
    // guard/pc-table invariant always wins over any derived observation.
    validate_coverage_ranges(&ranges.guards, &ranges.pcs)?;
    let summary = coverage_summary(ranges);
    if requested && summary.edges_covered == 0 {
        return Err(CoverageError::Empty {
            edges_total: summary.edges_total,
        });
    }
    let map = requested.then(|| build_coverage_map(ranges)).transpose()?;
    Ok(Some(PreparedCoverage { summary, map }))
}

pub(crate) fn finalize_coverage() -> Result<(), String> {
    let coverage_fd = control_coverage_fd().map_err(|error| error.to_string())?;
    let requested = coverage_fd.is_some();
    let ranges = coverage_snapshot();
    let Some(prepared) =
        prepare_coverage_output(requested, &ranges).map_err(|error| error.to_string())?
    else {
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
