//! Cross-module native-shim regression tests.

use super::*;

/// The recorder-budget exception to patina's fail-closed shutdown: a run that
/// outgrew its trace budget keeps its own verdict and says so in one greppable
/// line, while every other finalization failure still aborts.
#[cfg(test)]
mod over_budget_trace_tests {
    use super::*;

    /// The refusal `Context::finish` returns when the serialized bundle is over
    /// budget, verbatim in shape (see `enforce_trace_byte_limit`).
    fn over_budget() -> TraceError {
        TraceError::ResourceLimit {
            message: format!(
                "serialized trace is {} bytes; limit is {MAX_TRACE_BYTES}; reduce recorded event \
                 count or payload volume, or split the run",
                MAX_TRACE_BYTES + 1
            ),
            bytes: Some((MAX_TRACE_BYTES + 1, MAX_TRACE_BYTES)),
        }
    }

    #[test]
    fn an_over_budget_trace_is_classified_and_reported_with_its_figures() {
        let error = over_budget();
        assert!(
            error.is_resource_limit(),
            "the shutdown downgrade keys off this predicate; got {error}"
        );
        let (bytes, limit) = error.resource_limit_bytes().expect("a byte budget");
        assert_eq!((bytes, limit), (MAX_TRACE_BYTES + 1, MAX_TRACE_BYTES));

        let diagnostic = over_budget_diagnostic(&error);
        let mut lines = diagnostic.lines();
        assert_eq!(
            lines.next().unwrap(),
            format!(
                "PATINA_INFRA trace=incomplete reason=resource-limit bytes={bytes} limit={limit}"
            )
        );
        let human = lines.next().unwrap();
        assert!(
            human.contains("verdict stands unchanged") && human.contains("unusable for replay"),
            "the human line must say the run stands and the trace does not; got {human}"
        );
        assert!(lines.next().is_none(), "the report is exactly two lines");
    }

    #[test]
    fn a_broken_recorder_is_not_downgraded() {
        // The shutdown path downgrades ONLY a budget refusal. An I/O failure —
        // the shape an unwritable `--record` path takes — must stay fatal.
        let broken = RuntimeError::Io {
            action: "write temporary trace".into(),
            source: io::Error::from(io::ErrorKind::PermissionDenied),
        };
        assert!(
            !matches!(&broken, RuntimeError::Trace(error) if error.is_resource_limit()),
            "an I/O failure must not take the budget exception"
        );
        assert_eq!(runtime_errno(&broken), EIO);
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn coverage_summary_counts_hits_and_saturation() {
        let counters = [0u32, 2, u32::MAX];
        let ranges = [CoverageRange {
            start: counters.as_ptr() as usize,
            len: counters.len(),
        }];
        let summary = coverage_summary(&ranges);
        assert_eq!(summary.edges_total, 3);
        assert_eq!(summary.edges_covered, 2);
        assert_eq!(summary.covered_permille, 666);
        assert_eq!(summary.hits_total, u64::from(2u32) + u64::from(u32::MAX));
        assert_eq!(summary.hits_max, u32::MAX);
        assert_eq!(summary.saturated, 1);
    }

    #[test]
    fn requested_coverage_with_zero_ranges_refuses() {
        let error = prepare_coverage_output(true, &[], &[]).unwrap_err();
        eprintln!("D1_RED {error}");
        assert!(
            error.contains("requested coverage is unavailable")
                && error.contains("zero SanitizerCoverage guard ranges")
                && error.contains("cargo patina build --yield-points"),
            "D1 refusal should name the missing instrumentation; got {error}"
        );
    }

    #[test]
    fn requested_coverage_with_zero_hits_refuses() {
        let counters = [0u32, 0];
        let pcs = [
            patina_yield_point as *const () as usize,
            0usize,
            patina_yield_point as *const () as usize,
            0usize,
        ];
        let guards = [CoverageRange {
            start: counters.as_ptr() as usize,
            len: counters.len(),
        }];
        let pc_ranges = [CoverageRange {
            start: pcs.as_ptr() as usize,
            len: counters.len(),
        }];
        let error = prepare_coverage_output(true, &guards, &pc_ranges).unwrap_err();
        eprintln!("D1_EMPTY_RED {error}");
        assert!(
            error.contains("requested coverage is empty")
                && error.contains("edges_total=2")
                && error.contains("edges_covered=0"),
            "empty-coverage refusal should name the zero covered count; got {error}"
        );
    }

    #[test]
    fn coverage_count_mismatch_refuses_naming_both_counts() {
        let guards = [CoverageRange {
            start: 0x1000,
            len: 3,
        }];
        let pcs = [CoverageRange {
            start: 0x2000,
            len: 2,
        }];
        let error = prepare_coverage_output(true, &guards, &pcs).unwrap_err();
        eprintln!("D2_RED {error}");
        assert!(
            error.contains("guard/pc-table count mismatch")
                && error.contains("guards=3")
                && error.contains("pcs=2"),
            "D2 refusal should name both counts; got {error}"
        );
    }

    #[test]
    fn coverage_map_serializes_counters_and_anchor_deltas() {
        let counters = [1u32, 0, 7];
        let anchor = patina_yield_point as *const () as usize;
        let pcs = [
            anchor.wrapping_add(4),
            0usize,
            anchor.wrapping_sub(8),
            0usize,
            anchor,
            1usize,
        ];
        let guards = [CoverageRange {
            start: counters.as_ptr() as usize,
            len: counters.len(),
        }];
        let pc_ranges = [CoverageRange {
            start: pcs.as_ptr() as usize,
            len: counters.len(),
        }];
        let map = build_coverage_map(&guards, &pc_ranges).unwrap();
        assert!(map.starts_with(COVERAGE_MAGIC));
        let header_len = COVERAGE_MAGIC.len() + 4 + 8 + 8 + 32;
        assert_eq!(
            &map[header_len..header_len + 12],
            &[1, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0]
        );
        let deltas = &map[header_len + 12..];
        assert_eq!(&deltas[0..8], &4i64.to_le_bytes());
        assert_eq!(&deltas[8..16], &(-8i64).to_le_bytes());
        assert_eq!(&deltas[16..24], &0i64.to_le_bytes());
    }

    #[test]
    fn coverage_map_normalizes_unhit_pc_sentinel_and_refuses_hit_sentinel() {
        let counters = [0u32];
        let pcs = [1usize, 0usize];
        let guards = [CoverageRange {
            start: counters.as_ptr() as usize,
            len: counters.len(),
        }];
        let pc_ranges = [CoverageRange {
            start: pcs.as_ptr() as usize,
            len: counters.len(),
        }];
        let map = build_coverage_map(&guards, &pc_ranges).unwrap();
        let delta_start = COVERAGE_MAGIC.len() + 4 + 8 + 8 + 32 + 4;
        assert_eq!(&map[delta_start..delta_start + 8], &0i64.to_le_bytes());

        let hit = [1u32];
        let guards = [CoverageRange {
            start: hit.as_ptr() as usize,
            len: hit.len(),
        }];
        let error = build_coverage_map(&guards, &pc_ranges).unwrap_err();
        assert!(
            error.contains("sentinel pc=1") && error.contains("covered guard"),
            "covered sentinel pc should fail loudly; got {error}"
        );
    }
}

#[cfg(test)]
mod timestamp_tests {
    use super::PatinaTimestamp;

    #[test]
    fn a_stored_time_splits_with_its_nanoseconds_never_negative() {
        const SEC: i128 = 1_000_000_000;
        let at = |sec, nsec| PatinaTimestamp { sec, nsec };
        assert_eq!(PatinaTimestamp::from_nanos(-SEC + 5), at(-1, 5));
        assert_eq!(PatinaTimestamp::from_nanos(-1), at(-1, 999_999_999));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod directory_iteration_tests {
    #[test]
    fn a_directory_seeks_like_tmpfs_and_never_answers_espipe() {
        use crate::sud::{release_dir_iteration, seek_dir_iteration};
        use linux_raw_sys::general::{SEEK_CUR, SEEK_DATA, SEEK_END, SEEK_SET};
        // A number no other test touches; the position table is keyed by it.
        let fd = 900;
        assert_eq!(seek_dir_iteration(fd, 0, SEEK_CUR), Some(0));
        assert_eq!(seek_dir_iteration(fd, 3, SEEK_SET), Some(3));
        assert_eq!(seek_dir_iteration(fd, 0, SEEK_CUR), Some(3));
        assert_eq!(seek_dir_iteration(fd, -1, SEEK_CUR), Some(2));
        assert_eq!(seek_dir_iteration(fd, -5, SEEK_CUR), None);
        assert_eq!(seek_dir_iteration(fd, -1, SEEK_SET), None);
        assert_eq!(seek_dir_iteration(fd, 0, SEEK_END), None);
        assert_eq!(seek_dir_iteration(fd, 0, SEEK_DATA), None);
        assert_eq!(seek_dir_iteration(fd, 0, SEEK_CUR), Some(2));
        assert_eq!(seek_dir_iteration(fd, 0, SEEK_SET), Some(0));
        release_dir_iteration(fd);
        assert_eq!(seek_dir_iteration(fd, 0, SEEK_CUR), Some(0));
    }
}
