//! Cross-module native-shim regression tests and source lints.

use super::*;

mod source;

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

/// Source-level enumeration gate for the shim-bootstrap window.
///
/// The window answers interposed calls WITHOUT reaching `ensure_runtime`, which
/// is exactly the shape that once swallowed a fail-closed init error: a
/// fingerprint-mismatched replay of a clock-only guest spun at 100% CPU instead
/// of aborting. The structural answer is that the window is entered through one
/// predicate that consults the stored init error, so every path is covered by
/// construction — including paths not yet written. These lints keep that true:
/// the flag may not be read anywhere else, and a new call site has to be
/// enumerated here (and given a leg in the cargo-patina e2e
/// `native_replay_init_error_reaches_every_bootstrap_window_entry_point`).
#[cfg(test)]
mod bootstrap_window_lints {
    /// Every function that answers from the shim-bootstrap window, in source
    /// order. The three `os_unfair_lock` sites forward an allocator-internal
    /// lock to the real host primitive; the rest synthesize a value for the
    /// guest.
    const BOOTSTRAP_WINDOW_SITES: &[&str] = &[
        "patina_clock_now",
        "patina_cpu_time_nanos",
        "patina_read_link",
        "patina_os_unfair_lock_lock",
        "patina_os_unfair_lock_trylock",
        "patina_os_unfair_lock_unlock",
        "deliver",
        "fire_due",
    ];

    /// Assembled at runtime so this module's own text cannot match itself.
    fn call_needle() -> String {
        format!("in_shim_bootstrap{}", "()")
    }

    #[test]
    fn the_bootstrap_flag_is_read_only_through_the_guarded_predicate() {
        let source = super::source::production_sources("src");
        let needle = format!("SHIM_BOOTSTRAP.load{}", "(");
        assert_eq!(
            source.matches(&needle).count(),
            1,
            "the bootstrap flag must be read only by the window predicate, which is where the \
             stored init error is consulted; a second reader would answer from the window \
             without that check"
        );
    }

    #[test]
    fn every_bootstrap_window_call_site_is_enumerated() {
        let source = super::source::production_sources("src");
        // One occurrence is the definition itself; the rest are call sites.
        let sites = source.matches(&call_needle()).count() - 1;
        assert_eq!(
            sites,
            BOOTSTRAP_WINDOW_SITES.len(),
            "the shim-bootstrap window gained or lost an answer path: list it in \
             BOOTSTRAP_WINDOW_SITES and give it a leg in the cargo-patina e2e \
             native_replay_init_error_reaches_every_bootstrap_window_entry_point, so a path that \
             answers before the runtime is installed keeps proving it refuses a failed init"
        );
        for site in BOOTSTRAP_WINDOW_SITES {
            assert!(
                source.contains(&format!("fn {site}(")),
                "BOOTSTRAP_WINDOW_SITES names {site}, which this crate does not define"
            );
        }
    }
}

/// Source-level convention lint: `isize`-returning interposer paths (read/
/// write/send/recv shapes) must report errors as `fail(errno) as isize` — `-1`
/// with the errno cell set — never by returning `ThreadError::into_posix()`'s
/// positive errno directly, which a guest would read as a successful byte
/// count (a deadlock-rescue errno of 35 becomes "35 bytes transferred").
/// The positive-return form is correct only for the pthread-convention `c_int`
/// sites, which this pattern does not match.
#[cfg(test)]
mod source_lints {
    #[test]
    fn no_bare_into_posix_on_isize_paths() {
        let source = super::source::production_sources("src");
        // Assembled at runtime so this test's own text cannot match itself.
        let needle = format!(".{}() as isize", "into_posix");
        assert!(
            !source.contains(&needle),
            "an isize-returning interposer path returns a positive errno as a \
             byte count; wrap it in fail(..) so the guest sees -1 with errno"
        );
    }
}

/// Source lints over the C translation unit's shape: the umbrella
/// `c/patina_posix.c` must `#include` exactly the slices [`POSIX_C_FAMILY_SOURCES`]
/// exports, in that order, and those must be exactly the files under `c/posix/`.
/// A slice added on disk but not exported would compile in-tree (the umbrella
/// resolves the include locally) and fail only in an installed `cargo-patina`,
/// whose staged sandbox carries only the exported slices.
#[cfg(test)]
mod posix_source_lints {
    use super::{POSIX_C_FAMILY_SOURCES, POSIX_C_SOURCE};

    /// The names one X-macro list in `c/posix/dlsym.c` holds.
    #[cfg(target_os = "linux")]
    fn routed(list: &str) -> std::collections::BTreeSet<String> {
        let (_, source) = POSIX_C_FAMILY_SOURCES
            .iter()
            .find(|(relative, _)| *relative == "posix/dlsym.c")
            .expect("the dlsym slice is exported");
        let start = source
            .find(&format!("#define {list}(X)"))
            .unwrap_or_else(|| panic!("dlsym.c defines {list}"));
        source[start..]
            .lines()
            .skip(1)
            .map_while(|line| line.trim().strip_prefix("X("))
            .map(|rest| rest.split(')').next().unwrap().to_owned())
            .collect()
    }

    /// Linux's dlsym table is exactly the registry's libc definitions: every
    /// `Modeled` or `Partial` row this architecture defines (`__wrap_dlsym`
    /// answering as `dlsym`), so a name the shim defines is never NULL to a
    /// dynamic lookup and nothing else is ever routed.
    #[cfg(target_os = "linux")]
    #[test]
    fn dlsym_routes_are_the_registry_definitions() {
        use crate::registry::{Platform, SYMBOLS, SymbolStatus};
        let expected: std::collections::BTreeSet<String> = SYMBOLS
            .iter()
            .filter(|row| matches!(row.platform, Platform::Linux | Platform::Both))
            .filter(|row| matches!(row.status, SymbolStatus::Modeled | SymbolStatus::Partial))
            .map(|row| row.name)
            .filter(|name| *name != "__wrap_dlsym")
            .map(str::to_owned)
            .collect();
        let mut table = routed("PATINA_ROUTED");
        let assembly = routed("PATINA_ROUTED_ASM");
        assert!(table.is_disjoint(&assembly));
        table.extend(assembly);
        let x86 = routed("PATINA_ROUTED_X86_64");
        assert!(table.is_disjoint(&x86));
        if cfg!(target_arch = "x86_64") {
            table.extend(x86);
        }
        let missing: Vec<_> = expected.difference(&table).collect();
        let extra: Vec<_> = table.difference(&expected).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "c/posix/dlsym.c's routing lists and the registry disagree: \
             missing {missing:?}, not defined as a libc contract {extra:?}"
        );
    }

    #[test]
    fn posix_umbrella_includes_every_family_slice() {
        let included: Vec<&str> = POSIX_C_SOURCE
            .lines()
            .filter_map(|line| line.strip_prefix("#include \""))
            .map(|rest| rest.trim_end_matches('"'))
            .collect();
        let exported: Vec<&str> = POSIX_C_FAMILY_SOURCES
            .iter()
            .map(|(relative, _)| *relative)
            .collect();
        assert_eq!(
            included, exported,
            "c/patina_posix.c's #include list and POSIX_C_FAMILY_SOURCES must agree, in order"
        );
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("c/posix");
        let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
            .expect("c/posix exists")
            .map(|entry| format!("posix/{}", entry.unwrap().file_name().to_string_lossy()))
            .collect();
        on_disk.sort();
        let mut exported_sorted: Vec<String> = exported.iter().map(|s| s.to_string()).collect();
        exported_sorted.sort();
        assert_eq!(
            on_disk, exported_sorted,
            "every file under c/posix/ must be exported by POSIX_C_FAMILY_SOURCES and vice versa"
        );
        for (relative, source) in POSIX_C_FAMILY_SOURCES {
            assert!(
                *relative == "posix/core.c" || !source.contains("#include <"),
                "{relative}: system headers belong in posix/core.c, which every slice shares"
            );
        }
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
