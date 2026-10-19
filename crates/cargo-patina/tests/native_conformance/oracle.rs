//! Host-oracle authority, native judgments, crash classification, and diagnostics.

use super::process::required;
use patina_dst_conformance::catalog;
use patina_dst_conformance::compare::{self, Ending, Failure, Observation, Termination};
use patina_dst_conformance::host;
use patina_dst_conformance::observe::EXPECT_DEATH_OP;
use patina_dst_conformance::vehicle::Vehicle;
use patina_dst_syscalls::{VIRTUAL_ABI, parse_release};
use std::io::Write;
use std::path::Path;
use std::sync::OnceLock;

/// This host as the oracle of the pinned system: whether a
/// native-versus-patina judgement fails the test, or only reports.
pub(super) struct Oracle {
    release: String,
    glibc: String,
    /// The pinned kernel series and glibc (`host::pinned`), or
    /// `PATINA_REQUIRE_PINNED_KERNEL=1`.
    authoritative: bool,
}

/// The host's glibc release (`gnu_get_libc_version`).
fn glibc_version() -> String {
    // SAFETY: glibc answers a static NUL-terminated string.
    unsafe { std::ffi::CStr::from_ptr(libc::gnu_get_libc_version()) }
        .to_string_lossy()
        .into_owned()
}

impl Oracle {
    pub(super) fn detect() -> &'static Oracle {
        static ORACLE: OnceLock<Oracle> = OnceLock::new();
        ORACLE.get_or_init(|| {
            Oracle::on(
                &host::kernel_release(),
                &glibc_version(),
                required("PATINA_REQUIRE_PINNED_KERNEL"),
            )
        })
    }

    fn on(release: &str, glibc: &str, strict: bool) -> Oracle {
        Oracle {
            release: release.to_string(),
            glibc: glibc.to_string(),
            authoritative: strict || host::pinned(release, glibc),
        }
    }

    /// A judgement of patina against the native run: its failures, on an
    /// authoritative host; elsewhere they join `diverged` and it holds.
    pub(super) fn judged<T>(
        &self,
        judgement: Result<T, Vec<String>>,
        diverged: &mut Vec<String>,
    ) -> Result<(), Vec<String>> {
        match judgement {
            Ok(_) => Ok(()),
            Err(failures) if self.authoritative => Err(failures),
            Err(failures) => {
                diverged.extend(failures);
                Ok(())
            }
        }
    }

    fn prefix(&self) -> String {
        let host = parse_release(&self.release).map_or_else(
            || self.release.clone(),
            |(major, minor, _)| format!("{major}.{minor}"),
        );
        format!(
            "DIVERGES (host {host}/glibc {}, pinned {VIRTUAL_ABI}/glibc {})",
            self.glibc,
            host::PINNED_GLIBC
        )
    }

    /// Print `scenario`'s divergences on `stderr` and, when `summary` names
    /// a file (`$GITHUB_STEP_SUMMARY`), append them to it as one Markdown
    /// section (one write, so concurrent tests' sections do not interleave).
    pub(super) fn report(
        &self,
        scenario: &str,
        diverged: &[String],
        stderr: &mut dyn Write,
        summary: Option<&Path>,
    ) {
        let prefix = self.prefix();
        for line in diverged {
            writeln!(stderr, "{prefix} {line}").unwrap();
        }
        let Some(summary) = summary else { return };
        let section = format!(
            "### `{scenario}` diverges from the pinned kernel (report-only)\n\n\
             Host kernel `{}`; only Linux {VIRTUAL_ABI} is authoritative.\n\n\
             ```text\n{}\n```\n\n",
            self.release,
            diverged.join("\n")
        );
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(summary)
            .and_then(|mut file| file.write_all(section.as_bytes()))
            .unwrap_or_else(|error| panic!("append to {}: {error}", summary.display()));
    }
}

/// Judge a native run: an oracle (every check holds, it ends as announced)
/// that agrees with the scenario's first oracle vehicle (`reference`, which
/// that vehicle sets). Off the pinned system a native run that answers
/// otherwise ([`answered_otherwise`]) is the host answering as its own
/// kernel and glibc do: a divergence, and no oracle (`Ok(false)`), neither
/// the reference nor compared with it, so the vehicle's patina run is judged
/// against no expectation (only by what needs none). Native
/// vehicles that are oracles and disagree, and a native run that fails
/// otherwise, fail on every host.
pub(super) fn judge_native(
    oracle: &Oracle,
    native: &Observation,
    reference: &mut Option<Observation>,
    diverged: &mut Vec<String>,
) -> Result<bool, Vec<String>> {
    if let Err(error) = compare::verdict(native) {
        if oracle.authoritative || !answered_otherwise(native) {
            return Err(vec![format!(
                "the native run is no oracle: {error}\n{}",
                tail(&native.stderr)
            )]);
        }
        diverged.push(format!(
            "native: {error}; no oracle, so the patina leg is unjudged"
        ));
        return Ok(false);
    }
    match reference {
        Some(first) => compare::vehicles_agree(first, native).map_err(|failures| {
            prefixed(
                &format!("natively, differs from {}: ", first.origin.vehicle.name()),
                failures,
            )
        })?,
        None => *reference = Some(native.clone()),
    }
    Ok(true)
}

/// Whether a native run that is no oracle failed as a host answering
/// otherwise than the pinned system does: one of the scenario's checks
/// failed, or the run died of a signal it did not announce (a glibc that
/// writes the caller's buffer in user space where the pinned one enters the
/// kernel, an `abort` that no longer runs a blocked handler). A run that
/// recorded nothing or exited otherwise (a precondition the probe could not
/// meet) is no answer of the host's.
fn answered_otherwise(native: &Observation) -> bool {
    !native.events.is_empty()
        && (compare::failed_check(native).is_some()
            || matches!(native.termination, Termination::Signaled { .. }))
}

pub(super) fn prefixed(prefix: &str, lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .map(|line| format!("{prefix}{line}"))
        .collect()
}

/// A patina signal death that nothing accounts for: a crash, which fails on
/// every host. A native oracle (`native`) dying of the same signal accounts
/// for it, as does a stopping gap of the vehicle declaring that signal; with
/// no native oracle, the patina run announcing that death itself
/// (`Probe::dies_by` as its last event) does instead. A native run that is
/// no oracle accounts for nothing, its own death of the same signal
/// included.
pub(super) fn undeclared_death(
    native: Option<&Observation>,
    recorded: &Observation,
    gaps: &[&catalog::Gap],
) -> Option<String> {
    let Termination::Signaled { signal, .. } = recorded.termination else {
        return None;
    };
    let accounted = match native {
        Some(native) => {
            matches!(native.termination, Termination::Signaled { signal: s, .. } if s == signal)
        }
        None => announced_death(recorded) == Some(signal),
    };
    let declared = gaps.iter().any(|gap| {
        matches!(gap.failure, Failure::Stops { ending: Ending::Signal(s), .. } if s == signal)
    });
    (!accounted && !declared).then(|| match native {
        Some(native) => format!(
            "patina: the run died ({}) where natively it {}, and no gap declares it",
            recorded.termination, native.termination
        ),
        None => format!(
            "patina: the run died ({}) unannounced, with no native oracle, and no gap declares it",
            recorded.termination
        ),
    })
}

/// The signal a run's last event announces it dies by (`Probe::dies_by`).
fn announced_death(run: &Observation) -> Option<i32> {
    let last = run
        .events
        .last()
        .filter(|event| event.op == EXPECT_DEATH_OP)?;
    last.args
        .get("signal")
        .and_then(serde_json::Value::as_i64)
        .and_then(|signal| i32::try_from(signal).ok())
}

pub(super) fn with_stderr(mut failures: Vec<String>, observation: &Observation) -> Vec<String> {
    failures.push(tail(&observation.stderr));
    failures
}

/// The last lines of a run's stderr, for a failure message.
pub(super) fn tail(stderr: &str) -> String {
    const LINES: usize = 12;
    let lines: Vec<&str> = stderr.lines().collect();
    let start = lines.len().saturating_sub(LINES);
    format!("stderr (tail):\n    {}", lines[start..].join("\n    "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planted;
    use patina_dst_conformance::compare::{Leg, Origin};

    /// On a faked host off the pinned kernel, or on the pinned kernel with
    /// another glibc, a difference from patina and a failed native check are
    /// reported — printed with the prefix and summarized — and fail nothing; on
    /// the pinned system, or forced strict, they fail. Native vehicles that
    /// disagree fail off the pin too.
    #[test]
    fn off_the_pinned_kernel_differences_only_report() {
        let (major, minor, _) = parse_release(VIRTUAL_ABI).unwrap();
        let glibc = host::PINNED_GLIBC;
        let off = Oracle::on(&format!("{major}.{}.0-1017-azure", minor + 9), glibc, false);
        let pinned = Oracle::on(&format!("{major}.{minor}.0-139-generic"), glibc, false);
        let other_glibc = Oracle::on(&pinned.release, "2.40", false);
        let forced = Oracle::on(&off.release, glibc, true);
        let from = |leg, vehicle| Origin { leg, vehicle };
        let libc = from(Leg::Native, Vehicle::Libc);
        let native = planted(libc, &[("close", 0), ("check", 1)], Termination::Exited(0));
        let patina = planted(
            from(Leg::Patina, Vehicle::Libc),
            &[("close", -1), ("check", 1)],
            Termination::Exited(0),
        );
        let failed = planted(
            libc,
            &[("close", 0), ("check", 0)],
            Termination::Exited(101),
        );
        let judge = || compare::judge(&native, &patina, &[]);

        let mut diverged = Vec::new();
        assert_eq!(off.judged(judge(), &mut diverged), Ok(()));
        assert!(!diverged.is_empty());
        assert!(pinned.judged(judge(), &mut Vec::new()).is_err());
        assert!(forced.judged(judge(), &mut Vec::new()).is_err());
        let mut reported = Vec::new();
        assert_eq!(other_glibc.judged(judge(), &mut reported), Ok(()));
        assert!(!reported.is_empty());
        assert!(other_glibc.prefix().contains("glibc 2.40"));

        let before = diverged.len();
        let mut reference = None;
        assert_eq!(
            judge_native(&off, &failed, &mut reference, &mut diverged),
            Ok(false)
        );
        assert_eq!(diverged.len(), before + 1);
        assert!(judge_native(&pinned, &failed, &mut None, &mut Vec::new()).is_err());

        let mut reference = Some(native.clone());
        let disagreeing = planted(
            from(Leg::Native, Vehicle::Syscall),
            &[("close", 0), ("check", 1), ("close", 0)],
            Termination::Exited(0),
        );
        let mut none = Vec::new();
        assert!(judge_native(&off, &disagreeing, &mut reference, &mut none).is_err());
        assert!(none.is_empty());

        let summary = tempfile::NamedTempFile::new().unwrap();
        let mut printed = Vec::new();
        off.report("planted", &diverged, &mut printed, Some(summary.path()));
        let printed = String::from_utf8(printed).unwrap();
        let summarized = std::fs::read_to_string(summary.path()).unwrap();
        for line in &diverged {
            assert!(
                printed.contains(&format!("{} {line}\n", off.prefix())),
                "{printed}"
            );
            assert!(summarized.contains(line.as_str()), "{summarized}");
        }
    }

    /// Off the pinned system a native run that fails a check or dies of a
    /// signal it did not announce is reported and is no oracle: it neither
    /// becomes the reference nor is compared with it, so the next oracle
    /// vehicle becomes the reference. On the pinned system, or forced strict,
    /// it fails; a native run that stops otherwise (a precondition, nothing
    /// recorded) fails on every host, as do two oracles that disagree.
    #[test]
    fn off_the_pinned_system_a_native_run_answering_otherwise_is_no_oracle() {
        let (major, minor, _) = parse_release(VIRTUAL_ABI).unwrap();
        let off = Oracle::on(&format!("{major}.{minor}.0-139-generic"), "2.43", false);
        let pinned = Oracle::on(&off.release, host::PINNED_GLIBC, false);
        let forced = Oracle::on(&off.release, "2.43", true);
        let on = |vehicle| Origin {
            leg: Leg::Native,
            vehicle,
        };
        let segv = Termination::Signaled {
            signal: libc::SIGSEGV,
            core: Some(true),
        };
        let crashed = planted(on(Vehicle::Libc), &[("getrandom", 16)], segv);
        let failed = planted(
            on(Vehicle::Libc),
            &[("utimensat", 0), ("check", 0)],
            Termination::Exited(101),
        );
        for answer in [&crashed, &failed] {
            let mut reference = None;
            let mut diverged = Vec::new();
            assert_eq!(
                judge_native(&off, answer, &mut reference, &mut diverged),
                Ok(false)
            );
            assert_eq!(diverged.len(), 1);
            assert!(reference.is_none());
            for strict in [&pinned, &forced] {
                let judged = judge_native(strict, answer, &mut None, &mut Vec::new());
                assert!(judged.is_err());
            }
        }

        let oracle = planted(
            on(Vehicle::Syscall),
            &[("utimensat", 0), ("check", 1)],
            Termination::Exited(0),
        );
        let mut reference = None;
        let mut diverged = Vec::new();
        assert_eq!(
            judge_native(&off, &failed, &mut reference, &mut diverged),
            Ok(false)
        );
        assert_eq!(
            judge_native(&off, &oracle, &mut reference, &mut diverged),
            Ok(true)
        );
        assert_eq!(
            reference.as_ref().map(|first| first.origin),
            Some(oracle.origin)
        );
        assert_eq!(
            judge_native(&off, &failed, &mut reference, &mut diverged),
            Ok(false)
        );

        let disagreeing = planted(
            on(Vehicle::Libc),
            &[("utimensat", -22), ("check", 1)],
            Termination::Exited(0),
        );
        assert!(judge_native(&off, &disagreeing, &mut reference, &mut Vec::new()).is_err());
        let stopped = planted(
            on(Vehicle::Libc),
            &[("rseq", -22)],
            Termination::Exited(101),
        );
        let silent = planted(on(Vehicle::Libc), &[], segv);
        for stopped_otherwise in [&stopped, &silent] {
            let judged = judge_native(&off, stopped_otherwise, &mut None, &mut Vec::new());
            assert!(judged.is_err());
        }
    }

    /// A patina signal death is a crash on every host unless a native
    /// oracle died of the same signal or a stopping gap of the vehicle
    /// declares it; with no native oracle, unless the patina run announced
    /// it itself. A native run that is no oracle accounts for nothing, its
    /// own death of the same signal included.
    #[test]
    fn an_undeclared_patina_signal_death_is_a_crash() {
        let signaled = |signal| Termination::Signaled {
            signal,
            core: Some(true),
        };
        let stop = |signal| catalog::Gap {
            status: catalog::Status::ByDesign,
            vehicles: Vehicle::ALL,
            what: "planted",
            failure: Failure::Stops {
                events: 1,
                ending: Ending::Signal(signal),
                diagnostic: "planted",
            },
        };
        let (abort, segv) = (stop(libc::SIGABRT), stop(libc::SIGSEGV));
        let (exited, failed, died) = (
            Termination::Exited(0),
            Termination::Exited(1),
            signaled(libc::SIGABRT),
        );
        let run = |leg, termination| {
            planted(
                Origin {
                    leg,
                    vehicle: Vehicle::Libc,
                },
                &[("check", 1)],
                termination,
            )
        };
        // A patina run of `checks` that dies of SIGABRT, its last event
        // announcing a death by `signal`.
        let announcing = |checks, signal: i32| {
            let mut announced = planted(
                Origin {
                    leg: Leg::Patina,
                    vehicle: Vehicle::Libc,
                },
                checks,
                died,
            );
            let mut announcement = announced.events[0].clone();
            announcement.seq = announced.events.len() as u64;
            announcement.op = EXPECT_DEATH_OP.to_string();
            announcement.args = [("signal".to_string(), signal.into())].into();
            announced.events.push(announcement);
            announced
        };
        let announced = announcing(&[("check", 1)], libc::SIGABRT);
        // With no oracle the patina leg's checks are unjudged: only whether
        // it announced its death is asked.
        let announced_after_a_failed_check = announcing(&[("check", 0)], libc::SIGABRT);
        let announced_another = announcing(&[("check", 1)], libc::SIGSEGV);
        for (native, patina, gaps, crash) in [
            (Some(exited), &run(Leg::Patina, died), &[][..], true),
            (Some(exited), &run(Leg::Patina, died), &[&segv][..], true),
            (Some(exited), &run(Leg::Patina, died), &[&abort][..], false),
            (Some(died), &run(Leg::Patina, died), &[][..], false),
            (Some(exited), &run(Leg::Patina, failed), &[][..], false),
            (None, &run(Leg::Patina, died), &[][..], true),
            (None, &run(Leg::Patina, died), &[&abort][..], false),
            (None, &announced, &[][..], false),
            (None, &announced_after_a_failed_check, &[][..], false),
            (None, &announced_another, &[][..], true),
            (None, &run(Leg::Patina, failed), &[][..], false),
        ] {
            let native = native.map(|termination| run(Leg::Native, termination));
            assert_eq!(
                undeclared_death(native.as_ref(), patina, gaps).is_some(),
                crash,
                "{:?} vs {}",
                native.as_ref().map(|native| native.termination),
                patina.termination
            );
        }
    }
}
