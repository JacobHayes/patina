//! Host-oracle authority, native judgments, crash classification, and diagnostics.

use super::process::required;
use patina_dst_conformance::catalog;
use patina_dst_conformance::compare::{self, Ending, Failure, Observation, Termination};
use patina_dst_conformance::host;
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
/// that agrees with the scenario's first vehicle (`reference`, which the
/// first sets). Off the pinned kernel a failed native check is the host
/// answering as its own release does: a divergence, and no oracle for
/// patina (`Ok(false)`). Native vehicles that disagree, and a native run
/// that fails otherwise, fail on every host.
pub(super) fn judge_native(
    oracle: &Oracle,
    vehicle: Vehicle,
    native: &Observation,
    reference: &mut Option<(Vehicle, Observation)>,
    diverged: &mut Vec<String>,
) -> Result<bool, Vec<String>> {
    let judged = match compare::native_verdict(native) {
        Ok(()) => true,
        Err(error) if !oracle.authoritative && compare::failed_check(native).is_some() => {
            diverged.push(format!("native: {error}"));
            false
        }
        Err(error) => {
            return Err(vec![format!(
                "the native run is no oracle: {error}\n{}",
                tail(&native.stderr)
            )]);
        }
    };
    match reference {
        Some((first, observation)) => {
            compare::vehicles_agree(observation, native).map_err(|failures| {
                prefixed(
                    &format!("natively, differs from {}: ", first.name()),
                    failures,
                )
            })?
        }
        None => *reference = Some((vehicle, native.clone())),
    }
    Ok(judged)
}

pub(super) fn prefixed(prefix: &str, lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .map(|line| format!("{prefix}{line}"))
        .collect()
}

/// A patina signal death that neither the native run (dying of the same
/// signal) nor a stopping gap of the vehicle (declaring that signal)
/// accounts for: a crash, which fails on every host.
pub(super) fn undeclared_death(
    native: &Observation,
    recorded: &Observation,
    gaps: &[&catalog::Gap],
) -> Option<String> {
    let Termination::Signaled { signal, .. } = recorded.termination else {
        return None;
    };
    let natively =
        matches!(native.termination, Termination::Signaled { signal: s, .. } if s == signal);
    let declared = gaps.iter().any(|gap| {
        matches!(gap.failure, Failure::Stops { ending: Ending::Signal(s), .. } if s == signal)
    });
    (!natively && !declared).then(|| {
        format!(
            "patina: the run died ({}) where natively it {}, and no gap declares it",
            recorded.termination, native.termination
        )
    })
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
        let native = planted(&[("close", 0), ("check", 1)], Termination::Exited(0));
        let patina = planted(&[("close", -1), ("check", 1)], Termination::Exited(0));
        let failed = planted(&[("close", 0), ("check", 0)], Termination::Exited(101));
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
            judge_native(&off, Vehicle::Libc, &failed, &mut reference, &mut diverged),
            Ok(false)
        );
        assert_eq!(diverged.len(), before + 1);
        assert!(judge_native(&pinned, Vehicle::Libc, &failed, &mut None, &mut Vec::new()).is_err());

        let mut reference = Some((Vehicle::Libc, native.clone()));
        let disagreeing = planted(
            &[("close", 0), ("check", 1), ("close", 0)],
            Termination::Exited(0),
        );
        let mut none = Vec::new();
        assert!(
            judge_native(
                &off,
                Vehicle::Syscall,
                &disagreeing,
                &mut reference,
                &mut none
            )
            .is_err()
        );
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

    /// A patina signal death is a crash on every host unless the native run
    /// died of the same signal or a stopping gap of the vehicle declares it.
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
        for (native, patina, gaps, crash) in [
            (exited, died, &[][..], true),
            (exited, died, &[&segv][..], true),
            (exited, died, &[&abort][..], false),
            (died, died, &[][..], false),
            (exited, failed, &[][..], false),
        ] {
            let native = planted(&[("check", 1)], native);
            let patina = planted(&[("check", 1)], patina);
            assert_eq!(
                undeclared_death(&native, &patina, gaps).is_some(),
                crash,
                "{} vs {}",
                native.termination,
                patina.termination
            );
        }
    }
}
