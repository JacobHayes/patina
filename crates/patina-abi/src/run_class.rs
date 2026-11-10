//! How a run ended: the one outcome vocabulary, and who each outcome is
//! attributed to.

/// How one run ended. The single classification `run`, `test` and `campaign`
/// report, in their human output and in their JSON: the native shim names a
/// class when it stops a run, the supervisor names one for every run it
/// finishes, and a campaign files each generation under the same name.
///
/// A **closed** enum: its attribution and the tool's exit status are total
/// functions of the class ([`RunClass::attribution`], [`RunClass::exit_code`]),
/// so no outcome can exist without either.
///
/// The declaration order is the order a campaign resolves two matching
/// declarations in, more severe first after [`RunClass::Ok`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RunClass {
    /// The run finished and nothing was found.
    Ok,
    /// Two runs of one recording or one generation disagreed: a replay left
    /// its trace, or a campaign's reproduction did not reproduce. Every other
    /// class's reproduction rests on determinism, so nothing outranks it.
    Nondeterministic,
    /// An invariant the guest declared was violated: an `always!`, a
    /// `violation` verdict, a class a campaign spec declared for this guest,
    /// or an SDK contract the guest broke.
    Violation,
    /// The guest stopped making progress: the virtual-time liveness or
    /// convergence watchdog fired, or every thread is blocked with none left
    /// to run (a deadlock).
    Liveness,
    /// The guest died on a signal: its own `abort()`, a failed C `assert`, a
    /// segmentation fault or another fatal signal.
    Crash,
    /// The guest ended with a nonzero exit status, a Rust panic's included.
    Failure,
    /// A fault or exploration plane a campaign configured had nothing to act
    /// on in a generation that otherwise passed.
    Vacuous,
    /// The run did not finish within a bound: the host-time compute bound,
    /// the step budget, or a campaign's wall-clock backstop.
    Timeout,
    /// The guest did something Patina does not model.
    Unsupported,
    /// Patina itself failed, or the host took the run away.
    Internal,
    /// The request could not be carried out as given: a usage error, a build
    /// that failed, an input that is missing or belongs to another build.
    Error,
}

/// Who a run's outcome is attributed to: whose move it is next.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Attribution {
    /// A finding in the guest: investigate the program under test.
    Guest,
    /// The guest reached something Patina does not model. Not evidence of a
    /// bug in the guest.
    PatinaUnsupported,
    /// A bug in Patina, or a failure of the host it ran on. Not evidence of a
    /// bug in the guest.
    PatinaInternal,
    /// The request itself: the command, its inputs or its configuration.
    Request,
}

impl RunClass {
    /// Every class, in declaration order. The compiler holds it complete: see
    /// the exhaustive match below the `impl`.
    pub const ALL: &'static [RunClass] = &[
        RunClass::Ok,
        RunClass::Nondeterministic,
        RunClass::Violation,
        RunClass::Liveness,
        RunClass::Crash,
        RunClass::Failure,
        RunClass::Vacuous,
        RunClass::Timeout,
        RunClass::Unsupported,
        RunClass::Internal,
        RunClass::Error,
    ];

    /// The class's one name, everywhere it is written.
    pub const fn as_str(self) -> &'static str {
        match self {
            RunClass::Ok => "ok",
            RunClass::Nondeterministic => "nondeterministic",
            RunClass::Violation => "violation",
            RunClass::Liveness => "liveness",
            RunClass::Crash => "crash",
            RunClass::Failure => "failure",
            RunClass::Vacuous => "vacuous",
            RunClass::Timeout => "timeout",
            RunClass::Unsupported => "unsupported",
            RunClass::Internal => "internal",
            RunClass::Error => "error",
        }
    }

    /// What the class means, in one line: the outcome table's own text, for
    /// the help and the docs to print rather than restate.
    pub const fn summary(self) -> &'static str {
        match self {
            RunClass::Ok => "the run finished and nothing was found",
            RunClass::Nondeterministic => {
                "two runs of one recording or generation disagreed (a replay left its trace)"
            }
            RunClass::Violation => {
                "an invariant the guest declared was violated (always!, a violation verdict)"
            }
            RunClass::Liveness => {
                "the guest stopped making progress (the liveness watchdog, a deadlock)"
            }
            RunClass::Crash => "the guest died on a signal (abort, a segmentation fault)",
            RunClass::Failure => "the guest exited nonzero (a panic, a failed assertion)",
            RunClass::Vacuous => {
                "a configured fault or exploration plane had nothing to act on (campaign)"
            }
            RunClass::Timeout => {
                "the run did not finish within a bound (compute bound, step budget, campaign backstop)"
            }
            RunClass::Unsupported => "the guest did something Patina does not model",
            RunClass::Internal => "Patina itself failed, or the host took the run away",
            RunClass::Error => {
                "the request could not be carried out (usage, build, a missing or mismatched input)"
            }
        }
    }

    /// Parse the name [`RunClass::as_str`] renders. `None` for anything else:
    /// a caller refuses the document rather than guess a class.
    pub fn from_name(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|class| class.as_str() == text)
    }

    /// Who the outcome is attributed to; `None` only for a clean run.
    pub const fn attribution(self) -> Option<Attribution> {
        match self {
            RunClass::Ok => None,
            RunClass::Violation | RunClass::Liveness | RunClass::Crash | RunClass::Failure => {
                Some(Attribution::Guest)
            }
            RunClass::Timeout | RunClass::Unsupported => Some(Attribution::PatinaUnsupported),
            RunClass::Nondeterministic | RunClass::Internal => Some(Attribution::PatinaInternal),
            RunClass::Vacuous | RunClass::Error => Some(Attribution::Request),
        }
    }

    /// The tool's exit status for this outcome: 0 clean, 1 a finding in the
    /// guest, 2 Patina could not do what was asked.
    pub const fn exit_code(self) -> i32 {
        match self.attribution() {
            None => 0,
            Some(Attribution::Guest) => 1,
            Some(
                Attribution::PatinaUnsupported | Attribution::PatinaInternal | Attribution::Request,
            ) => 2,
        }
    }

    /// Whether the run is anything but clean.
    pub const fn is_failure(self) -> bool {
        !matches!(self, RunClass::Ok)
    }

    /// Whether this is a finding in the guest.
    pub const fn is_finding(self) -> bool {
        matches!(self.attribution(), Some(Attribution::Guest))
    }
}

impl Attribution {
    /// The attribution's one name, everywhere it is written.
    pub const fn as_str(self) -> &'static str {
        match self {
            Attribution::Guest => "guest",
            Attribution::PatinaUnsupported => "patina_unsupported",
            Attribution::PatinaInternal => "patina_internal",
            Attribution::Request => "request",
        }
    }
}

impl std::fmt::Display for RunClass {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::fmt::Display for Attribution {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

// `RunClass::ALL` is complete by construction. The match has no wildcard, so
// a variant added to the enum does not compile until it is given a place
// here, its index in `ALL`; the loop then holds every entry of `ALL` to its
// place and to declaration order.
const _: () = {
    const fn place(class: RunClass) -> usize {
        match class {
            RunClass::Ok => 0,
            RunClass::Nondeterministic => 1,
            RunClass::Violation => 2,
            RunClass::Liveness => 3,
            RunClass::Crash => 4,
            RunClass::Failure => 5,
            RunClass::Vacuous => 6,
            RunClass::Timeout => 7,
            RunClass::Unsupported => 8,
            RunClass::Internal => 9,
            RunClass::Error => 10,
        }
    }
    let all = RunClass::ALL;
    let mut index = 0;
    while index < all.len() {
        assert!(place(all[index]) == index && all[index] as usize == index);
        index += 1;
    }
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_class_round_trips_and_only_a_clean_run_exits_zero() {
        for class in RunClass::ALL {
            assert_eq!(RunClass::from_name(class.as_str()), Some(*class));
            assert_eq!(class.exit_code() == 0, *class == RunClass::Ok);
            assert_eq!(class.attribution().is_none(), *class == RunClass::Ok);
            assert_eq!(class.exit_code() == 1, class.is_finding());
        }
        assert_eq!(RunClass::from_name("OK"), None);
    }
}
