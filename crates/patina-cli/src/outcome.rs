//! The one outcome model: the supervisor's verdict (one line over the outcome pipe), the
//! eleven outcome classes, and the tool's exit status. `classify` is the only place a
//! verdict becomes an outcome; nothing else names one.

/// What the supervisor (or the launcher) decided. Sent as
/// `class \t exit_status \t signal \t detail \n`. `class` is the engine's own token
/// (`ok`, `failed`, `deadlock`, `liveness`, `stall`, `containment`, `unsupported`, `infra`, `timeout`,
/// `crash` between incarnations); `classify` maps it to an [`Outcome`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub class: String,
    pub exit_status: Option<i64>,
    pub signal: Option<i64>,
    pub detail: String,
}

impl Verdict {
    pub fn new(class: &str, detail: impl Into<String>) -> Verdict {
        Verdict {
            class: class.into(),
            exit_status: None,
            signal: None,
            detail: detail.into(),
        }
    }
    pub fn encode(&self) -> String {
        let opt = |v: Option<i64>| v.map(|x| x.to_string()).unwrap_or_else(|| "-".into());
        let detail: String = self
            .detail
            .chars()
            .map(|c| if c == '\t' || c == '\n' { ' ' } else { c })
            .collect();
        format!(
            "{}\t{}\t{}\t{}\n",
            self.class,
            opt(self.exit_status),
            opt(self.signal),
            detail
        )
    }
    pub fn decode(s: &str) -> Option<Verdict> {
        let line = s.lines().next()?;
        let mut f = line.splitn(4, '\t');
        let class = f.next()?.to_string();
        let num = |x: Option<&str>| x.and_then(|v| v.parse::<i64>().ok());
        let exit_status = num(f.next());
        let signal = num(f.next());
        let detail = f.next().unwrap_or("").to_string();
        Some(Verdict {
            class,
            exit_status,
            signal,
            detail,
        })
    }
}

/// How a run ended. A closed set: the exit status is a total function of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Outcome {
    Ok,
    Violation,
    Liveness,
    Failure,
    Crash,
    Unsupported,
    Timeout,
    Nondeterministic,
    Internal,
    Vacuous,
    Error,
}

impl Outcome {
    pub const ALL: [Outcome; 11] = [
        Outcome::Ok,
        Outcome::Violation,
        Outcome::Liveness,
        Outcome::Failure,
        Outcome::Crash,
        Outcome::Unsupported,
        Outcome::Timeout,
        Outcome::Nondeterministic,
        Outcome::Internal,
        Outcome::Vacuous,
        Outcome::Error,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Violation => "violation",
            Outcome::Liveness => "liveness",
            Outcome::Failure => "failure",
            Outcome::Crash => "crash",
            Outcome::Unsupported => "unsupported",
            Outcome::Timeout => "timeout",
            Outcome::Nondeterministic => "nondeterministic",
            Outcome::Internal => "internal",
            Outcome::Vacuous => "vacuous",
            Outcome::Error => "error",
        }
    }

    /// The tool's exit status: 0 clean, 1 a finding in the guest, 2 anything that is not
    /// evidence about the guest (Patina could not decide, or the request was wrong).
    pub const fn exit(self) -> u8 {
        match self {
            Outcome::Ok => 0,
            Outcome::Violation | Outcome::Liveness | Outcome::Failure | Outcome::Crash => 1,
            Outcome::Unsupported
            | Outcome::Timeout
            | Outcome::Nondeterministic
            | Outcome::Internal
            | Outcome::Vacuous
            | Outcome::Error => 2,
        }
    }
}

/// A classified run: the outcome, a short `stop` token and one sentence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classified {
    pub outcome: Outcome,
    pub stop: String,
    pub message: String,
}

impl Classified {
    pub fn new(outcome: Outcome, stop: &str, message: impl Into<String>) -> Classified {
        Classified {
            outcome,
            stop: stop.into(),
            message: message.into(),
        }
    }
}

/// The signal's name (`SIGABRT`), or its number.
pub fn signal_name(sig: i64) -> String {
    let n = match sig {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        10 => "SIGUSR1",
        11 => "SIGSEGV",
        12 => "SIGUSR2",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        24 => "SIGXCPU",
        25 => "SIGXFSZ",
        31 => "SIGSYS",
        _ => return format!("signal {sig}"),
    };
    n.to_string()
}

/// The one mapping from a verdict to an outcome.
pub fn classify(v: &Verdict) -> Classified {
    use Outcome::*;
    let d = v.detail.as_str();
    match v.class.as_str() {
        "ok" => Classified::new(Ok, "exit", "the program exited 0"),
        "failed" => match v.signal {
            Some(sig) => Classified::new(
                Crash,
                "signal",
                format!("killed by signal {sig} ({})", signal_name(sig)),
            ),
            None => Classified::new(Failure, "exit", d),
        },
        "violation" => Classified::new(Violation, "always", d),
        "deadlock" => Classified::new(
            Liveness,
            "deadlock",
            format!("every thread is blocked with no deadline: {d}"),
        ),
        "liveness" => Classified::new(Liveness, "time-limit", d),
        "stall" => Classified::new(Unsupported, "compute-stall", d),
        "containment" => Classified::new(Unsupported, "containment", d),
        "unsupported" => Classified::new(
            Unsupported,
            "syscall",
            format!("the program called {d}, which Patina does not support"),
        ),
        "timeout" => Classified::new(Timeout, "timeout", d),
        "infra" => Classified::new(Internal, "internal", d),
        other => Classified::new(
            Internal,
            "internal",
            format!("unknown verdict {other}: {d}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip_and_exit_codes_partition() {
        for o in Outcome::ALL {
            let finding = matches!(
                o,
                Outcome::Violation | Outcome::Liveness | Outcome::Failure | Outcome::Crash
            );
            let want = if o == Outcome::Ok {
                0
            } else if finding {
                1
            } else {
                2
            };
            assert_eq!(o.exit(), want, "{o:?}");
        }
    }

    #[test]
    fn signals_are_crashes_and_statuses_failures() {
        let mut v = Verdict::new("failed", "killed by signal 6");
        v.signal = Some(6);
        assert_eq!(classify(&v).outcome, Outcome::Crash);
        let mut v = Verdict::new("failed", "exit status 3");
        v.exit_status = Some(3);
        assert_eq!(classify(&v).outcome, Outcome::Failure);
        assert_eq!(
            classify(&Verdict::new("stall", "x")).stop,
            "compute-stall".to_string()
        );
        assert_eq!(
            classify(&Verdict::new("bogus", "x")).outcome,
            Outcome::Internal
        );
    }
}
