//! The one outcome model: the supervisor's verdict (one line over the outcome pipe), the
//! eleven outcome classes, and the tool's exit status. `classify` is the only place a
//! verdict becomes an outcome; nothing else names one.

/// What the supervisor (or the launcher) decided. Sent as
/// `class \t exit_status \t signal \t detail \n`. `class` is the engine's own token
/// (`ok`, `failed`, `deadlock`, `liveness`, `stall`, `containment`, `unsupported`, `capacity`,
/// `log-limit`, `disk-full`, `killed`, `infra`, `exec`, `exec-unsupported`, `timeout`, `crash` between boots); `classify` maps it to an [`Outcome`].
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

    /// What the outcome means and what to do about it: one line, for `patina guide outcomes`.
    pub const fn means(self) -> &'static str {
        match self {
            Outcome::Ok => "the program exited 0 (or with a status `--ok-exit` names) and failed no check; what that proves is what the checks could detect",
            Outcome::Violation => "a check failed: an SDK `always` or `unreachable`, or the `--check` command answered 1",
            Outcome::Liveness => "every thread blocked (deadlock), `[run] time-limit` of virtual time passed, or the log reached `[run] log-limit` (livelock)",
            Outcome::Failure => "the program exited nonzero with a status `--ok-exit` does not name",
            Outcome::Crash => "the program died on a signal",
            Outcome::Unsupported => "the program did something Patina does not model; the message names it. Not a bug in the program",
            Outcome::Timeout => "`--timeout` of wall time passed: a loop in code without points, or a hang outside virtual time",
            Outcome::Nondeterministic => "a replay differed from its run: a Patina bug. Keep the run directory and report it",
            Outcome::Internal => "Patina failed, or the host refused a resource: run `patina doctor`",
            Outcome::Vacuous => "something asked for never happened: a fault you named, an SDK `sometimes`, `reachable` or fault point, a check that judged no run, a `!ID` known finding",
            Outcome::Error => "the command could not be carried out: the program cannot run, its setup did not complete (stop `setup`, `setup-mark`), or the `--check` command broke or answered differently on replay",
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

/// A run that ended `ok` on its own, by its exit status: 0, or one `--ok-exit` allows.
pub fn ok_end(exit: i64) -> Classified {
    if exit == 0 {
        Classified::new(Outcome::Ok, "exit", "the program exited 0")
    } else {
        Classified::new(
            Outcome::Ok,
            "ok-exit",
            format!("the program exited {exit}, a status --ok-exit allows"),
        )
    }
}

/// The one mapping from a verdict to an outcome. `ok_exit` holds the exit statuses that end
/// the run `ok` (`--ok-exit`): a clean failure the program documents, stop `ok-exit`. A
/// signal is a crash whatever the list says, an exit after the program's `INVARIANT` line a
/// failure, and every other verdict stands.
pub fn classify(v: &Verdict, ok_exit: &[u8]) -> Classified {
    use Outcome::*;
    let d = v.detail.as_str();
    match v.class.as_str() {
        "ok" => ok_end(0),
        "failed" => match (v.signal, v.exit_status) {
            (Some(sig), _) => Classified::new(
                Crash,
                "signal",
                format!("killed by signal {sig} ({})", signal_name(sig)),
            ),
            // A program's own `INVARIANT` line (its detail) is a finding whatever its status.
            (None, Some(x))
                if ok_exit.iter().any(|&o| i64::from(o) == x) && !d.starts_with("INVARIANT ") =>
            {
                ok_end(x)
            }
            (None, _) => Classified::new(Failure, "exit", d),
        },
        // A machine's command (`proto::machine`): an exit outside its `ok-exit`, or a signal Patina
        // did not send. The detail names the machine.
        "machine-failed" => Classified::new(Failure, "exit", d),
        "machine-crash" => Classified::new(Crash, "signal", d),
        "violation" => Classified::new(Violation, "always", d),
        "deadlock" => Classified::new(
            Liveness,
            "deadlock",
            format!("every thread is blocked with no deadline: {d}"),
        ),
        "liveness" => Classified::new(Liveness, "time-limit", d),
        "stall" => Classified::new(Unsupported, "compute-stall", d),
        "containment" => Classified::new(Unsupported, "containment", d),
        "compute-cell" => Classified::new(Unsupported, "compute-cell", d),
        "unsupported" => Classified::new(
            Unsupported,
            "syscall",
            format!("the program called {d}, which Patina does not support"),
        ),
        "capacity" => Classified::new(Unsupported, "capacity", d),
        "signal-context" => Classified::new(Unsupported, "signal-context", d),
        // A run that never finished: as a time limit, a log full of a loop is a liveness finding.
        "log-limit" => Classified::new(Liveness, "log-limit", d),
        "output-limit" => Classified::new(Unsupported, "output-limit", d),
        "timeout" => Classified::new(Timeout, "timeout", d),
        "disk-full" => Classified::new(Internal, "disk-full", d),
        "infra" => Classified::new(Internal, "internal", d),
        // A guest process killed by SIGKILL from outside the run (the host's OOM killer).
        "killed" => Classified::new(Internal, "killed", d),
        // The program cannot run, as `execve` would refuse it: the request is wrong.
        "exec" => Classified::new(Error, "exec", d),
        // The program marked `setup-complete` and the run does not declare that it does.
        crate::sup::sdk::SETUP_MARK => Classified::new(Error, "setup-mark", d),
        // An image the kernel would run that Patina does not load (a 32-bit program).
        "exec-unsupported" => Classified::new(Unsupported, "exec", d),
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
        assert_eq!(classify(&v, &[]).outcome, Outcome::Crash);
        let mut v = Verdict::new("failed", "exit status 3");
        v.exit_status = Some(3);
        assert_eq!(classify(&v, &[]).outcome, Outcome::Failure);
        assert_eq!(
            classify(&Verdict::new("stall", "x"), &[]).stop,
            "compute-stall".to_string()
        );
        assert_eq!(
            classify(&Verdict::new("bogus", "x"), &[]).outcome,
            Outcome::Internal
        );
    }

    #[test]
    fn ok_exit_takes_only_its_statuses_and_never_a_signal() {
        let failed = |status: i64, sig: Option<i64>| Verdict {
            class: "failed".into(),
            exit_status: Some(status),
            signal: sig,
            detail: String::new(),
        };
        let ok = classify(&failed(1, None), &[1, 3]);
        assert_eq!((ok.outcome, ok.stop.as_str()), (Outcome::Ok, "ok-exit"));
        assert_eq!(
            classify(&failed(2, None), &[1, 3]).outcome,
            Outcome::Failure
        );
        // A signal's status (128 + N) in the list is still a crash.
        assert_eq!(
            classify(&failed(134, Some(6)), &[134]).outcome,
            Outcome::Crash
        );
        let mut v = failed(1, None);
        v.detail = "INVARIANT kept: no".into();
        assert_eq!(classify(&v, &[1]).outcome, Outcome::Failure);
        let mut v = Verdict::new("violation", "always");
        v.exit_status = Some(1);
        assert_eq!(classify(&v, &[1]).outcome, Outcome::Violation);
    }
}
