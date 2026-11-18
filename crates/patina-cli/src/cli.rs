//! The command line: one static table of commands and one of flags. The parser, `--help`
//! and `--help --format json` all read these tables, so they cannot disagree.

use crate::outcome::Outcome;
use std::collections::BTreeMap;

pub type Res<T> = Result<T, String>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmd {
    Run,
    Replay,
    Verify,
    Log,
    Table,
    Doctor,
    Sweep,
    Report,
    Minimize,
}

pub struct Command {
    pub cmd: Cmd,
    pub name: &'static str,
    pub usage: &'static str,
    pub help: &'static str,
}

pub const COMMANDS: &[Command] = &[
    Command {
        cmd: Cmd::Run,
        name: "run",
        usage: "patina run [options] [-- CMD ARGS...]",
        help: "one run of a program under a seed",
    },
    Command {
        cmd: Cmd::Replay,
        name: "replay",
        usage: "patina replay RUNDIR [--out DIR]",
        help: "run again from a run directory and compare with its log",
    },
    Command {
        cmd: Cmd::Verify,
        name: "verify",
        usage: "patina verify [options] [-- CMD ARGS...]",
        help: "one seed several times under varied host conditions; names the first differing record",
    },
    Command {
        cmd: Cmd::Sweep,
        name: "sweep",
        usage: "patina sweep --seeds A..B [--cases FILE] [-j N] [run options] [-- CMD ARGS...]",
        help: "many seeds in parallel, each a normal run; findings grouped by signature",
    },
    Command {
        cmd: Cmd::Report,
        name: "report",
        usage: "patina report DIR...",
        help: "summarise run directories (a sweep's, or any made by patina run --out)",
    },
    Command {
        cmd: Cmd::Minimize,
        name: "minimize",
        usage: "patina minimize RUNDIR [--out DIR]",
        help: "drop and halve a failing run's fault settings while it fails the same way",
    },
    Command {
        cmd: Cmd::Log,
        name: "log",
        usage: "patina log dump LOG [--from SEQ] [--to SEQ] | log diff LOG LOG | log ops INCDIR | log ops --check RUNDIR",
        help: "read a boundary log, compare two, list file operations",
    },
    Command {
        cmd: Cmd::Table,
        name: "table",
        usage: "patina table",
        help: "the syscall table: every number, what Patina does with it, why",
    },
    Command {
        cmd: Cmd::Doctor,
        name: "doctor",
        usage: "patina doctor",
        help: "check the host; say what is missing and the command that fixes it",
    },
];

/// One option. `value` is the grammar of its argument (empty for a switch).
pub struct Flag {
    pub name: &'static str,
    pub value: &'static str,
    pub default: &'static str,
    pub help: &'static str,
    pub cmds: &'static [Cmd],
    pub repeat: bool,
    /// Commands whose default and help differ from `default` and `help`.
    pub per: &'static [(Cmd, &'static str, &'static str)],
    /// Commands whose value differs from `value` (a switch in one, a value in another).
    pub per_value: &'static [(Cmd, &'static str)],
}

impl Flag {
    /// The value this flag takes for `c` (empty: a switch).
    pub fn value_for(&self, c: Cmd) -> &'static str {
        self.per_value
            .iter()
            .find(|p| p.0 == c)
            .map(|p| p.1)
            .unwrap_or(self.value)
    }

    /// The default and help this flag has for `c`.
    pub fn for_cmd(&self, c: Cmd) -> (&'static str, &'static str) {
        self.per
            .iter()
            .find(|p| p.0 == c)
            .map(|p| (p.1, p.2))
            .unwrap_or((self.default, self.help))
    }
}

const RUNLIKE: &[Cmd] = &[Cmd::Run, Cmd::Verify, Cmd::Sweep];
const ALL: &[Cmd] = &[
    Cmd::Run,
    Cmd::Replay,
    Cmd::Verify,
    Cmd::Log,
    Cmd::Table,
    Cmd::Doctor,
    Cmd::Sweep,
    Cmd::Report,
    Cmd::Minimize,
];

const fn flag(
    name: &'static str,
    value: &'static str,
    default: &'static str,
    help: &'static str,
    cmds: &'static [Cmd],
) -> Flag {
    Flag {
        name,
        value,
        default,
        help,
        cmds,
        repeat: false,
        per: &[],
        per_value: &[],
    }
}

const fn many(
    name: &'static str,
    value: &'static str,
    help: &'static str,
    cmds: &'static [Cmd],
) -> Flag {
    Flag {
        name,
        value,
        default: "",
        help,
        cmds,
        repeat: true,
        per: &[],
        per_value: &[],
    }
}

pub const FLAGS: &[Flag] = &[
    flag(
        "--seed",
        "N",
        "0",
        "the seed (default from PATINA_SEED)",
        &[Cmd::Run, Cmd::Verify],
    ),
    Flag {
        name: "--out",
        value: "DIR",
        default: "patina-out/run-SEED",
        help: "run directory; an earlier run there is replaced",
        cmds: &[Cmd::Run, Cmd::Verify, Cmd::Replay, Cmd::Sweep, Cmd::Minimize],
        repeat: false,
        per: &[
            (
                Cmd::Verify,
                "patina-out/verify-SEED",
                "directory of the runs (run-0, run-1, ...); an earlier one there is replaced",
            ),
            (
                Cmd::Replay,
                "RUNDIR/replay",
                "the replay's run directory; an earlier one there is replaced",
            ),
            (
                Cmd::Sweep,
                "patina-out/sweep",
                "sweep directory: the same sweep there (program, command, settings, patina) resumes, running only the runs it lacks; any other is replaced",
            ),
            (
                Cmd::Minimize,
                "RUNDIR/minimized",
                "the reduced run's directory; an earlier one there is replaced",
            ),
        ],
        per_value: &[],
    },
    flag(
        "--config",
        "FILE",
        "./patina.toml if present",
        "configuration file: a patina.toml, or a run's run.json for all its settings; flags override it",
        RUNLIKE,
    ),
    many("--env", "K=V", "add to the guest environment", RUNLIKE),
    many(
        "--mount",
        "SRC:DST[:copy]",
        "host file or directory, read-only in the guest; :copy copies a directory in at start",
        RUNLIKE,
    ),
    flag(
        "--work",
        "DIR[:GUEST]",
        "empty",
        "initial contents of the guest's writable, crash-modelled disk, at GUEST (default /work)",
        RUNLIKE,
    ),
    flag("--stdin", "FILE", "empty", "guest standard input", RUNLIKE),
    flag("--cpus", "N", "4", "CPU count the guest sees (1 to 64)", RUNLIKE),
    flag(
        "--preempt",
        "traps|branches",
        "traps",
        "where threads are preempted: system calls and spin-waits, or also after N branches (needs CAP_PERFMON and a supported CPU)",
        RUNLIKE,
    ),
    flag(
        "--faults",
        "NAME",
        "off",
        "fault preset: disk, net, all (or several: disk,net); its rates are ranges the seed resolves",
        RUNLIKE,
    ),
    many(
        "--fault",
        "KEY=VALUE",
        "one fault setting; replaces the preset's (keys below)",
        RUNLIKE,
    ),
    flag(
        "--crash",
        "KIND[:VALUE]",
        "off",
        "crash and restart: machine[:PERMILLE], process[:PERMILLE] (default 3), machine-at:N, process-at:N (the N-th crash point); PERMILLE and N may be A..B",
        RUNLIKE,
    ),
    flag(
        "--buggify",
        "",
        "off",
        "let SDK fault points fire (rates: --fault buggify-permille=N, --fault point:LABEL=N)",
        RUNLIKE,
    ),
    flag(
        "--time-limit",
        "SECONDS",
        "3600",
        "virtual time after which the run ends liveness",
        RUNLIKE,
    ),
    flag(
        "--timeout",
        "SECONDS",
        "600",
        "wall time after which the run ends timeout",
        RUNLIKE,
    ),
    flag(
        "--log-limit",
        "MIB",
        "1024",
        "size of the run's logs at which it ends unsupported (log-limit): a livelock's log fills the disk",
        RUNLIKE,
    ),
    flag("--runs", "N", "3", "runs to compare", &[Cmd::Verify]),
    flag(
        "--vary",
        "LIST",
        "none",
        "what to change between runs: cpu,load,aslr,sandbox,repeat,parallel,env,time",
        &[Cmd::Verify],
    ),
    flag(
        "--seeds",
        "A..B|N,M,...",
        "",
        "the seeds: an inclusive range, a list, or both (1..100,250)",
        &[Cmd::Sweep],
    ),
    flag(
        "--jobs",
        "N",
        "half the CPUs, at most 8",
        "runs at once, each pinned to its own CPU (also -j N)",
        &[Cmd::Sweep],
    ),
    flag(
        "--cases",
        "FILE",
        "none",
        "one case per line, each (case, seed) one run: a line is a whole command (shell quoting), or fills {} in the command after --",
        &[Cmd::Sweep],
    ),
    flag(
        "--keep",
        "fail|all|none",
        "fail",
        "whose logs to keep (run.json and result.json are always kept)",
        &[Cmd::Sweep],
    ),
    flag(
        "--max-findings",
        "N",
        "no limit",
        "stop launching runs once N distinct findings (signatures) are seen; 1: the first",
        &[Cmd::Sweep],
    ),
    flag(
        "--branch",
        "",
        "off",
        "run each seed once without a crash, then once per crash point, crashing there (needs --crash machine or process, without a rate)",
        &[Cmd::Sweep],
    ),
    flag(
        "--budget",
        "SECONDS",
        "no limit",
        "stop launching runs after this much wall time",
        &[Cmd::Sweep],
    ),
    many(
        "--allow-unmet",
        "LABEL",
        "an SDK label or fault class that may stay unmet without making the result vacuous",
        &[Cmd::Sweep, Cmd::Report],
    ),
    flag("--from", "SEQ", "0", "log dump: first record", &[Cmd::Log]),
    flag("--to", "SEQ", "last", "log dump: last record", &[Cmd::Log]),
    Flag {
        name: "--check",
        value: "'CMD ARGS'",
        default: "none",
        help: "after a run that ends ok, run CMD ARGS RUNDIR on the host, as you, not sandboxed, from this directory (env PATINA_SEED, PATINA_EXIT, PATINA_CASE, PATINA_CASE_NAME; output in RUNDIR/check.out); exit 0 pass, 1 finding named by its first stdout line LABEL: detail, 77 not judged, else error; at most --timeout seconds",
        cmds: &[Cmd::Run, Cmd::Verify, Cmd::Sweep, Cmd::Log],
        repeat: false,
        per: &[(
            Cmd::Log,
            "",
            "log ops: replay the whole operation log and compare with the exported tree",
        )],
        per_value: &[(Cmd::Log, "")],
    },
    flag(
        "--format",
        "text|json",
        "text",
        "output format (default from PATINA_FORMAT); json prints result.json",
        ALL,
    ),
    flag("--help", "", "", "this help", ALL),
];

pub fn find_flag(name: &str) -> Option<&'static Flag> {
    FLAGS.iter().find(|f| f.name == name)
}

/// A parsed command line: the flags given (in order, by name), the positional words, and
/// the guest command after `--`.
#[derive(Debug, Default)]
pub struct Args {
    pub flags: BTreeMap<&'static str, Vec<String>>,
    pub positional: Vec<String>,
    pub cmd: Option<Vec<String>>,
}

impl Args {
    pub fn last(&self, name: &str) -> Option<&str> {
        self.flags
            .get(name)
            .and_then(|v| v.last())
            .map(|s| s.as_str())
    }
    pub fn all(&self, name: &str) -> &[String] {
        self.flags.get(name).map(|v| v.as_slice()).unwrap_or(&[])
    }
    pub fn has(&self, name: &str) -> bool {
        self.flags.contains_key(name)
    }
    pub fn num<T: std::str::FromStr>(&self, name: &str) -> Res<Option<T>> {
        match self.last(name) {
            None => Ok(None),
            Some(v) => v
                .parse()
                .map(Some)
                .map_err(|_| format!("{name}: not a number: {v}")),
        }
    }
    pub fn json(&self) -> bool {
        match self.last("--format") {
            Some(f) => f == "json",
            None => std::env::var("PATINA_FORMAT").is_ok_and(|v| v == "json"),
        }
    }
}

/// Parse `args` (after the command name) against the flag table.
pub fn parse(cmd: Cmd, args: &[String]) -> Res<Args> {
    let mut out = Args::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--" {
            out.cmd = Some(it.cloned().collect());
            break;
        }
        if !a.starts_with("--") || a == "-" {
            if a == "-h" {
                out.flags.entry("--help").or_default();
                continue;
            }
            if a == "-j" && cmd == Cmd::Sweep {
                let v = it.next().ok_or("-j needs N")?;
                out.flags.insert("--jobs", vec![v.clone()]);
                continue;
            }
            out.positional.push(a.clone());
            continue;
        }
        let (name, inline) = match a.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (a.as_str(), None),
        };
        let f = find_flag(name)
            .filter(|f| f.cmds.contains(&cmd))
            .ok_or_else(|| format!("unknown option {name} (patina {} --help)", cmd_name(cmd)))?;
        let v = if f.value_for(cmd).is_empty() {
            if inline.is_some() {
                return Err(format!("{name} takes no value"));
            }
            String::new()
        } else {
            match inline {
                Some(v) => v,
                None => it
                    .next()
                    .cloned()
                    .ok_or_else(|| format!("{name} needs {}", f.value_for(cmd)))?,
            }
        };
        if f.name == "--format" && v != "text" && v != "json" {
            return Err(format!("--format: expected text or json, not {v}"));
        }
        let e = out.flags.entry(f.name).or_default();
        if !f.repeat {
            e.clear();
        }
        e.push(v);
    }
    Ok(out)
}

pub fn cmd_name(c: Cmd) -> &'static str {
    COMMANDS
        .iter()
        .find(|x| x.cmd == c)
        .map(|x| x.name)
        .unwrap()
}

pub fn find_cmd(name: &str) -> Option<Cmd> {
    COMMANDS.iter().find(|x| x.name == name).map(|x| x.cmd)
}

fn flag_text(f: &Flag, c: Cmd) -> String {
    let mut lhs = f.name.to_string();
    if !f.value_for(c).is_empty() {
        lhs = format!("{lhs} {}", f.value_for(c));
    }
    let (default, help) = f.for_cmd(c);
    let mut s = format!("  {lhs:<26} {help}");
    if !default.is_empty() {
        s.push_str(&format!(" [default: {default}]"));
    }
    if f.repeat {
        s.push_str(" (repeatable)");
    }
    s
}

/// Help text: every command, or one command and its flags.
pub fn help_text(cmd: Option<Cmd>) -> String {
    let mut s = String::new();
    match cmd {
        None => {
            s.push_str("patina: deterministic simulation testing of any Linux program (x86_64, arm64)\n\nusage: patina COMMAND [options]\n\ncommands:\n");
            for c in COMMANDS {
                s.push_str(&format!("  {:<8} {}\n", c.name, c.help));
            }
            s.push_str(
                "\npatina COMMAND --help for its options; --help --format json for all of them;\npatina --version for the version.\n",
            );
            s.push_str("\noutcomes and exit status:\n");
            for o in Outcome::ALL {
                s.push_str(&format!("  {:<17} {}\n", o.name(), o.exit()));
            }
        }
        Some(c) => {
            let info = COMMANDS.iter().find(|x| x.cmd == c).unwrap();
            s.push_str(&format!("{}\n\n{}\n\noptions:\n", info.usage, info.help));
            for f in FLAGS.iter().filter(|f| f.cmds.contains(&c)) {
                s.push_str(&flag_text(f, c));
                s.push('\n');
            }
            if RUNLIKE.contains(&c) {
                s.push_str(&crate::faults::help_text());
            }
        }
    }
    s
}

/// The tables as JSON, for agents: every command and every flag with the commands taking it.
pub fn help_json() -> String {
    let cmds: Vec<serde_json::Value> = COMMANDS
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "usage": c.usage,
                "help": c.help,
                "flags": FLAGS.iter().filter(|f| f.cmds.contains(&c.cmd)).map(|f| f.name).collect::<Vec<_>>(),
            })
        })
        .collect();
    let flags: Vec<serde_json::Value> = FLAGS
        .iter()
        .map(|f| {
            serde_json::json!({
                "name": f.name,
                "value": f.value,
                "default": f.default,
                "help": f.help,
                "repeat": f.repeat,
                "commands": f.cmds.iter().map(|c| cmd_name(*c)).collect::<Vec<_>>(),
                "by_command": f.per.iter().map(|(c, d, h)| (cmd_name(*c).to_string(), serde_json::json!({"value": f.value_for(*c), "default": d, "help": h}))).collect::<serde_json::Map<_, _>>(),
            })
        })
        .collect();
    let outcomes: Vec<serde_json::Value> = Outcome::ALL
        .iter()
        .map(|o| serde_json::json!({ "name": o.name(), "exit": o.exit() }))
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "commands": cmds,
        "flags": flags,
        "outcomes": outcomes,
        "faults": crate::faults::help_json(),
    }))
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn every_flag_parses_for_every_command_listing_it() {
        for f in FLAGS {
            for &c in f.cmds {
                let mut a = vec![f.name.to_string()];
                if !f.value_for(c).is_empty() {
                    a.push(if f.name == "--format" { "json" } else { "1" }.into());
                }
                let p = parse(c, &a).unwrap_or_else(|e| panic!("{} {}: {e}", cmd_name(c), f.name));
                assert!(p.has(f.name));
            }
        }
    }

    #[test]
    fn unknown_and_foreign_flags_are_refused() {
        assert!(parse(Cmd::Run, &v(&["--bogus"])).is_err());
        assert!(parse(Cmd::Run, &v(&["--runs", "3"])).is_err());
        let p = parse(
            Cmd::Run,
            &v(&[
                "--seed=4", "--env", "A=1", "--env", "B=2", "--", "x", "--seed",
            ]),
        )
        .unwrap();
        assert_eq!(p.last("--seed"), Some("4"));
        assert_eq!(p.all("--env").len(), 2);
        assert_eq!(p.cmd, Some(v(&["x", "--seed"])));
    }
}
