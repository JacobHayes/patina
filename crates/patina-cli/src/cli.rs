//! The command line: one static table of commands and one of flags. The parser, `--help`
//! and `--help --format json` all read these tables, so they cannot disagree.

use crate::outcome::Outcome;
use std::collections::BTreeMap;

pub type Res<T> = Result<T, String>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmd {
    Run,
    Replay,
    Explain,
    Debug,
    Verify,
    Log,
    Doctor,
    Sweep,
    Report,
    Minimize,
    Ctl,
    Wait,
    Guide,
    Skill,
}

pub struct Command {
    pub cmd: Cmd,
    pub name: &'static str,
    pub usage: &'static str,
    pub help: &'static str,
}

pub const COMMANDS: &[Command] = &[
    Command {
        cmd: Cmd::Guide,
        name: "guide",
        usage: "patina guide [TOPIC] [--list] [--format md]",
        help: "start here: how to find bugs with patina, then one topic at a time",
    },
    Command {
        cmd: Cmd::Run,
        name: "run",
        usage: "patina run [options] [-- CMD ARGS...]",
        help: "one run of a program under a seed; CMD is what machine main runs",
    },
    Command {
        cmd: Cmd::Replay,
        name: "replay",
        usage: "patina replay RUNDIR [--out DIR]",
        help: "run again from a run directory and compare with its log",
    },
    Command {
        cmd: Cmd::Explain,
        name: "explain",
        usage: "patina explain RUNDIR [--from SEQ] [--to SEQ] [--full]",
        help: "a run as a story: messages, faults, output, its end, and the event to stop at",
    },
    Command {
        cmd: Cmd::Debug,
        name: "debug",
        usage: "patina debug RUNDIR [--at EVENT] [--no-gdb]",
        help: "replay a run and stop it under gdb just before one event",
    },
    Command {
        cmd: Cmd::Verify,
        name: "verify",
        usage: "patina verify [options] [-- CMD ARGS...]",
        help: "one seed under varied host conditions; names the first differing record",
    },
    Command {
        cmd: Cmd::Sweep,
        name: "sweep",
        usage: "patina sweep [--seeds A..B] [--cases FILE] [-j N] [run options] [-- CMD ARGS...]",
        help: "many seeds in parallel, each a normal run; findings grouped by signature",
    },
    Command {
        cmd: Cmd::Report,
        name: "report",
        usage: "patina report [--known FILE] [--group N] [--recheck [--check 'CMD ARGS'] [-j N]] DIR...",
        help: "summarise run directories; --recheck judges the kept runs again first",
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
        usage: "patina log dump LOG [--from SEQ] [--to SEQ] | log diff LOG LOG | log ops BOOTDIR | log ops --check RUNDIR | log tree BOOTDIR DIR [--post-crash] | log events RUNDIR [--types T,T] [--from SEQ] [--to SEQ]",
        help: "read and compare logs; list file operations; export disks and events",
    },
    Command {
        cmd: Cmd::Ctl,
        name: "ctl",
        usage: "patina ctl partition A B | partition --from A --to B | heal [A B] | crash MACHINE | kill MACHINE | start MACHINE | pause MACHINE | resume MACHINE | clock MACHINE +90s | settle [SECONDS]",
        help: "from main: act on links, machines and clocks; settle: end the faults, wait for recovery",
    },
    Command {
        cmd: Cmd::Wait,
        name: "wait",
        usage: "patina wait HOST:PORT | wait :PORT",
        help: "inside a run: one TCP connect, exit 0 if it succeeds; a `ready` probe for a server",
    },
    Command {
        cmd: Cmd::Doctor,
        name: "doctor",
        usage: "patina doctor [--print-apparmor-profile]",
        help: "check the host; say what is missing and the command that fixes it",
    },
    Command {
        cmd: Cmd::Skill,
        name: "skill",
        usage: "patina skill [DIR]",
        help: "write the skill for coding agents to DIR/patina; no DIR: where to put it",
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
/// Listed apart in `patina --help`: plumbing most users never type.
const ADVANCED: &[Cmd] = &[Cmd::Verify, Cmd::Log, Cmd::Ctl, Cmd::Wait, Cmd::Skill];
/// The commands that print a result (`--format`).
const FORMATTED: &[Cmd] = &[
    Cmd::Run,
    Cmd::Replay,
    Cmd::Explain,
    Cmd::Debug,
    Cmd::Verify,
    Cmd::Log,
    Cmd::Doctor,
    Cmd::Sweep,
    Cmd::Report,
    Cmd::Minimize,
    Cmd::Ctl,
    Cmd::Guide,
];
const ALL: &[Cmd] = &[
    Cmd::Run,
    Cmd::Replay,
    Cmd::Explain,
    Cmd::Debug,
    Cmd::Verify,
    Cmd::Log,
    Cmd::Doctor,
    Cmd::Sweep,
    Cmd::Report,
    Cmd::Minimize,
    Cmd::Ctl,
    Cmd::Wait,
    Cmd::Guide,
    Cmd::Skill,
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
    flag("--seed", "N", "0", "the seed", &[Cmd::Run, Cmd::Verify]),
    Flag {
        name: "--out",
        value: "DIR",
        default: "patina-out/run-SEED",
        help: "run directory (replaced)",
        cmds: &[
            Cmd::Run,
            Cmd::Verify,
            Cmd::Replay,
            Cmd::Sweep,
            Cmd::Minimize,
        ],
        repeat: false,
        per: &[
            (
                Cmd::Verify,
                "patina-out/verify-SEED",
                "directory of the runs (replaced)",
            ),
            (
                Cmd::Replay,
                "RUNDIR/replay",
                "the replay's run directory (replaced)",
            ),
            (
                Cmd::Sweep,
                "patina-out/sweep",
                "sweep directory (the same sweep resumes)",
            ),
            (
                Cmd::Minimize,
                "RUNDIR/minimized",
                "the reduced run's directory (replaced)",
            ),
        ],
        per_value: &[],
    },
    flag(
        "--config",
        "FILE",
        "./patina.toml",
        "patina.toml or run.json; flags override it",
        RUNLIKE,
    ),
    many("--env", "K=V", "add to the guest environment", RUNLIKE),
    many(
        "--machine",
        "NAME='CMD ARGS'",
        "another machine, which runs CMD ARGS at each boot",
        RUNLIKE,
    ),
    many(
        "--mount",
        "SRC:DST[:copy]",
        "host path, read-only in the guest (:copy: copied in)",
        RUNLIKE,
    ),
    flag(
        "--disk",
        "DIR[:GUEST]",
        "empty",
        "main's starting disk, mounted at GUEST (/work)",
        RUNLIKE,
    ),
    flag("--stdin", "FILE", "empty", "guest standard input", RUNLIKE),
    many(
        "--faults",
        "CLASS[,...][@MACHINE]",
        "disk, net...; all: no crash/kill (--fault help)",
        RUNLIKE,
    ),
    many(
        "--fault",
        "KEY=VALUE[@MACHINE]",
        "one fault key, over its class's (--fault help: the keys)",
        RUNLIKE,
    ),
    flag(
        "--timeout",
        "SECONDS",
        "600",
        "wall time after which the run ends timeout",
        RUNLIKE,
    ),
    flag("--runs", "N", "3", "runs to compare", &[Cmd::Verify]),
    flag(
        "--vary",
        "LIST",
        "cpu,load,aslr,sandbox,repeat",
        "varied; also parallel,env,time",
        &[Cmd::Verify],
    ),
    flag(
        "--seeds",
        "A..B|N,M,...",
        "1..100",
        "inclusive range, list, or both (1..100,250)",
        &[Cmd::Sweep],
    ),
    Flag {
        name: "--jobs",
        value: "N",
        default: "the CPUs, at most 8",
        help: "runs at once, one CPU each (also -j N)",
        cmds: &[Cmd::Sweep, Cmd::Report],
        repeat: false,
        per: &[(
            Cmd::Report,
            "the CPUs, at most 8",
            "with --recheck: checkers at once",
        )],
        per_value: &[],
    },
    flag(
        "--cases",
        "FILE",
        "none",
        "one case per line: a whole command, or fills {} in CMD",
        &[Cmd::Sweep],
    ),
    flag(
        "--keep",
        "fail|all",
        "fail",
        "fail: each group's first three runs, and checked runs",
        &[Cmd::Sweep],
    ),
    flag(
        "--max-findings",
        "N",
        "no limit",
        "stop once N distinct findings are seen",
        &[Cmd::Sweep],
    ),
    flag(
        "--crash-points",
        "[=N]",
        "off",
        "one run per crash point per seed; =N: at most N",
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
        "SDK label, fault class or check that may stay unmet",
        &[Cmd::Sweep, Cmd::Report],
    ),
    flag(
        "--known",
        "FILE",
        "none",
        "known findings (lines: ID PATTERN); they do not fail",
        &[Cmd::Sweep, Cmd::Report],
    ),
    flag(
        "--group",
        "N",
        "none",
        "print group N in full (from 1)",
        &[Cmd::Report],
    ),
    flag(
        "--recheck",
        "",
        "off",
        "judge the kept runs again, with --check or their own",
        &[Cmd::Report],
    ),
    flag(
        "--from",
        "SEQ",
        "0",
        "log dump, log events, explain: first sequence number",
        &[Cmd::Log, Cmd::Explain],
    ),
    flag(
        "--to",
        "SEQ",
        "last",
        "log dump, log events, explain: last sequence number",
        &[Cmd::Log, Cmd::Explain],
    ),
    flag(
        "--full",
        "",
        "off",
        "explain: every story line, nothing folded",
        &[Cmd::Explain],
    ),
    flag(
        "--at",
        "EVENT",
        "stop",
        "event to stop before: SEQ, stop, end, call:NAME, ...",
        &[Cmd::Debug],
    ),
    flag(
        "--no-gdb",
        "",
        "off",
        "print how to attach, without starting gdb",
        &[Cmd::Debug],
    ),
    flag(
        "--post-crash",
        "",
        "off",
        "log tree: the tree its crash left, not its last",
        &[Cmd::Log],
    ),
    flag(
        "--types",
        "T,T",
        "all",
        "only these event types: call, op, fault, crash, ...",
        &[Cmd::Log],
    ),
    Flag {
        name: "--check",
        value: "'CMD ARGS'",
        default: "none",
        help: "judge ok runs: exit 0 pass, 1 finding, 77 not judged",
        cmds: &[Cmd::Run, Cmd::Verify, Cmd::Sweep, Cmd::Log, Cmd::Report],
        repeat: false,
        per: &[
            (
                Cmd::Log,
                "",
                "log ops: replay the op log and compare with the tree",
            ),
            (
                Cmd::Report,
                "each run's own",
                "with --recheck: the checker to judge with",
            ),
        ],
        per_value: &[(Cmd::Log, "")],
    },
    flag(
        "--ok-exit",
        "N[,N...]|any",
        "none",
        "exit statuses that end the run ok (any: every status)",
        RUNLIKE,
    ),
    Flag {
        name: "--format",
        value: "text|json",
        default: "text",
        help: "output format: json prints result.json",
        cmds: FORMATTED,
        repeat: false,
        per: &[(Cmd::Guide, "text", "md: the markdown it is written in")],
        per_value: &[(Cmd::Guide, "text|md")],
    },
    flag(
        "--list",
        "",
        "off",
        "the topics, one line each",
        &[Cmd::Guide],
    ),
    flag(
        "--print-apparmor-profile",
        "",
        "",
        "print the AppArmor profile this patina needs on Ubuntu",
        &[Cmd::Doctor],
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
        self.last("--format") == Some("json")
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
            if a == "-j" && matches!(cmd, Cmd::Sweep | Cmd::Report) {
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
        let f = match find_flag(name) {
            Some(f) if f.cmds.contains(&cmd) => f,
            // An option of other commands says whose it is (a sweep's flags on a single run).
            Some(f) => {
                let whose: Vec<&str> = f.cmds.iter().map(|c| cmd_name(*c)).collect();
                return Err(format!(
                    "{name} is an option of patina {}, not of patina {} (patina {} --help)",
                    whose.join(", "),
                    cmd_name(cmd),
                    cmd_name(cmd)
                ));
            }
            None => {
                return Err(format!(
                    "unknown option {name} (patina {} --help)",
                    cmd_name(cmd)
                ))
            }
        };
        let v = if f.value_for(cmd).is_empty() {
            if inline.is_some() {
                return Err(format!("{name} takes no value"));
            }
            String::new()
        } else if f.value_for(cmd).starts_with("[=") {
            // An optional value, given only as NAME=VALUE.
            inline.unwrap_or_default()
        } else {
            match inline {
                Some(v) => v,
                None => it
                    .next()
                    .cloned()
                    .ok_or_else(|| format!("{name} needs {}", f.value_for(cmd)))?,
            }
        };
        if f.name == "--format" && !f.value_for(cmd).split('|').any(|x| x == v) {
            return Err(format!(
                "--format: expected {}, not {v}",
                f.value_for(cmd).replace('|', " or ")
            ));
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
    if f.value_for(c).starts_with('[') {
        lhs.push_str(f.value_for(c));
    } else if !f.value_for(c).is_empty() {
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
            for c in COMMANDS.iter().filter(|c| !ADVANCED.contains(&c.cmd)) {
                s.push_str(&format!("  {:<8} {}\n", c.name, c.help));
            }
            s.push_str("\nadvanced:\n");
            for c in COMMANDS.iter().filter(|c| ADVANCED.contains(&c.cmd)) {
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
        }
    }
    s
}

/// The syscall table, generated from `proto`: every number of this architecture, what Patina
/// does with it (`class`: Pass, Virt, Attempt, Rewrite, Place, Deny(ERRNO) or Stop, the last
/// for a number with no row), how faithfully (`strength`) and why.
fn syscalls() -> Vec<serde_json::Value> {
    use proto::table::{known, Class};
    known()
        .map(|r| {
            let class = match r.class {
                Class::Deny(1) => "Deny(EPERM)".to_string(),
                Class::Deny(38) => "Deny(ENOSYS)".to_string(),
                Class::Deny(e) => format!("Deny({e})"),
                c => format!("{c:?}"),
            };
            serde_json::json!({
                "nr": r.nr,
                "name": r.name,
                "class": class,
                "strength": r.strength.letter().to_string(),
                "why": r.why,
            })
        })
        .collect()
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
        .map(|o| serde_json::json!({ "name": o.name(), "exit": o.exit(), "means": o.means() }))
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "commands": cmds,
        "flags": flags,
        "outcomes": outcomes,
        "faults": crate::faults::help_json(),
        "config": crate::config::TOML_KEYS.iter().map(|k| serde_json::json!({
            "table": k.table, "key": k.key, "value": k.value, "default": k.default, "help": k.help,
        })).collect::<Vec<_>>(),
        "guide": crate::guide::TOPICS.iter().map(|t| t.name).collect::<Vec<_>>(),
        "syscalls": syscalls(),
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
    fn help_is_one_short_line_per_flag_and_command() {
        let lines = FLAGS
            .iter()
            .flat_map(|f| f.cmds.iter().map(|&c| flag_text(f, c)))
            .chain(
                COMMANDS
                    .iter()
                    .map(|c| format!("  {:<8} {}", c.name, c.help)),
            );
        let long: Vec<String> = lines
            .filter(|l| l.contains('\n') || l.chars().count() >= 100)
            .collect();
        assert!(long.is_empty(), "{}", long.join("\n"));
    }

    #[test]
    fn every_flag_parses_for_every_command_listing_it() {
        for f in FLAGS {
            for &c in f.cmds {
                let mut a = vec![f.name.to_string()];
                if !f.value_for(c).is_empty() {
                    let first = f.value_for(c).split('|').next().unwrap();
                    a.push(if f.name == "--format" { first } else { "1" }.into());
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
        // Another command's option names the commands that take it.
        let e = parse(Cmd::Run, &v(&["--allow-unmet", "x"])).unwrap_err();
        assert!(e.contains(cmd_name(Cmd::Sweep)), "{e}");
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
