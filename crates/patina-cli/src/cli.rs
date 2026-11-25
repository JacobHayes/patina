//! The command line: one static table of commands and one of flags. The parser, `--help`
//! and `--help --format json` all read these tables, so they cannot disagree.

use crate::outcome::Outcome;
use std::collections::BTreeMap;

pub type Res<T> = Result<T, String>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmd {
    Guide,
    GuideList,
    GuideSkill,
    Run,
    Sweep,
    InspectSummary,
    InspectProfile,
    InspectServe,
    InspectHtml,
    InspectStory,
    InspectTrace,
    InspectFolded,
    InspectEvents,
    InspectTree,
    InspectDump,
    InspectDiff,
    InspectOps,
    InspectCheckOps,
    Replay,
    Minimize,
    Debug,
    Recheck,
    Doctor,
    DoctorApparmor,
    Batch,
    Verify,
    Ctl,
}

/// A parent command namespace (e.g. `inspect`, `doctor`, `guide`).
pub struct Group {
    pub name: &'static str,
    pub usage: &'static str,
    pub help: &'static str,
    /// When true, `patina <name>` with no subcommand prints group help and exits with an error.
    /// When false, `patina <name>` resolves to the leaf command with `path == &[name]`.
    pub require_sub: bool,
}

pub const GROUPS: &[Group] = &[
    Group {
        name: "inspect",
        usage: "patina inspect <subcommand> [options]",
        help: "analyze, triage, visualize, and export run or sweep outputs",
        require_sub: true,
    },
    Group {
        name: "doctor",
        usage: "patina doctor [apparmor] [options]",
        help: "check the host; say what is missing and the command that fixes it",
        require_sub: false,
    },
    Group {
        name: "guide",
        usage: "patina guide [TOPIC | list | skill [DIR]]",
        help: "start here: how to find bugs with patina, then one topic at a time",
        require_sub: false,
    },
];

pub struct Command {
    pub cmd: Cmd,
    /// Full command path after `patina`: `&["run"]` or `&["inspect", "summary"]`.
    pub path: &'static [&'static str],
    /// Space-joined command name: `"run"` or `"inspect summary"`.
    pub name: &'static str,
    /// Optional section label inside a group's `--help`.
    pub section: &'static str,
    pub usage: &'static str,
    pub help: &'static str,
}

pub const COMMANDS: &[Command] = &[
    Command {
        cmd: Cmd::Guide,
        path: &["guide"],
        name: "guide",
        section: "",
        usage: "patina guide [TOPIC] [--format text|md]",
        help: "start here: how to find bugs with patina, then one topic at a time",
    },
    Command {
        cmd: Cmd::GuideList,
        path: &["guide", "list"],
        name: "guide list",
        section: "subcommands",
        usage: "patina guide list",
        help: "list the guide topics, one line each",
    },
    Command {
        cmd: Cmd::GuideSkill,
        path: &["guide", "skill"],
        name: "guide skill",
        section: "subcommands",
        usage: "patina guide skill [DIR]",
        help: "write the skill for coding agents to DIR/patina; no DIR: where to put it",
    },
    Command {
        cmd: Cmd::Run,
        path: &["run"],
        name: "run",
        section: "",
        usage: "patina run [options] [-- CMD ARGS...]",
        help: "one run of a program under a seed; CMD is what machine main runs",
    },
    Command {
        cmd: Cmd::Sweep,
        path: &["sweep"],
        name: "sweep",
        section: "",
        usage: "patina sweep [--seeds A..B] [--cases FILE] [-j N] [run options] [-- CMD ARGS...]",
        help: "many seeds in parallel, each a normal run; findings grouped by signature",
    },
    Command {
        cmd: Cmd::InspectSummary,
        path: &["inspect", "summary"],
        name: "inspect summary",
        section: "views & triage",
        usage: "patina inspect summary [--known FILE] [--group N] DIR...",
        help: "triage and summarise run or sweep directories",
    },
    Command {
        cmd: Cmd::InspectProfile,
        path: &["inspect", "profile"],
        name: "inspect profile",
        section: "views & triage",
        usage: "patina inspect profile PATH [--format text|json] [--out FILE]",
        help: "4-bucket cost, virtual latency, memory, CPU, and coverage profile",
    },
    Command {
        cmd: Cmd::InspectServe,
        path: &["inspect", "serve"],
        name: "inspect serve",
        section: "views & triage",
        usage: "patina inspect serve [--addr ADDR] PATH",
        help: "serve the interactive HTML dashboard over HTTP",
    },
    Command {
        cmd: Cmd::InspectHtml,
        path: &["inspect", "html"],
        name: "inspect html",
        section: "views & triage",
        usage: "patina inspect html [--out FILE] PATH",
        help: "write a standalone HTML dashboard for a run or sweep",
    },
    Command {
        cmd: Cmd::InspectStory,
        path: &["inspect", "story"],
        name: "inspect story",
        section: "views & triage",
        usage: "patina inspect story RUNDIR [--from SEQ] [--to SEQ] [--full]",
        help: "a run as a story: messages, faults, output, and the stop event",
    },
    Command {
        cmd: Cmd::InspectTrace,
        path: &["inspect", "trace"],
        name: "inspect trace",
        section: "exports & forensics",
        usage: "patina inspect trace [--out FILE] RUNDIR",
        help: "export a Perfetto JSON trace of a run",
    },
    Command {
        cmd: Cmd::InspectFolded,
        path: &["inspect", "folded"],
        name: "inspect folded",
        section: "exports & forensics",
        usage: "patina inspect folded [--out FILE] RUNDIR",
        help: "export folded CPU stacks for flamegraph tools",
    },
    Command {
        cmd: Cmd::InspectEvents,
        path: &["inspect", "events"],
        name: "inspect events",
        section: "exports & forensics",
        usage: "patina inspect events RUNDIR [--types T,T] [--from SEQ] [--to SEQ]",
        help: "export a run as normalized JSON lines",
    },
    Command {
        cmd: Cmd::InspectTree,
        path: &["inspect", "tree"],
        name: "inspect tree",
        section: "exports & forensics",
        usage: "patina inspect tree BOOTDIR DIR [--post-crash]",
        help: "materialize a boot's final or post-crash disk directory",
    },
    Command {
        cmd: Cmd::InspectDump,
        path: &["inspect", "dump"],
        name: "inspect dump",
        section: "exports & forensics",
        usage: "patina inspect dump LOG [--from SEQ] [--to SEQ]",
        help: "dump raw records from a boundary log",
    },
    Command {
        cmd: Cmd::InspectDiff,
        path: &["inspect", "diff"],
        name: "inspect diff",
        section: "exports & forensics",
        usage: "patina inspect diff LOG LOG",
        help: "find the first differing record between two boundary logs",
    },
    Command {
        cmd: Cmd::InspectOps,
        path: &["inspect", "ops"],
        name: "inspect ops",
        section: "exports & forensics",
        usage: "patina inspect ops BOOTDIR",
        help: "list filesystem operations recorded for a boot",
    },
    Command {
        cmd: Cmd::InspectCheckOps,
        path: &["inspect", "check-ops"],
        name: "inspect check-ops",
        section: "exports & forensics",
        usage: "patina inspect check-ops RUNDIR",
        help: "replay the op log and verify it matches the disk tree",
    },
    Command {
        cmd: Cmd::Replay,
        path: &["replay"],
        name: "replay",
        section: "",
        usage: "patina replay RUNDIR [--out DIR]",
        help: "run again from a run directory and compare with its log",
    },
    Command {
        cmd: Cmd::Minimize,
        path: &["minimize"],
        name: "minimize",
        section: "",
        usage: "patina minimize RUNDIR [--out DIR]",
        help: "drop and halve a failing run's fault settings while it fails the same way",
    },
    Command {
        cmd: Cmd::Debug,
        path: &["debug"],
        name: "debug",
        section: "",
        usage: "patina debug RUNDIR [--at EVENT] [--no-gdb]",
        help: "replay a run and stop it under gdb just before one event",
    },
    Command {
        cmd: Cmd::Recheck,
        path: &["recheck"],
        name: "recheck",
        section: "",
        usage: "patina recheck [--check 'CMD ARGS'] [-j N] [--known FILE] DIR...",
        help: "judge kept runs again with a checker, without re-running",
    },
    Command {
        cmd: Cmd::Doctor,
        path: &["doctor"],
        name: "doctor",
        section: "",
        usage: "patina doctor [--format text|json]",
        help: "check the host; say what is missing and the command that fixes it",
    },
    Command {
        cmd: Cmd::DoctorApparmor,
        path: &["doctor", "apparmor"],
        name: "doctor apparmor",
        section: "subcommands",
        usage: "patina doctor apparmor",
        help: "print the AppArmor profile this patina needs on Ubuntu",
    },
    Command {
        cmd: Cmd::Batch,
        path: &["batch"],
        name: "batch",
        section: "",
        usage: "patina batch [-j N] [run options] [-- CMD ARGS...]",
        help: "persistent worker pool reading NDJSON runs on stdin",
    },
    Command {
        cmd: Cmd::Verify,
        path: &["verify"],
        name: "verify",
        section: "",
        usage: "patina verify [options] [-- CMD ARGS...]",
        help: "one seed under varied host conditions; names the first differing record",
    },
    Command {
        cmd: Cmd::Ctl,
        path: &["ctl"],
        name: "ctl",
        section: "",
        usage: "patina ctl partition A B | partition --from A --to B | heal [A B] | crash MACHINE | kill MACHINE | start MACHINE | pause MACHINE | resume MACHINE | clock MACHINE +90s | settle [SECONDS] | wait HOST:PORT",
        help: "inside a run: control links, machines and clocks, or wait for a port",
    },
];

/// Top-level entries shown in `patina --help` in order (name, advanced).
const TOP_LEVEL: &[(&str, bool)] = &[
    ("guide", false),
    ("run", false),
    ("sweep", false),
    ("inspect", false),
    ("replay", false),
    ("minimize", false),
    ("debug", false),
    ("recheck", false),
    ("doctor", false),
    ("batch", true),
    ("verify", true),
    ("ctl", true),
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

const RUNLIKE: &[Cmd] = &[Cmd::Run, Cmd::Verify, Cmd::Sweep, Cmd::Batch];

/// The commands that print a formatted result (`--format`).
const FORMATTED: &[Cmd] = &[
    Cmd::Run,
    Cmd::Replay,
    Cmd::InspectSummary,
    Cmd::InspectProfile,
    Cmd::InspectStory,
    Cmd::Debug,
    Cmd::Verify,
    Cmd::Doctor,
    Cmd::Sweep,
    Cmd::Batch,
    Cmd::Recheck,
    Cmd::Minimize,
    Cmd::Ctl,
    Cmd::Guide,
];

const ALL: &[Cmd] = &[
    Cmd::Guide,
    Cmd::GuideList,
    Cmd::GuideSkill,
    Cmd::Run,
    Cmd::Sweep,
    Cmd::InspectSummary,
    Cmd::InspectProfile,
    Cmd::InspectServe,
    Cmd::InspectHtml,
    Cmd::InspectStory,
    Cmd::InspectTrace,
    Cmd::InspectFolded,
    Cmd::InspectEvents,
    Cmd::InspectTree,
    Cmd::InspectDump,
    Cmd::InspectDiff,
    Cmd::InspectOps,
    Cmd::InspectCheckOps,
    Cmd::Replay,
    Cmd::Minimize,
    Cmd::Debug,
    Cmd::Recheck,
    Cmd::Doctor,
    Cmd::DoctorApparmor,
    Cmd::Batch,
    Cmd::Verify,
    Cmd::Ctl,
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
        "the seed",
        &[Cmd::Run, Cmd::Verify, Cmd::Batch],
    ),
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
            Cmd::InspectProfile,
            Cmd::InspectHtml,
            Cmd::InspectTrace,
            Cmd::InspectFolded,
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
            (Cmd::InspectProfile, "stdout", "write output to FILE"),
            (Cmd::InspectHtml, "stdout", "write HTML dashboard to FILE"),
            (Cmd::InspectTrace, "stdout", "write Perfetto trace to FILE"),
            (Cmd::InspectFolded, "stdout", "write folded stacks to FILE"),
        ],
        per_value: &[
            (Cmd::InspectProfile, "FILE"),
            (Cmd::InspectHtml, "FILE"),
            (Cmd::InspectTrace, "FILE"),
            (Cmd::InspectFolded, "FILE"),
        ],
    },
    flag(
        "--addr",
        "ADDR",
        "127.0.0.1:8080",
        "listen address for the HTML UI",
        &[Cmd::InspectServe],
    ),
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
        cmds: &[Cmd::Sweep, Cmd::Batch, Cmd::Recheck],
        repeat: false,
        per: &[(
            Cmd::Recheck,
            "the CPUs, at most 8",
            "checkers at once (also -j N)",
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
        &[Cmd::Sweep, Cmd::Recheck, Cmd::InspectSummary],
    ),
    flag(
        "--known",
        "FILE",
        "none",
        "known findings (lines: ID PATTERN); they do not fail",
        &[Cmd::Sweep, Cmd::Recheck, Cmd::InspectSummary],
    ),
    flag(
        "--group",
        "N",
        "none",
        "print group N in full (from 1)",
        &[Cmd::InspectSummary],
    ),
    flag(
        "--from",
        "SEQ",
        "0",
        "first sequence number",
        &[Cmd::InspectDump, Cmd::InspectEvents, Cmd::InspectStory],
    ),
    flag(
        "--to",
        "SEQ",
        "last",
        "last sequence number",
        &[Cmd::InspectDump, Cmd::InspectEvents, Cmd::InspectStory],
    ),
    flag(
        "--full",
        "",
        "off",
        "every story line, nothing folded",
        &[Cmd::InspectStory],
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
        "the tree its crash left, not its last",
        &[Cmd::InspectTree],
    ),
    flag(
        "--types",
        "T,T",
        "all",
        "only these event types: call, op, fault, crash, ...",
        &[Cmd::InspectEvents],
    ),
    Flag {
        name: "--check",
        value: "'CMD ARGS'",
        default: "none",
        help: "judge ok runs: exit 0 pass, 1 finding, 77 not judged",
        cmds: &[Cmd::Run, Cmd::Verify, Cmd::Sweep, Cmd::Recheck],
        repeat: false,
        per: &[(Cmd::Recheck, "each run's own", "the checker to judge with")],
        per_value: &[],
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
        per: &[
            (Cmd::Guide, "text", "md: the markdown it is written in"),
            (Cmd::InspectProfile, "text", "text summary or JSON"),
        ],
        per_value: &[(Cmd::Guide, "text|md")],
    },
    flag(
        "--profile-cpu",
        "[=N]",
        "off",
        "deterministic CPU samples every N compute events",
        &[Cmd::Run, Cmd::Replay, Cmd::Verify, Cmd::Sweep, Cmd::Batch],
    ),
    flag(
        "--coverage",
        "",
        "off",
        "record black-box ELF edge-coverage bitmap",
        &[Cmd::Run, Cmd::Replay, Cmd::Verify, Cmd::Sweep, Cmd::Batch],
    ),
    flag("--help", "", "", "this help", ALL),
];

pub fn find_flag(name: &str) -> Option<&'static Flag> {
    FLAGS.iter().find(|f| f.name == name)
}

pub fn find_group(name: &str) -> Option<&'static Group> {
    GROUPS.iter().find(|g| g.name == name)
}

pub fn find_cmd_path(path: &[&str]) -> Option<Cmd> {
    COMMANDS.iter().find(|c| c.path == path).map(|c| c.cmd)
}

pub fn cmd_info(c: Cmd) -> &'static Command {
    COMMANDS.iter().find(|x| x.cmd == c).unwrap()
}

pub fn cmd_name(c: Cmd) -> &'static str {
    cmd_info(c).name
}

/// Result of resolving the command word(s) at the front of argv.
pub enum Resolved<'a> {
    Cmd(Cmd, &'a [String]),
    GroupHelp {
        group: &'static Group,
        json: bool,
        exit_err: bool,
    },
    Unknown {
        group: Option<&'static Group>,
        word: &'a str,
    },
}

fn wants_json(rest: &[String]) -> bool {
    rest.windows(2)
        .any(|w| w[0] == "--format" && w[1] == "json")
        || rest.iter().any(|a| a == "--format=json")
}

/// Resolve `args` (non-empty, after the binary name) to a leaf command, a group help page,
/// or an unknown-command error.
pub fn resolve(args: &[String]) -> Resolved<'_> {
    let first = args[0].as_str();
    let rest = &args[1..];
    if let Some(group) = find_group(first) {
        if rest.is_empty() {
            if group.require_sub {
                return Resolved::GroupHelp {
                    group,
                    json: false,
                    exit_err: true,
                };
            }
            return Resolved::Cmd(find_cmd_path(&[first]).unwrap(), rest);
        }
        let second = rest[0].as_str();
        if group.require_sub {
            if second == "--help" || second == "-h" {
                return Resolved::GroupHelp {
                    group,
                    json: wants_json(&rest[1..]),
                    exit_err: false,
                };
            }
            if let Some(cmd) = find_cmd_path(&[first, second]) {
                return Resolved::Cmd(cmd, &rest[1..]);
            }
            return Resolved::Unknown {
                group: Some(group),
                word: second,
            };
        }
        if let Some(cmd) = find_cmd_path(&[first, second]) {
            return Resolved::Cmd(cmd, &rest[1..]);
        }
        return Resolved::Cmd(find_cmd_path(&[first]).unwrap(), rest);
    }
    if let Some(cmd) = find_cmd_path(&[first]) {
        return Resolved::Cmd(cmd, rest);
    }
    Resolved::Unknown {
        group: None,
        word: first,
    }
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

/// Parse `args` (after the command path) against the flag table.
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
            if a == "-j" && matches!(cmd, Cmd::Sweep | Cmd::Batch | Cmd::Recheck) {
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

fn top_help_line(name: &str) -> String {
    let help = if let Some(g) = find_group(name) {
        g.help
    } else {
        COMMANDS
            .iter()
            .find(|c| c.path == [name])
            .map(|c| c.help)
            .unwrap()
    };
    format!("  {name:<8} {help}")
}

fn subcommands_of(parent: &str) -> Vec<&'static Command> {
    COMMANDS
        .iter()
        .filter(|c| c.path.len() == 2 && c.path[0] == parent)
        .collect()
}

fn append_subcommands(s: &mut String, parent: &str) {
    let subs = subcommands_of(parent);
    if subs.is_empty() {
        return;
    }
    let mut sections: Vec<&str> = vec![];
    for c in &subs {
        let sec = if c.section.is_empty() {
            "subcommands"
        } else {
            c.section
        };
        if !sections.contains(&sec) {
            sections.push(sec);
        }
    }
    for sec in sections {
        s.push_str(&format!("\n{sec}:\n"));
        for c in subs.iter().filter(|c| {
            let cs = if c.section.is_empty() {
                "subcommands"
            } else {
                c.section
            };
            cs == sec
        }) {
            s.push_str(&format!("  {:<10} {}\n", c.path[1], c.help));
        }
    }
}

/// Help text for a parent command group (e.g. `patina inspect --help`).
pub fn group_help_text(g: &Group) -> String {
    let mut s = format!("{}\n\n{}\n", g.usage, g.help);
    append_subcommands(&mut s, g.name);
    s.push_str(&format!(
        "\npatina {} SUBCOMMAND --help for its options.\n",
        g.name
    ));
    s
}

/// Help text: every command, or one command and its flags.
pub fn help_text(cmd: Option<Cmd>) -> String {
    let mut s = String::new();
    match cmd {
        None => {
            s.push_str("patina: deterministic simulation testing of any Linux program (x86_64, arm64)\n\nusage: patina COMMAND [options]\n\ncommands:\n");
            for &(name, adv) in TOP_LEVEL {
                if !adv {
                    s.push_str(&top_help_line(name));
                    s.push('\n');
                }
            }
            s.push_str("\nadvanced:\n");
            for &(name, adv) in TOP_LEVEL {
                if adv {
                    s.push_str(&top_help_line(name));
                    s.push('\n');
                }
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
            let info = cmd_info(c);
            s.push_str(&format!("{}\n\n{}\n\noptions:\n", info.usage, info.help));
            for f in FLAGS.iter().filter(|f| f.cmds.contains(&c)) {
                s.push_str(&flag_text(f, c));
                s.push('\n');
            }
            if info.path.len() == 1 {
                append_subcommands(&mut s, info.path[0]);
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

/// The tables as JSON, for agents: every command, group, and flag with the commands taking it.
pub fn help_json() -> String {
    let cmds: Vec<serde_json::Value> = COMMANDS
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "path": c.path,
                "usage": c.usage,
                "help": c.help,
                "flags": FLAGS.iter().filter(|f| f.cmds.contains(&c.cmd)).map(|f| f.name).collect::<Vec<_>>(),
            })
        })
        .collect();
    let groups: Vec<serde_json::Value> = GROUPS
        .iter()
        .map(|g| {
            serde_json::json!({
                "name": g.name,
                "usage": g.usage,
                "help": g.help,
                "require_sub": g.require_sub,
                "subcommands": subcommands_of(g.name).iter().map(|c| c.path[1]).collect::<Vec<_>>(),
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
        "groups": groups,
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
            .chain(TOP_LEVEL.iter().map(|&(name, _)| top_help_line(name)))
            .chain(
                COMMANDS
                    .iter()
                    .filter(|c| c.path.len() == 2)
                    .map(|c| format!("  {:<10} {}", c.path[1], c.help)),
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
        let e = parse(Cmd::Run, &v(&["--allow-unmet", "x"])).unwrap_err();
        assert!(e.contains(cmd_name(Cmd::Sweep)), "{e}");
        let e = parse(Cmd::InspectTrace, &v(&["--known", "k"])).unwrap_err();
        assert!(e.contains("inspect summary"), "{e}");
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

    #[test]
    fn resolve_nested_and_flat_commands() {
        assert!(matches!(
            resolve(&v(&["inspect"])),
            Resolved::GroupHelp {
                group: Group {
                    name: "inspect",
                    ..
                },
                exit_err: true,
                ..
            }
        ));
        assert!(matches!(
            resolve(&v(&["inspect", "--help"])),
            Resolved::GroupHelp {
                group: Group {
                    name: "inspect",
                    ..
                },
                exit_err: false,
                ..
            }
        ));
        assert!(matches!(
            resolve(&v(&["inspect", "summary", "dir"])),
            Resolved::Cmd(Cmd::InspectSummary, rest) if rest == ["dir"]
        ));
        assert!(matches!(
            resolve(&v(&["inspect", "bogus"])),
            Resolved::Unknown {
                group: Some(Group {
                    name: "inspect",
                    ..
                }),
                word: "bogus"
            }
        ));
        assert!(matches!(
            resolve(&v(&["doctor"])),
            Resolved::Cmd(Cmd::Doctor, rest) if rest.is_empty()
        ));
        assert!(matches!(
            resolve(&v(&["doctor", "apparmor"])),
            Resolved::Cmd(Cmd::DoctorApparmor, rest) if rest.is_empty()
        ));
        assert!(matches!(
            resolve(&v(&["guide", "faults"])),
            Resolved::Cmd(Cmd::Guide, rest) if rest == ["faults"]
        ));
        assert!(matches!(
            resolve(&v(&["guide", "list"])),
            Resolved::Cmd(Cmd::GuideList, rest) if rest.is_empty()
        ));
        assert!(matches!(
            resolve(&v(&["guide", "skill", "/tmp"])),
            Resolved::Cmd(Cmd::GuideSkill, rest) if rest == ["/tmp"]
        ));
        assert!(matches!(
            resolve(&v(&["recheck", "dir"])),
            Resolved::Cmd(Cmd::Recheck, rest) if rest == ["dir"]
        ));
    }
}
