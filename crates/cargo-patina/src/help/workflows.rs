//! Workflow and report verb registry rows.

use super::*;

pub(super) const CAMPAIGN: Verb = Verb {
    name: "campaign",
    summary: "Config-driven deterministic fault-and-schedule sweep over one artifact.",
    synopsis: &[
        "cargo patina campaign <ARTIFACT|SOURCE.rs|DIR|Cargo.toml> [--gens N] [--out-dir DIR] [--spec FILE.json] [--seed-start N] [--progress-every N] [--allow-unmet-sometimes[=MIN_GENS]] [--buggify] [--swarm] [--sched-pct] [--yield-stride] [--faults[=PLANE,...]] [--fault-scale-permille N] [--dns-entry NAME=ADDR] [--liveness-watchdog N] [--converge-within N] [--report-failures] [--no-verify] [--allow SYMBOL]... [--allow-unsupported-symbols all|name,...] [--allow-randomized-address-layout] [-- GUEST ARGS]",
        "cargo patina campaign --extend N [--out-dir DIR] [--progress-every N] [--timeout-secs N]",
        "cargo patina campaign --resume [--out-dir DIR] [--progress-every N] [--timeout-secs N]",
    ],
    prose: "\
A campaign runs `--gens` independent child `cargo patina run` processes over one \
artifact. Everything is a pure function of the generation number, so a re-run with \
the same spec reproduces the same seeds, knobs, outcomes, and failure signatures. \
Each generation runs with --format json and is classified from its \
patina.result/v1 envelope ALONE — verdicts, per-plane fault_reports vacuity, \
runtime_findings, refusal, guest_exit — into one outcome class: a finding \
(VIOLATION, LIVENESS, GUEST_ABORT), a harness class (FAIL_CLOSED_ABORT, \
INFRA), OK, the loud UNCLASSIFIED catch-all, or VACUOUS, the \
coverage class whose signature names the inert fault or exploration planes; \
nothing in the classifier reads guest output. An unattributed SIGABRT is \
GUEST_ABORT (the guest's own doing); the same abort carrying a patina refusal is \
FAIL_CLOSED_ABORT. A guest that never calls the verdict ABI declares its own \
rules in the spec (\"classify\": {\"patterns\": {CLASS: [substring, ...]}, \
\"exit_codes\": {CLASS: [code, ...]}}), which may only ADD a finding where the \
envelope reached none. Novel failure \
signatures are deduped and their traces saved with a reproduce command. Before a \
novel finding is reported the campaign runs that reproduce command once — replay \
of the saved trace, or the seeded re-run for a traceless failure — and a seeded \
sample of clean generations (one in 16, chosen from --seed-start) runs twice; a \
differing class, signature, verdict set or trace digest is NONDETERMINISM, the \
most severe class, reported with both outcomes. A second run patina could not \
finish (a timeout, a host kill) is counted as infra and leaves the class as \
observed. --no-verify skips these runs for cost. A --spec \
FILE.json supplies overrides and individual flags override the spec. Campaigns \
checkpoint their state in --out-dir; `--extend N` adds N generations to the recorded \
target, and `--resume` finishes an interrupted campaign from the recorded out-dir \
without re-supplying the artifact or spec flags. Output is summary-first: a human \
report (novel/failing generations plus a periodic progress heartbeat, tuned by \
--progress-every) or a patina.campaign/v2 JSON envelope (class counts, deduped \
signatures, per-run detail for novel/failing generations, and pointers to the full \
on-disk artifacts). Campaigns also write <out-dir>/sites.json (schema \
patina.campaign.sites/v1), summarize SDK site coverage, and fail by default \
when a `sometimes!`/`reachable!` oracle is never satisfied. Literal-label SDK \
macro sites are declared through the link-time table, so never-reached oracles \
appear with registered_gens=0; --allow-unmet-sometimes[=MIN_GENS] reports but \
waives that gate (unconditionally or only below the observed generation \
threshold). `--faults` draws every fault plane; `--faults=net,sleep` draws only the \
named planes, for a guest that needs one plane always off (a store that must \
open on the simulated disk, say), and is recorded and pinned like every spec \
flag. The spec key `\"exclude_knobs\": [\"--net-reset-permille\"]` turns single \
knobs of a selected plane off, for a guest that models only some of a plane's \
faults (a client that treats a reset connection as fatal, say); a name that is \
not a knob --faults draws, or whose plane is not selected, is refused. The \
`--faults` bands are tuned for an aggressive sweep (up to 100 \
per-mille of filesystem operations failed, 200 per-mille short); \
--fault-scale-permille dampens every intensity band uniformly for a workload that \
needs faults to be RARE enough to run to completion. It is part of the campaign's \
shape, so it is recorded in the out-dir spec, baked into the per-generation flags \
the reproduce commands replay, and refused on a continuation like every other spec \
flag.\n\
\n\
The crash plane (`crash` in --faults) draws a per-crash-point crash rate on a \
power-of-two sweep and a process or machine crash kind; a generation whose crash \
lands restarts once from the image the crash leaves. `minimize --generation` on a crash generation shrinks the crashed and the \
restarted incarnation separately, keeping the crash on the operation it followed.\n\
\n\
A native artifact's `run` invocation shape is forwarded verbatim to every \
generation: the pre-run gate surface `--allow SYMBOL` / `--allow-unsupported-symbols`. \
Without it a guest needing either is refused identically in every generation \
rather than swept. It is part of the campaign's shape, so it is recorded in \
the out-dir spec, replayed by the reproduce commands, and refused on a \
continuation like every other spec flag; a non-native artifact carrying one is \
refused by name.",
    families: &[fam(Family::Sole, "`campaign`", None)],
    groups: &[
        Group {
            title: "Campaign options",
            families: SOLE,
            flags: &[
                f(
                    "--gens",
                    None,
                    Value::Required("N", Kind::U64),
                    "Number of generations (default 40).",
                    false,
                ),
                f(
                    "--out-dir",
                    None,
                    Value::Required("DIR", Kind::Path),
                    "Output directory (default patina-campaign-out).",
                    false,
                ),
                f(
                    "--extend",
                    None,
                    Value::Required("N", Kind::PositiveU64),
                    "Continue the recorded out-dir with N additional generations (N >= 1; use --resume to finish an interrupted campaign without adding any); the out-dir's spec is authoritative.",
                    false,
                ),
                f(
                    "--resume",
                    None,
                    Value::None,
                    "Finish an interrupted recorded out-dir without adding generations.",
                    false,
                ),
                f(
                    "--spec",
                    None,
                    Value::Required("FILE.json", Kind::Path),
                    "JSON spec of campaign overrides.",
                    false,
                ),
                f(
                    "--seed-start",
                    None,
                    Value::Required("N", Kind::U64),
                    "Base for the per-generation seed derivation (default 0).",
                    false,
                ),
                f(
                    "--timeout-secs",
                    None,
                    Value::Required("N", Kind::U64),
                    "Per-generation child timeout in seconds (default 60).",
                    false,
                ),
                f(
                    "--progress-every",
                    None,
                    Value::Required("N", Kind::U64),
                    "Human-mode progress heartbeat every N generations (default 100; 1 = \
                 full per-generation stream; 0 = silent).",
                    false,
                ),
                f(
                    "--plateau-after",
                    None,
                    Value::Required("N", Kind::U64),
                    "Report native edge-coverage plateau after N generations without new edges (default 200; 0 disables).",
                    false,
                ),
                f(
                    "--guided",
                    None,
                    Value::None,
                    "Bias each generation's seed and knobs toward configurations that previously \
                 found new edge coverage (an --instrument build); refused \
                 when there is none.",
                    false,
                ),
                f(
                    "--allow-unmet-sometimes",
                    None,
                    Value::Optional("MIN_GENS", Kind::PositiveU64),
                    "Waive the default unmet SDK oracle coverage gate; with =MIN_GENS, waive only while observed generations are below MIN_GENS.",
                    false,
                ),
                f(
                    "--buggify",
                    None,
                    Value::None,
                    "Randomize cooperative-SUT (buggify) activation/fire per generation.",
                    false,
                ),
                f(
                    "--swarm",
                    None,
                    Value::None,
                    "Apply seed-derived swarm fault-class selection.",
                    false,
                ),
                f(
                    "--sched-pct",
                    None,
                    Value::None,
                    "Randomize a PCT bug depth per generation.",
                    false,
                ),
                f(
                    "--yield-stride",
                    None,
                    Value::None,
                    "Randomize the yield stride (1 to 1024 edges) per generation; needs an --instrument artifact.",
                    false,
                ),
                f(
                    "--faults",
                    None,
                    Value::Optional(
                        "PLANE,...",
                        Kind::EnumList(crate::campaign::FAULT_PLANE_NAMES),
                    ),
                    "Randomize fault knobs per generation over every fault plane (bare) or only the named ones: fs (error, short I/O, latency), net (drop, latency, jitter, duplicate, connect refuse, reset, TCP buffer), dns (failure, latency; needs --dns-entry), entropy (GRND_NONBLOCK failure), sleep (sleep jitter), epoch (realtime-epoch jump). A plane left out draws none of its knobs, and --swarm masks within the planes selected.",
                    false,
                ),
                f(
                    "--fault-scale-permille",
                    None,
                    Value::Required("N", Kind::Permille),
                    "Dampen every --faults intensity band to N per-mille of its default (default 1000 = the tuned aggressive bands; 10 = a hundredfold rarer, the regime where the workload runs to completion and only unusual paths are faulted). Shape bands such as the crash kind and TCP buffer size, and the cooperative-SUT knobs, are left alone.",
                    false,
                ),
                f(
                    "--custom-op-faults",
                    None,
                    Value::None,
                    "Also band the custom-op failure knob under --faults; declare this only for a guest whose custom operations declare a failure shape, since a guest without one can never fire it.",
                    false,
                ),
                f(
                    "--report-failures",
                    None,
                    Value::None,
                    "Also write a --report HTML for each failing generation.",
                    false,
                ),
                f(
                    "--no-verify",
                    None,
                    Value::None,
                    "Skip reproduction verification: by default each novel finding's reproduce command runs once and a seeded one-in-16 sample of clean generations runs twice, and a differing outcome is NONDETERMINISM.",
                    false,
                ),
                COMPUTE_WATCHDOG_FLAG,
                f(
                    "--liveness-watchdog",
                    None,
                    Value::Required("N", Kind::U64),
                    "Liveness-watchdog budget (virtual nanoseconds) applied every generation.",
                    false,
                ),
                f(
                    "--converge-within",
                    None,
                    Value::Required("N", Kind::U64),
                    "Heal-then-converge budget (virtual nanoseconds) applied every generation.",
                    false,
                ),
                f(
                    "--heal-after",
                    None,
                    Value::Required("N", Kind::U64),
                    "Explicit heal-then-converge arm-time override (virtual nanoseconds).",
                    false,
                ),
            ],
        },
        Group {
            // Part of the campaign's shape, so it is recorded in the out-dir spec and
            // refused on `--extend`/`--resume` like every other spec flag.
            title: "DNS host table (forwarded to every generation)",
            families: SOLE,
            flags: DNS_ENTRY_FLAGS,
        },
        Group {
            // `run <BINARY>`'s pre-run-gate surface, forwarded verbatim to
            // every generation's child `run` (and to the reproduce commands, since
            // these are host/build facts a trace cannot carry).
            title: "Native run options (forwarded to every generation)",
            families: SOLE,
            flags: &[
                Flag {
                    doc: "Add a known-safe symbol to every generation's pre-run gate allow list.",
                    ..ALLOW_FLAG
                },
                Flag {
                    doc: "Downgrade matching unsupported-symbol denials to a warning in every generation. An instruction-class finding (`instruction@.text+OFF`) also matches by the containing symbol its provenance names.",
                    ..ALLOW_UNSUPPORTED_FLAG
                },
                Flag {
                    doc: "Run, record and replay every generation with the host's address-space randomization, for a host that forbids turning it off; every generation's determinism is qualified.",
                    ..ALLOW_RANDOMIZED_LAYOUT_FLAG
                },
                Flag {
                    doc: "The number of CPUs every generation's guest sees (default 4, at most 1024); recorded in the campaign's state and pinned on --extend/--resume.",
                    ..CPUS_FLAG
                },
            ],
        },
    ],
    refusals: NO_REFUSALS,
};

pub(super) const COVERAGE: Verb = Verb {
    name: "coverage",
    summary: "Symbolize and roll up native yield-point coverage maps or campaign stores.",
    synopsis: &[
        "cargo patina coverage <BINARY> <MAP|CAMPAIGN-OUT-DIR> [--focus CRATE::module] [--top N]",
    ],
    prose: "\
`coverage` is a read-only offline report over native `--instrument` coverage. \
Pass the same binary that produced a `patina.covmap/v1` map (from run/replay \
--coverage-out) or a campaign out-dir with `<out-dir>/coverage/`. The report \
uses the map's anchor-relative PCs, resolves them against the binary's \
`patina_yield_point` symbol, demangles Rust symbols, buckets edges into the \
shared crate/module rollup, and reports covered percentages plus hit \
concentration. The JSON form emits schema patina.coverage/v1.",
    families: &[fam(Family::Sole, "`coverage`", None)],
    groups: &[Group {
        title: "Coverage options",
        families: SOLE,
        flags: &[
            f(
                "--focus",
                None,
                Value::Required("CRATE::module", Kind::Str),
                "Drill down to one crate/module/function prefix.",
                false,
            ),
            f(
                "--top",
                None,
                Value::Required("N", Kind::Usize),
                "List the N hottest and N coldest functions after the crate index.",
                false,
            ),
        ],
    }],
    refusals: NO_REFUSALS,
};

pub(super) const TRACE: Verb = Verb {
    name: "trace",
    summary: "Inspect a recorded trace: metadata, filtered events, aggregates, or a two-trace diff.",
    synopsis: &[
        "cargo patina trace info <TRACE>",
        "cargo patina trace events <TRACE> [--kind LIST] [--task SEL]... [--seq A..B] [--first N | --last N] [--notable]",
        "cargo patina trace stats <TRACE>",
        "cargo patina trace diff <A.patina> <B.patina> [--context N]",
    ],
    prose: "\
`trace` strictly loads and validates an existing .patina trace, then inspects it \n\
without executing a guest. `trace info` is the cheap index: metadata, event \n\
count, and the virtual-time span. `trace events` runs the shared \n\
semantic walk used by the HTML renderer, so task attribution, operation \n\
categories, virtual time, summaries, and notable-event detection match the \n\
rendered timeline. `trace stats` aggregates that same walk by kind, category, \n\
task, notable class, and virtual time. `trace diff` compares two traces \n\
operation-first, then outcome, mirroring replay mismatch semantics and \n\
reporting the first divergence without attempting LCS/re-sync alignment.\n\
\n\
`trace info --format json` follows the normal result-envelope contract: one \n\
patina.result/v1 object carrying a nested patina.trace.info/v1 `trace_info` \n\
payload. `trace stats --format json` and `trace diff --format json` likewise \n\
return one patina.result/v1 envelope carrying nested patina.trace.stats/v1 or \n\
patina.trace.diff/v1 payloads. `trace events --format json` intentionally \n\
streams JSON Lines instead of one large envelope: a patina.trace.events/v1 \n\
header, one object per emitted event (with raw operation/outcome JSON intact), \n\
then a matched/emitted summary. Different-seed diffs commonly diverge near the \n\
first entropy/clock/schedule decision; `trace diff` reports the metadata delta, \n\
aligned prefix, first divergence, context, and tails rather than trying to \n\
re-align different executions. Buggify per-evaluation firings are not recorded \n\
in traces; `info` reports the recorded config, active sites, and knobs from \n\
metadata.",
    families: &[
        fam(
            Family::Info,
            "trace info",
            Some("trace info reads metadata only"),
        ),
        fam(Family::Events, "trace events", None),
        fam(
            Family::Stats,
            "trace stats",
            Some("trace stats aggregates the whole trace"),
        ),
        fam(
            Family::Diff,
            "trace diff",
            Some("trace diff compares whole traces"),
        ),
    ],
    groups: &[
        Group {
            title: "Events options (trace events)",
            families: &[Family::Events],
            flags: &[
                f(
                    "--kind",
                    None,
                    Value::Required("LIST", Kind::OpKindList),
                    "Comma-separated operation tags and/or categories (filesystem, network, scheduling, sleep, clock, entropy, crash, other).",
                    false,
                ),
                f(
                    "--task",
                    None,
                    Value::Required("SEL", Kind::TaskSelector),
                    "Task id or the literal main; repeat to include multiple lanes.",
                    true,
                ),
                f(
                    "--seq",
                    None,
                    Value::Required("A..B", Kind::U64Range),
                    "Inclusive sequence-number range.",
                    false,
                ),
                f(
                    "--first",
                    None,
                    Value::Required("N", Kind::PositiveU64),
                    "Emit the first N events after filtering (mutually exclusive with --last).",
                    false,
                ),
                f(
                    "--last",
                    None,
                    Value::Required("N", Kind::PositiveU64),
                    "Emit the last N events after filtering (mutually exclusive with --first).",
                    false,
                ),
                f(
                    "--notable",
                    None,
                    Value::None,
                    "Only crashes, boundary errors, and dropped datagrams.",
                    false,
                ),
            ],
        },
        Group {
            title: "Diff options (trace diff)",
            families: &[Family::Diff],
            flags: &[f(
                "--context",
                None,
                Value::Required("N", Kind::Usize),
                "Number of surrounding events to show per side around the first divergence (default 3).",
                false,
            )],
        },
    ],
    refusals: NO_REFUSALS,
};

pub(super) const MINIMIZE: Verb = Verb {
    name: "minimize",
    summary: "Reduce a failing campaign generation's fault knobs or a failing run's parameters.",
    synopsis: &[
        "cargo patina minimize --generation <N> [--out-dir <DIR>] [--marker <TEXT>] [--output <PATH>] [--jobs N]",
        "cargo patina minimize --params -- cargo patina run <BINARY> --param K=V... [RUN OPTIONS] [-- GUEST ARGS]",
    ],
    prose: "\
`minimize --generation N` reduces one failing generation of a recorded campaign: it \
delta-debugs the fault-knob vector that generation drew (each candidate is a fresh \
seeded `run`, so the answer is a standalone reproduction command, printed and \
written into the out-dir), then records the minimal-knob run so the failure replays \
without flags. The oracle is patina's own and needs no hand-written failure text: \
it targets the verdicts the campaign recorded for that generation, and a candidate \
still fails only when it reports every one of them, so candidates are hermetic and \
evaluated in parallel by default. --marker overrides the target with literal failure \
text, for a guest that reports nothing through the verdict ABI; a generation with \
neither is refused rather than reduced against a guess. A NONDETERMINISM generation \
is refused, --marker or not: its failure is that two runs disagree, which no \
single-run oracle can preserve.\n\
\n\
`minimize --params` reduces a failing run's parameters instead: it drops and shrinks \
the --param values of the command after `--` (those before the command's own `--`), \
re-running the command with each candidate set. A candidate still fails when it exits \
with the original's non-zero status, so a candidate that fails differently is not \
mistaken for the failure. The reduced command is printed as the reproduction.",
    families: &[
        fam(
            Family::Generation,
            "minimize --generation",
            Some(
                "minimize --generation reduces a recorded campaign generation and builds its own oracle",
            ),
        ),
        fam(
            Family::Params,
            "minimize --params",
            Some("minimize --params reduces a failing command's --param set"),
        ),
    ],
    groups: &[
        Group {
            title: "Generation minimization (--generation)",
            families: &[Family::Generation],
            flags: &[
                f(
                    "--generation",
                    None,
                    Value::Required("N", Kind::U64),
                    "Reduce this recorded campaign generation's fault knobs.",
                    false,
                ),
                f(
                    "--out-dir",
                    None,
                    Value::Required("DIR", Kind::Path),
                    "The campaign out-dir holding campaign-state.json (default patina-campaign-out).",
                    false,
                ),
                f(
                    "--marker",
                    None,
                    Value::Required("TEXT", Kind::Symbol),
                    "Override the auto-derived verdict target with failure text the built-in oracle requires on a candidate's output; `A|B` matches either.",
                    false,
                ),
            ],
        },
        Group {
            title: "Candidate evaluation",
            families: &[Family::Generation],
            flags: &[
                f(
                    "--output",
                    Some("-o"),
                    Value::Required("PATH", Kind::Path),
                    "Write the recorded minimal-knob trace to PATH (default under the out-dir).",
                    false,
                ),
                f(
                    "--jobs",
                    None,
                    Value::Required("N", Kind::PositiveU64),
                    "Candidates to evaluate at once (default half the CPUs).",
                    false,
                ),
            ],
        },
        Group {
            title: "Parameter minimization (--params)",
            families: &[Family::Params],
            flags: &[f(
                "--params",
                None,
                Value::None,
                "Reduce the --param set of the failing command after `--`.",
                false,
            )],
        },
    ],
    refusals: NO_REFUSALS,
};

pub(super) const SYSCALLS: Verb = Verb {
    name: "syscalls",
    summary: "Print the target-local kernel-entry inventory and C symbol coverage.",
    synopsis: &["cargo patina syscalls"],
    prose: "\
`syscalls` prints the target-local kernel-entry inventory and C symbol layer \
(this compiled target only). Linux x86_64/aarch64 rows describe runtime dispositions \
and drive syscall-user-dispatch. Darwin aarch64 inventories pinned BSD, Mach \
and ARM-specific entries, including guarded alternatives and invalid slots; \
source status and C symbol interposition are not raw-entry models. Darwin \
x86_64 is not inventoried. MIG messages and commpage APIs are outside the \
kernel-entry scope. The JSON form \
emits the shared schema patina.syscalls/v3.",
    families: &[fam(Family::Sole, "`syscalls`", None)],
    groups: &[],
    refusals: NO_REFUSALS,
};
