//! Workflow and report verb registry rows.

use super::*;

pub(super) const EXPLORE: Verb = Verb {
    name: "explore",
    summary: "Sweep a seed range of `run`/`test`, reporting per-seed outcomes.",
    synopsis: &[
        "cargo patina explore run <ARTIFACT|SOURCE.rs|DIR|Cargo.toml> [--target native|wasi] [--seeds N] [--seed-start N] [RUN OPTIONS]",
        "cargo patina explore test [--seeds N] [--seed-start N] [PATINA/CARGO OPTIONS]",
    ],
    prose: "\
`explore run`/`explore test` sweeps a contiguous seed range over one artifact or \
Cargo target, running each seed as a child and reporting per-seed outcomes. The \
wrapped command must be in a plain seeded mode — record/replay/branch pin a single \
run and have nothing to sweep. Every option after the seed controls is the wrapped \
`run`/`test` command's; run `cargo patina run --help` or `cargo patina test --help` \
for those.",
    families: &[fam(Family::Sole, "`explore`", None)],
    groups: &[Group {
        title: "Explore options",
        families: SOLE,
        flags: &[
            f(
                "--seeds",
                None,
                Value::Required("N", Kind::PositiveU64),
                "Number of seeds to sweep (1..=1000000, default 100).",
                false,
            ),
            f(
                "--seed-start",
                None,
                Value::Required("N", Kind::U64),
                "First seed in the range (default: the wrapped command's seed).",
                false,
            ),
        ],
    }],
    refusals: NO_REFUSALS,
};

pub(super) const CAMPAIGN: Verb = Verb {
    name: "campaign",
    summary: "Config-driven deterministic fault-and-schedule sweep over one artifact.",
    synopsis: &[
        "cargo patina campaign <ARTIFACT|SOURCE.rs|DIR|Cargo.toml> [--gens N] [--out-dir DIR] [--spec FILE.json] [--seed-start N] [--progress-every N] [--allow-unmet-sometimes[=MIN_GENS]] [--buggify] [--swarm] [--sched-pct] [--faults] [--fault-scale-permille N] [--starve-scale-permille N] [--dns-entry NAME=ADDR] [--liveness-watchdog N] [--converge-within N] [--report-failures] [--harness] [--allow SYMBOL]... [--allow-unsupported-symbols all|name,...] [-- GUEST ARGS]",
        "cargo patina campaign --extend N [--out-dir DIR] [--progress-every N] [--timeout-secs N]",
        "cargo patina campaign --resume [--out-dir DIR] [--progress-every N] [--timeout-secs N]",
        "cargo patina campaign --selftest",
    ],
    prose: "\
A campaign runs `--gens` independent child `cargo patina run` processes over one \
artifact. Everything is a pure function of the generation number, so a re-run with \
the same spec reproduces the same seeds, knobs, outcomes, and failure signatures. \
Each generation runs with --format json and is classified from its \
patina.result/v1 envelope ALONE — verdicts, per-plane fault_reports vacuity, \
runtime_findings, refusal, guest_exit — into one of fourteen outcome classes; \
nothing in the classifier reads guest output. An unattributed SIGABRT is \
GUEST_ABORT (the guest's own doing); the same abort carrying a patina refusal is \
FAIL_CLOSED_ABORT. A guest that never calls the verdict ABI declares its own \
rules in the spec (\"classify\": {\"patterns\": {CLASS: [substring, ...]}, \
\"exit_codes\": {CLASS: [code, ...]}}), which may only ADD a finding where the \
envelope reached none. Novel failure \
signatures are deduped and their traces saved with a reproduce command. A --spec \
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
threshold). `--selftest` proves every classifier class and the coverage gate \
classes. The `--faults` bands are tuned for an aggressive sweep (up to 100 \
per-mille of filesystem operations failed, 200 per-mille short); \
--fault-scale-permille dampens every intensity band uniformly for a workload that \
needs faults to be RARE enough to run to completion. It is part of the campaign's \
shape, so it is recorded in the out-dir spec, baked into the per-generation flags \
the reproduce commands replay, and refused on a continuation like every other spec \
flag. --starve-scale-permille is the same dial over the starvation policy, for the \
same measured reason: a starvation sweep that wedges most of its generations spends \
its budget on runs that finish nothing. It gates how often a generation starves at \
all and dampens the interval count and hold length; the start window is placement \
rather than intensity and keeps its full sweep. A generation the stall backstop \
kills is reported as STARVATION_STALL and is NOT counted as a distinct bug found: \
the backstop only arms under --starve, so the wedge is patina's own injector, not a \
verdict on the guest.\n\
\n\
A native artifact's `run` invocation shape is forwarded verbatim to every \
generation: `--harness` for a patina-dst-harness (configure-then-run) binary, and \
the pre-run gate surface `--allow SYMBOL` / `--allow-unsupported-symbols`. \
Without them a guest needing either is refused identically in every generation \
rather than swept. They are part of the campaign's shape, so they are recorded in \
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
                 found new coverage (native --yield-points) or depth (WASI); refused when \
                 neither is available.",
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
                    "Apply seed-derived swarm fault-class selection (native only).",
                    false,
                ),
                f(
                    "--sched-pct",
                    None,
                    Value::None,
                    "Randomize a PCT bug depth per generation (native only).",
                    false,
                ),
                f(
                    "--starve",
                    None,
                    Value::None,
                    "Randomize a bounded starvation-interval policy (count, start window, max length) per generation (native only).",
                    false,
                ),
                f(
                    "--starve-scale-permille",
                    None,
                    Value::Required("N", Kind::Permille),
                    "Dampen the --starve policy to N per-mille of its default (default 1000 = today's bands; 100 = a tenth as many generations starve, with a tenth the holds and a tenth the hold length when they do). Gates how often a generation starves at all, and scales the interval count and the maximum hold length. The start window is placement rather than intensity — which end of it is harsh depends on the guest's own schedule — so it keeps its full sweep.",
                    false,
                ),
                f(
                    "--faults",
                    None,
                    Value::None,
                    "Randomize fault knobs (fs error/short I/O/crash placement, net drop/latency, sleep jitter, and — with --dns-entry — DNS failure/latency) per generation.",
                    false,
                ),
                f(
                    "--fault-scale-permille",
                    None,
                    Value::Required("N", Kind::Permille),
                    "Dampen every --faults intensity band to N per-mille of its default (default 1000 = the tuned aggressive bands; 10 = a hundredfold rarer, the regime where the workload runs to completion and only unusual paths are faulted). Crash/torn-write placement is not drawn. Shape bands such as TCP buffer size and the cooperative-SUT knobs are not intensity and are left alone.",
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
                f(
                    "--selftest",
                    None,
                    Value::None,
                    "Prove every classifier class and the signature store, then exit.",
                    false,
                ),
            ],
        },
        Group {
            // Part of the campaign's shape, so it is recorded in the out-dir spec and
            // refused on `--extend`/`--resume` like every other spec flag. A WASI
            // artifact is refused outright — wasip1 has no resolution surface.
            title: "DNS host table (forwarded to every generation; native artifacts only)",
            families: SOLE,
            flags: DNS_ENTRY_FLAGS,
        },
        Group {
            // `run <BINARY>`'s harness/pre-run-gate surface, forwarded verbatim to
            // every generation's child `run` (and to the reproduce commands, since
            // these are host/build facts a trace cannot carry). Campaign has one
            // parsing family — the artifact family is a runtime fact read from magic
            // bytes, not a parse-time one — so the native restriction is enforced
            // where the family is finally known, exactly like the DNS host table
            // above, and the refusal names the offending flag.
            title: "Native run options (forwarded to every generation; native artifacts only)",
            families: SOLE,
            flags: &[
                Flag {
                    doc: "Sweep a patina-dst-harness binary: every generation runs with --harness (defers runtime init).",
                    ..HARNESS_FLAG
                },
                Flag {
                    doc: "Add a known-safe symbol to every generation's pre-run gate allow list.",
                    ..ALLOW_FLAG
                },
                Flag {
                    doc: "Downgrade matching unsupported-symbol denials to a warning in every generation. An instruction-class finding (`instruction@.text+OFF`) also matches by the containing symbol its provenance names.",
                    ..ALLOW_UNSUPPORTED_FLAG
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
`coverage` is a read-only offline report over native `--yield-points` coverage. \
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
        "cargo patina trace info <TRACE> [--timeline ID]",
        "cargo patina trace events <TRACE> [--timeline ID] [--kind LIST] [--task SEL]... [--seq A..B] [--first N | --last N] [--notable]",
        "cargo patina trace stats <TRACE> [--timeline ID]",
        "cargo patina trace diff <A.patina> <B.patina> [--timeline ID] [--context N]",
    ],
    prose: "\
`trace` strictly loads and validates an existing .patina trace, then inspects it \n\
without executing a guest. `trace info` is the cheap index: metadata, timelines, \n\
resolved event count, and the virtual-time span. `trace events` runs the shared \n\
semantic walk used by the HTML renderer, so task attribution, operation \n\
categories, virtual time, summaries, and notable-event detection match the \n\
rendered timeline. `trace stats` aggregates that same walk by kind, category, \n\
task, notable class, and virtual time. `trace diff` compares two resolved \n\
timelines operation-first, then outcome, mirroring replay mismatch semantics and \n\
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
            Some("trace stats aggregates the whole resolved timeline"),
        ),
        fam(
            Family::Diff,
            "trace diff",
            Some("trace diff compares full resolved timelines"),
        ),
    ],
    groups: &[
        Group {
            title: "Trace options (trace info/events/stats/diff)",
            families: &[Family::Info, Family::Events, Family::Stats, Family::Diff],
            flags: &[f(
                "--timeline",
                None,
                Value::Required("ID", Kind::Str),
                "Resolved timeline to inspect (default main). For diff, applies to both traces.",
                false,
            )],
        },
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

pub(super) const SITES: Verb = Verb {
    name: "sites",
    summary: "Inventory static assertion/oracle sites in the current workspace.",
    synopsis: &[
        "cargo patina sites [--crate NAME] [--module PATH] [--group NAME] [--site LABEL] [--all] [--exercised FILE|OUTDIR] [--kind KIND] [--runtime driven|observed|invisible] [--no-cache]",
        "cargo patina sites --selftest",
    ],
    prose: "\
`sites` scans the current Cargo workspace with a syn-based static analyzer and reports \
where Patina SDK sites, Rust assertions, proptest/quickcheck checks, and \
antithesis-sdk assertions live. With --exercised FILE, it parses runtime PATINA_SDK_REPORT line(s); \
with --exercised OUTDIR, it reads OUTDIR/sites.json from a campaign. Both forms join \
runtime counters and link-time declared SDK rows to the static SDK rows by label or \
dynamic-label file:line; declared-but-never-evaluated rows carry registered_gens=0. \
Invisible sites remain inventory rows rather than coverage claims. The default output is a \
crate/module index; scoped flags \
or --all opt into per-site drill-down rows. Results are cached per file under \
.patina/out/sites-cache.json unless --no-cache is set. `--selftest` scans a \
planted fixture and proves every recognizer class fires.",
    families: &[fam(Family::Sole, "`sites`", None)],
    groups: &[Group {
        title: "Sites options",
        families: SOLE,
        flags: &[
            f(
                "--crate",
                None,
                Value::Required("NAME", Kind::Str),
                "Drill down to one Cargo package/crate name.",
                false,
            ),
            f(
                "--module",
                None,
                Value::Required("PATH", Kind::Str),
                "Drill down to one Rust module path.",
                false,
            ),
            f(
                "--group",
                None,
                Value::Required("NAME", Kind::Str),
                "Drill down to one configured group (groups arrive with .patina config in a later wave).",
                false,
            ),
            f(
                "--site",
                None,
                Value::Required("LABEL", Kind::Str),
                "Drill down to one SDK/Antithesis label or anonymous site id.",
                false,
            ),
            f(
                "--all",
                None,
                Value::None,
                "Emit every static site record instead of the summary index.",
                false,
            ),
            f(
                "--exercised",
                None,
                Value::Required("FILE|OUTDIR", Kind::Path),
                "Read raw PATINA_SDK_REPORT line(s) from FILE, or OUTDIR/sites.json from a campaign, and join runtime counters into the static inventory.",
                false,
            ),
            f(
                "--kind",
                None,
                Value::Required(
                    "KIND",
                    Kind::Enum(&[
                        "fault",
                        "delay",
                        "knob",
                        "always",
                        "sometimes",
                        "reachable",
                        "assert",
                        "debug_assert",
                        "prop_assert",
                        "proptest",
                        "quickcheck",
                        "antithesis_always",
                        "antithesis_sometimes",
                        "antithesis_reachable",
                        "antithesis_unreachable",
                        "unreachable",
                    ]),
                ),
                "Filter by static site kind.",
                false,
            ),
            f(
                "--runtime",
                None,
                Value::Required(
                    "driven|observed|invisible",
                    Kind::Enum(&["driven", "observed", "invisible"]),
                ),
                "Filter by Patina runtime relationship.",
                false,
            ),
            f(
                "--no-cache",
                None,
                Value::None,
                "Rescan files and do not read or write .patina/out/sites-cache.json.",
                false,
            ),
            f(
                "--selftest",
                None,
                Value::None,
                "Prove the static recognizers fire on a planted fixture, then exit.",
                false,
            ),
        ],
    }],
    refusals: NO_REFUSALS,
};

const MINIMIZE_TRACE_FAMILIES: &[Family] = &[Family::Sole, Family::Generation];

pub(super) const MINIMIZE: Verb = Verb {
    name: "minimize",
    summary: "Reduce a failing campaign generation, a recorded trace, or experiment inputs.",
    synopsis: &[
        "cargo patina minimize --generation <N> [--out-dir <DIR>] [--marker <TEXT>] [--output <PATH>] [--no-trace-phase] [--jobs N]",
        "cargo patina minimize <TRACE> --output <PATH> [-o <PATH>] [--timeline ID] [--prune-branches] [--jobs N] -- <ORACLE> [ARGS]...",
        "cargo patina minimize --scenario --seed <U64> [--param K=V]... [--seed-budget N] -- <ORACLE> [ARGS]...",
    ],
    prose: "\
`minimize --generation N` reduces one failing generation of a recorded campaign, \
knobs first: it delta-debugs the fault-knob vector that generation drew (each \
candidate is a fresh seeded `run`, so the answer is a standalone reproduction \
command, printed and written into the out-dir), then delta-debugs a trace recorded \
from that minimal-knob run. --no-trace-phase stops after the knobs. The oracle is \
patina's own and needs no hand-written failure text: it targets the verdicts the \
campaign recorded for that generation, and a candidate still fails only when it \
reports every one of them AND the replay did not diverge — so candidates are \
hermetic and evaluated in parallel by default. --marker overrides the target with \
literal failure text, for a guest that reports nothing through the verdict ABI; a \
generation with neither is refused rather than reduced against a guess.\n\
\n\
`minimize <TRACE>` shrinks a recorded trace: an unbranched main timeline or a leaf \
--timeline ID is delta-debugged directly, while a branched bundle is shrunk under a \
branch-tree policy that never touches an inherited replay prefix. --prune-branches \
also drops whole branch subtrees the failure does not need. The oracle runs once \
per candidate with the candidate written to $PATINA_MINIMIZE_TRACE; a non-zero exit \
means the failure is still present. An external oracle is run serially unless --jobs \
opts in, because only a patina-owned oracle is hermetic by construction.\n\
\n\
`minimize --scenario` shrinks experiment inputs instead: it drops and shrinks \
--param values and canonicalizes --seed toward zero, bounded by --seed-budget. Each \
candidate re-runs the oracle as a fresh seeded child through the \
PATINA_SEED/PATINA_PARAMS_JSON protocol.",
    families: &[
        fam(Family::Sole, "`minimize`", None),
        fam(
            Family::Generation,
            "minimize --generation",
            Some(
                "minimize --generation reduces a recorded campaign generation and builds its own oracle",
            ),
        ),
        fam(
            Family::Scenario,
            "minimize --scenario",
            Some("minimize --scenario reduces experiment inputs rather than a recorded trace"),
        ),
    ],
    groups: &[
        Group {
            title: "Trace minimization",
            families: SOLE,
            flags: &[
                f(
                    "--timeline",
                    None,
                    Value::Required("ID", Kind::Str),
                    "Minimize a specific leaf timeline.",
                    false,
                ),
                f(
                    "--prune-branches",
                    None,
                    Value::None,
                    "Also drop whole branch subtrees the failure does not need.",
                    false,
                ),
            ],
        },
        Group {
            title: "Generation minimization (--generation)",
            families: &[Family::Generation],
            flags: &[
                f(
                    "--generation",
                    None,
                    Value::Required("N", Kind::U64),
                    "Reduce this recorded campaign generation: fault knobs first, then its trace.",
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
                f(
                    "--no-trace-phase",
                    None,
                    Value::None,
                    "Stop after the fault-knob reduction instead of also shrinking a trace.",
                    false,
                ),
            ],
        },
        Group {
            title: "Candidate evaluation",
            families: MINIMIZE_TRACE_FAMILIES,
            flags: &[
                f(
                    "--output",
                    Some("-o"),
                    Value::Required("PATH", Kind::Path),
                    "Write the minimized trace to PATH (required for a trace; defaults under the out-dir for --generation).",
                    false,
                ),
                f(
                    "--jobs",
                    None,
                    Value::Required("N", Kind::PositiveU64),
                    "Candidates to evaluate at once (default half the CPUs for the built-in oracle, 1 for an external one).",
                    false,
                ),
            ],
        },
        Group {
            title: "Scenario minimization (--scenario)",
            families: &[Family::Scenario],
            flags: &[
                f(
                    "--scenario",
                    None,
                    Value::None,
                    "Shrink experiment inputs (seed/params) instead of a trace.",
                    false,
                ),
                f(
                    "--seed",
                    None,
                    Value::Required("U64", Kind::U64),
                    "The failing seed to canonicalize toward zero (required).",
                    false,
                ),
                f(
                    "--seed-budget",
                    None,
                    Value::Required("N", Kind::U64),
                    "Seed canonicalization budget (default 256).",
                    false,
                ),
                f(
                    "--param",
                    None,
                    Value::Required("K=V", Kind::KeyValue),
                    "A scenario parameter to drop/shrink.",
                    true,
                ),
            ],
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
