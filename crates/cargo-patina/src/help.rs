//! The declarative flag registry and the help/usage renderers it generates.
//!
//! Every flag the CLI parsers accept is described once here — canonical name,
//! optional short form, value kind, placeholder, one-line doc, repeatability —
//! grouped per verb and per FAMILY within a verb (the disjoint flag sets a verb
//! chooses between at routing time). This registry is the SINGLE SOURCE for both
//! halves of the CLI:
//!
//! * the help — the compact top-level overview, each verb's focused `--help`
//!   section, the machine-readable `--help --format json` payload, and the
//!   synopsis lines a usage error prints; and
//! * the PARSING — `cli::command` builds each family's `clap::Command` from
//!   these same rows, so arity, the `=`-only optional form, repeatability, the
//!   typed value grammar, and cross-flag dependencies are declared once and
//!   enforced by construction.
//!
//! Because one declaration produces both, a parser cannot accept a flag the
//! help omits or reject one it advertises: those drift classes are
//! unrepresentable rather than merely tested. It also documents the `PATINA_*`
//! environment protocol and the honored tool variables.

/// The value grammar a flag's argument must satisfy — the typed shape the
/// parsers accept, declared once here so a value-syntax mismatch between what a
/// component emits/documents and what a parser accepts is caught by one generic
/// property test (`tests::registry_value_grammars_match_the_parsers` in `lib.rs`)
/// rather than a per-flag point test. Every variant is derived from the actual
/// value validation in `lib.rs`/`campaign.rs`; the test feeds valid and invalid
/// samples per kind through the real verb parsers, so a parser that tightens or
/// loosens a grammar without updating the kind here (or vice versa) fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An unsigned 64-bit integer (`parse_u64`), no further bound.
    U64,
    /// An unsigned 32-bit integer (`parse_u32`).
    U32,
    /// A non-negative machine integer (`parse_usize`).
    Usize,
    /// An unsigned integer required to be `>= 1` (a positive count).
    PositiveU64,
    /// A per-mille in `[0, 1000]`.
    Permille,
    /// An inclusive `MIN..MAX` nanosecond range with `MIN <= MAX`.
    NanosRange,
    /// An inclusive `A..B` unsigned sequence-number range with `A <= B`.
    U64Range,
    /// A comma-separated list of operation tags and/or category labels.
    OpKindList,
    /// A scheduler task id (`u64`) or the literal `main`.
    TaskSelector,
    /// A filesystem crash spec `open|write|sync|close[:N]` (`N >= 1`).
    CrashSpec,
    /// A `KEY=VALUE` pair with a non-empty key.
    KeyValue,
    /// `NAME=IPV4`: a DNS host-table entry. Distinct from [`Kind::KeyValue`]
    /// because the value half must be a dotted-quad address, and a typo there is
    /// worth catching at parse time rather than at the guest's first lookup.
    DnsEntry,
    /// A datagram socket `FD=BIND->PEER` (FD a u32 above 3, non-empty addresses).
    Socket,
    /// A preopen `GUEST[:ro|:rw]` with a non-empty guest path.
    Preopen,
    /// `all`, or a comma-separated list of at least one non-empty symbol.
    UnsupportedSymbols,
    /// One of a fixed set of string literals.
    Enum(&'static [&'static str]),
    /// A non-empty free-form string (rejected only when empty).
    Symbol,
    /// A filesystem path — any string, accepted verbatim (no value grammar).
    Path,
    /// A free-form string the parser stores verbatim (no value grammar).
    Str,
}

impl Kind {
    /// The grammar tag exposed in the JSON payload.
    fn tag(self) -> &'static str {
        match self {
            Kind::U64 => "u64",
            Kind::U32 => "u32",
            Kind::Usize => "usize",
            Kind::PositiveU64 => "positive-u64",
            Kind::Permille => "permille",
            Kind::NanosRange => "nanos-range",
            Kind::U64Range => "u64-range",
            Kind::OpKindList => "op-kind-list",
            Kind::TaskSelector => "task-selector",
            Kind::CrashSpec => "crash-spec",
            Kind::KeyValue => "key-value",
            Kind::DnsEntry => "dns-entry",
            Kind::Socket => "socket",
            Kind::Preopen => "preopen",
            Kind::UnsupportedSymbols => "unsupported-symbols",
            Kind::Enum(_) => "enum",
            Kind::Symbol => "symbol",
            Kind::Path => "path",
            Kind::Str => "string",
        }
    }
}

/// How a flag takes its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    /// A valueless switch (`--release`, `--swarm`).
    None,
    /// A required value with the given placeholder and grammar (`--seed <U64>`).
    Required(&'static str, Kind),
    /// An optional value (`--buggify[=<PERMILLE>]`): the switch alone is valid,
    /// and an `=VALUE` form supplies a value of the given grammar.
    Optional(&'static str, Kind),
}

impl Value {
    /// The value-kind tag used in the JSON payload.
    fn kind(self) -> &'static str {
        match self {
            Value::None => "none",
            Value::Required(..) => "required",
            Value::Optional(..) => "optional",
        }
    }

    pub fn placeholder(self) -> Option<&'static str> {
        match self {
            Value::None => None,
            Value::Required(p, _) | Value::Optional(p, _) => Some(p),
        }
    }

    /// The value grammar this flag's argument must satisfy, or `None` for a
    /// valueless switch. The single source the value-grammar property test walks.
    pub fn grammar(self) -> Option<Kind> {
        match self {
            Value::None => None,
            Value::Required(_, kind) | Value::Optional(_, kind) => Some(kind),
        }
    }
}

/// One flag the parsers accept.
#[derive(Clone, Copy, Debug)]
pub struct Flag {
    pub name: &'static str,
    pub short: Option<&'static str>,
    pub value: Value,
    pub doc: &'static str,
    pub repeatable: bool,
    /// The flag this one is inert without. A dependent knob supplied alone is
    /// refused rather than silently ignored, so a mistyped sweep flag fails
    /// loudly — and the generic grammar walk knows to supply the parent when it
    /// exercises the child.
    pub requires: Option<&'static str>,
    /// The families that accept this flag, when they are narrower than its
    /// [`Group`]'s. `None` — the common case — means "exactly the group's".
    /// [`only`] sets it for the few flags that share a group with flags of wider
    /// reach: `--budget`/`--param` are Cargo-family knobs sitting beside
    /// `--seed`/`--record`, which every family of `run` accepts.
    pub families: Option<&'static [Family]>,
}

/// Terse constructor so the registry tables stay one-flag-per-line.
const fn f(
    name: &'static str,
    short: Option<&'static str>,
    value: Value,
    doc: &'static str,
    repeatable: bool,
) -> Flag {
    Flag {
        name,
        short,
        value,
        doc,
        repeatable,
        requires: None,
        families: None,
    }
}

/// Declare that a flag is inert without `parent`.
const fn needs(flag: Flag, parent: &'static str) -> Flag {
    Flag {
        requires: Some(parent),
        ..flag
    }
}

/// Narrow one flag to a subset of its group's families.
const fn only(flag: Flag, families: &'static [Family]) -> Flag {
    Flag {
        families: Some(families),
        ..flag
    }
}

/// A parsing family within a verb: one verb and one positional shape, but
/// several disjoint flag sets, chosen at routing time from an artifact's magic
/// bytes, a subcommand token, or a mode switch. Families are why `--fuel` is
/// valid on `run <MODULE.wasm>` and invalid on `run <BINARY>`.
///
/// The registry is the single declaration of that mapping. It builds each
/// family's parser, decides which flags a family refuses and in what words, and
/// routes the generic grammar walks — so a family cannot accept a flag the help
/// does not advertise for it, and cannot advertise one it does not accept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    /// A verb with one form: `campaign`, `coverage`, `sites`, `explore`, and
    /// `minimize`'s default trace-reduction mode.
    Sole,
    /// The Cargo package family: an in-process `cargo run`/`cargo test` that
    /// forwards every unrecognized option to Cargo verbatim.
    Cargo,
    /// A `wasm32-wasip1` module under the WASI host.
    Wasi,
    /// A shim-linked native binary under the native supervisor.
    Native,
    /// `test <DIR|Cargo.toml>`: native libtest harness mode.
    Harness,
    /// `minimize --scenario`: seed/parameter rather than trace reduction.
    Scenario,
    /// `trace info`.
    Info,
    /// `trace events`.
    Events,
    /// `trace stats`.
    Stats,
    /// `trace diff`.
    Diff,
}

impl Family {
    /// The stable tag exposed in the JSON payload.
    pub fn tag(self) -> &'static str {
        match self {
            Family::Sole => "sole",
            Family::Cargo => "cargo",
            Family::Wasi => "wasi",
            Family::Native => "native",
            Family::Harness => "harness",
            Family::Scenario => "scenario",
            Family::Info => "info",
            Family::Events => "events",
            Family::Stats => "stats",
            Family::Diff => "diff",
        }
    }
}

/// The family list of a verb with exactly one form.
const SOLE: &[Family] = &[Family::Sole];

/// One family of a verb, with the wording its errors use.
#[derive(Clone, Copy, Debug)]
pub struct FamilySpec {
    pub family: Family,
    /// How an unknown-option error names this family: "`run` of a native
    /// binary", "trace events".
    pub label: &'static str,
    /// Why this family refuses a flag a SIBLING family of the same verb accepts
    /// — "trace info reads metadata only". Rendered as
    /// "<because> and does not accept <flag>"; `None` falls back to
    /// "<label> does not accept <flag>".
    pub because: Option<&'static str>,
}

const fn fam(family: Family, label: &'static str, because: Option<&'static str>) -> FamilySpec {
    FamilySpec {
        family,
        label,
        because,
    }
}

/// A family's refusal of a flag it does not register: a flag that is real
/// elsewhere in the CLI but meaningless here, answered with an explanation
/// rather than the generic unknown-option error.
///
/// `replay` is the motivating case. It restores every semantic input from the
/// trace, so `--seed`/`--fs-*`/`--buggify*` are not replay flags at all — but
/// "unknown option" would leave the operator guessing why a knob vanished. The
/// refused set is declared here by REFERENCE to the shared flag slices, so a
/// knob added to [`FAULT_FLAGS`] is refused by every family that refuses faults
/// with no second list to remember.
#[derive(Clone, Copy, Debug)]
pub struct Refusal {
    pub families: &'static [Family],
    /// Shared registry slices whose every flag is refused.
    pub flags: &'static [&'static [Flag]],
    /// Individually named refusals that are not a whole slice.
    pub names: &'static [&'static str],
    /// The explanation; `{flag}` is replaced with the offending flag.
    pub message: &'static str,
}

/// A titled group of flags within a verb's help section.
#[derive(Clone, Copy, Debug)]
pub struct Group {
    pub title: &'static str,
    /// The families whose parsers accept this group's flags. Individual flags
    /// may narrow it with [`only`].
    pub families: &'static [Family],
    pub flags: &'static [Flag],
}

/// A verb's full help entry.
#[derive(Clone, Copy, Debug)]
pub struct Verb {
    pub name: &'static str,
    pub summary: &'static str,
    pub synopsis: &'static [&'static str],
    pub prose: &'static str,
    /// The verb's families, in routing order.
    pub families: &'static [FamilySpec],
    pub groups: &'static [Group],
    pub refusals: &'static [Refusal],
}

/// No declared refusals: every flag this verb rejects is simply unknown to it.
const NO_REFUSALS: &[Refusal] = &[];

/// A `PATINA_*` environment variable's documentation.
#[derive(Clone, Copy, Debug)]
pub struct EnvVar {
    pub name: &'static str,
    /// `"user"` (an operator-facing knob), `"protocol"` (an internal
    /// supervisor↔guest / oracle protocol var, set for you), or `"tool"`.
    pub scope: &'static str,
    pub doc: &'static str,
}

/// Which help section to render.
#[derive(Clone, Copy, Debug)]
pub enum Topic {
    /// The compact top-level overview.
    Overview,
    /// A single verb's focused section.
    Verb(&'static str),
}

// ===========================================================================
// Shared flag groups
// ===========================================================================

/// Output options, parsed once globally (before routing) and honored by every
/// verb. Documented in the overview and appended to each verb section.
pub const GLOBAL_OUTPUT: &[Flag] = &[
    f(
        "--format",
        None,
        Value::Required("human|json", Kind::Enum(&["human", "json"])),
        "Result format (default human). `json` prints one machine-readable result envelope (schema patina.result/v1) on stdout; `coverage --format json` prints patina.coverage/v1, and `trace events --format json` is the streaming exception and prints patina.trace.events/v1 JSON Lines. `--help --format json` prints this registry as JSON.",
        false,
    ),
    f(
        "--render",
        None,
        Value::Required("OUT.html", Kind::Path),
        "For a run/replay with a trace, write a self-contained HTML timeline to OUT.html.",
        false,
    ),
    f(
        "--report",
        None,
        Value::Required("OUT.html", Kind::Path),
        "Like --render but only when the run fails; the HTML leads with a failure summary.",
        false,
    ),
    f(
        "--no-config",
        None,
        Value::None,
        "Ignore .patina/config.toml for this invocation (PATINA_* environment defaults still apply).",
        false,
    ),
];

pub const HELP_FLAGS: &[Flag] = &[
    f(
        "--help",
        Some("-h"),
        Value::None,
        "Print help (accepted anywhere before `--`).",
        false,
    ),
    f(
        "--version",
        Some("-V"),
        Value::None,
        "Print version.",
        false,
    ),
];

const TARGET_FLAG: Flag = f(
    "--target",
    None,
    Value::Required("native|wasi", Kind::Enum(&["native", "wasi"])),
    "Select the family for a source/package argument (default native); stripped before routing.",
    false,
);

const SOURCE_SELECT: &[Flag] = &[
    f(
        "--package",
        Some("-p"),
        Value::Required("NAME", Kind::Str),
        "Select a workspace member to build on the fly.",
        false,
    ),
    f(
        "--bin",
        None,
        Value::Required("NAME", Kind::Str),
        "Select the binary when the package defines more than one.",
        false,
    ),
    TARGET_FLAG,
];

const FAULT_FLAGS: &[Flag] = &[
    f(
        "--fs-crash-at",
        None,
        Value::Required("SPEC", Kind::CrashSpec),
        "Inject a filesystem crash after the Nth boundary op: open|write|sync|close[:N] (bare = :1).",
        false,
    ),
    f(
        "--fs-torn-granularity",
        None,
        Value::Required("block|byte", Kind::Enum(&["block", "byte"])),
        "Torn-write granularity for --fs-crash-at: block (default) or byte.",
        false,
    ),
    f(
        "--fs-error-permille",
        None,
        Value::Required("N", Kind::Permille),
        "Fail eligible fs ops at N per-mille with a seeded errno (EIO/ENOSPC/EINTR per op).",
        false,
    ),
    f(
        "--fs-short-permille",
        None,
        Value::Required("N", Kind::Permille),
        "Truncate fs reads/writes at N per-mille (short I/O, ≥1 byte).",
        false,
    ),
    f(
        "--fs-latency-nanos",
        None,
        Value::Required("MIN..MAX", Kind::NanosRange),
        "Add seeded latency drawn from [MIN, MAX] to every fault-eligible fs op, before it runs.",
        false,
    ),
    f(
        "--sleep-jitter-nanos",
        None,
        Value::Required("MIN..MAX", Kind::NanosRange),
        "Add seeded latency drawn from [MIN, MAX] to every guest sleep.",
        false,
    ),
    f(
        "--net-jitter-nanos",
        None,
        Value::Required("MIN..MAX", Kind::NanosRange),
        "Add seeded per-datagram delivery jitter drawn from [MIN, MAX].",
        false,
    ),
    f(
        "--net-drop-permille",
        None,
        Value::Required("N", Kind::Permille),
        "Drop datagrams at N per-mille (0..=1000).",
        false,
    ),
    f(
        "--net-latency-nanos",
        None,
        Value::Required("N", Kind::U64),
        "Base per-datagram/segment delivery latency in nanoseconds.",
        false,
    ),
];

/// The DNS domain: the host table (semantic configuration, like `--param`) and
/// its two seeded fault knobs.
///
/// A slice of its own rather than rows in [`FAULT_FLAGS`], because wasip1 has no
/// name-resolution surface at all — no `getaddrinfo`, no `sock_addr_resolve` — so
/// the WASI parser must refuse these loudly instead of accepting knobs that could
/// never fire. That family exception is declared once, by the owning GROUP in
/// each verb, which is also the only place that can name families the verb
/// actually has.
/// The host table itself, split out because `campaign` takes it WITHOUT the fault
/// knobs: a campaign draws `--dns-fail-permille`/`--dns-latency-nanos` per
/// generation from the generation hash, so accepting them from the operator too
/// would be two authorities over one knob.
const DNS_ENTRY_FLAG: Flag = f(
    "--dns-entry",
    None,
    Value::Required("NAME=ADDR", Kind::DnsEntry),
    "Define NAME to resolve to IPv4 ADDR (repeatable). Undefined names are NXDOMAIN.",
    true,
);

const DNS_ENTRY_FLAGS: &[Flag] = &[DNS_ENTRY_FLAG];

const DNS_FLAGS: &[Flag] = &[
    DNS_ENTRY_FLAG,
    f(
        "--dns-fail-permille",
        None,
        Value::Required("N", Kind::Permille),
        "Fail resolutions of DEFINED names at N per-mille (seeded NXDOMAIN or timeout).",
        false,
    ),
    f(
        "--dns-latency-nanos",
        None,
        Value::Required("MIN..MAX", Kind::NanosRange),
        "Add seeded latency drawn from [MIN, MAX] to every resolution of a defined name.",
        false,
    ),
];

const WASI_HOST_FLAGS: &[Flag] = &[
    f(
        "--fuel",
        None,
        Value::Required("N", Kind::U64),
        "Maximum wasm fuel (execution budget).",
        false,
    ),
    f(
        "--arg",
        None,
        Value::Required("VALUE", Kind::Str),
        "Append a guest argv entry (recorded and restored on replay).",
        true,
    ),
    f(
        "--env",
        None,
        Value::Required("K=V", Kind::KeyValue),
        "Set a guest environment variable.",
        true,
    ),
    f(
        "--socket",
        None,
        Value::Required("FD=BIND->PEER", Kind::Socket),
        "Configure a datagram socket at a unique FD above 3.",
        true,
    ),
    f(
        "--preopen",
        None,
        Value::Required("GUEST[:ro|:rw]", Kind::Preopen),
        "Preopen an absolute guest path (default rw; first explicit preopen replaces the implicit rw `/`).",
        true,
    ),
    f(
        "--max-memory-pages",
        None,
        Value::Required("N", Kind::U32),
        "Maximum guest memory pages (64 KiB each).",
        false,
    ),
    f(
        "--max-descriptors",
        None,
        Value::Required("N", Kind::Usize),
        "Maximum open WASI descriptors.",
        false,
    ),
    f(
        "--max-preopens",
        None,
        Value::Required("N", Kind::Usize),
        "Maximum configured preopened directories.",
        false,
    ),
    f(
        "--max-path-bytes",
        None,
        Value::Required("N", Kind::Usize),
        "Maximum bytes in a single guest path.",
        false,
    ),
    f(
        "--max-io-bytes",
        None,
        Value::Required("N", Kind::Usize),
        "Maximum bytes in one WASI I/O operation.",
        false,
    ),
    f(
        "--max-iovecs",
        None,
        Value::Required("N", Kind::Usize),
        "Maximum iovec entries in one WASI operation.",
        false,
    ),
];

const BUGGIFY_FLAGS: &[Flag] = &[
    f(
        "--buggify",
        None,
        Value::Optional("PERMILLE", Kind::Permille),
        "Enable cooperative-SUT (buggify) fault injection; PERMILLE is the per-evaluation firing probability (default 250 = 25%).",
        false,
    ),
    f(
        "--buggify-activation-permille",
        None,
        Value::Required("N", Kind::Permille),
        "Fraction of buggify sites made active this run (default 250). Implies --buggify.",
        false,
    ),
    f(
        "--buggify-cutoff-nanos",
        None,
        Value::Required("N", Kind::U64),
        "Virtual-time cutoff after which buggify stops firing (default 300000000000). Implies --buggify.",
        false,
    ),
    f(
        "--buggify-after-setup",
        None,
        Value::None,
        "Buggify stays inert until the guest calls patina_dst::lifecycle::setup_complete(). Implies --buggify.",
        false,
    ),
];

const LIVENESS_FLAGS_OPTIONAL: &[Flag] = &[
    f(
        "--liveness-watchdog",
        None,
        Value::Optional("NANOS", Kind::U64),
        "Arm a no-progress watchdog over virtual time (bare = runtime default budget).",
        false,
    ),
    f(
        "--converge-within",
        None,
        Value::Optional("NANOS", Kind::U64),
        "Require convergence within NANOS of the last injected fault (bare = default).",
        false,
    ),
    needs(
        f(
            "--heal-after",
            None,
            Value::Required("NANOS", Kind::U64),
            "Fault-free convergence arm-time override; requires --converge-within.",
            false,
        ),
        "--converge-within",
    ),
];

const NATIVE_SCHEDULE_FLAGS: &[Flag] = &[
    f(
        "--sched-pct",
        None,
        Value::Optional("N", Kind::PositiveU64),
        "PCT priority-scheduling exploration; N is the bug depth (>= 1).",
        false,
    ),
    needs(
        f(
            "--sched-pct-steps",
            None,
            Value::Required("N", Kind::PositiveU64),
            "Number of PCT priority-change points (>= 1). Requires --sched-pct.",
            false,
        ),
        "--sched-pct",
    ),
    f(
        "--starve",
        None,
        Value::Optional("N", Kind::PositiveU64),
        "Starvation exploration; N is the interval count (>= 1).",
        false,
    ),
    needs(
        f(
            "--starve-max-len",
            None,
            Value::Required("N", Kind::PositiveU64),
            "Maximum starvation run length (>= 1). Requires --starve.",
            false,
        ),
        "--starve",
    ),
    needs(
        f(
            "--starve-window",
            None,
            Value::Required("N", Kind::PositiveU64),
            "Starvation window (>= 1). Requires --starve.",
            false,
        ),
        "--starve",
    ),
    f(
        "--swarm",
        None,
        Value::None,
        "Seed-derived swarm selection of a fault-class subset.",
        false,
    ),
];

const REPLAY_TIMELINE_FLAGS: &[Flag] = &[
    f(
        "--timeline",
        None,
        Value::Required("ID", Kind::Str),
        "Replay a named timeline (default main).",
        false,
    ),
    f(
        "--branch",
        None,
        Value::None,
        "Replay the parent prefix then append a new branch timeline.",
        false,
    ),
    f(
        "--from",
        None,
        Value::Required("N", Kind::U64),
        "Branch point sequence number. Requires --branch.",
        false,
    ),
    f(
        "--branch-seed",
        None,
        Value::Required("S", Kind::U64),
        "Seed for the appended branch. Requires --branch.",
        false,
    ),
    f(
        "--branch-id",
        None,
        Value::Required("ID", Kind::Str),
        "Id for the appended branch timeline. Requires --branch.",
        false,
    ),
    f(
        "--parent",
        None,
        Value::Required("ID", Kind::Str),
        "Parent timeline to branch from (default main). Requires --branch.",
        false,
    ),
];

// ===========================================================================
// The verb registry
// ===========================================================================

const RUN: Verb = Verb {
    name: "run",
    summary: "Build (on the fly) and/or run an artifact under the deterministic runtime.",
    synopsis: &[
        "cargo patina run [--seed N | --record PATH] [FAULT/BUGGIFY OPTIONS] [--budget N] [--param K=V]... [CARGO OPTIONS] [-- PROGRAM OPTIONS]",
        "cargo patina run <MODULE.wasm> [--seed N | --record PATH] [--fuel N] [--budget N] [--arg VALUE]... [--env K=V]... [--preopen GUEST[:ro|:rw]]... [FAULT OPTIONS] [BUGGIFY/LIVENESS OPTIONS]",
        "cargo patina run <BINARY> [--seed N | --record PATH] [--env K=V]... [--budget N] [--coverage-out PATH] [--fingerprint STR] [--mount HOST_DIR] [--harness] [FAULT OPTIONS] [BUGGIFY/SCHEDULE/LIVENESS OPTIONS] [--allow SYMBOL]... [-- PROGRAM ARGS]",
        "cargo patina run <SOURCE.rs|DIR|Cargo.toml> [--target native|wasi] [--release] [RUN OPTIONS]   (builds on the fly, then runs)",
    ],
    prose: "\
`run` is source-first with artifacts accepted uniformly. A built artifact \
(recognized by its leading magic bytes) is used as-is; a <SOURCE.rs|DIR|Cargo.toml> \
is built on the fly through the same pipeline as `build` and its product is run \
(a one-line PATINA_BUILD_ON_RUN note reports the built artifact and its hash). A \
`run` with a directory, a Cargo.toml, or no artifact and no --target stays the \
Cargo package family (the same seed/record/param/budget machinery as `test`); \
--target opts a source/package into build-then-run.\n\
\n\
`run <MODULE.wasm>` runs under WASI; `run <BINARY>` runs a shim-linked native \
binary under a pre-run default-deny audit: every externally resolved symbol must \
be interposed or known-safe, and any unsupported symbol on the \
blocking/time/scheduling/effect surface hard-errors. --allow SYMBOL adds a \
known-safe symbol; --allow-unsupported-symbols <all|name,...> downgrades matching \
denials to a loud warning.\n\
\n\
`--harness` marks a patina-dst-harness (configure-then-run) binary: it defers \
runtime installation so the harness installs and configures the context itself. \
Supply it on both the record `run` and the `replay`. Reproduce a recorded run with \
`cargo patina replay`.",
    families: &[
        fam(Family::Cargo, "`run`", None),
        fam(Family::Wasi, "`run` of a WASI module", None),
        fam(Family::Native, "`run` of a native binary", None),
    ],
    groups: &[
        Group {
            title: "Patina options (run/test)",
            families: &[Family::Cargo, Family::Wasi, Family::Native],
            flags: &[
                f(
                    "--seed",
                    None,
                    Value::Required("U64", Kind::U64),
                    "Deterministic root seed (default 0).",
                    false,
                ),
                f(
                    "--record",
                    None,
                    Value::Required("PATH", Kind::Path),
                    "Record boundary operations and outcomes to PATH.",
                    false,
                ),
                f(
                    "--budget",
                    None,
                    Value::Required("STEPS", Kind::U64),
                    "Maximum boundary operations before explicit failure.",
                    false,
                ),
                only(
                    f(
                        "--param",
                        None,
                        Value::Required("K=V", Kind::KeyValue),
                        "Typed-builder parameter exposed through Context (cargo family).",
                        true,
                    ),
                    &[Family::Cargo],
                ),
            ],
        },
        Group {
            title: "Source-first selection (building a source/package on the fly)",
            families: &[Family::Wasi, Family::Native],
            flags: SOURCE_SELECT,
        },
        Group {
            title: "Build profile (source-first)",
            families: &[Family::Wasi, Family::Native],
            flags: &[f(
                "--release",
                None,
                Value::None,
                "Build the on-the-fly guest in release mode (default debug; debug is the bug-finding profile — see the debug-vs-release note).",
                false,
            )],
        },
        Group {
            title: "Fault options (seed-driven, default off)",
            families: &[Family::Cargo, Family::Wasi, Family::Native],
            flags: FAULT_FLAGS,
        },
        Group {
            // wasip1 has no resolution surface, so the WASI family is absent
            // here and `run <MODULE.wasm> --dns-entry` is refused.
            title: "DNS options (no wasip1 resolution surface, so not under --target wasi)",
            families: &[Family::Cargo, Family::Native],
            flags: DNS_FLAGS,
        },
        Group {
            title: "Native run options (run <BINARY>)",
            families: &[Family::Native],
            flags: &[
                f(
                    "--harness",
                    None,
                    Value::None,
                    "Treat the binary as a patina-dst-harness (defers runtime init).",
                    false,
                ),
                f(
                    "--mount",
                    None,
                    Value::Required("HOST_DIR", Kind::Path),
                    "Capture a host directory read-only into the guest filesystem at `/`.",
                    false,
                ),
                f(
                    "--coverage-out",
                    None,
                    Value::Required("PATH", Kind::Path),
                    "Write a patina.covmap/v1 edge-counter map (requires --yield-points build).",
                    false,
                ),
                f(
                    "--env",
                    None,
                    Value::Required("K=V", Kind::KeyValue),
                    "Set a deterministic native guest environment variable (recorded and restored on replay).",
                    true,
                ),
                // The label a RECORDING carries: the supervisor composes it (base
                // label plus the `+buggify`/`+pct`/`+swarm` components the run
                // really armed), the runtime writes it into the trace, and replay
                // recomputes and compares it. A seeded run writes no trace and the
                // runtime never even reads `PATINA_FINGERPRINT` in seeded mode, so
                // a label supplied there could not be checked by anything —
                // declared dependent on `--record` so it is refused rather than
                // silently discarded.
                needs(
                    f(
                        "--fingerprint",
                        None,
                        Value::Required("STR", Kind::Str),
                        "Compatibility label written into the recorded trace; requires --record (default patina-native).",
                        false,
                    ),
                    "--record",
                ),
                f(
                    "--allow",
                    None,
                    Value::Required("SYMBOL", Kind::Symbol),
                    "Add a known-safe symbol to the pre-run gate allow list.",
                    true,
                ),
                f(
                    "--allow-unsupported-symbols",
                    None,
                    Value::Required("all|name,...", Kind::UnsupportedSymbols),
                    "Downgrade matching unsupported-symbol denials to a warning.",
                    false,
                ),
            ],
        },
        Group {
            title: "Native scheduling options (run <BINARY>)",
            families: &[Family::Native],
            flags: NATIVE_SCHEDULE_FLAGS,
        },
        Group {
            title: "Buggify options",
            families: &[Family::Cargo, Family::Wasi, Family::Native],
            flags: BUGGIFY_FLAGS,
        },
        Group {
            title: "Liveness options (run <MODULE.wasm> & run <BINARY>)",
            families: &[Family::Wasi, Family::Native],
            flags: LIVENESS_FLAGS_OPTIONAL,
        },
        Group {
            title: "WASI run options (run <MODULE.wasm>)",
            families: &[Family::Wasi],
            flags: WASI_HOST_FLAGS,
        },
    ],
    refusals: NO_REFUSALS,
};

const TEST: Verb = Verb {
    name: "test",
    summary: "Run tests under Patina: Cargo-family by default, or a shim-linked native libtest harness for a source package.",
    synopsis: &[
        "cargo patina test [--seed N | --record PATH] [FAULT/BUGGIFY OPTIONS] [--budget N] [--param K=V]... [CARGO OPTIONS] [-- PROGRAM OPTIONS]",
        "cargo patina test <DIR|Cargo.toml> --harness-target NAME --exact MOD::test [--seed N | --seeds N] [--release] [--budget N] [--yield-points] [FAULT/BUGGIFY/SCHEDULE/LIVENESS OPTIONS]",
    ],
    prose: "\
With no source positional, `test` is the Cargo package family: the seed/record \
machinery, seed-driven fault knobs, and typed --param values, with every \
unrecognized option forwarded to Cargo. Reproducing a recording is the `replay` \
verb's job, so the Cargo-family form carries no replay/branch/timeline flags. A \
--record run captures its seed and fault knobs into the trace metadata so \
`replay` restores them.\n\
\n\
A directory or Cargo.toml positional selects native harness mode: Patina rebuilds \
the requested Cargo libtest target shim-linked with `cargo test --no-run`, stages \
the harness under target/patina/dst, and runs only the `--exact` test with \
`--test-threads=1`. `--seeds N` sweeps 0..N (default 20); `--seed N` runs one \
seed. On the first failure Patina re-runs that seed with --record and prints \
copy-paste `test` and `replay` repro commands.",
    families: &[
        fam(Family::Cargo, "`test`", None),
        fam(Family::Harness, "`test` native harness mode", None),
    ],
    groups: &[
        Group {
            title: "Patina options (Cargo-family run/test)",
            families: &[Family::Cargo, Family::Harness],
            flags: &[
                f(
                    "--seed",
                    None,
                    Value::Required("U64", Kind::U64),
                    "Deterministic root seed (default 0). In native harness mode, run exactly this seed instead of a sweep.",
                    false,
                ),
                only(
                    f(
                        "--record",
                        None,
                        Value::Required("PATH", Kind::Path),
                        "Record boundary operations and outcomes to PATH (Cargo-family form; native harness mode records failures automatically).",
                        false,
                    ),
                    &[Family::Cargo],
                ),
                f(
                    "--budget",
                    None,
                    Value::Required("STEPS", Kind::U64),
                    "Maximum boundary operations before explicit failure.",
                    false,
                ),
                only(
                    f(
                        "--param",
                        None,
                        Value::Required("K=V", Kind::KeyValue),
                        "Typed-builder parameter exposed through Context (Cargo-family form).",
                        true,
                    ),
                    &[Family::Cargo],
                ),
            ],
        },
        Group {
            title: "Native libtest harness selection (test <DIR|Cargo.toml>)",
            families: &[Family::Harness],
            flags: &[
                f(
                    "--harness-target",
                    None,
                    Value::Required("NAME", Kind::Symbol),
                    "Cargo libtest target name to rebuild shim-linked (library, integration test, or bin harness). Required in native harness mode.",
                    false,
                ),
                f(
                    "--exact",
                    None,
                    Value::Required("MOD::test", Kind::Symbol),
                    "Exact libtest filter to run inside the shim-linked harness. Required in native harness mode.",
                    false,
                ),
                f(
                    "--seeds",
                    None,
                    Value::Required("N", Kind::PositiveU64),
                    "Run seeds 0..N in native harness mode (default 20; mutually exclusive with --seed).",
                    false,
                ),
                f(
                    "--package",
                    Some("-p"),
                    Value::Required("NAME", Kind::Str),
                    "Select a workspace member before building the native libtest harness.",
                    false,
                ),
                f(
                    "--release",
                    None,
                    Value::None,
                    "Build the native libtest harness in release mode (default debug).",
                    false,
                ),
                f(
                    "--yield-points",
                    None,
                    Value::None,
                    "Instrument the native libtest harness with deterministic yield points.",
                    false,
                ),
            ],
        },
        Group {
            title: "Fault options (seed-driven, default off)",
            families: &[Family::Cargo, Family::Harness],
            flags: FAULT_FLAGS,
        },
        Group {
            title: "DNS options",
            families: &[Family::Cargo, Family::Harness],
            flags: DNS_FLAGS,
        },
        Group {
            title: "Buggify options",
            families: &[Family::Cargo, Family::Harness],
            flags: BUGGIFY_FLAGS,
        },
        Group {
            title: "Native scheduling options (native harness mode)",
            families: &[Family::Harness],
            flags: NATIVE_SCHEDULE_FLAGS,
        },
        Group {
            title: "Liveness options (native harness mode)",
            families: &[Family::Harness],
            flags: LIVENESS_FLAGS_OPTIONAL,
        },
    ],
    refusals: NO_REFUSALS,
};

const BUILD: Verb = Verb {
    name: "build",
    summary: "Build the native linked-shim target (default) or a wasm32-wasip1 package.",
    synopsis: &[
        "cargo patina build <SOURCE.rs> --output <PATH> [--edition YEAR] [--release] [--yield-points] [-- RUSTC OPTIONS]",
        "cargo patina build <DIR|Cargo.toml> [--output <PATH>] [--package NAME] [--bin NAME] [--release] [--yield-points]",
        "cargo patina build <DIR|Cargo.toml> --target wasi [--output PATH] [--package NAME] [--bin NAME] [--release]",
    ],
    prose: "\
`build` (default --target native) packages the native linked-shim target: it \
builds the patina-dst-native-shim staticlib, compiles the embedded POSIX C layer, \
injects cfg(patina)/cfg(dst), and links the shim below the user program. A `.rs` \
path builds a single source directly; a directory or Cargo.toml drives the \
package's own cargo build under Patina control. Select the member with --package \
and the binary with --bin; --output copies the built binary out.\n\
\n\
`--yield-points` instruments the native guest with deterministic cooperative \
preemption (a hook at every basic block routes into the scheduler), making \
atomics-only race windows schedulable. It is native-only and rejected under \
--target wasi (wasip1 has no threads to preempt). `build --target wasi` compiles a \
Cargo package for wasm32-wasip1 and is package-only (a single .rs source is \
native-only).",
    families: &[
        fam(Family::Native, "`build`", None),
        fam(
            Family::Wasi,
            "`build --target wasi`",
            Some(
                "wasip1 has no threads to preempt and takes its edition from the package's Cargo.toml",
            ),
        ),
    ],
    groups: &[Group {
        title: "Build options",
        families: &[Family::Native, Family::Wasi],
        flags: &[
            f(
                "--output",
                Some("-o"),
                Value::Required("PATH", Kind::Path),
                "Copy the built binary out to PATH (required for a single .rs source).",
                false,
            ),
            only(
                f(
                    "--edition",
                    None,
                    Value::Required("YEAR", Kind::Str),
                    "Rust edition for a single-source build (default 2024).",
                    false,
                ),
                &[Family::Native],
            ),
            f(
                "--release",
                None,
                Value::None,
                "Build in release mode.",
                false,
            ),
            only(
                f(
                    "--yield-points",
                    None,
                    Value::None,
                    "Instrument deterministic cooperative preemption (native only).",
                    false,
                ),
                &[Family::Native],
            ),
            f(
                "--package",
                Some("-p"),
                Value::Required("NAME", Kind::Str),
                "Select a workspace member.",
                false,
            ),
            f(
                "--bin",
                None,
                Value::Required("NAME", Kind::Str),
                "Select the binary when the package defines more than one.",
                false,
            ),
            TARGET_FLAG,
        ],
    }],
    refusals: NO_REFUSALS,
};

const AUDIT: Verb = Verb {
    name: "audit",
    summary: "Report the true post-interposition residual effect surface of a binary.",
    synopsis: &[
        "cargo patina audit <SOURCE.rs|DIR|Cargo.toml> [--package NAME] [--bin NAME] [--target native|wasi] [--allow SYMBOL]...   (builds shim-linked, then audits)",
        "cargo patina audit <ARTIFACT> [--allow SYMBOL]... [--raw]   (a prebuilt binary; must be `cargo patina build`-linked unless --raw)",
    ],
    prose: "\
`audit` is source-first: only a shim-linked binary shows the true \
post-interposition residual, so auditing a source/package links the shim first and \
the report is the handful of effect-surface symbols that genuinely escape. A stock \
`cargo build` binary lists every libc call the shim would interpose as an \
unsupported import — the opposite of the truth — so `audit <prebuilt>` fails closed \
unless the binary was produced by `cargo patina build`. `--raw` overrides that gate \
and runs the full audit anyway under a loud banner. A WASI module lists its imports \
and takes no --allow (the allow list is native-only).",
    families: &[
        fam(Family::Native, "`audit` of a native binary", None),
        fam(
            Family::Wasi,
            "`audit` of a WASI module",
            Some(
                "a module's imports are read from the module itself; the allow list is native-only",
            ),
        ),
    ],
    groups: &[
        Group {
            title: "Audit options",
            families: &[Family::Native],
            flags: &[
                f(
                    "--allow",
                    None,
                    Value::Required("SYMBOL", Kind::Symbol),
                    "Treat SYMBOL as known-safe (native only).",
                    true,
                ),
                f(
                    "--raw",
                    None,
                    Value::None,
                    "Audit a non-Patina-built binary anyway (import findings are pre-interposition).",
                    false,
                ),
            ],
        },
        Group {
            title: "Source-first selection",
            families: &[Family::Native, Family::Wasi],
            flags: SOURCE_SELECT,
        },
    ],
    refusals: NO_REFUSALS,
};

const REPLAY: Verb = Verb {
    name: "replay",
    summary: "Reproduce a recorded run; routes by the same inference as `run`.",
    synopsis: &[
        "cargo patina replay <ARTIFACT|SOURCE.rs|DIR|Cargo.toml> <TRACE> [--target native|wasi] [REPLAY OPTIONS]",
    ],
    prose: "\
`replay <ARTIFACT|SOURCE|PKG> <TRACE>` is the sole replay entry point for all three \
families: a wasm module replays under WASI, a native binary under the native \
supervisor, and a directory/Cargo.toml (no --target) under the Cargo package \
family. Each restores every recorded semantic input (seed, fault knobs, buggify, \
guest argv, and native `--env` values) from the trace — the trace is authoritative \
— so replay exposes no semantic flags; any re-supplied value must match the \
recording or the replay is refused.\n\
\n\
Only host/build inputs the trace cannot carry stay as flags. The Cargo and WASI \
families carry the timeline/branch controls (--timeline, and --branch --from \
--branch-seed --branch-id [--parent]); WASI re-takes its host environment \
(--fuel/--env/--socket/--preopen and resource limits). Native traces restore \
`run --env` values from metadata and reject re-supplied native `--env`; native \
traces are single-timeline (native runs cannot branch), so native replay accepts \
only --fingerprint, --mount, --coverage-out, --harness, and the \
--allow/--allow-unsupported-symbols audit surface.",
    families: &[
        fam(Family::Cargo, "`replay` of a Cargo package", None),
        fam(Family::Wasi, "`replay` of a WASI module", None),
        fam(Family::Native, "`replay` of a native binary", None),
    ],
    groups: &[
        Group {
            title: "Native replay options (host/build facts the trace cannot carry)",
            families: &[Family::Native],
            flags: &[
                f(
                    "--fingerprint",
                    None,
                    Value::Required("STR", Kind::Str),
                    "Compatibility fingerprint label (default patina-native).",
                    false,
                ),
                f(
                    "--mount",
                    None,
                    Value::Required("HOST_DIR", Kind::Path),
                    "Re-supply the host corpus whose hash the fingerprint verifies.",
                    false,
                ),
                f(
                    "--coverage-out",
                    None,
                    Value::Required("PATH", Kind::Path),
                    "Write a patina.covmap/v1 edge-counter map for the replayed native run.",
                    false,
                ),
                f(
                    "--harness",
                    None,
                    Value::None,
                    "Replay a patina-dst-harness binary (defers runtime init).",
                    false,
                ),
                f(
                    "--allow",
                    None,
                    Value::Required("SYMBOL", Kind::Symbol),
                    "Add a known-safe symbol to the pre-run gate allow list.",
                    true,
                ),
                f(
                    "--allow-unsupported-symbols",
                    None,
                    Value::Required("all|name,...", Kind::UnsupportedSymbols),
                    "Downgrade matching unsupported-symbol denials to a warning.",
                    false,
                ),
            ],
        },
        Group {
            title: "Timeline/branch replay (Cargo package & WASI families)",
            families: &[Family::Cargo, Family::Wasi],
            flags: REPLAY_TIMELINE_FLAGS,
        },
        Group {
            title: "WASI host environment (re-supplied and fingerprint-checked)",
            families: &[Family::Wasi],
            flags: WASI_HOST_FLAGS,
        },
        Group {
            title: "Family selection",
            families: &[Family::Wasi, Family::Native],
            flags: &[TARGET_FLAG],
        },
    ],
    refusals: &[
        // Every semantic input is recorded in the trace and restored from it, so
        // re-supplying one could only diverge the replay. Declared by reference
        // to the shared slices: a knob added to FAULT_FLAGS or BUGGIFY_FLAGS is
        // refused here the day it is added, with no second list to remember.
        Refusal {
            families: &[Family::Cargo, Family::Wasi, Family::Native],
            flags: &[FAULT_FLAGS, DNS_FLAGS, BUGGIFY_FLAGS, NATIVE_SCHEDULE_FLAGS],
            names: &["--seed", "--record", "--env"],
            message: "replay restores run semantics from the trace and does not accept {flag}; the trace is authoritative",
        },
        // Native traces are single-timeline and a native run cannot branch.
        Refusal {
            families: &[Family::Native],
            flags: &[REPLAY_TIMELINE_FLAGS],
            names: &[],
            message: "{flag} is not supported for native replay: native traces are single-timeline and native runs cannot branch; branch/timeline replay is the Cargo package and WASI families",
        },
    ],
};

const EXPLORE: Verb = Verb {
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

const CAMPAIGN: Verb = Verb {
    name: "campaign",
    summary: "Config-driven deterministic fault-and-schedule sweep over one artifact.",
    synopsis: &[
        "cargo patina campaign <ARTIFACT|SOURCE.rs|DIR|Cargo.toml> [--gens N] [--out-dir DIR] [--spec FILE.json] [--seed-start N] [--progress-every N] [--allow-unmet-sometimes[=MIN_GENS]] [--buggify] [--swarm] [--sched-pct] [--faults] [--dns-entry NAME=ADDR] [--liveness-watchdog N] [--converge-within N] [--report-failures] [-- GUEST ARGS]",
        "cargo patina campaign --extend N [--out-dir DIR] [--progress-every N] [--timeout-secs N]",
        "cargo patina campaign --resume [--out-dir DIR] [--progress-every N] [--timeout-secs N]",
        "cargo patina campaign --selftest",
    ],
    prose: "\
A campaign runs `--gens` independent child `cargo patina run` processes over one \
artifact. Everything is a pure function of the generation number, so a re-run with \
the same spec reproduces the same seeds, knobs, outcomes, and failure signatures. \
Each generation is classified into one of nine outcome classes; novel failure \
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
classes.",
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
                    "--faults",
                    None,
                    Value::None,
                    "Randomize fault knobs (fs error/short I/O/crash placement, net drop/latency, sleep jitter, and — with --dns-entry — DNS failure/latency) per generation.",
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
    ],
    refusals: NO_REFUSALS,
};

const COVERAGE: Verb = Verb {
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

const TRACE: Verb = Verb {
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

const SITES: Verb = Verb {
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

const MINIMIZE: Verb = Verb {
    name: "minimize",
    summary: "Shrink a recorded trace, or shrink experiment inputs (--scenario).",
    synopsis: &[
        "cargo patina minimize <TRACE> --output <PATH> [-o <PATH>] [--timeline ID] [--prune-branches] -- <ORACLE> [ARGS]...",
        "cargo patina minimize --scenario --seed <U64> [--param K=V]... [--seed-budget N] -- <ORACLE> [ARGS]...",
    ],
    prose: "\
`minimize <TRACE>` shrinks a recorded trace: an unbranched main timeline or a leaf \
--timeline ID is delta-debugged directly, while a branched bundle is shrunk under a \
branch-tree policy that never touches an inherited replay prefix. --prune-branches \
also drops whole branch subtrees the failure does not need. The oracle runs once \
per candidate with the candidate written to $PATINA_MINIMIZE_TRACE; a non-zero exit \
means the failure is still present.\n\
\n\
`minimize --scenario` shrinks experiment inputs instead: it drops and shrinks \
--param values and canonicalizes --seed toward zero, bounded by --seed-budget. Each \
candidate re-runs the oracle as a fresh seeded child through the \
PATINA_SEED/PATINA_PARAMS_JSON protocol.",
    families: &[
        fam(Family::Sole, "`minimize`", None),
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
                    "--output",
                    Some("-o"),
                    Value::Required("PATH", Kind::Path),
                    "Write the minimized trace to PATH (required).",
                    false,
                ),
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

/// Every verb, in overview order.
pub const VERBS: &[&Verb] = &[
    &RUN, &TEST, &BUILD, &AUDIT, &REPLAY, &EXPLORE, &CAMPAIGN, &COVERAGE, &SITES, &TRACE, &MINIMIZE,
];

/// The `PATINA_*` environment protocol and honored tool variables.
pub const ENVIRONMENT: &[EnvVar] = &[
    EnvVar {
        name: "PATINA_SEED",
        scope: "user",
        doc: "Deterministic root seed (mirrors --seed; a scenario-minimize oracle receives its candidate seed here).",
    },
    EnvVar {
        name: "PATINA_<DEFAULT_KEY>",
        scope: "user",
        doc: "CLI default override for `.patina/config.toml` keys (for example PATINA_SEED, PATINA_GENERATIONS): explicit flags still win; campaign scrubs run-default env names from child runs.",
    },
    EnvVar {
        name: "PATINA_PARAMS_JSON",
        scope: "user",
        doc: "Typed --param values as a JSON object (the scenario-minimize oracle protocol).",
    },
    EnvVar {
        name: "PATINA_MINIMIZE_TRACE",
        scope: "user",
        doc: "Path to the candidate trace a trace-minimize oracle must judge; a non-zero exit means the failure is still present.",
    },
    EnvVar {
        name: "PATINA_MODE",
        scope: "protocol",
        doc: "Run mode (seeded/record/replay/branch); set by the supervisor for the guest.",
    },
    EnvVar {
        name: "PATINA_TRACE",
        scope: "protocol",
        doc: "On-disk trace path for record/replay.",
    },
    EnvVar {
        name: "PATINA_TRACE_FD",
        scope: "protocol",
        doc: "Inherited already-open trace descriptor (native), so a fully interposed guest never recurses into the deterministic FS while finalizing its trace.",
    },
    EnvVar {
        name: "PATINA_COVERAGE_FD / PATINA_COVERAGE_REPORT",
        scope: "protocol",
        doc: "Native coverage dump descriptor for --coverage-out, plus a false-y suppressor for the default-on PATINA_COVERAGE_REPORT line.",
    },
    EnvVar {
        name: "PATINA_FS_IMAGE_FD",
        scope: "protocol",
        doc: "Inherited descriptor streaming the --mount host-directory image to the guest.",
    },
    EnvVar {
        name: "PATINA_DEFER_INIT",
        scope: "protocol",
        doc: "Set by --harness: defer runtime installation so the harness owns configure-then-run.",
    },
    EnvVar {
        name: "PATINA_STEP_BUDGET",
        scope: "protocol",
        doc: "Maximum boundary operations (mirrors --budget).",
    },
    EnvVar {
        name: "PATINA_FINGERPRINT",
        scope: "protocol",
        doc: "Compatibility fingerprint checked on replay.",
    },
    EnvVar {
        name: "PATINA_TIMELINE / PATINA_PARENT_TIMELINE / PATINA_BRANCH_FROM / PATINA_BRANCH_SEED / PATINA_BRANCH_ID",
        scope: "protocol",
        doc: "Timeline and branch-append controls (mirror the replay --timeline/--branch flags).",
    },
    EnvVar {
        name: "PATINA_GUEST_ARGV",
        scope: "protocol",
        doc: "Recorded guest argv restored on replay.",
    },
    EnvVar {
        name: "PATINA_GUEST_ENV_JSON",
        scope: "protocol",
        doc: "Recorded native guest environment map from run --env, restored on replay.",
    },
    EnvVar {
        name: "PATINA_FS_CRASH_AT / PATINA_FS_TORN_GRANULARITY / PATINA_FS_ERROR_PERMILLE / PATINA_FS_SHORT_PERMILLE",
        scope: "protocol",
        doc: "Filesystem crash, error, and short-I/O fault knobs (mirror the --fs-* flags).",
    },
    EnvVar {
        name: "PATINA_SLEEP_JITTER_NANOS / PATINA_NET_JITTER_NANOS / PATINA_NET_DROP_PERMILLE / PATINA_NET_LATENCY_NANOS",
        scope: "protocol",
        doc: "Seed-driven timing/network fault knobs (mirror the --*-nanos/--net-* flags).",
    },
    EnvVar {
        name: "PATINA_BUGGIFY / PATINA_BUGGIFY_ACTIVATION_PERMILLE / PATINA_BUGGIFY_CUTOFF_NANOS / PATINA_BUGGIFY_AFTER_SETUP",
        scope: "protocol",
        doc: "Cooperative-SUT (buggify) knobs (mirror the --buggify* flags).",
    },
    EnvVar {
        name: "PATINA_SCHED_PCT / PATINA_SCHED_PCT_STEPS / PATINA_SCHED_STARVE / PATINA_SCHED_STARVE_MAX_LEN / PATINA_SCHED_STARVE_WINDOW",
        scope: "protocol",
        doc: "Native scheduling exploration knobs (mirror --sched-pct/--starve*). A wedged run is killed by the starvation stall backstop (exit 111).",
    },
    EnvVar {
        name: "PATINA_SWARM",
        scope: "protocol",
        doc: "Seed-derived swarm fault-class selection (mirrors --swarm).",
    },
    EnvVar {
        name: "PATINA_LIVENESS_WATCHDOG_NANOS / PATINA_CONVERGE_WITHIN_NANOS / PATINA_HEAL_AFTER_NANOS",
        scope: "protocol",
        doc: "Liveness watchdog / convergence budgets (mirror --liveness-watchdog/--converge-within/--heal-after).",
    },
    EnvVar {
        name: "CARGO / RUSTC / CC",
        scope: "tool",
        doc: "Override the cargo, rustc, and C compiler binaries (default cargo/rustc/cc).",
    },
    EnvVar {
        name: "RUSTFLAGS / CARGO_TARGET_DIR",
        scope: "tool",
        doc: "Honored as usual; Patina augments RUSTFLAGS via CARGO_ENCODED_RUSTFLAGS for package builds and respects CARGO_TARGET_DIR for staging.",
    },
];

// ===========================================================================
// Lookup
// ===========================================================================

/// The verb entry named `name`, if any.
pub fn verb(name: &str) -> Option<&'static Verb> {
    VERBS.iter().copied().find(|verb| verb.name == name)
}

/// Every seed-driven fault knob's flag name, in registry order. The gate surface
/// for the CLI's shared knob table, so a knob added to [`FAULT_FLAGS`] cannot be
/// forwarded by one family and silently dropped by another.
#[cfg(test)]
pub fn fault_flag_names() -> impl Iterator<Item = &'static str> {
    FAULT_FLAGS
        .iter()
        .chain(DNS_FLAGS.iter())
        // `--dns-entry` is semantic configuration on its own control-plane
        // variable (like `--param`), not a seeded knob, so it is not part of the
        // knob table this list gates.
        .filter(|flag| flag.name != "--dns-entry")
        .map(|flag| flag.name)
}

/// The registered value-arity of a flag (matched by its long OR short name)
/// under `verb`, consulting the verb's own flag groups plus the always-available
/// global output and help flags. `None` means the flag is not registered for
/// this verb — an unknown passthrough token. This is the SINGLE arity source the
/// positional scanner in `lib.rs` consults so it never builds a second flag
/// table; the same lookup surface (`groups` + `GLOBAL_OUTPUT` + `HELP_FLAGS`) is
/// what `registry_covers_every_parsed_flag` asserts every parsed flag lives in,
/// so a parsed-but-unregistered flag is caught there rather than silently read as
/// an unknown-flag stop.
pub fn flag_arity(verb_name: &str, name: &str) -> Option<Value> {
    flag_by_cli_name(verb_name, name).map(|flag| flag.value)
}

/// Registered flag lookup by long or short CLI spelling, including global/help
/// flags. This is the parser-facing surface; config defaults use the narrower
/// `configurable_*` helpers below so help/output switches do not become project
/// defaults.
pub fn flag_by_cli_name(verb_name: &str, name: &str) -> Option<&'static Flag> {
    verb(verb_name)
        .into_iter()
        .flat_map(|verb| verb.groups.iter())
        .flat_map(|group| group.flags.iter())
        .chain(GLOBAL_OUTPUT.iter())
        .chain(HELP_FLAGS.iter())
        .find(|flag| flag.name == name || flag.short == Some(name))
}

impl Group {
    /// The families that accept `flag` within this group — the flag's own
    /// narrowing if it has one, else the group's.
    fn families_of(&self, flag: &Flag) -> &'static [Family] {
        flag.families.unwrap_or(self.families)
    }
}

impl Verb {
    /// The spec of one of this verb's families.
    pub fn family(&self, family: Family) -> &'static FamilySpec {
        self.families
            .iter()
            .find(|spec| spec.family == family)
            .unwrap_or_else(|| panic!("verb `{}` has no family {family:?}", self.name))
    }

    /// Every flag `family`'s parser accepts. Parser and help are built from this
    /// one call, so a family cannot accept a flag its help omits, nor advertise
    /// one it rejects.
    pub fn family_flags(&self, family: Family) -> impl Iterator<Item = &'static Flag> + use<'_> {
        self.groups.iter().flat_map(move |group| {
            group
                .flags
                .iter()
                .filter(move |flag| group.families_of(flag).contains(&family))
        })
    }

    /// Flags registered for this verb but NOT accepted by `family` — a sibling
    /// family's flags, answered in this family's own words rather than with a
    /// bare unknown-option error. Yields `(flag, message)`.
    pub fn cross_family_refusals(
        &self,
        family: Family,
    ) -> impl Iterator<Item = (&'static Flag, String)> + use<'_> {
        let spec = self.family(family);
        self.groups
            .iter()
            .flat_map(move |group| {
                group
                    .flags
                    .iter()
                    .filter(move |flag| !group.families_of(flag).contains(&family))
            })
            .map(move |flag| (flag, refusal_message(spec, flag.name)))
    }

    /// The verb's DECLARED refusals for `family`: flags that are real elsewhere
    /// in the CLI but meaningless here. Yields `(flag name, message)`.
    pub fn declared_refusals(&self, family: Family) -> Vec<(&'static str, String)> {
        self.refusals
            .iter()
            .filter(|refusal| refusal.families.contains(&family))
            .flat_map(|refusal| {
                refusal
                    .flags
                    .iter()
                    .flat_map(|slice| slice.iter().map(|flag| flag.name))
                    .chain(refusal.names.iter().copied())
                    .map(|name| (name, refusal.message.replace("{flag}", name)))
            })
            .collect()
    }
}

/// The wording a family uses to refuse a sibling family's flag.
fn refusal_message(spec: &FamilySpec, flag: &str) -> String {
    match spec.because {
        Some(because) => format!("{} does not accept {flag} ({because})", spec.label),
        None => format!("{} does not accept {flag}", spec.label),
    }
}

/// Verb-local flags that may be supplied by `.patina/config.toml` defaults or
/// PATINA_* env defaults. Global output/help switches are intentionally excluded:
/// they are parsed before config discovery and are invocation presentation, not
/// verb defaults.
pub fn configurable_flags(verb_name: &str) -> Vec<&'static Flag> {
    verb(verb_name)
        .into_iter()
        .flat_map(|verb| verb.groups.iter())
        .flat_map(|group| group.flags.iter())
        .collect()
}

/// Lookup a configurable flag by CLI spelling.
pub fn configurable_flag_by_cli_name(verb_name: &str, name: &str) -> Option<&'static Flag> {
    configurable_flags(verb_name)
        .into_iter()
        .find(|flag| flag.name == name || flag.short == Some(name))
}

/// The TOML/env key for a configurable flag. Most keys are the long flag without
/// leading dashes; `--gens` intentionally uses the readable config key
/// `generations`, matching `.patina/config.toml`'s project-level vocabulary
/// without adding a CLI flag alias.
pub fn config_key(flag: &Flag) -> &'static str {
    match flag.name {
        "--gens" => "generations",
        name => name.trim_start_matches('-'),
    }
}

/// Lookup a configurable flag by its TOML/env key.
pub fn configurable_flag_by_key(verb_name: &str, key: &str) -> Option<&'static Flag> {
    configurable_flags(verb_name)
        .into_iter()
        .find(|flag| config_key(flag) == key)
}

/// The canonical `Topic` for a routed verb token. `explore run`/`explore test`
/// all map to the `explore` overview; `test` has its own section.
pub fn topic_for(verb_token: &str) -> Topic {
    match verb_token {
        name if verb(name).is_some() => Topic::Verb(verb(name).unwrap().name),
        _ => Topic::Overview,
    }
}

// ===========================================================================
// Human rendering
// ===========================================================================

/// Column at which flag docs begin (a flag whose left column overruns it wraps
/// its doc onto the next line).
const DOC_COLUMN: usize = 34;
/// Right margin for word-wrapped prose and docs.
const WRAP_WIDTH: usize = 92;

/// The rendered left column for a flag, e.g. `  -o, --output <PATH>`.
fn flag_left(flag: &Flag) -> String {
    let mut left = String::from("  ");
    match flag.short {
        Some(short) => left.push_str(&format!("{short}, {}", flag.name)),
        None => left.push_str(&format!("    {}", flag.name)),
    }
    match flag.value {
        Value::None => {}
        Value::Required(p, _) => left.push_str(&format!(" <{p}>")),
        Value::Optional(p, _) => left.push_str(&format!("[=<{p}>]")),
    }
    if flag.repeatable {
        left.push_str("...");
    }
    left
}

/// Greedy word-wrap of `text` to at most `width` columns per line.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        let candidate = if current.is_empty() {
            word.to_string()
        } else {
            format!("{current} {word}")
        };
        if candidate.chars().count() > width && !current.is_empty() {
            lines.push(current);
            current = word.to_string();
        } else {
            current = candidate;
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn push_flag(out: &mut String, flag: &Flag) {
    let left = flag_left(flag);
    let doc_lines = wrap(flag.doc, WRAP_WIDTH.saturating_sub(DOC_COLUMN));
    // The left column and the first doc line share a row unless the left column
    // overruns the doc column, in which case the doc starts on the next line.
    if left.chars().count() + 2 > DOC_COLUMN {
        out.push_str(&left);
        out.push('\n');
        for line in &doc_lines {
            out.push_str(&" ".repeat(DOC_COLUMN));
            out.push_str(line);
            out.push('\n');
        }
    } else {
        out.push_str(&left);
        out.push_str(&" ".repeat(DOC_COLUMN - left.chars().count()));
        for (index, line) in doc_lines.iter().enumerate() {
            if index > 0 {
                out.push_str(&" ".repeat(DOC_COLUMN));
            }
            out.push_str(line);
            out.push('\n');
        }
        if doc_lines.is_empty() {
            out.push('\n');
        }
    }
}

fn push_prose(out: &mut String, prose: &str) {
    for paragraph in prose.split('\n') {
        if paragraph.trim().is_empty() {
            out.push('\n');
            continue;
        }
        for line in wrap(paragraph, WRAP_WIDTH) {
            out.push_str(&line);
            out.push('\n');
        }
    }
}

fn push_output_and_env_footer(out: &mut String) {
    out.push_str("\nOutput options (all verbs; stripped before routing, never reach the guest):\n");
    for flag in GLOBAL_OUTPUT {
        push_flag(out, flag);
    }
    out.push_str("\nRun `cargo patina --help` for the environment protocol and shared sections.\n");
}

/// Render the compact top-level overview.
fn render_overview() -> String {
    let mut out = String::new();
    out.push_str("Patina deterministic Cargo runner\n\n");
    out.push_str("Usage: cargo patina <VERB> [OPTIONS]\n\n");
    out.push_str("Verbs (run `cargo patina <verb> --help` for details):\n");
    let width = VERBS.iter().map(|v| v.name.len()).max().unwrap_or(0);
    for verb in VERBS {
        out.push_str(&format!(
            "  {:<width$}  {}\n",
            verb.name,
            verb.summary,
            width = width
        ));
    }
    out.push('\n');
    out.push_str("Global options:\n");
    for flag in HELP_FLAGS {
        push_flag(&mut out, flag);
    }
    for flag in GLOBAL_OUTPUT {
        push_flag(&mut out, flag);
    }

    out.push_str("\nFlag value syntax:\n");
    push_prose(
        &mut out,
        "A flag that takes a required value accepts both `--flag VALUE` and `--flag=VALUE` in \
every family. A flag with an OPTIONAL value (e.g. --buggify, --sched-pct, --starve, \
--liveness-watchdog, --converge-within) accepts only the bare `--flag` or `--flag=VALUE` — the \
space form is ambiguous with a positional. Everything after a `--` separator is passed to the \
guest/oracle untouched, so `--arg=--help` is how a WASI guest receives a literal `--help`.",
    );

    out.push_str("\nArtifact inference:\n");
    push_prose(
        &mut out,
        "`run`, `audit`, and `replay` are source-first with artifacts accepted uniformly. A \
built artifact is recognized by its leading magic bytes (\\0asm for a WASI module, Mach-O/ELF \
for a native binary) and used as-is; a <SOURCE.rs|DIR|Cargo.toml> is built on the fly through \
the same pipeline as `build` (honoring --target, default native). For `test`, no source \
positional stays the Cargo package family, while a <DIR|Cargo.toml> positional selects native \
libtest harness mode. A positional that names a file path (.wasm/.rs/Cargo.toml, or with a \
separator) but does not exist is a hard error.\n\
\n\
Options and the artifact may appear in any order, like `cargo build`/`cargo run` — \
`run --seed 5 app.wasm` and `run app.wasm --seed 5` are identical. Only known options are \
skipped when scanning for the artifact; an UNKNOWN option (a forwarded cargo flag) stops the \
scan, since its value could otherwise be misread as the artifact. Past that stop an unknown \
option is only forwarded silently in the Cargo package family — if a real artifact stands \
behind it the routing is a hard error, never a surprising Cargo fallthrough.",
    );

    out.push_str("\nENVIRONMENT:\n");
    push_prose(
        &mut out,
        "User-facing knobs, the internal supervisor/oracle protocol vars (set for you; listed \
for transparency), and honored tool vars. `--help --format json` emits the full registry.",
    );
    out.push('\n');
    for env in ENVIRONMENT {
        let tag = match env.scope {
            "protocol" => " [internal protocol]",
            "tool" => " [tool]",
            _ => "",
        };
        out.push_str(&format!("  {}{}\n", env.name, tag));
        for line in wrap(env.doc, WRAP_WIDTH - 6) {
            out.push_str("      ");
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

/// Render a single verb's focused section.
fn render_verb(verb: &Verb) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "cargo patina {} — {}\n\n",
        verb.name, verb.summary
    ));
    out.push_str("Usage:\n");
    for line in verb.synopsis {
        out.push_str("  ");
        out.push_str(line);
        out.push('\n');
    }
    out.push('\n');
    for group in verb.groups {
        out.push_str(group.title);
        out.push_str(":\n");
        for flag in group.flags {
            push_flag(&mut out, flag);
        }
        out.push('\n');
    }
    push_prose(&mut out, verb.prose);
    push_output_and_env_footer(&mut out);
    out
}

/// Render the requested help topic as human text (exit 0).
pub fn render(topic: Topic) -> String {
    match topic {
        Topic::Overview => render_overview(),
        Topic::Verb(name) => match verb(name) {
            Some(verb) => render_verb(verb),
            None => render_overview(),
        },
    }
}

// ===========================================================================
// Usage-error synopsis (message + synopsis lines + pointer)
// ===========================================================================

/// The synopsis block a usage error appends: the offending verb's synopsis
/// lines plus a `--help` pointer, or the compact top-level list before a verb is
/// resolved.
pub fn usage_synopsis(current_verb: Option<&str>) -> String {
    let mut out = String::new();
    match current_verb.and_then(verb) {
        Some(verb) => {
            out.push_str("Usage:\n");
            for line in verb.synopsis {
                out.push_str("  ");
                out.push_str(line);
                out.push('\n');
            }
            out.push_str(&format!(
                "\nrun `cargo patina {} --help` for details",
                verb.name
            ));
        }
        None => {
            out.push_str("Usage: cargo patina <VERB> [OPTIONS]\n");
            for verb in VERBS {
                out.push_str("  ");
                out.push_str(verb.synopsis[0]);
                out.push('\n');
            }
            out.push_str("\nrun `cargo patina <verb> --help` for details");
        }
    }
    out
}

// ===========================================================================
// JSON rendering (schema patina.help/v2, progressive disclosure)
// ===========================================================================
//
// The machine-readable help is served in two shapes under one schema tag:
//
//   * `cargo patina --help --format json` — the INDEX: the schema tag, the
//     global output flags, the `PATINA_*` environment protocol, and every verb
//     as `{summary, forms}` (NO flag_groups). A `verb_detail` hint field names
//     the command that yields a verb's full flag detail.
//   * `cargo patina <verb> --help --format json` — one VERB's detail: the schema
//     tag, the same global flags, and that verb's full entry (name, summary,
//     forms, flag_groups). No other verb and no environment block appear — the
//     env protocol is a single global contract that lives only in the index.
//
// This keeps the per-verb payload small (an agent fetches only the verb it is
// about to run) and the index a compact directory. Both are slices of the same
// underlying registry; there is no separate full-registry emission.
//
// Field-omission convention: a flag serializes only its non-default fields.
// `name`, `value_kind`, and `doc` are always present; `short`, `placeholder`,
// `value_grammar`, and `choices` are omitted when the flag has none, and
// `repeatable` is omitted unless true. Absent therefore means the default (no
// short form / no value / not repeatable), so a reader must treat a missing key
// as that default rather than expecting an explicit `null`/`false`.

/// The schema identifier stamped into both the index and per-verb JSON payloads.
/// Bumped from `patina.help/v1` when progressive disclosure changed the shape
/// (split index vs per-verb payloads; default-valued flag fields omitted).
pub const HELP_SCHEMA: &str = "patina.help/v2";

fn flag_json(flag: &Flag, group: &Group) -> serde_json::Value {
    use serde_json::{Map, Value as J};
    let mut m = Map::new();
    m.insert("name".into(), J::from(flag.name));
    if let Some(short) = flag.short {
        m.insert("short".into(), J::from(short));
    }
    m.insert("value_kind".into(), J::from(flag.value.kind()));
    if let Some(placeholder) = flag.value.placeholder() {
        m.insert("placeholder".into(), J::from(placeholder));
    }
    // The typed value grammar: the syntax a value must satisfy, plus the allowed
    // literals for an `enum` grammar. Omitted entirely for a valueless switch.
    // Lets an agent construct a well-formed value without guessing from the
    // placeholder.
    if let Some(kind) = flag.value.grammar() {
        m.insert("value_grammar".into(), J::from(kind.tag()));
        if let Kind::Enum(choices) = kind {
            m.insert("choices".into(), J::from(choices.to_vec()));
        }
    }
    m.insert("doc".into(), J::from(flag.doc));
    if flag.repeatable {
        m.insert("repeatable".into(), J::from(true));
    }
    // Present only when this flag reaches fewer families than its group, which
    // is how an agent learns that `--budget` is Cargo-family-only while the
    // `--seed` beside it is universal.
    if let Some(parent) = flag.requires {
        m.insert("requires".into(), J::from(parent));
    }
    if let Some(families) = flag.families {
        m.insert(
            "families".into(),
            J::from(families.iter().map(|f| f.tag()).collect::<Vec<_>>()),
        );
    }
    let _ = group;
    J::Object(m)
}

/// One titled flag group as `{title, families, flags}`. `families` names the
/// verb forms whose parser accepts the group — the same declaration that builds
/// those parsers, so an agent reading this payload learns exactly which flags a
/// given form will take.
fn group_json(group: &Group) -> serde_json::Value {
    use serde_json::{Map, Value as J};
    let mut gm = Map::new();
    gm.insert("title".into(), J::from(group.title));
    if group.families != SOLE {
        gm.insert(
            "families".into(),
            J::from(group.families.iter().map(|f| f.tag()).collect::<Vec<_>>()),
        );
    }
    gm.insert(
        "flags".into(),
        J::Array(
            group
                .flags
                .iter()
                .map(|flag| flag_json(flag, group))
                .collect(),
        ),
    );
    J::Object(gm)
}

/// The stand-in group for the always-available flags, which belong to no verb.
const GLOBAL_GROUP: Group = Group {
    title: "",
    families: SOLE,
    flags: &[],
};

/// The always-available output flags as `{title, flags}` (present in both the
/// index and every per-verb payload).
fn global_flags_json() -> serde_json::Value {
    use serde_json::{Map, Value as J};
    let mut global = Map::new();
    global.insert("title".into(), J::from("Output options (all verbs)"));
    global.insert(
        "flags".into(),
        J::Array(
            GLOBAL_OUTPUT
                .iter()
                .map(|flag| flag_json(flag, &GLOBAL_GROUP))
                .collect(),
        ),
    );
    J::Object(global)
}

/// The `PATINA_*` environment protocol as an array of `{name, scope, doc}` (index
/// only — the env contract is global, not per-verb).
fn environment_json() -> serde_json::Value {
    use serde_json::{Map, Value as J};
    let environment: Vec<J> = ENVIRONMENT
        .iter()
        .map(|e| {
            let mut em = Map::new();
            em.insert("name".into(), J::from(e.name));
            em.insert("scope".into(), J::from(e.scope));
            em.insert("doc".into(), J::from(e.doc));
            J::Object(em)
        })
        .collect();
    J::Array(environment)
}

/// The top-level index payload: schema, global flags, environment, every verb as
/// `{summary, forms}` (no flag_groups), and a `verb_detail` hint pointing at the
/// per-verb command.
fn index_json() -> serde_json::Value {
    use serde_json::{Map, Value as J};
    let mut verbs = Map::new();
    for verb in VERBS {
        let mut vm = Map::new();
        vm.insert("summary".into(), J::from(verb.summary));
        vm.insert("forms".into(), J::from(verb.synopsis.to_vec()));
        verbs.insert(verb.name.to_string(), J::Object(vm));
    }

    let mut verb_detail = Map::new();
    verb_detail.insert(
        "hint".into(),
        J::from(
            "Per-verb flag_groups are omitted from this index. Fetch a verb's full \
detail with the command below, substituting {verb} with the verb name.",
        ),
    );
    verb_detail.insert(
        "command_template".into(),
        J::from("cargo patina {verb} --help --format json"),
    );

    let mut root = Map::new();
    root.insert("schema".into(), J::from(HELP_SCHEMA));
    root.insert("global_flags".into(), global_flags_json());
    root.insert("environment".into(), environment_json());
    root.insert("verbs".into(), J::Object(verbs));
    root.insert("verb_detail".into(), J::Object(verb_detail));
    J::Object(root)
}

/// One verb's detail payload: schema, global flags, and the verb's full entry
/// (name, summary, forms, flag_groups). No other verb and no environment block.
fn verb_scoped_json(verb: &Verb) -> serde_json::Value {
    use serde_json::{Map, Value as J};
    let mut vm = Map::new();
    vm.insert("name".into(), J::from(verb.name));
    vm.insert("summary".into(), J::from(verb.summary));
    vm.insert("forms".into(), J::from(verb.synopsis.to_vec()));
    vm.insert(
        "flag_groups".into(),
        J::Array(verb.groups.iter().map(group_json).collect()),
    );

    let mut root = Map::new();
    root.insert("schema".into(), J::from(HELP_SCHEMA));
    root.insert("global_flags".into(), global_flags_json());
    root.insert("verb".into(), J::Object(vm));
    J::Object(root)
}

/// Render the requested help topic as pretty JSON (for `--help --format json`):
/// the compact index for the overview, or one verb's full detail for a verb
/// topic. An unresolved verb name falls back to the index, mirroring [`render`].
pub fn render_json(topic: Topic) -> String {
    let value = match topic {
        Topic::Overview => index_json(),
        Topic::Verb(name) => match verb(name) {
            Some(verb) => verb_scoped_json(verb),
            None => index_json(),
        },
    };
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".into())
}
