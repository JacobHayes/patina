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

mod environment;
mod execution;
mod flags;
mod human;
mod json;
mod workflows;
pub use json::*;

pub use environment::ENVIRONMENT;
use execution::AUDIT;
use execution::BUILD;
use execution::REPLAY;
use execution::RUN;
use execution::TEST;
use flags::BUGGIFY_FLAGS;
use flags::COMPUTE_WATCHDOG_FLAG;
use flags::DNS_ENTRY_FLAGS;
use flags::DNS_FLAGS;
use flags::FAULT_FLAGS;
pub use flags::GLOBAL_OUTPUT;
pub use flags::HELP_FLAGS;
use flags::LIVENESS_FLAGS_OPTIONAL;
use flags::NATIVE_SCHEDULE_FLAGS;
use flags::SOURCE_SELECT;
use flags::{
    ALLOW_FLAG, ALLOW_RANDOMIZED_LAYOUT_FLAG, ALLOW_UNSUPPORTED_FLAG, CPUS_FLAG, PARAM_FLAG,
};
pub use human::render;
pub use human::usage_synopsis;
use workflows::CAMPAIGN;
use workflows::COVERAGE;
use workflows::MINIMIZE;
use workflows::SITES;
use workflows::SYSCALLS;
use workflows::TRACE;

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
    /// A non-negative machine integer (`parse_usize`).
    Usize,
    /// An unsigned 32-bit integer.
    U32,
    /// An unsigned integer required to be `>= 1` (a positive count).
    PositiveU64,
    /// Native host-time watchdog, in milliseconds: 1..=86400000.
    WatchdogMillis,
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
    /// A `KEY=VALUE` pair with a non-empty key.
    KeyValue,
    /// An RFC 3339 UTC timestamp `YYYY-MM-DDTHH:MM:SS[.FRACTION]Z` between the
    /// Unix epoch and the last instant `u64` nanoseconds can hold.
    UtcTimestamp,
    /// A node name under the kernel's rules: at most 64 bytes, no NUL
    /// (`patina_dst_runtime::validate_hostname`).
    Hostname,
    /// A virtual CPU count: 1 to `patina_dst_abi::MAX_CPUS`
    /// (`patina_dst_runtime::validate_cpus`).
    Cpus,
    /// `NAME=IPV4`: a DNS host-table entry. Distinct from [`Kind::KeyValue`]
    /// because the value half must be a dotted-quad address, and a typo there is
    /// worth catching at parse time rather than at the guest's first lookup.
    DnsEntry,
    /// `A,B`: two different non-empty virtual addresses to partition from each
    /// other. Its own Kind rather than a free-form string because a pair naming
    /// one address twice, or carrying a third, is a typo worth refusing at parse
    /// time rather than at the end-of-run vacuity report.
    AddressPair,
    /// `KIND:N[:ERRNO]`: a targeted filesystem fault
    /// (`patina_dst_driver_api::FsErrorTarget`), refused at parse time when
    /// the kind is unknown, the ordinal below 1, or the errno one the kind
    /// cannot fail with.
    FsErrorTarget,
    /// `all`, or a comma-separated list of at least one non-empty symbol.
    UnsupportedSymbols,
    /// One of a fixed set of string literals.
    Enum(&'static [&'static str]),
    /// A comma-separated list of one or more of a fixed set of string literals.
    EnumList(&'static [&'static str]),
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
            Kind::Usize => "usize",
            Kind::U32 => "u32",
            Kind::PositiveU64 => "positive-u64",
            Kind::WatchdogMillis => "watchdog-millis",
            Kind::Permille => "permille",
            Kind::NanosRange => "nanos-range",
            Kind::U64Range => "u64-range",
            Kind::OpKindList => "op-kind-list",
            Kind::TaskSelector => "task-selector",
            Kind::KeyValue => "key-value",
            Kind::UtcTimestamp => "utc-timestamp",
            Kind::Hostname => "hostname",
            Kind::Cpus => "cpus",
            Kind::DnsEntry => "dns-entry",
            Kind::AddressPair => "address-pair",
            Kind::FsErrorTarget => "fs-error-target",
            Kind::UnsupportedSymbols => "unsupported-symbols",
            Kind::Enum(_) => "enum",
            Kind::EnumList(_) => "enum-list",
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
}

/// The prefix of every flag's environment default (`--seed` → `PATINA_SEED`).
pub const FLAG_ENV_PREFIX: &str = "PATINA_";

impl Flag {
    /// The environment variable that defaults this flag when it is not typed:
    /// `PATINA_` plus the long name in upper snake case (`--seed-start` →
    /// `PATINA_SEED_START`). The help/version switches have none.
    pub fn env_name(&self) -> Option<String> {
        if HELP_FLAGS.iter().any(|help| help.name == self.name) {
            return None;
        }
        Some(format!(
            "{FLAG_ENV_PREFIX}{}",
            self.name
                .trim_start_matches('-')
                .replace('-', "_")
                .to_ascii_uppercase()
        ))
    }
}

/// Every environment variable that defaults a registry flag, deduplicated.
/// A flag name shared by several verbs shares one variable.
pub fn flag_env_names() -> std::collections::BTreeSet<String> {
    VERBS
        .iter()
        .flat_map(|verb| verb.groups.iter())
        .flat_map(|group| group.flags.iter())
        .chain(GLOBAL_OUTPUT.iter())
        .filter_map(Flag::env_name)
        .collect()
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
    }
}

/// Declare that a flag is inert without `parent`.
const fn needs(flag: Flag, parent: &'static str) -> Flag {
    Flag {
        requires: Some(parent),
        ..flag
    }
}

/// A parsing family within a verb: one verb, but several disjoint flag sets,
/// chosen at routing time from a subcommand token or a mode switch. Families
/// are why `--marker` is valid on `minimize --generation` and invalid on
/// `trace info`.
///
/// The registry is the single declaration of that mapping. It builds each
/// family's parser, decides which flags a family refuses and in what words, and
/// routes the generic grammar walks — so a family cannot accept a flag the help
/// does not advertise for it, and cannot advertise one it does not accept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    /// A verb with a single argument surface.
    Sole,
    /// `minimize --scenario`: seed/parameter reduction.
    Scenario,
    /// `minimize --generation N`: reduce a recorded campaign generation's knobs.
    Generation,
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
            Family::Scenario => "scenario",
            Family::Generation => "generation",
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

/// Every verb, in overview order.
pub const VERBS: &[&Verb] = &[
    &RUN, &TEST, &BUILD, &AUDIT, &REPLAY, &CAMPAIGN, &COVERAGE, &SITES, &TRACE, &MINIMIZE,
    &SYSCALLS,
];

// ===========================================================================
// Lookup
// ===========================================================================

/// The verb entry named `name`, if any.
pub fn verb(name: &str) -> Option<&'static Verb> {
    VERBS.iter().copied().find(|verb| verb.name == name)
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
/// flags.
pub fn flag_by_cli_name(verb_name: &str, name: &str) -> Option<&'static Flag> {
    verb(verb_name)
        .into_iter()
        .flat_map(|verb| verb.groups.iter())
        .flat_map(|group| group.flags.iter())
        .chain(GLOBAL_OUTPUT.iter())
        .chain(HELP_FLAGS.iter())
        .find(|flag| flag.name == name || flag.short == Some(name))
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
        self.groups
            .iter()
            .filter(move |group| group.families.contains(&family))
            .flat_map(|group| group.flags.iter())
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
            .filter(move |group| !group.families.contains(&family))
            .flat_map(|group| group.flags.iter())
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

/// The canonical `Topic` for a routed verb token.
pub fn topic_for(verb_token: &str) -> Topic {
    match verb_token {
        name if verb(name).is_some() => Topic::Verb(verb(name).unwrap().name),
        _ => Topic::Overview,
    }
}

// Every group's families must belong to its verb, and a verb with no flags has
// only the sole form. This gate evaluates at build time.
const _: () = {
    let mut v = 0;
    while v < VERBS.len() {
        let verb = &VERBS[v];
        if verb.groups.is_empty() {
            assert!(
                verb.families.len() == 1
                    && verb.families[0].family as usize == Family::Sole as usize,
                "invalid flagless family"
            );
        }
        let mut g = 0;
        while g < verb.groups.len() {
            let group = &verb.groups[g];
            let mut i = 0;
            while i < group.families.len() {
                let mut declared = false;
                let mut j = 0;
                while j < verb.families.len() {
                    if verb.families[j].family as usize == group.families[i] as usize {
                        declared = true;
                    }
                    j += 1;
                }
                assert!(declared, "undeclared registry family");
                i += 1;
            }
            g += 1;
        }
        v += 1;
    }
};
