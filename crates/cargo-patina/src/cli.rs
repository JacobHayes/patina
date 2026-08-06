//! The registry-driven clap layer: one generic translation from
//! [`help::Flag`] to [`clap::Arg`], and one typed view over the result.
//!
//! There is no second flag table. A verb+family's parser is BUILT from the same
//! registry rows that render its help, its JSON payload, and its usage synopsis
//! ([`help::Verb::family_flags`]), so the classes of drift the CLI used to police
//! with property tests — a parser accepting a flag the help omits, an arity that
//! disagrees with the documented `=`-only form, a value validated by the wrong
//! grammar — are not tested away here, they are unrepresentable.
//!
//! What clap does NOT own, and why:
//!
//! * **Positional location.** A `run` positional decides which family parses the
//!   rest (magic bytes pick WASI vs native), so the artifact must be found
//!   BEFORE a `Command` exists. `crate::locate_positionals` does that, using the
//!   registry for arity, and hands each family a flags-only token list.
//! * **Cargo passthrough.** The Cargo family forwards every unrecognized option
//!   to Cargo verbatim, interleaved, order-preserving, and non-UTF-8-safe. clap
//!   has no such mode, so [`partition`] splits the token list first — again from
//!   the registry, so the split cannot disagree with the parser about arity.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use clap::builder::ValueParser;
use clap::{Arg, ArgAction, ArgMatches, Command};

use crate::CliError;
use crate::help::{self, Family, Flag, Kind, Value};
use crate::values;

/// The value a bare optional-value switch records (`--buggify` with no `=N`).
///
/// It is a sentinel rather than the empty string because clap runs the value
/// parser over `default_missing_value` too: with `""` as the marker, an explicit
/// `--buggify=` would be indistinguishable from the bare switch and would slip
/// past the flag's grammar. No CLI value carries a lone control byte, so this
/// cannot collide with something a user typed. [`Args::text`] translates it back
/// to the empty string the parsers store for "supplied, take the default".
const BARE: &str = "\u{1}";

/// Translate one registry flag into a clap argument.
///
/// The three shapes of [`Value`] map exactly onto clap:
///
/// * `None` — a switch. `--release=x` is rejected because a `SetTrue` arg takes
///   no value.
/// * `Required` — `--seed N` and `--seed=N` both work, which is clap's default.
/// * `Optional` — `require_equals` with a missing-value default is precisely the
///   documented `=`-only form: `--buggify` or `--buggify=500`, never
///   `--buggify 500`, whose space form would be ambiguous with a positional.
///
/// Every value-bearing arg is `Append`, whatever its declared repeatability, so
/// that repeats are visible after parsing: [`Args::new`] then rejects a second
/// occurrence of a flag the registry marks non-repeatable. That is one generic
/// check in place of a `set_once` call per flag per family.
fn arg_of(flag: &'static Flag) -> Arg {
    let mut arg = Arg::new(flag.name).long(flag.name.trim_start_matches('-'));
    if let Some(short) = flag.short {
        arg = arg.short(short.trim_start_matches('-').chars().next().expect("short"));
    }
    match flag.value {
        Value::None => arg.action(ArgAction::SetTrue),
        Value::Required(placeholder, kind) => arg
            .action(ArgAction::Append)
            .num_args(1)
            .value_name(placeholder)
            .value_parser(parser_for(flag.name, kind, false)),
        Value::Optional(placeholder, kind) => arg
            .action(ArgAction::Append)
            .num_args(0..=1)
            .require_equals(true)
            .default_missing_value(BARE)
            .value_name(placeholder)
            .value_parser(parser_for(flag.name, kind, true)),
    }
}

/// The value parser for a declared grammar, carrying the flag name so the
/// message names the flag the user typed.
///
/// [`Kind::Path`] yields an `OsString`: a path value may be non-UTF-8, and a
/// `--record`/`--output` path is used verbatim. Every other grammar yields the
/// validated text, which later conversions re-read knowing it is well-formed.
fn parser_for(name: &'static str, kind: Kind, optional: bool) -> ValueParser {
    if matches!(kind, Kind::Path) {
        // A path may be non-UTF-8 and is used verbatim, so it stays an
        // `OsString`; only its emptiness is checked.
        return ValueParser::new(clap::builder::TypedValueParser::try_map(
            clap::builder::OsStringValueParser::new(),
            move |value: OsString| -> Result<OsString, String> {
                if value.is_empty() {
                    return Err(format!("{name} must not be empty"));
                }
                Ok(value)
            },
        ));
    }
    ValueParser::from(move |value: &str| -> Result<String, String> {
        if optional && value == BARE {
            return Ok(BARE.to_string());
        }
        values::validate(kind, name, value).map(|()| value.to_string())
    })
}

/// Build the parser for one verb+family from the registry.
///
/// Family parsers see a flags-only token list — the routing layer has already
/// taken the positionals and any `--` tail — so the `Command` declares no
/// positionals and a stray one is an error, which is what the bespoke loops did
/// by falling through to "unexpected positional".
pub(crate) fn command(verb: &'static help::Verb, family: Family) -> Command {
    let mut command = Command::new(verb.name)
        .no_binary_name(true)
        .disable_help_flag(true)
        .disable_version_flag(true);
    for flag in verb.family_flags(family) {
        command = command.arg(arg_of(flag));
    }
    // Flags the family refuses with an explanation rather than "unknown option".
    // They are registered so the explanation can fire, and hidden so they never
    // appear in this family's advertised surface. Arity is deliberately loose —
    // the value, if any, is discarded along with the flag.
    for (name, _) in refusals(verb, family) {
        command = command.arg(
            Arg::new(name)
                .long(name.trim_start_matches('-'))
                .action(ArgAction::Append)
                .num_args(0..=1)
                .hide(true),
        );
    }
    command
}

/// Every flag `family` refuses with a reason: a sibling family's flags, plus the
/// verb's declared refusals, minus anything the family actually accepts (a flag
/// two families share is not a refusal for either).
fn refusals(verb: &'static help::Verb, family: Family) -> Vec<(&'static str, String)> {
    let mut refusals: Vec<(&'static str, String)> = verb
        .declared_refusals(family)
        .into_iter()
        .chain(
            verb.cross_family_refusals(family)
                .map(|(flag, message)| (flag.name, message)),
        )
        .filter(|(name, _)| verb.family_flags(family).all(|flag| flag.name != *name))
        .collect();
    // A flag can be refused by both routes; the declared reason is the one
    // written for it, so it comes first and wins. clap must see each name once.
    let mut seen = std::collections::BTreeSet::new();
    refusals.retain(|(name, _)| seen.insert(*name));
    refusals
}

/// Parse a flags-only token list for `verb`'s `family`.
pub(crate) fn parse(
    verb_name: &str,
    family: Family,
    arguments: Vec<OsString>,
) -> Result<Args, CliError> {
    let verb = help::verb(verb_name).expect("routed verb is registered");
    let matches = command(verb, family)
        .try_get_matches_from(arguments)
        .map_err(|error| CliError::usage(clap_message(error)))?;
    Args::new(verb, family, matches)
}

/// Reduce a clap error to the one line the CLI prints. The `usage` feature is
/// off, so clap contributes no usage block of its own — the verb synopsis the
/// registry renders is richer and is appended by [`CliError`].
fn clap_message(error: clap::Error) -> String {
    let rendered = error.render().to_string();
    let message = rendered
        .lines()
        .map(|line| line.trim().trim_start_matches("error: ").trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    if message.is_empty() {
        "invalid arguments".to_string()
    } else {
        message
    }
}

/// A parsed family invocation: typed reads keyed by the flag's CLI spelling.
///
/// Reading by CLI name rather than a generated identifier keeps the extraction
/// side legible next to the registry and the help text, and a name that is not
/// registered for the family panics rather than silently returning `None` — a
/// typo in an extraction site is a build-time-shaped bug, not a knob that
/// quietly stops working.
pub(crate) struct Args {
    verb: &'static help::Verb,
    family: Family,
    matches: ArgMatches,
}

impl Args {
    fn new(
        verb: &'static help::Verb,
        family: Family,
        matches: ArgMatches,
    ) -> Result<Self, CliError> {
        // A refused flag, answered in this family's own words.
        for (name, message) in refusals(verb, family) {
            if supplied(&matches, name) {
                return Err(CliError::usage(message));
            }
        }
        // A dependent knob is inert without its parent policy, so it is refused
        // rather than silently ignored — one generic check for every "requires"
        // the registry declares.
        for flag in verb.family_flags(family) {
            let Some(parent) = flag.requires else {
                continue;
            };
            if supplied(&matches, flag.name) && !supplied(&matches, parent) {
                return Err(CliError::usage(format!("{} requires {parent}", flag.name)));
            }
        }
        // One generic duplicate check in place of a `set_once` per flag: the
        // registry says which flags repeat, and every value flag is `Append`, so
        // a second occurrence of a non-repeatable flag is visible here.
        for flag in verb.family_flags(family) {
            if flag.repeatable || matches!(flag.value, Value::None) {
                continue;
            }
            let count = match flag.value {
                Value::Required(_, Kind::Path) | Value::Optional(_, Kind::Path) => matches
                    .get_many::<OsString>(flag.name)
                    .map(Iterator::count)
                    .unwrap_or(0),
                _ => matches
                    .get_many::<String>(flag.name)
                    .map(Iterator::count)
                    .unwrap_or(0),
            };
            if count > 1 {
                return Err(CliError::usage(format!(
                    "{} was provided more than once",
                    flag.name
                )));
            }
        }
        Ok(Self {
            verb,
            family,
            matches,
        })
    }

    fn flag_of(&self, name: &str) -> &'static Flag {
        self.verb
            .family_flags(self.family)
            .find(|flag| flag.name == name)
            .unwrap_or_else(|| {
                panic!(
                    "`{}` reads {name}, which the registry does not give family {:?}",
                    self.verb.name, self.family
                )
            })
    }

    /// Whether the operator typed this flag, whatever its shape.
    pub(crate) fn supplied(&self, name: &str) -> bool {
        let _ = self.flag_of(name);
        supplied(&self.matches, name)
    }

    /// Whether a valueless switch was supplied.
    pub(crate) fn flag(&self, name: &str) -> bool {
        debug_assert!(matches!(self.flag_of(name).value, Value::None));
        self.matches.get_flag(name)
    }

    /// The validated text of a value flag, or `None` when it was not supplied.
    /// An optional-value flag supplied bare yields `Some("")`.
    pub(crate) fn text(&self, name: &str) -> Option<&str> {
        debug_assert!(
            !matches!(self.flag_of(name).value.grammar(), Some(Kind::Path)),
            "{name} is a path flag; read it with `path`, which keeps non-UTF-8 values"
        );
        self.matches
            .get_one::<String>(name)
            .map(String::as_str)
            .map(|value| if value == BARE { "" } else { value })
    }

    /// Every occurrence of a repeatable value flag, in order.
    pub(crate) fn texts(&self, name: &str) -> Vec<&str> {
        let _ = self.flag_of(name);
        self.matches
            .get_many::<String>(name)
            .map(|values| values.map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// A `Kind::Path` value, which may be non-UTF-8.
    pub(crate) fn path(&self, name: &str) -> Option<PathBuf> {
        let _ = self.flag_of(name);
        self.matches.get_one::<OsString>(name).map(PathBuf::from)
    }

    /// A `u64`-grammar value. The grammar already ran, so the reparse cannot
    /// fail.
    pub(crate) fn u64(&self, name: &str) -> Option<u64> {
        self.text(name).map(|value| parsed(name, value))
    }

    pub(crate) fn u32(&self, name: &str) -> Option<u32> {
        self.text(name).map(|value| parsed(name, value))
    }

    pub(crate) fn usize(&self, name: &str) -> Option<usize> {
        self.text(name).map(|value| parsed(name, value))
    }

    /// An owned copy of a value flag's text.
    pub(crate) fn string(&self, name: &str) -> Option<String> {
        self.text(name).map(str::to_string)
    }
}

/// Whether an argument was actually typed, as opposed to defaulted or absent.
fn supplied(matches: &ArgMatches, name: &str) -> bool {
    matches.value_source(name) == Some(clap::parser::ValueSource::CommandLine)
}

fn parsed<T: std::str::FromStr>(name: &str, value: &str) -> T {
    value
        .parse()
        .unwrap_or_else(|_| panic!("{name} passed its registry grammar but did not reparse"))
}

/// Split a token list into the tokens `family` owns and the tokens forwarded
/// verbatim — the Cargo family's conservative passthrough, and `explore`'s
/// wrapping of a whole `run`/`test` command.
///
/// Arity comes from the registry, so the split and the parser can never disagree
/// about whether a flag swallows the next token. Everything else keeps its
/// original `OsString`: order is preserved, and a non-UTF-8 token — never a
/// Patina flag — is forwarded untouched. A `--` and everything after it is
/// forwarded whole.
///
/// The family's DECLARED refusals are kept too, so `replay <pkg> <trace>
/// --fs-crash-at close` is answered with "the trace is authoritative" rather
/// than handed to Cargo as an unknown flag. Sibling-family flags are NOT: they
/// are exactly the names a legitimate Cargo argument might share (`--bin`,
/// `--release`), and forwarding them is the passthrough's whole purpose.
pub(crate) fn partition(
    verb: &'static help::Verb,
    family: Family,
    arguments: Vec<OsString>,
) -> (Vec<OsString>, Vec<OsString>) {
    let mut arity: BTreeMap<&'static str, Value> = BTreeMap::new();
    for (name, _) in verb.declared_refusals(family) {
        // A refused flag's value, if any, is discarded with it, so it is treated
        // as taking no separate token.
        arity.insert(name, Value::None);
    }
    for flag in verb.family_flags(family) {
        arity.insert(flag.name, flag.value);
        if let Some(short) = flag.short {
            arity.insert(short, flag.value);
        }
    }
    let mut owned = Vec::new();
    let mut forwarded = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--" {
            forwarded.extend_from_slice(&arguments[index..]);
            break;
        }
        let name = argument.to_str().map(split_name);
        match name.and_then(|name| arity.get(name).copied()) {
            Some(Value::Required(..)) if !is_inline(argument) => {
                owned.push(argument.clone());
                if let Some(value) = arguments.get(index + 1) {
                    owned.push(value.clone());
                    index += 1;
                }
            }
            Some(_) => owned.push(argument.clone()),
            None => forwarded.push(argument.clone()),
        }
        index += 1;
    }
    (owned, forwarded)
}

/// The flag name of a token, without any inline `=VALUE`. A non-flag token is
/// returned whole, so a positional like `zone=a` is never read as a flag.
pub(crate) fn split_name(token: &str) -> &str {
    match token.split_once('=') {
        Some((name, _)) if name.starts_with('-') => name,
        _ => token,
    }
}

fn is_inline(argument: &OsStr) -> bool {
    argument
        .to_str()
        .is_some_and(|text| split_name(text) != text)
}

/// The values a pre-pass stripped, keyed by canonical flag name and in the order
/// they were supplied.
pub(crate) type Stripped = BTreeMap<&'static str, Vec<OsString>>;

/// A pre-pass: remove a fixed set of registry flags from the pre-`--` region of
/// a token list, returning each stripped flag's values (in order) and the tokens
/// that remain.
///
/// Four flags are settled before a family parser can exist, because each one
/// changes which parser that is: the global output/config switches (parsed once
/// before routing), `--target` (chooses the family outright), and
/// `--package`/`--bin`/`--release` (apply to the build a source positional
/// implies, and are forwarded to Cargo in the Cargo family instead). One
/// registry-driven pre-pass serves all four, so their idea of arity cannot drift
/// from the parser's.
///
/// A `--` and everything after it belongs to the guest program and is left
/// untouched.
pub(crate) fn strip(
    flags: &[&'static Flag],
    arguments: Vec<OsString>,
) -> Result<(Stripped, Vec<OsString>), CliError> {
    let mut found = Stripped::new();
    let mut rest = Vec::with_capacity(arguments.len());
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--" {
            rest.extend_from_slice(&arguments[index..]);
            break;
        }
        let text = argument.to_str();
        let name = text.map(split_name);
        let matched = name.and_then(|name| {
            flags
                .iter()
                .find(|flag| flag.name == name || flag.short == Some(name))
        });
        let Some(flag) = matched else {
            rest.push(argument.clone());
            index += 1;
            continue;
        };
        let inline = text.and_then(|text| text.split_once('=')).map(|(_, v)| v);
        let value = match (flag.value, inline) {
            (Value::None, Some(value)) => {
                return Err(CliError::usage(format!(
                    "{} takes no value; got {value:?}",
                    flag.name
                )));
            }
            (Value::None, None) => OsString::new(),
            (_, Some(value)) => OsString::from(value),
            (_, None) => {
                index += 1;
                arguments.get(index).cloned().ok_or_else(|| {
                    let placeholder = flag.value.placeholder().unwrap_or("VALUE");
                    CliError::usage(format!("{} requires a value <{placeholder}>", flag.name))
                })?
            }
        };
        // A pre-pass value is held to the SAME declared grammar the family
        // parsers enforce, so a flag stripped before routing cannot quietly
        // accept what the same flag would reject after it.
        if let Some(kind) = flag.value.grammar() {
            match value.to_str() {
                Some(text) => values::validate(kind, flag.name, text).map_err(CliError::usage)?,
                None if matches!(kind, Kind::Path) => {}
                None => {
                    return Err(CliError::usage(format!(
                        "{} requires a UTF-8 value",
                        flag.name
                    )));
                }
            }
        }
        found.entry(flag.name).or_default().push(value);
        index += 1;
    }
    Ok((found, rest))
}

/// The single value of a stripped flag, refusing a repeat.
pub(crate) fn single(found: &Stripped, name: &str) -> Result<Option<OsString>, CliError> {
    match found.get(name).map(Vec::as_slice) {
        None => Ok(None),
        Some([value]) => Ok(Some(value.clone())),
        Some(_) => Err(CliError::usage(format!(
            "{name} was provided more than once"
        ))),
    }
}

/// A registry flag by CLI spelling, for the pre-passes.
pub(crate) fn flag(verb: &str, name: &str) -> &'static Flag {
    help::flag_by_cli_name(verb, name)
        .unwrap_or_else(|| panic!("`{verb}` pre-pass reads unregistered flag {name}"))
}
