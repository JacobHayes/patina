//! Cross-module CLI registry and control-plane tests.

use super::*;
use crate::parse::{
    ParseResult, knob_env_pairs, knobs_of, parse, parse_cargo, parse_cargo_replay, parse_explore,
    parse_minimize, parse_native_audit_from, parse_native_build, parse_native_harness_from,
    parse_native_replay, parse_native_run, parse_native_run_from, parse_trace, parse_wasi_build,
    parse_wasi_replay, parse_wasi_run, parse_wasi_run_from, repeatable_payload,
};
use crate::wasi_exec::execute_wasi_run;
use crate::{campaign, cli, coverage, help, output, sites, syscalls, values};
use patina_dst_runtime::{FaultKnob, Plumbing};
use patina_dst_wasi_host::DEFAULT_WASM_FUEL;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::PathBuf;

pub(super) fn strings(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

pub(super) fn invocation(values: &[&str]) -> Invocation {
    match parse(strings(values)).unwrap() {
        ParseResult::Run(value) => value,
        _ => panic!("expected invocation"),
    }
}

// `run`/`audit`/`build` infer their target from artifact magic bytes at the
// routing layer (covered by the e2e suite with real artifacts and by
// `detects_artifact_family_from_magic` below). These helpers exercise the
// per-target parsers directly, so the first element is a readable label the
// helper drops before parsing.
pub(super) fn wasi_invocation(values: &[&str]) -> WasiInvocation {
    parse_wasi_run(strings(&values[1..])).unwrap()
}

pub(super) fn native_run(values: &[&str]) -> NativeRunInvocation {
    parse_native_run(strings(&values[1..])).unwrap()
}

pub(super) fn native_build_invocation(values: &[&str]) -> NativeBuildInvocation {
    // The first element is a readable label; `build` routing lives in
    // `parse_build`, exercised separately.
    parse_native_build(strings(&values[1..])).unwrap()
}

/// A sample value of the right grammar for each knob, so the family and
/// round-trip gates below can drive every knob off `FaultKnob::ALL` instead
/// of a hand-kept list that a new knob can be left out of.
pub(super) fn knob_sample(knob: FaultKnob) -> &'static str {
    match knob {
        FaultKnob::FsCrashAt => "write:2",
        FaultKnob::FsTornGranularity => "byte",
        FaultKnob::NetLatencyNanos | FaultKnob::EpochJumpNanos => "500",
        FaultKnob::NetTcpBufferBytes => "4096",
        FaultKnob::NetPartition => "a,b",
        FaultKnob::DnsEntry => "svc=10.0.0.9",
        FaultKnob::FsLatencyNanos
        | FaultKnob::SleepJitterNanos
        | FaultKnob::NetJitterNanos
        | FaultKnob::DnsLatencyNanos => "10..20",
        FaultKnob::FsErrorPermille
        | FaultKnob::FsShortPermille
        | FaultKnob::NetDropPermille
        | FaultKnob::NetDuplicatePermille
        | FaultKnob::NetConnectRefusePermille
        | FaultKnob::NetResetPermille
        | FaultKnob::DnsFailPermille
        | FaultKnob::EntropyFailPermille
        | FaultKnob::CustomOpFailPermille => "100",
    }
}

/// The message of a top-level `parse` that must fail (`ParseResult` is not
/// `Debug`, so `unwrap_err` cannot be used directly).
pub(super) fn parse_error(values: &[&str]) -> String {
    match parse(strings(values)) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("expected a usage error for {values:?}"),
    }
}

mod registry {
    //! CLI registry and execution-family control-plane tests.

    use super::*;

    /// Parse the index payload (`--help --format json`, overview topic).
    fn index_json() -> serde_json::Value {
        serde_json::from_str(&help::render_json(help::Topic::Overview))
            .expect("index help JSON parses")
    }

    /// Parse a verb's scoped payload (`<verb> --help --format json`).
    fn verb_json(name: &'static str) -> serde_json::Value {
        serde_json::from_str(&help::render_json(help::Topic::Verb(name)))
            .expect("verb help JSON parses")
    }

    #[test]
    fn json_index_lists_every_verb_without_flag_groups() {
        let json = index_json();
        assert_eq!(json["schema"], help::HELP_SCHEMA);
        // The env protocol and global flags live in the index.
        assert!(json["environment"].is_array(), "index carries environment");
        assert!(
            json["global_flags"]["flags"].is_array(),
            "index carries global flags"
        );
        // A machine-readable pointer to per-verb detail, with a substitutable
        // {verb} template.
        let template = json["verb_detail"]["command_template"]
            .as_str()
            .expect("verb_detail.command_template is a string");
        assert!(
            template.contains("{verb}") && template.contains("--format json"),
            "command_template should be a substitutable per-verb command: {template}"
        );
        // Every registered verb appears with a summary + forms but NO flag_groups
        // (the index is a directory, not a flag dump).
        let verbs = json["verbs"].as_object().expect("verbs object");
        assert_eq!(
            verbs.len(),
            help::VERBS.len(),
            "index verb count matches the registry"
        );
        for verb in help::VERBS {
            let entry = &verbs[verb.name];
            assert_eq!(
                entry["summary"], verb.summary,
                "index summary for {}",
                verb.name
            );
            assert!(
                entry["forms"].is_array(),
                "index carries {} forms",
                verb.name
            );
            assert!(
                entry.get("flag_groups").is_none(),
                "index must NOT carry flag_groups for {}",
                verb.name
            );
        }
    }

    #[test]
    fn json_verb_scope_carries_only_that_verbs_detail() {
        // Class-shaped: walk the registry. Each verb's scoped payload names that
        // verb, carries its own flag_groups and global flags, and leaks neither
        // the environment block nor any other verb's entry.
        for verb in help::VERBS {
            let json = verb_json(verb.name);
            assert_eq!(json["schema"], help::HELP_SCHEMA, "{} schema", verb.name);
            assert_eq!(json["verb"]["name"], verb.name, "verb name");
            assert_eq!(json["verb"]["summary"], verb.summary, "verb summary");
            assert!(
                json["verb"]["flag_groups"].is_array(),
                "{} carries flag_groups",
                verb.name
            );
            assert_eq!(
                json["verb"]["flag_groups"].as_array().unwrap().len(),
                verb.groups.len(),
                "{} flag_groups count matches the registry",
                verb.name
            );
            assert!(
                json["global_flags"]["flags"].is_array(),
                "{} carries global flags",
                verb.name
            );
            // Scoping: no top-level `verbs` map and no environment block.
            assert!(
                json.get("verbs").is_none(),
                "{} scoped payload must not carry the verbs index",
                verb.name
            );
            assert!(
                json.get("environment").is_none(),
                "{} scoped payload must not carry the environment block",
                verb.name
            );
            // The verb's own flags are present; a DIFFERENT verb's unique flag is
            // not. `run`'s `--mount` (re-supplying a host corpus) is unique to
            // run/replay, so it never appears in, say, `build`'s payload.
            // Deliberately NOT `--harness`: `campaign` forwards that one to its
            // child runs and registers it too, so it would not be a probe of
            // leakage.
            let names = flag_names(&json["verb"]["flag_groups"]);
            if verb.name != "run" && verb.name != "replay" {
                assert!(
                    !names.contains("--mount"),
                    "{}'s payload leaked run's unique --mount flag",
                    verb.name
                );
            }
        }
        // Positive: run's payload does contain its unique flag.
        let run = verb_json("run");
        assert!(
            flag_names(&run["verb"]["flag_groups"]).contains("--mount"),
            "run's payload should contain its own --mount flag"
        );
    }

    #[test]
    fn json_flag_omits_default_valued_fields() {
        // `--release` (build) is a valueless, non-repeatable switch with no short
        // form: only name/value_kind/doc survive; the default-valued keys are gone.
        let build = verb_json("build");
        let release = find_flag(&build["verb"]["flag_groups"], "--release")
            .expect("build registers --release");
        assert_eq!(release["value_kind"], "none");
        for absent in [
            "short",
            "placeholder",
            "value_grammar",
            "choices",
            "repeatable",
        ] {
            assert!(
                release.get(absent).is_none(),
                "--release should omit default-valued `{absent}`, got {release}"
            );
        }
        // `--output` (build) has a short form and a required value: those keys are
        // present, but `repeatable` (false) is still omitted.
        let output =
            find_flag(&build["verb"]["flag_groups"], "--output").expect("build registers --output");
        assert_eq!(output["short"], "-o");
        assert_eq!(output["value_kind"], "required");
        assert_eq!(output["placeholder"], "PATH");
        assert!(
            output.get("repeatable").is_none(),
            "non-repeatable --output should omit `repeatable`"
        );
        // A repeatable flag emits `repeatable: true`; a `--param` is repeatable.
        let run = verb_json("run");
        let param =
            find_flag(&run["verb"]["flag_groups"], "--param").expect("run registers --param");
        assert_eq!(param["repeatable"], true);
        // An enum-valued flag emits its choices; `--format` (global) is native|json.
        let format = find_flag(&run["global_flags"], "--format").expect("global --format");
        assert_eq!(format["value_grammar"], "enum");
        assert!(
            format["choices"].as_array().is_some(),
            "an enum flag lists its choices"
        );
    }

    /// The set of flag `name`s across an array of `{title, flags}` groups (or a
    /// single such group object).
    fn flag_names(groups_or_group: &serde_json::Value) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        collect_flags(groups_or_group, &mut |flag| {
            if let Some(name) = flag["name"].as_str() {
                names.insert(name.to_string());
            }
        });
        names
    }

    /// The first flag object named `name` across an array of groups or a single
    /// `{title, flags}` group.
    fn find_flag(groups_or_group: &serde_json::Value, name: &str) -> Option<serde_json::Value> {
        let mut found = None;
        collect_flags(groups_or_group, &mut |flag| {
            if found.is_none() && flag["name"].as_str() == Some(name) {
                found = Some(flag.clone());
            }
        });
        found
    }

    /// Invoke `visit` on every flag object inside an array of `{title, flags}`
    /// groups or a single such group.
    fn collect_flags(
        groups_or_group: &serde_json::Value,
        visit: &mut dyn FnMut(&serde_json::Value),
    ) {
        let groups: Vec<&serde_json::Value> = match groups_or_group {
            serde_json::Value::Array(groups) => groups.iter().collect(),
            single => vec![single],
        };
        for group in groups {
            if let Some(flags) = group["flags"].as_array() {
                for flag in flags {
                    visit(flag);
                }
            }
        }
    }

    // ---- Value-grammar drift gate (registry Kind <-> real parsers) ----

    /// Valid and invalid sample values for a registry value grammar. Every valid
    /// sample must parse through the real verb parser that owns the flag; every
    /// invalid sample must be rejected (a usage error, never a panic or silent
    /// acceptance). The samples are the intersection-safe set for every flag of a
    /// kind: a valid `PositiveU64` stays small so it also satisfies `--seeds`'
    /// tighter `1..=1000000` bound, and a valid `U64` never triggers `--seed-start`
    /// overflow (its driver pins `--seeds 1`). A `Path`/`Str` grammar accepts any
    /// string, so it has no invalid samples.
    fn kind_samples(kind: help::Kind) -> (Vec<&'static str>, Vec<&'static str>) {
        use help::Kind;
        match kind {
            Kind::U64 => (
                vec!["0", "1", "42", "18446744073709551615"],
                vec!["-1", "abc", "", "1.5", "99999999999999999999999"],
            ),
            Kind::U32 => (
                vec!["0", "1", "4294967295"],
                vec!["-1", "abc", "", "4294967296"],
            ),
            Kind::Usize => (vec!["0", "1", "65536"], vec!["-1", "abc", ""]),
            Kind::PositiveU64 => (vec!["1", "5", "100"], vec!["0", "-1", "abc", ""]),
            Kind::WatchdogMillis => (
                vec!["1", "10000", "86400000"],
                vec!["0", "86400001", "-1", "abc", ""],
            ),
            Kind::Permille => (
                vec!["0", "1", "250", "1000"],
                vec!["1001", "2000", "-1", "abc", ""],
            ),
            Kind::NanosRange => (
                vec!["0..0", "0..1000", "5..10", "0..18446744073709551615"],
                vec!["0:1000", "abc", "", "10..5", "0..", "..5", "5", "0..abc"],
            ),
            Kind::U64Range => (
                vec!["0..0", "0..1000", "5..10", "0..18446744073709551615"],
                vec!["0:1000", "abc", "", "10..5", "0..", "..5", "5", "0..abc"],
            ),
            Kind::OpKindList => (
                vec!["fs_write", "network", "fs_write,net_send", "clock,entropy"],
                vec!["unknown_op", "", "fs_write,", ",network", "NETWORK"],
            ),
            Kind::TaskSelector => (vec!["main", "0", "1", "42"], vec!["-1", "abc", ""]),
            Kind::CrashSpec => (
                vec![
                    "open", "write", "sync", "close", "open:1", "write:3", "close:10",
                ],
                vec!["read", "", "open:0", "open:abc", "open:", ":3", "OPEN"],
            ),
            Kind::KeyValue => (
                vec!["k=v", "key=", "a=b=c", "x=1"],
                vec!["=v", "novalue", "", "= "],
            ),
            Kind::UtcTimestamp => (
                vec![
                    "2026-07-22T23:00:09Z",
                    "1970-01-01T00:00:00Z",
                    "2000-02-29t12:34:56.5z",
                    "2554-07-21T23:34:33.709551615Z",
                ],
                vec![
                    "",
                    "1784761209",
                    "2026-07-22 23:00:09Z",
                    "2026-07-22T23:00:09",
                    "2026-07-22T23:00:09+00:00",
                    "2026-07-22T23:00:09.Z",
                    "2026-07-22T23:00:09.1234567890Z",
                    "2026-13-01T00:00:00Z",
                    "2026-02-29T00:00:00Z",
                    "2026-07-22T23:00:60Z",
                    "1969-12-31T23:59:59Z",
                    "2554-07-21T23:34:33.709551616Z",
                ],
            ),
            Kind::Hostname => (
                vec![
                    "patina",
                    "db-1.internal",
                    "",
                    "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh",
                ],
                vec![
                    "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh",
                    "a\0b",
                ],
            ),
            Kind::DnsEntry => (
                vec!["db.internal=10.0.0.5", "a=0.0.0.0", "x=255.255.255.255"],
                vec![
                    "=10.0.0.5",
                    "db.internal",
                    "db.internal=",
                    "db.internal=10.0.0",
                    "db.internal=10.0.0.256",
                    "db.internal=example.com",
                    "",
                ],
            ),
            Kind::AddressPair => (
                vec!["a,b", "10.0.0.1:80,10.0.0.2:80", "left, right"],
                vec!["a", "a,", ",b", "a,b,c", "", "a,a", " , "],
            ),
            Kind::Socket => (
                vec!["4=a->b", "5=x->y", "100=addr1->addr2"],
                vec!["3=a->b", "4=a->", "4=->b", "foo=a->b", "4=ab", "", "0=a->b"],
            ),
            Kind::Preopen => (
                vec!["/data", "/data:ro", "/data:rw", "rel", "/a/b"],
                vec!["", "/data:xx", ":ro"],
            ),
            Kind::UnsupportedSymbols => (
                vec!["all", "memcpy", "a,b", "foo , bar"],
                vec!["", ",", " , "],
            ),
            Kind::Enum(choices) => (choices.to_vec(), vec!["bogus", ""]),
            Kind::Symbol => (vec!["memcpy", "foo_bar", "x"], vec![""]),
            Kind::Path => (vec!["/tmp/x", "out.html", "x"], vec![""]),
            Kind::Str => (vec!["x", "hello", ""], vec![]),
        }
    }

    // Family-parser drivers. Each feeds an argument list to the real per-family
    // parser exactly as routing would, with a leading binary/module label where
    // the parser strips one, so a sample exercises the true value validation.

    /// The syntactic form a flag drive renders — the registry's arity decides
    /// which forms must parse, so the generic tests exercise every form of every
    /// flag rather than a hand-picked sample.
    #[derive(Clone, Copy)]
    enum FlagForm<'a> {
        /// `--flag=VALUE` — valid for required- and optional-value flags alike.
        Inline,
        /// `--flag VALUE` — a required-value flag consumes the next token; an
        /// optional-value flag must NOT (the sample lands as a stray positional).
        Spaced,
        /// `-x VALUE` — the registry short, space form.
        Short(&'a str),
        /// `--flag=A --flag=B` — rejected (`set_once`) unless registry-repeatable.
        Repeated(&'a str),
    }

    /// Drive `args` through the real parser of `verb`'s `family`, supplying the
    /// context that family's routing would already have consumed: the
    /// positionals it takes, and the companion flags a successful parse needs
    /// (a native harness needs a target and a test filter; a branch replay needs
    /// its whole quorum).
    ///
    /// This is the ONLY hand-written table left in the walk, and it is keyed by
    /// family rather than by flag — twenty entries that change when a family
    /// is added, not sixty that change when a flag is. Which flags to drive
    /// comes from the registry ([`help::Verb::family_flags`]), so a new flag is
    /// exercised in every family that accepts it without touching this file.
    fn drive_family(
        verb: &str,
        family: help::Family,
        flag: &str,
        args: &[&str],
    ) -> Result<(), CliError> {
        // A companion the parse needs but the flag under test does not supply.
        let unless = |name: &'static str, tokens: &[&'static str]| -> Vec<String> {
            if flag == name {
                Vec::new()
            } else {
                tokens.iter().map(|t| t.to_string()).collect()
            }
        };
        // The branch quorum is all-or-nothing and conflicts with `--timeline`, so
        // it is supplied only when the flag under test is part of it.
        let quorum = |names: &[&'static str]| -> Vec<String> {
            if !names.contains(&flag) && flag != "--parent" {
                return Vec::new();
            }
            names
                .iter()
                .filter(|name| **name != flag)
                .map(|name| match *name {
                    "--branch" => "--branch".to_string(),
                    "--from" => "--from=0".to_string(),
                    "--branch-seed" => "--branch-seed=1".to_string(),
                    other => format!("{other}=b"),
                })
                .collect()
        };
        let with = |prefix: Vec<String>, suffix: &[&str]| -> Vec<OsString> {
            prefix
                .iter()
                .map(String::as_str)
                .chain(args.iter().copied())
                .chain(suffix.iter().copied())
                .map(OsString::from)
                .collect()
        };
        let none: Vec<String> = Vec::new();
        let prebuilt = |name: &str| ArtifactRef::Prebuilt(PathBuf::from(name));
        let trace = || PathBuf::from("t.patina");
        match (verb, family) {
            ("run" | "test", help::Family::Cargo) => {
                parse_cargo(verb.to_string(), with(none, &[])).map(|_| ())
            }
            ("run", help::Family::Wasi) => {
                parse_wasi_run_from(prebuilt("m.wasm"), with(none, &[])).map(|_| ())
            }
            ("run", help::Family::Native) => {
                parse_native_run_from(prebuilt("bin"), with(none, &[])).map(|_| ())
            }
            ("test", help::Family::Harness) => {
                let mut prefix = unless("--harness-target", &["--harness-target=harness"]);
                prefix.extend(unless("--exact", &["--exact=module::test"]));
                parse_native_harness_from(
                    PathBuf::from("."),
                    PathBuf::from("Cargo.toml"),
                    with(prefix, &[]),
                )
                .map(|_| ())
            }
            ("build", help::Family::Native) => {
                // A single-source build needs an output; a package build is what
                // `--package`/`--bin` select.
                let prefix = if matches!(flag, "--package" | "--bin") {
                    vec!["sub/Cargo.toml".to_string()]
                } else {
                    let mut prefix = vec!["x.rs".to_string()];
                    prefix.extend(unless("--output", &["--output=/tmp/o"]));
                    prefix
                };
                parse_native_build(with(prefix, &[])).map(|_| ())
            }
            ("build", help::Family::Wasi) => {
                parse_wasi_build(with(vec!["sub/Cargo.toml".to_string()], &[])).map(|_| ())
            }
            ("audit", help::Family::Native) => {
                parse_native_audit_from(prebuilt("bin"), with(none, &[])).map(|_| ())
            }
            ("audit", help::Family::Wasi) => {
                cli::parse("audit", family, with(none, &[])).map(|_| ())
            }
            ("replay", help::Family::Cargo) => parse_cargo_replay(
                PathBuf::from("."),
                trace(),
                with(
                    quorum(&["--branch", "--from", "--branch-seed", "--branch-id"]),
                    &[],
                ),
            )
            .map(|_| ()),
            ("replay", help::Family::Wasi) => parse_wasi_replay(
                prebuilt("m.wasm"),
                trace(),
                with(
                    quorum(&["--branch", "--from", "--branch-seed", "--branch-id"]),
                    &[],
                ),
            )
            .map(|_| ()),
            ("replay", help::Family::Native) => {
                parse_native_replay(prebuilt("bin"), trace(), with(none, &[])).map(|_| ())
            }
            // `--seed-start` pins `--seeds 1` so a max-u64 start never overflows
            // the swept range.
            ("explore", _) => {
                parse_explore(with(unless("--seeds", &["--seeds=1"]), &["test"])).map(|_| ())
            }
            // A continuation takes no artifact; every other campaign flag needs
            // one. `--spec` reads its file while parsing, so the driver makes
            // whatever path the sample names a readable empty spec — otherwise
            // the drive would fail for a reason that is not the grammar's.
            ("campaign", _) => {
                let prefix = if matches!(flag, "--extend" | "--resume") {
                    none
                } else {
                    vec!["art.wasm".to_string()]
                };
                let mut argv = with(prefix, &[]);
                if flag == "--spec" {
                    // `--spec` reads its file while parsing, so a non-empty
                    // sampled path is redirected to a real empty spec in a temp
                    // dir. What is under test is the grammar, not the
                    // filesystem — and nothing is written into the source tree.
                    // An EMPTY value is left alone: it is the invalid sample and
                    // must still be rejected.
                    let dir = tempfile::tempdir().expect("tempdir");
                    let real = dir.path().join("spec.json");
                    std::fs::write(&real, b"{}").expect("write spec");
                    let real = real.display().to_string();
                    let mut after_spec = false;
                    for token in &mut argv {
                        let text = token.to_string_lossy().into_owned();
                        match text.strip_prefix("--spec=") {
                            Some(value) if !value.is_empty() => {
                                *token = OsString::from(format!("--spec={real}"));
                            }
                            _ if after_spec && !text.is_empty() => {
                                *token = OsString::from(&real);
                            }
                            _ => {}
                        }
                        after_spec = text == "--spec";
                    }
                    return campaign::parse(argv).map(|_| ());
                }
                campaign::parse(argv).map(|_| ())
            }
            ("coverage", _) => coverage::parse(with(
                vec!["guest".to_string(), "run.covmap".to_string()],
                &[],
            ))
            .map(|_| ()),
            ("sites", _) => sites::parse(with(none, &[])).map(|_| ()),
            ("syscalls", _) => syscalls::parse(with(none, &[])).map(|_| ()),
            ("minimize", help::Family::Sole) => {
                let mut prefix = vec!["t.patina".to_string()];
                prefix.extend(unless("--output", &["--output=/tmp/o"]));
                parse_minimize(with(prefix, &["--", "oracle"])).map(|_| ())
            }
            ("minimize", help::Family::Generation) => {
                let prefix = unless("--generation", &["--generation=1"]);
                parse_minimize(with(prefix, &[])).map(|_| ())
            }
            ("minimize", help::Family::Scenario) => {
                let mut prefix = vec!["--scenario".to_string()];
                prefix.extend(unless("--seed", &["--seed=0"]));
                parse_minimize(with(prefix, &["--", "oracle"])).map(|_| ())
            }
            ("trace", help::Family::Diff) => parse_trace(with(
                vec![
                    "diff".to_string(),
                    "a.patina".to_string(),
                    "b.patina".to_string(),
                ],
                &[],
            ))
            .map(|_| ()),
            ("trace", subcommand) => parse_trace(with(
                vec![subcommand.tag().to_string(), "t.patina".to_string()],
                &[],
            ))
            .map(|_| ()),
            (verb, family) => panic!("no driver for `{verb}` family {family:?}"),
        }
    }

    /// Parse a single flag with `value`, rendered in `form`, through the family
    /// parser under test, prefixing whatever the registry says the flag is inert
    /// without.
    fn drive_flag(
        verb: &str,
        family: help::Family,
        flag: &'static help::Flag,
        value: &str,
        form: FlagForm<'_>,
    ) -> Result<(), CliError> {
        let rendered: Vec<String> = match form {
            FlagForm::Inline => vec![format!("{}={value}", flag.name)],
            FlagForm::Spaced => vec![flag.name.to_string(), value.to_string()],
            FlagForm::Short(short) => vec![short.to_string(), value.to_string()],
            FlagForm::Repeated(second) => vec![
                format!("{}={value}", flag.name),
                format!("{}={second}", flag.name),
            ],
        };
        // A dependent knob is refused without its parent, so supply the parent in
        // whichever form it takes: an optional-value switch is armed bare, while a
        // required-value parent (`--fingerprint` needs `--record PATH`) needs a
        // sample of its own kind, taken from the registry rather than hardcoded.
        let parent = flag.requires.map(|name| {
            let parent = help::verb(verb)
                .expect("registered verb")
                .family_flags(family)
                .find(|candidate| candidate.name == name)
                .unwrap_or_else(|| {
                    panic!(
                        "`{verb}` flag `{}` requires unregistered `{name}`",
                        flag.name
                    )
                });
            match parent.value.grammar() {
                Some(kind) => format!(
                    "{name}={}",
                    kind_samples(kind).0.first().expect("a valid sample")
                ),
                None => name.to_string(),
            }
        });
        let mut tokens: Vec<&str> = parent.iter().map(String::as_str).collect();
        tokens.extend(rendered.iter().map(String::as_str));
        drive_family(verb, family, flag.name, &tokens)
    }

    #[test]
    fn cargo_and_wasi_refuse_fs_crash_at_without_restart_semantics() {
        let mut knobs = KnobValues::default();
        knobs.0.insert(FaultKnob::FsCrashAt, vec!["write:1".into()]);
        let cargo = execute(Invocation {
            cargo_command: "run".into(),
            cargo_args: Vec::new(),
            mode: Mode::Seeded { seed: 0 },
            step_budget: None,
            realtime_epoch_nanos: None,
            hostname: None,
            params: BTreeMap::new(),
            knobs: knobs.clone(),
            buggify: None,
            working_dir: None,
        })
        .unwrap_err()
        .to_string();
        assert!(cargo.contains("cargo-family --fs-crash-at crash-restart is not implemented"));

        let wasi = execute_wasi_run(WasiInvocation {
            module: ArtifactRef::Prebuilt(PathBuf::from("missing.wasm")),
            mode: Mode::Seeded { seed: 0 },
            fuel: DEFAULT_WASM_FUEL,
            arguments: Vec::new(),
            environment: BTreeMap::new(),
            sockets: Vec::new(),
            preopens: Vec::new(),
            resource_limits: WasiResourceLimitOverrides::default(),
            step_budget: None,
            realtime_epoch_nanos: None,
            knobs,
            buggify: None,
            liveness: NativeLiveness::default(),
        })
        .unwrap_err()
        .to_string();
        assert!(wasi.contains("WASI --fs-crash-at crash-restart is not implemented"));
    }

    /// A Cargo-family replay refuses a semantic knob by name instead of handing
    /// it to Cargo: the trace is authoritative, and silently forwarding
    /// `--fs-crash-at` would surface as a confusing cargo error rather than the
    /// reason the knob is not accepted.
    #[test]
    fn cargo_replay_refuses_semantic_knobs_rather_than_forwarding_them() {
        for flag in ["--fs-crash-at", "--seed", "--buggify", "--sched-pct"] {
            let argv = vec![
                OsString::from(flag),
                OsString::from("close"),
                OsString::from("--example"),
                OsString::from("demo"),
            ];
            let Err(error) =
                parse_cargo_replay(PathBuf::from("."), PathBuf::from("t.patina"), argv)
            else {
                panic!("{flag} should be refused, not forwarded to Cargo");
            };
            let message = error.to_string();
            assert!(
                message.contains(flag) && message.contains("trace is authoritative"),
                "{flag}: {message}"
            );
        }
    }

    /// The Cargo family forwards every unrecognized token verbatim, in place,
    /// including one that is not valid UTF-8 — such a token can never be a
    /// Patina flag, and dropping or re-encoding it would corrupt a legitimate
    /// cargo argument (a path under a non-UTF-8 locale). The `--` section is
    /// the guest's and is passed through whole, so a `--seed` after it stays a
    /// guest argument.
    #[cfg(unix)]
    #[test]
    fn cargo_passthrough_preserves_order_and_non_utf8_tokens() {
        use std::os::unix::ffi::OsStringExt;
        let raw = OsString::from_vec(vec![b'-', b'-', b'p', b'=', 0xff, 0xfe]);
        let forwarded = [
            OsString::from("--manifest-path"),
            OsString::from("./x/Cargo.toml"),
            raw.clone(),
            OsString::from("--example"),
            OsString::from("demo"),
            OsString::from("--"),
            OsString::from("--seed=99"),
        ];
        let mut argv = vec![
            OsString::from("--manifest-path"),
            OsString::from("./x/Cargo.toml"),
        ];
        argv.push(OsString::from("--seed=7"));
        argv.extend(forwarded[2..].iter().cloned());

        let ParseResult::Run(invocation) = parse_cargo("run".to_string(), argv).unwrap() else {
            panic!("expected a Cargo-family run");
        };
        assert_eq!(invocation.mode, Mode::Seeded { seed: 7 });
        assert_eq!(
            invocation.cargo_args,
            forwarded.to_vec(),
            "forwarded tokens keep their order and bytes; only the Patina flag is taken"
        );
    }

    #[test]
    fn no_verb_redeclares_a_global_flag() {
        let globals: BTreeSet<&str> = help::GLOBAL_OUTPUT
            .iter()
            .chain(help::HELP_FLAGS.iter())
            .flat_map(|flag| [Some(flag.name), flag.short])
            .flatten()
            .collect();
        for verb in help::VERBS {
            for flag in verb.groups.iter().flat_map(|group| group.flags.iter()) {
                for name in [Some(flag.name), flag.short].into_iter().flatten() {
                    assert!(
                        !globals.contains(name),
                        "verb `{}` registers `{name}`, which the global pre-pass strips before \
                         routing — the verb's flag is unreachable",
                        verb.name
                    );
                }
            }
        }
    }

    /// Every family a group claims is one the verb declares, and every family a
    /// verb with flag groups declares owns at least one flag. Flagless commands
    /// have exactly one `Sole` form. Without this a typo in a group's
    /// `families` would silently drop flags from a parser (they would simply
    /// stop being accepted) rather than failing loudly.
    #[test]
    fn registry_families_are_declared_and_populated() {
        for verb in help::VERBS {
            let declared: BTreeSet<help::Family> =
                verb.families.iter().map(|spec| spec.family).collect();
            for group in verb.groups {
                for family in group
                    .families
                    .iter()
                    .chain(group.flags.iter().filter_map(|f| f.families).flatten())
                {
                    assert!(
                        declared.contains(family),
                        "verb `{}` group {:?} claims undeclared family {family:?}",
                        verb.name,
                        group.title
                    );
                }
            }
            if verb.groups.is_empty() {
                assert_eq!(declared, BTreeSet::from([help::Family::Sole]));
                assert_eq!(verb.families.len(), 1);
                continue;
            }
            for spec in verb.families {
                assert!(
                    verb.family_flags(spec.family).next().is_some(),
                    "verb `{}` declares family {:?} but no flag reaches it",
                    verb.name,
                    spec.family
                );
            }
        }
    }

    #[test]
    fn every_report_knob_is_documented_in_the_environment_registry() {
        // Same drift gate as the fault knobs, for the report suppressors: the
        // registry is what `--help` and the JSON index publish, so a report the
        // runtime can silence but the registry never names is a working knob
        // nobody can discover — and an undocumented knob is the first step back
        // toward one family carrying it and the rest dropping it.
        let documented: String = help::ENVIRONMENT
            .iter()
            .map(|entry| entry.name)
            .collect::<Vec<_>>()
            .join(" ");
        for report in patina_dst_runtime::Report::ALL {
            assert!(
                documented.contains(report.env()),
                "{} has no row in the help environment registry",
                report.env()
            );
        }
    }

    #[test]
    fn knob_table_covers_every_registry_fault_flag() {
        // The drift gate behind `FaultKnob`: every knob the registry declares has
        // a variant, so every family's plumbing carries it. Without this, a knob
        // can be parsed by one family and silently dropped on the way to the
        // guest — the silent-inertness class, which looks exactly like a clean
        // run. Compared in ORDER, not as a set: `FaultKnob::ALL` order is what
        // the control plane and the re-emitted command line follow, and the
        // registry is where that order is decided.
        let table: Vec<&str> = FaultKnob::ALL.iter().map(|knob| knob.meta().flag).collect();
        let registry: Vec<&str> = help::fault_flag_names().collect();
        assert_eq!(
            registry, table,
            "every registry fault flag needs a FaultKnob variant, in registry order (and vice versa)"
        );
    }

    /// The error arm in `repeatable_payload` must be dead: every knob the table
    /// marks repeatable has an encoder, and every knob it marks scalar is
    /// filtered out before one is asked for. A knob switched to
    /// `Plumbing::Repeatable` without an encoder fails here rather than at the
    /// first invocation that sets it.
    #[test]
    fn every_repeatable_knob_has_an_encoder() {
        let mut repeatable = 0;
        for knob in FaultKnob::ALL {
            let sample = vec![knob_sample(*knob).to_string()];
            match knob.meta().plumbing {
                Plumbing::Repeatable => {
                    repeatable += 1;
                    repeatable_payload(*knob, &sample)
                        .unwrap_or_else(|error| panic!("{knob:?} has no encoder: {error}"));
                }
                Plumbing::Scalar => assert!(
                    repeatable_payload(*knob, &sample).is_err(),
                    "{knob:?} is scalar but answered to a repeatable payload"
                ),
            }
        }
        assert!(repeatable > 0, "no repeatable knobs left to prove anything");
    }

    #[test]
    fn every_fault_knob_reaches_every_family_and_is_refused_by_replay() {
        // Each knob, set to a valid value, must survive parsing into the same
        // control-plane variable for the Cargo, WASI and native families, and must
        // be REFUSED by `replay` — which derives its refusal list from the same
        // registry slice, so a new knob is refused the day it is registered.
        for knob in FaultKnob::ALL {
            let meta = knob.meta();
            let flag = meta.flag;
            let value = knob_sample(*knob);
            // A repeatable knob's variable carries the ENCODED set, not the raw
            // text, so the expected payload comes from the same encoder the
            // forwarding path uses.
            let expected = match meta.plumbing {
                Plumbing::Scalar => value.to_string(),
                Plumbing::Repeatable => repeatable_payload(*knob, &[value.to_string()])
                    .expect("every repeatable knob encodes its sample"),
            };
            for (verb, family) in [
                ("run", help::Family::Cargo),
                ("run", help::Family::Wasi),
                ("run", help::Family::Native),
                ("test", help::Family::Cargo),
                ("test", help::Family::Harness),
            ] {
                // wasip1 has no name-resolution surface at all, so the DNS knobs
                // are a DECLARED family exception: the WASI parser must refuse
                // them rather than accept a knob that could never fire. The
                // registry narrows them, so this asks the registry rather than
                // hard-coding which flags are excepted.
                if !help::verb(verb)
                    .expect("registered verb")
                    .family_flags(family)
                    .any(|registered| registered.name == flag)
                {
                    assert!(
                        cli::parse(verb, family, strings(&[flag, value])).is_err(),
                        "{verb} {family:?} must refuse the unregistered {flag}"
                    );
                    continue;
                }
                let args = cli::parse(verb, family, strings(&[flag, value]))
                    .unwrap_or_else(|error| panic!("{verb} {family:?} rejected {flag}: {error}"));
                let pairs = knob_env_pairs(&knobs_of(&args).expect("knob parse")).expect("encode");
                assert!(
                    pairs.contains(&(meta.env, expected.clone())),
                    "{verb} {family:?} did not carry {flag} to {}: {pairs:?}",
                    meta.env
                );
            }
            for family in [
                help::Family::Cargo,
                help::Family::Wasi,
                help::Family::Native,
            ] {
                let message = match cli::parse("replay", family, strings(&[flag, value])) {
                    Err(error) => error.to_string(),
                    Ok(_) => panic!("replay accepted a re-supplied {flag}"),
                };
                assert!(
                    message.contains(flag) && message.contains("the trace is authoritative"),
                    "replay refusal for {flag} should explain itself: {message}"
                );
            }
        }
    }

    #[test]
    fn realtime_epoch_timestamps_convert_to_exact_unix_nanoseconds() {
        let nanos = |text: &str| values::utc_timestamp_nanos("--realtime-epoch", text);
        // The default epoch is spelled by the timestamp it documents.
        assert_eq!(
            nanos("2026-07-22T23:00:09Z"),
            Ok(patina_dst_runtime::DEFAULT_REALTIME_EPOCH_NANOS)
        );
        assert_eq!(nanos("1970-01-01T00:00:00Z"), Ok(0));
        assert_eq!(nanos("2001-09-09T01:46:40Z"), Ok(1_000_000_000_000_000_000));
        // Leap day, lowercase separators, a short fraction scaled to nanoseconds.
        assert_eq!(nanos("2000-02-29t12:34:56.5z"), Ok(951_827_696_500_000_000));
        assert_eq!(nanos("1970-01-01T00:00:00.000000001Z"), Ok(1));
        assert_eq!(nanos("2554-07-21T23:34:33.709551615Z"), Ok(u64::MAX));
        // Unix seconds, a numeric offset, ten fraction digits, a non-leap-year
        // Feb 29, a leap second, pre-epoch, and one nanosecond past u64.
        for text in [
            "1784761209",
            "2026-07-22T23:00:09+00:00",
            "2026-07-22T23:00:09.1234567890Z",
            "2100-02-29T00:00:00Z",
            "2026-07-22T23:00:60Z",
            "1969-12-31T23:59:59Z",
            "2554-07-21T23:34:33.709551616Z",
        ] {
            let error = nanos(text).expect_err(text);
            assert!(error.contains("--realtime-epoch"), "{text}: {error}");
        }
    }

    #[test]
    fn realtime_epoch_reaches_every_run_family_and_replay_refuses_it() {
        const TEXT: &str = "2001-09-09T01:46:40Z";
        const NANOS: u64 = 1_000_000_000_000_000_000;
        let native = parse_native_run(strings(&["guest", "--realtime-epoch", TEXT])).unwrap();
        assert_eq!(native.realtime_epoch_nanos, Some(NANOS));
        let wasi = parse_wasi_run(strings(&["guest.wasm", "--realtime-epoch", TEXT])).unwrap();
        assert_eq!(wasi.realtime_epoch_nanos, Some(NANOS));
        for command in ["run", "test"] {
            let ParseResult::Run(cargo) =
                parse_cargo(command.into(), strings(&["--realtime-epoch", TEXT])).unwrap()
            else {
                panic!("the Cargo family parses to a Run invocation");
            };
            assert_eq!(cargo.realtime_epoch_nanos, Some(NANOS), "{command}");
        }
        // Absent means the runtime default, not an explicit value.
        assert_eq!(
            parse_native_run(strings(&["guest"]))
                .unwrap()
                .realtime_epoch_nanos,
            None
        );
        // Unix seconds are not the grammar: the flag is refused by name.
        let error = parse_native_run(strings(&["guest", "--realtime-epoch", "1784761209"]))
            .err()
            .expect("unix seconds are refused");
        assert!(error.to_string().contains("--realtime-epoch"), "{error}");
        assert_replay_refuses("--realtime-epoch", TEXT);
    }

    /// `replay` refuses a re-supplied run fact in every family, by name.
    fn assert_replay_refuses(flag: &str, value: &str) {
        for family in [
            help::Family::Cargo,
            help::Family::Wasi,
            help::Family::Native,
        ] {
            match cli::parse("replay", family, strings(&[flag, value])) {
                Err(error) => assert!(error.to_string().contains(flag), "{family:?}: {error}"),
                Ok(_) => panic!("{family:?} replay accepted a re-supplied {flag}"),
            }
        }
    }

    #[test]
    fn hostname_reaches_every_family_that_can_observe_it_and_replay_refuses_it() {
        const NAME: &str = "db-1.internal";
        let native = parse_native_run(strings(&["guest", "--hostname", NAME])).unwrap();
        assert_eq!(native.hostname.as_deref(), Some(NAME));
        for command in ["run", "test"] {
            let ParseResult::Run(cargo) =
                parse_cargo(command.into(), strings(&["--hostname", NAME])).unwrap()
            else {
                panic!("the Cargo family parses to a Run invocation");
            };
            assert_eq!(cargo.hostname.as_deref(), Some(NAME), "{command}");
        }
        assert_eq!(
            parse_native_run(strings(&["guest"])).unwrap().hostname,
            None
        );
        // wasip1 has no hostname surface, so the WASI family refuses the flag.
        let error = parse_wasi_run(strings(&["guest.wasm", "--hostname", NAME]))
            .expect_err("WASI refuses --hostname");
        assert!(error.to_string().contains("--hostname"), "{error}");
        // The kernel's rules: 64 bytes fit, 65 do not, and a NUL never does.
        let longest = "h".repeat(patina_dst_runtime::HOSTNAME_MAX_BYTES);
        let too_long = "h".repeat(patina_dst_runtime::HOSTNAME_MAX_BYTES + 1);
        assert_eq!(
            parse_native_run(strings(&["guest", "--hostname", &longest]))
                .unwrap()
                .hostname
                .as_deref(),
            Some(longest.as_str())
        );
        for refused in [too_long.as_str(), "a\0b"] {
            let error = parse_native_run(strings(&["guest", "--hostname", refused]))
                .err()
                .expect("refused hostname");
            assert!(error.to_string().contains("--hostname"), "{error}");
        }
        assert_replay_refuses("--hostname", NAME);
    }

    #[test]
    fn registry_value_grammars_match_the_parsers() {
        // The generic drift gate: every registered value-bearing flag's declared
        // `help::Kind` is exercised against the REAL parser that consumes it, in
        // both directions. Valid samples of the kind must parse; invalid samples
        // must be rejected. A parser that tightens or loosens a value grammar
        // without updating the registry kind (or a kind that does not match parser
        // reality) fails here — the general form of the `--sleep-jitter-nanos
        // 0:N` vs `0..N` regression, for every flag at once.

        // Global output options are parsed once, before routing, by output::extract.
        // Both value forms must work here too (the uniform-value-syntax rule).
        for flag in help::GLOBAL_OUTPUT {
            let Some(kind) = flag.value.grammar() else {
                continue;
            };
            let (valid, invalid) = kind_samples(kind);
            for sample in valid {
                for args in [
                    vec![format!("{}={sample}", flag.name)],
                    vec![flag.name.to_string(), sample.to_string()],
                ] {
                    let args: Vec<&str> = args.iter().map(String::as_str).collect();
                    output::extract(strings(&args)).unwrap_or_else(|error| {
                        panic!(
                            "global `{}` rejected valid {sample:?} as {args:?}: {error}",
                            flag.name
                        )
                    });
                }
            }
            for sample in invalid {
                let arg = format!("{}={sample}", flag.name);
                assert!(
                    output::extract(strings(&[&arg])).is_err(),
                    "global `{}` accepted invalid {sample:?}",
                    flag.name
                );
            }
        }

        // Every per-verb flag, driven through its owning family parser, in every
        // registry-implied form: inline `=` always; the space form must parse for
        // required-value flags and must NOT consume the token for optional-value
        // flags (the sample lands as a stray positional and the parse fails); a
        // declared short takes the space form.
        for verb in help::VERBS {
            for spec in verb.families {
                let mut seen: BTreeSet<&str> = BTreeSet::new();
                for flag in verb.family_flags(spec.family) {
                    let Some(kind) = flag.value.grammar() else {
                        continue;
                    };
                    if !seen.insert(flag.name) {
                        continue;
                    }
                    let (valid, invalid) = kind_samples(kind);
                    for sample in &valid {
                        let drive = |form: FlagForm<'_>| {
                            drive_flag(verb.name, spec.family, flag, sample, form)
                        };
                        drive(FlagForm::Inline).unwrap_or_else(|error| {
                            panic!(
                                "verb `{}` flag `{}` ({kind:?}) rejected VALID sample {sample:?}: \
                             {error}",
                                verb.name, flag.name
                            )
                        });
                        match flag.value {
                            help::Value::Required(..) => {
                                drive(FlagForm::Spaced).unwrap_or_else(|error| {
                                    panic!(
                                        "verb `{}` flag `{}` rejected the space form of valid \
                                     {sample:?}: {error}",
                                        verb.name, flag.name
                                    )
                                });
                                if let Some(short) = flag.short {
                                    drive(FlagForm::Short(short)).unwrap_or_else(|error| {
                                    panic!(
                                        "verb `{}` flag `{}` rejected short `{short}` with valid \
                                         {sample:?}: {error}",
                                        verb.name, flag.name
                                    )
                                });
                                }
                            }
                            help::Value::Optional(..) => {
                                assert!(
                                    drive(FlagForm::Spaced).is_err(),
                                    "verb `{}` optional-value flag `{}` CONSUMED the space-form \
                                 token {sample:?} (optional values are `=`-only)",
                                    verb.name,
                                    flag.name
                                );
                            }
                            help::Value::None => unreachable!("grammar() returned Some"),
                        }
                    }
                    for sample in &invalid {
                        for form in [FlagForm::Inline, FlagForm::Spaced] {
                            // The space form only reaches the value validator on
                            // required-value flags.
                            if matches!(form, FlagForm::Spaced)
                                && !matches!(flag.value, help::Value::Required(..))
                            {
                                continue;
                            }
                            let outcome = drive_flag(verb.name, spec.family, flag, sample, form);
                            assert!(
                                outcome.is_err(),
                                "verb `{}` family {:?} flag `{}` ({kind:?}) ACCEPTED invalid \
                             sample {sample:?}",
                                verb.name,
                                spec.family,
                                flag.name
                            );
                        }
                    }
                }
            }
        }
    }

    /// The registry's `repeatable` field must match the parsers: a repeatable
    /// value flag accepts two occurrences; a non-repeatable one rejects them
    /// (`set_once`'s "provided more than once"). Scope is value-bearing flags —
    /// a repeated bare switch is idempotent and harmless by construction.
    #[test]
    fn registry_repeatable_flags_match_the_parsers() {
        for flag in help::GLOBAL_OUTPUT {
            let Some(kind) = flag.value.grammar() else {
                continue;
            };
            let (valid, _) = kind_samples(kind);
            let first = valid[0];
            let second = valid.get(1).copied().unwrap_or(first);
            let args = [
                format!("{}={first}", flag.name),
                format!("{}={second}", flag.name),
            ];
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let outcome = output::extract(strings(&args)).map(|_| ());
            assert_eq!(
                outcome.is_ok(),
                flag.repeatable,
                "global `{}` repeat behavior does not match registry repeatable={}: {outcome:?}",
                flag.name,
                flag.repeatable
            );
        }
        for verb in help::VERBS {
            for spec in verb.families {
                let mut seen: BTreeSet<&str> = BTreeSet::new();
                for flag in verb.family_flags(spec.family) {
                    let Some(kind) = flag.value.grammar() else {
                        continue;
                    };
                    if !seen.insert(flag.name) {
                        continue;
                    }
                    let (valid, _) = kind_samples(kind);
                    let first = valid[0];
                    let second = valid.get(1).copied().unwrap_or(first);
                    let outcome = drive_flag(
                        verb.name,
                        spec.family,
                        flag,
                        first,
                        FlagForm::Repeated(second),
                    );
                    assert_eq!(
                        outcome.is_ok(),
                        flag.repeatable,
                        "verb `{}` family {:?} flag `{}` repeat behavior does not match \
                         registry repeatable={}: {outcome:?}",
                        verb.name,
                        spec.family,
                        flag.name,
                        flag.repeatable
                    );
                }
            }
        }
    }
}
