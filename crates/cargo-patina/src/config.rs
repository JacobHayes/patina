//! Repository configuration layering for `.patina/config.toml`.
//!
//! The CLI parsers remain bespoke. This module is the thin pre-parse layer that
//! discovers project config, validates `[defaults.<verb>]` through the help
//! registry, injects lower-priority defaults only when the command line omitted
//! that flag, and records provenance for output envelopes.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::Serialize;
use serde_json::{Value as JsonValue, json};

type TomlValue = toml::Value;

use crate::CliError;
use crate::cli;
use crate::help::{self, Flag, Kind, Value};

#[derive(Clone, Debug)]
pub(crate) struct RepoConfig {
    path: PathBuf,
    text: String,
    groups: Vec<GroupConfig>,
    defaults: BTreeMap<String, BTreeMap<String, TomlValue>>,
}

#[derive(Clone, Debug)]
pub(crate) struct GroupConfig {
    pub(crate) name: String,
    paths: Vec<String>,
    labels: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct ConfigState {
    path: Option<PathBuf>,
    groups: Vec<String>,
    applied: Vec<AppliedDefault>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct AppliedDefault {
    pub(crate) key: String,
    pub(crate) flag: String,
    pub(crate) source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) column: Option<usize>,
}

#[derive(Clone, Debug)]
struct ResolvedDefault {
    flag: &'static Flag,
    tokens: Vec<OsString>,
    applied: AppliedDefault,
}

#[derive(Clone, Debug)]
struct ConfiguredValue {
    tokens: Vec<OsString>,
    display: Option<String>,
}

static REPO_CONFIG: OnceLock<Option<RepoConfig>> = OnceLock::new();
static STATE: OnceLock<ConfigState> = OnceLock::new();

/// Apply env/project defaults to the argument vector before the bespoke parser
/// runs. `--no-config` disables the TOML file only; `PATINA_*` env defaults still
/// count as user-scope configuration and are handled here.
pub(crate) fn layer_arguments(
    arguments: Vec<OsString>,
    no_config: bool,
) -> Result<Vec<OsString>, CliError> {
    let Some((verb_index, verb)) = routed_verb(&arguments) else {
        install_state(ConfigState::default());
        return Ok(arguments);
    };
    if help_or_version_requested(&arguments[(verb_index + 1)..]) {
        install_state(ConfigState::default());
        return Ok(arguments);
    }

    let repo = if no_config {
        None
    } else {
        load_repo_config()?.as_ref().cloned()
    };

    let explicit = explicit_flags(verb, &arguments[(verb_index + 1)..]);
    let mut applied = Vec::new();
    let mut injected = Vec::new();

    if let Some(repo) = repo.as_ref() {
        validate_replay_exclusion(verb, repo)?;
        for default in repo.defaults_for(verb)? {
            if explicit.contains(default.flag.name) {
                continue;
            }
            if env_default_is_present(default.flag) {
                // The env pass below is higher precedence and will validate/apply it.
                continue;
            }
            injected.extend(default.tokens.iter().cloned());
            applied.push(default.applied);
        }
    }

    for flag in help::configurable_flags(verb) {
        if explicit.contains(flag.name) {
            continue;
        }
        if applied.iter().any(|entry| entry.flag == flag.name) {
            continue;
        }
        if let Some(default) = env_default(flag)? {
            injected.extend(default.tokens.iter().cloned());
            applied.push(default.applied);
        }
    }

    let group_names = repo
        .as_ref()
        .map(|repo| repo.groups.iter().map(|group| group.name.clone()).collect())
        .unwrap_or_default();
    install_state(ConfigState {
        path: repo.as_ref().map(|repo| repo.path.clone()),
        groups: group_names,
        applied: applied.clone(),
    });

    if applied.iter().any(|entry| entry.source == "config") {
        if let Some(path) = repo.as_ref().map(|repo| repo.path.display().to_string()) {
            let keys = applied
                .iter()
                .filter(|entry| entry.source == "config")
                .map(|entry| entry.key.as_str())
                .collect::<Vec<_>>()
                .join(",");
            eprintln!("PATINA_CONFIG applied={verb}:{keys} path={path}");
        }
    }

    if injected.is_empty() {
        return Ok(arguments);
    }

    let mut layered = Vec::with_capacity(arguments.len() + injected.len());
    layered.extend(arguments[..=verb_index].iter().cloned());
    layered.extend(injected);
    layered.extend(arguments[(verb_index + 1)..].iter().cloned());
    Ok(layered)
}

fn routed_verb(arguments: &[OsString]) -> Option<(usize, &'static str)> {
    let mut index = 0;
    if arguments.first().and_then(|value| value.to_str()) == Some("patina") {
        index = 1;
    }
    let verb = arguments.get(index)?.to_str()?;
    help::verb(verb).map(|entry| (index, entry.name))
}

fn help_or_version_requested(arguments: &[OsString]) -> bool {
    for argument in arguments {
        if argument == "--" {
            return false;
        }
        if argument == "--help" || argument == "-h" || argument == "--version" || argument == "-V" {
            return true;
        }
    }
    false
}

fn load_repo_config() -> Result<&'static Option<RepoConfig>, CliError> {
    if let Some(existing) = REPO_CONFIG.get() {
        return Ok(existing);
    }
    let loaded = discover_config_file()?.map(|path| {
        let text = std::fs::read_to_string(&path).map_err(|error| {
            CliError(format!(
                "failed to read Patina config {}: {error}",
                path.display()
            ))
        })?;
        parse_config_text(path, text)
    });
    let loaded = loaded.transpose()?;
    let _ = REPO_CONFIG.set(loaded);
    Ok(REPO_CONFIG
        .get()
        .expect("repo config OnceLock was just initialized"))
}

fn discover_config_file() -> Result<Option<PathBuf>, CliError> {
    let mut dir = std::env::current_dir()
        .map_err(|error| CliError(format!("failed to get current directory: {error}")))?;
    loop {
        let candidate = dir.join(".patina/config.toml");
        if candidate.is_file() {
            return Ok(Some(candidate));
        }
        if !dir.pop() {
            return Ok(None);
        }
    }
}

fn parse_config_text(path: PathBuf, text: String) -> Result<RepoConfig, CliError> {
    let value: TomlValue = toml::from_str(&text).map_err(|error| {
        let position = error
            .span()
            .and_then(|span| line_col(&text, span.start))
            .map(|(line, col)| format!("{}:{line}:{col}", path.display()))
            .unwrap_or_else(|| path.display().to_string());
        CliError(format!("Patina config {position} is invalid TOML: {error}"))
    })?;
    let root = value.as_table().ok_or_else(|| {
        CliError(format!(
            "Patina config {} must be a TOML table",
            path.display()
        ))
    })?;

    let mut groups = Vec::new();
    let mut defaults = BTreeMap::new();
    for (key, value) in root {
        match key.as_str() {
            "groups" => groups = parse_groups(&path, &text, value)?,
            "defaults" => defaults = parse_defaults_tables(&path, &text, value)?,
            other => {
                return Err(config_error(
                    &path,
                    &text,
                    &[other],
                    format!("unknown Patina config key {other:?}; expected groups or defaults"),
                ));
            }
        }
    }

    Ok(RepoConfig {
        path,
        text,
        groups,
        defaults,
    })
}

fn parse_groups(path: &Path, text: &str, value: &TomlValue) -> Result<Vec<GroupConfig>, CliError> {
    let table = value.as_table().ok_or_else(|| {
        config_error(
            path,
            text,
            &["groups"],
            "Patina config [groups] must be a table".to_string(),
        )
    })?;
    let mut groups = Vec::new();
    for (name, group_value) in table {
        if name.is_empty() {
            return Err(config_error(
                path,
                text,
                &["groups", name],
                "Patina config group names must not be empty".to_string(),
            ));
        }
        let group = group_value.as_table().ok_or_else(|| {
            config_error(
                path,
                text,
                &["groups", name],
                format!("Patina config group {name:?} must be a table"),
            )
        })?;
        let mut paths = Vec::new();
        let mut labels = Vec::new();
        for (group_key, group_field) in group {
            match group_key.as_str() {
                "paths" => {
                    paths = string_array(path, text, &["groups", name, "paths"], group_field)?
                }
                "labels" => {
                    labels = string_array(path, text, &["groups", name, "labels"], group_field)?
                }
                other => {
                    return Err(config_error(
                        path,
                        text,
                        &["groups", name, other],
                        format!(
                            "unknown Patina config group key {other:?} in [groups.{name}]; expected paths or labels"
                        ),
                    ));
                }
            }
        }
        groups.push(GroupConfig {
            name: name.clone(),
            paths,
            labels,
        });
    }
    groups.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(groups)
}

fn parse_defaults_tables(
    path: &Path,
    text: &str,
    value: &TomlValue,
) -> Result<BTreeMap<String, BTreeMap<String, TomlValue>>, CliError> {
    let table = value.as_table().ok_or_else(|| {
        config_error(
            path,
            text,
            &["defaults"],
            "Patina config [defaults] must be a table".to_string(),
        )
    })?;
    let mut defaults = BTreeMap::new();
    for (verb, verb_value) in table {
        if help::verb(verb).is_none() {
            return Err(config_error(
                path,
                text,
                &["defaults", verb],
                format!("unknown Patina defaults verb {verb:?}"),
            ));
        }
        let values = verb_value.as_table().ok_or_else(|| {
            config_error(
                path,
                text,
                &["defaults", verb],
                format!("Patina config [defaults.{verb}] must be a table"),
            )
        })?;
        for (key, default_value) in values {
            let flag = help::configurable_flag_by_key(verb, key).ok_or_else(|| {
                config_error(
                    path,
                    text,
                    &["defaults", verb, key],
                    format!(
                        "unknown Patina config default key {key:?} for [defaults.{verb}]; keys must name registry-declared defaults for that verb"
                    ),
                )
            })?;
            let key_path = ["defaults", verb.as_str(), key.as_str()];
            let _ = configured_from_toml(path, text, &key_path, flag, default_value)?;
        }
        defaults.insert(
            verb.clone(),
            values
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        );
    }
    Ok(defaults)
}

fn string_array(
    path: &Path,
    text: &str,
    key_path: &[&str],
    value: &TomlValue,
) -> Result<Vec<String>, CliError> {
    let array = value.as_array().ok_or_else(|| {
        config_error(
            path,
            text,
            key_path,
            format!(
                "Patina config {} must be an array of strings",
                key_path.join(".")
            ),
        )
    })?;
    array
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value.as_str().map(str::to_string).ok_or_else(|| {
                config_error(
                    path,
                    text,
                    key_path,
                    format!(
                        "Patina config {}[{index}] must be a string",
                        key_path.join(".")
                    ),
                )
            })
        })
        .collect()
}

impl RepoConfig {
    fn defaults_for(&self, verb: &'static str) -> Result<Vec<ResolvedDefault>, CliError> {
        let Some(table) = self.defaults.get(verb) else {
            return Ok(Vec::new());
        };
        if verb == "replay" && !table.is_empty() {
            let key = table.keys().next().expect("non-empty defaults.replay");
            return Err(config_error(
                &self.path,
                &self.text,
                &["defaults", "replay", key],
                "Patina config defaults for replay are refused: replay is trace-authoritative and must not re-apply project defaults".to_string(),
            ));
        }
        let mut resolved = Vec::new();
        for (key, value) in table {
            let flag = help::configurable_flag_by_key(verb, key).ok_or_else(|| {
                config_error(
                    &self.path,
                    &self.text,
                    &["defaults", verb, key],
                    format!(
                        "unknown Patina config default key {key:?} for [defaults.{verb}]; keys must name registry-declared defaults for that verb"
                    ),
                )
            })?;
            let position = find_key_position(&self.text, &["defaults", verb, key]);
            if let Some(configured) = configured_from_toml(
                &self.path,
                &self.text,
                &["defaults", verb, key],
                flag,
                value,
            )? {
                resolved.push(ResolvedDefault {
                    flag,
                    tokens: configured.tokens,
                    applied: AppliedDefault {
                        key: key.clone(),
                        flag: flag.name.to_string(),
                        source: "config",
                        value: configured.display,
                        env: None,
                        path: Some(self.path.display().to_string()),
                        line: position.map(|(line, _)| line),
                        column: position.map(|(_, column)| column),
                    },
                });
            }
        }
        Ok(resolved)
    }

    pub(crate) fn apply_groups(&self, site: &mut crate::sites::SiteRecord) {
        let mut names = Vec::new();
        for group in &self.groups {
            if group.matches_site(site) {
                names.push(group.name.clone());
            }
        }
        site.groups = names;
    }
}

impl GroupConfig {
    fn matches_site(&self, site: &crate::sites::SiteRecord) -> bool {
        self.paths
            .iter()
            .any(|pattern| glob_match_path(pattern, &site.file))
            || site.label.as_deref().is_some_and(|label| {
                self.labels
                    .iter()
                    .any(|pattern| glob_match_label(pattern, label))
            })
            || self
                .labels
                .iter()
                .any(|pattern| glob_match_label(pattern, &site.id))
    }
}

pub(crate) fn apply_site_groups(sites: &mut [crate::sites::SiteRecord]) {
    let Some(Some(repo)) = REPO_CONFIG.get() else {
        return;
    };
    for site in sites {
        repo.apply_groups(site);
    }
}

pub(crate) fn provenance_json() -> Option<JsonValue> {
    let state = STATE.get()?;
    if state.path.is_none() && state.groups.is_empty() && state.applied.is_empty() {
        return None;
    }
    let mut object = serde_json::Map::new();
    object.insert("enabled".to_string(), json!(true));
    if let Some(path) = &state.path {
        object.insert("path".to_string(), json!(path.display().to_string()));
    }
    if !state.groups.is_empty() {
        object.insert("groups".to_string(), json!(state.groups));
    }
    if !state.applied.is_empty() {
        object.insert("applied".to_string(), json!(state.applied));
    }
    Some(JsonValue::Object(object))
}

pub(crate) fn scrub_child_config_env(command: &mut std::process::Command, verb: &str) {
    for name in env_var_names_for_verb(verb) {
        command.env_remove(name);
    }
}

fn install_state(state: ConfigState) {
    let _ = STATE.set(state);
}

fn validate_replay_exclusion(verb: &str, repo: &RepoConfig) -> Result<(), CliError> {
    if verb == "replay" {
        let _ = repo.defaults_for("replay")?;
    }
    Ok(())
}

fn explicit_flags(verb: &str, arguments: &[OsString]) -> BTreeSet<&'static str> {
    let mut explicit = BTreeSet::new();
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == "--" {
            break;
        }
        let Some(text) = arguments[index].to_str() else {
            index += 1;
            continue;
        };
        let name = cli::split_name(text);
        if let Some(flag) = help::configurable_flag_by_cli_name(verb, name) {
            explicit.insert(flag.name);
            if name == text && matches!(flag.value, Value::Required(..)) {
                index += 1;
            }
        }
        index += 1;
    }
    explicit
}

fn env_default_is_present(flag: &'static Flag) -> bool {
    std::env::var_os(env_var_for_key(help::config_key(flag))).is_some()
}

fn env_default(flag: &'static Flag) -> Result<Option<ResolvedDefault>, CliError> {
    let env = env_var_for_key(help::config_key(flag));
    let Some(raw) = std::env::var_os(&env) else {
        return Ok(None);
    };
    let raw = raw.into_string().map_err(|_| {
        CliError::usage(format!(
            "{env} contains non-UTF-8; config environment defaults must be UTF-8"
        ))
    })?;
    if let Some(configured) = configured_from_env(flag, &env, &raw)? {
        Ok(Some(ResolvedDefault {
            flag,
            tokens: configured.tokens,
            applied: AppliedDefault {
                key: help::config_key(flag).to_string(),
                flag: flag.name.to_string(),
                source: "env",
                value: configured.display,
                env: Some(env),
                path: None,
                line: None,
                column: None,
            },
        }))
    } else {
        Ok(None)
    }
}

fn configured_from_env(
    flag: &'static Flag,
    env: &str,
    raw: &str,
) -> Result<Option<ConfiguredValue>, CliError> {
    match flag.value {
        Value::None => match parse_env_bool(raw) {
            Some(true) => Ok(Some(ConfiguredValue {
                tokens: vec![OsString::from(flag.name)],
                display: Some("true".to_string()),
            })),
            Some(false) => Ok(None),
            None => Err(CliError::usage(format!(
                "{env} for {} must be a boolean (true/false/1/0); got {raw:?}",
                flag.name
            ))),
        },
        Value::Optional(_, kind) => match parse_env_bool(raw) {
            Some(true) => Ok(Some(ConfiguredValue {
                tokens: vec![OsString::from(flag.name)],
                display: Some("true".to_string()),
            })),
            Some(false) => Ok(None),
            None => {
                validate_kind(flag.name, kind, raw).map_err(|error| {
                    CliError::usage(format!(
                        "{env} for {} does not satisfy {}: {error}",
                        flag.name,
                        kind_tag(kind)
                    ))
                })?;
                Ok(Some(ConfiguredValue {
                    tokens: vec![OsString::from(format!("{}={raw}", flag.name))],
                    display: Some(raw.to_string()),
                }))
            }
        },
        Value::Required(_, kind) => {
            validate_kind(flag.name, kind, raw).map_err(|error| {
                CliError::usage(format!(
                    "{env} for {} does not satisfy {}: {error}",
                    flag.name,
                    kind_tag(kind)
                ))
            })?;
            Ok(Some(ConfiguredValue {
                tokens: vec![OsString::from(flag.name), OsString::from(raw)],
                display: Some(raw.to_string()),
            }))
        }
    }
}

fn configured_from_toml(
    path: &Path,
    text: &str,
    key_path: &[&str],
    flag: &'static Flag,
    value: &TomlValue,
) -> Result<Option<ConfiguredValue>, CliError> {
    match flag.value {
        Value::None => match value.as_bool() {
            Some(true) => Ok(Some(ConfiguredValue {
                tokens: vec![OsString::from(flag.name)],
                display: Some("true".to_string()),
            })),
            Some(false) => Ok(None),
            None => Err(config_error(
                path,
                text,
                key_path,
                format!(
                    "Patina config {} for {} must be a boolean",
                    key_path.join("."),
                    flag.name
                ),
            )),
        },
        Value::Optional(_, kind) => match value.as_bool() {
            Some(true) => Ok(Some(ConfiguredValue {
                tokens: vec![OsString::from(flag.name)],
                display: Some("true".to_string()),
            })),
            Some(false) => Ok(None),
            None => {
                let rendered = render_toml_scalar(path, text, key_path, value)?;
                validate_kind(flag.name, kind, &rendered).map_err(|error| {
                    config_error(
                        path,
                        text,
                        key_path,
                        format!(
                            "Patina config {} for {} does not satisfy {}: {error}",
                            key_path.join("."),
                            flag.name,
                            kind_tag(kind)
                        ),
                    )
                })?;
                Ok(Some(ConfiguredValue {
                    tokens: vec![OsString::from(format!("{}={rendered}", flag.name))],
                    display: Some(rendered),
                }))
            }
        },
        Value::Required(_, kind) => {
            let rendered = render_toml_scalar(path, text, key_path, value)?;
            validate_kind(flag.name, kind, &rendered).map_err(|error| {
                config_error(
                    path,
                    text,
                    key_path,
                    format!(
                        "Patina config {} for {} does not satisfy {}: {error}",
                        key_path.join("."),
                        flag.name,
                        kind_tag(kind)
                    ),
                )
            })?;
            Ok(Some(ConfiguredValue {
                tokens: vec![OsString::from(flag.name), OsString::from(rendered.clone())],
                display: Some(rendered),
            }))
        }
    }
}

fn render_toml_scalar(
    path: &Path,
    text: &str,
    key_path: &[&str],
    value: &TomlValue,
) -> Result<String, CliError> {
    if let Some(s) = value.as_str() {
        return Ok(s.to_string());
    }
    if let Some(i) = value.as_integer() {
        if i < 0 {
            return Err(config_error(
                path,
                text,
                key_path,
                format!("Patina config {} must not be negative", key_path.join(".")),
            ));
        }
        return Ok(i.to_string());
    }
    if let Some(f) = value.as_float() {
        return Ok(f.to_string());
    }
    Err(config_error(
        path,
        text,
        key_path,
        format!(
            "Patina config {} must be a string or integer scalar",
            key_path.join(".")
        ),
    ))
}

/// Validate a config/env-supplied value against the flag's declared grammar.
/// This is the SAME check the flag parser runs — a project default and a typed
/// flag cannot disagree about what a value means.
fn validate_kind(name: &str, kind: Kind, value: &str) -> Result<(), CliError> {
    crate::values::validate(kind, name, value).map_err(CliError::usage)
}

fn parse_env_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn env_var_for_key(key: &str) -> String {
    format!("PATINA_{}", key.replace('-', "_").to_ascii_uppercase())
}

pub(crate) fn env_var_names_for_verb(verb: &str) -> Vec<String> {
    help::configurable_flags(verb)
        .into_iter()
        .map(|flag| env_var_for_key(help::config_key(flag)))
        .collect()
}

fn kind_tag(kind: Kind) -> &'static str {
    match kind {
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

fn config_error(path: &Path, text: &str, key_path: &[&str], message: String) -> CliError {
    let position = find_key_position(text, key_path)
        .map(|(line, col)| format!("{}:{line}:{col}", path.display()))
        .unwrap_or_else(|| path.display().to_string());
    CliError(format!("{message} at {position}"))
}

fn find_key_position(text: &str, key_path: &[&str]) -> Option<(usize, usize)> {
    if key_path.is_empty() {
        return Some((1, 1));
    }
    let key = key_path.last()?;
    let table_path = &key_path[..key_path.len().saturating_sub(1)];
    let mut active_table: Vec<String> = Vec::new();
    for (line_index, raw_line) in text.lines().enumerate() {
        let without_comment = strip_comment(raw_line).trim();
        if without_comment.is_empty() {
            continue;
        }
        if let Some(header) = without_comment
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        {
            active_table = header
                .split('.')
                .map(|part| unquote_key(part.trim()))
                .collect();
            if key_path
                == active_table
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .as_slice()
            {
                let col = raw_line.find('[').map(|value| value + 1).unwrap_or(1);
                return Some((line_index + 1, col));
            }
            continue;
        }
        if active_table
            .iter()
            .map(String::as_str)
            .eq(table_path.iter().copied())
        {
            if let Some((left, _)) = without_comment.split_once('=') {
                if unquote_key(left.trim()) == *key {
                    let col = raw_line
                        .find(left.trim())
                        .map(|value| value + 1)
                        .unwrap_or(1);
                    return Some((line_index + 1, col));
                }
            }
        }
    }
    None
}

fn strip_comment(line: &str) -> &str {
    let mut in_string = false;
    let mut escaped = false;
    for (index, ch) in line.char_indices() {
        match ch {
            '\\' if in_string && !escaped => escaped = true,
            '"' if !escaped => in_string = !in_string,
            '#' if !in_string => return &line[..index],
            _ => escaped = false,
        }
    }
    line
}

fn unquote_key(value: &str) -> String {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value)
        .to_string()
}

fn line_col(text: &str, byte: usize) -> Option<(usize, usize)> {
    let mut line = 1;
    let mut col = 1;
    for (index, ch) in text.char_indices() {
        if index == byte {
            return Some((line, col));
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (byte == text.len()).then_some((line, col))
}

fn glob_match_path(pattern: &str, text: &str) -> bool {
    glob_match(pattern, &text.replace('\\', "/"), Some('/'))
}

fn glob_match_label(pattern: &str, text: &str) -> bool {
    glob_match(pattern, text, None)
}

fn glob_match(pattern: &str, text: &str, separator: Option<char>) -> bool {
    fn inner(
        pattern: &[char],
        text: &[char],
        separator: Option<char>,
        memo: &mut BTreeMap<(usize, usize), bool>,
        pi: usize,
        ti: usize,
    ) -> bool {
        if let Some(value) = memo.get(&(pi, ti)) {
            return *value;
        }
        let result = if pi == pattern.len() {
            ti == text.len()
        } else if pattern[pi] == '*' {
            let double = pi + 1 < pattern.len() && pattern[pi + 1] == '*';
            let next_pi = if double { pi + 2 } else { pi + 1 };
            inner(pattern, text, separator, memo, next_pi, ti)
                || (ti < text.len()
                    && (double || separator.is_none_or(|sep| text[ti] != sep))
                    && inner(pattern, text, separator, memo, pi, ti + 1))
        } else if pattern[pi] == '?' {
            ti < text.len()
                && separator.is_none_or(|sep| text[ti] != sep)
                && inner(pattern, text, separator, memo, pi + 1, ti + 1)
        } else {
            ti < text.len()
                && pattern[pi] == text[ti]
                && inner(pattern, text, separator, memo, pi + 1, ti + 1)
        };
        memo.insert((pi, ti), result);
        result
    }

    let pattern = pattern.chars().collect::<Vec<_>>();
    let text = text.chars().collect::<Vec<_>>();
    inner(&pattern, &text, separator, &mut BTreeMap::new(), 0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<RepoConfig, CliError> {
        parse_config_text(
            PathBuf::from("/tmp/repo/.patina/config.toml"),
            text.to_string(),
        )
    }

    #[test]
    fn config_rejects_unknown_group_key_with_position() {
        let error = parse("[groups.durability]\npathz = [\"src/**\"]\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("pathz"), "{error}");
        assert!(error.contains("config.toml:2:1"), "{error}");
    }

    #[test]
    fn defaults_reject_unknown_flag_key_with_position() {
        let error = parse("[defaults.run]\nseeed = 1\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("seeed"), "{error}");
        assert!(error.contains("config.toml:2:1"), "{error}");
    }

    #[test]
    fn defaults_reject_bad_value_grammar_with_position() {
        let error = parse("[defaults.run]\nseed = \"abc\"\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("seed"), "{error}");
        assert!(error.contains("u64"), "{error}");
        assert!(error.contains("config.toml:2:1"), "{error}");
    }

    #[test]
    fn replay_defaults_are_refused() {
        let repo = parse("[defaults.replay]\ntimeline = \"other\"\n").unwrap();
        let error = repo.defaults_for("replay").unwrap_err().to_string();
        assert!(error.contains("replay"), "{error}");
        assert!(error.contains("trace-authoritative"), "{error}");
    }

    #[test]
    fn group_globs_match_paths_and_labels() {
        assert!(glob_match_path("crates/wal/**", "crates/wal/src/lib.rs"));
        assert!(!glob_match_path("crates/wal/*", "crates/wal/src/lib.rs"));
        assert!(glob_match_label("wal-*", "wal-flush"));
        assert!(!glob_match_label("wal-*", "fsync"));
    }
}
