//! `cargo patina sites` — static inventory of assertion/oracle sites.
//!
//! Wave 4 joins a syn static inventory with runtime `PATINA_SDK_REPORT` rows
//! supplied through `--exercised FILE`, or with a campaign `<out>/sites.json`
//! store supplied through `--exercised OUTDIR`. `.patina/config.toml` groups are
//! applied after cache reads so grouping changes never poison the SCA cache;
//! link-time static site enumeration is a later wave.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use proc_macro2::{Delimiter, Span, TokenStream, TokenTree};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::rollup::{RollupLeaf, build_rollup};
use crate::sdk_report::{ExercisedSite, ExercisedSource, parse_exercised_file};
use crate::{CliError, output};

pub(crate) const SITES_SCHEMA: &str = "patina.sites/v1";
const CACHE_SCHEMA: &str = "patina.sites-cache/v1";
const RECOGNIZER_TABLE_VERSION: &str = "sites-sca-v1";

const RUNTIME_ORDER: &[&str] = &["driven", "observed", "invisible"];
const KIND_ORDER: &[&str] = &[
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
];

const SDK_SITE_MACROS: &[&str] = &[
    "buggify",
    "buggify_with_prob",
    "buggify_delay",
    "buggify_knob",
    "always",
    "sometimes",
    "reachable",
];

const RECOGNIZER_NAMES: &[&str] = &[
    "buggify",
    "buggify_with_prob",
    "buggify_delay",
    "buggify_knob",
    "always",
    "sometimes",
    "reachable",
    "assert",
    "assert_eq",
    "assert_ne",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
    "unreachable",
    "proptest",
    "prop_assert",
    "prop_assert_eq",
    "prop_assert_ne",
    "quickcheck",
    "#[quickcheck]",
    "antithesis_sdk::*",
    "assert_always",
    "assert_always_or_unreachable",
    "assert_sometimes",
    "assert_reachable",
    "assert_unreachable",
];

/// Parsed `sites` invocation.
pub(crate) enum SitesInvocation {
    Selftest,
    Scan(SitesOptions),
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SitesOptions {
    crate_filter: Option<String>,
    module_filter: Option<String>,
    group_filter: Option<String>,
    site_filter: Option<String>,
    all: bool,
    exercised: Option<PathBuf>,
    kind_filter: Option<String>,
    runtime_filter: Option<String>,
    no_cache: bool,
}

impl SitesOptions {
    fn scoped(&self) -> bool {
        self.all
            || self.crate_filter.is_some()
            || self.module_filter.is_some()
            || self.group_filter.is_some()
            || self.site_filter.is_some()
            || self.kind_filter.is_some()
            || self.runtime_filter.is_some()
    }
}

/// Parse `sites [--crate NAME] [--module PATH] [--group NAME] [--site LABEL]
/// [--all] [--exercised FILE] [--kind KIND]
/// [--runtime driven|observed|invisible] [--no-cache] [--selftest]`.
pub(crate) fn parse(arguments: Vec<OsString>) -> Result<SitesInvocation, CliError> {
    let mut options = SitesOptions::default();
    let mut selftest = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--" {
            return Err(CliError::usage(
                "sites takes no guest arguments or `--` separator",
            ));
        }
        let Some(text) = argument.to_str() else {
            return Err(CliError::usage("sites options must be valid UTF-8"));
        };
        if !text.starts_with('-') {
            return Err(CliError::usage(format!(
                "sites takes no positional arguments; unexpected {}",
                Path::new(text).display()
            )));
        }
        let opt = crate::split_opt(text);
        match opt.name {
            "--crate" => {
                let value = crate::required_value(opt, &arguments, &mut index)?.to_string();
                crate::set_once(&mut options.crate_filter, value, "--crate")?;
            }
            "--module" => {
                let value = crate::required_value(opt, &arguments, &mut index)?.to_string();
                crate::set_once(&mut options.module_filter, value, "--module")?;
            }
            "--group" => {
                let value = crate::required_value(opt, &arguments, &mut index)?.to_string();
                crate::set_once(&mut options.group_filter, value, "--group")?;
            }
            "--site" => {
                let value = crate::required_value(opt, &arguments, &mut index)?.to_string();
                crate::set_once(&mut options.site_filter, value, "--site")?;
            }
            "--exercised" => {
                let value = crate::required_os_value(opt, &arguments, &mut index)?;
                crate::set_once(&mut options.exercised, PathBuf::from(value), "--exercised")?;
            }
            "--kind" => {
                let value = crate::required_value(opt, &arguments, &mut index)?;
                if !KIND_ORDER.contains(&value) {
                    return Err(CliError::usage(format!(
                        "--kind must be one of {}; got {value:?}",
                        KIND_ORDER.join("|")
                    )));
                }
                crate::set_once(&mut options.kind_filter, value.to_string(), "--kind")?;
            }
            "--runtime" => {
                let value = crate::required_value(opt, &arguments, &mut index)?;
                if !RUNTIME_ORDER.contains(&value) {
                    return Err(CliError::usage(format!(
                        "--runtime must be driven, observed, or invisible; got {value:?}"
                    )));
                }
                crate::set_once(&mut options.runtime_filter, value.to_string(), "--runtime")?;
            }
            "--all" => {
                crate::reject_inline(opt)?;
                options.all = true;
            }
            "--no-cache" => {
                crate::reject_inline(opt)?;
                options.no_cache = true;
            }
            "--selftest" => {
                crate::reject_inline(opt)?;
                selftest = true;
            }
            other => {
                return Err(CliError::usage(format!(
                    "unsupported option {other:?} for `sites`"
                )));
            }
        }
        index += 1;
    }
    if selftest {
        if options != SitesOptions::default() {
            return Err(CliError::usage(
                "sites --selftest does not accept report filters",
            ));
        }
        Ok(SitesInvocation::Selftest)
    } else {
        Ok(SitesInvocation::Scan(options))
    }
}

impl PartialEq for SitesOptions {
    fn eq(&self, other: &Self) -> bool {
        self.crate_filter == other.crate_filter
            && self.module_filter == other.module_filter
            && self.group_filter == other.group_filter
            && self.site_filter == other.site_filter
            && self.all == other.all
            && self.exercised == other.exercised
            && self.kind_filter == other.kind_filter
            && self.runtime_filter == other.runtime_filter
            && self.no_cache == other.no_cache
    }
}

impl Eq for SitesOptions {}

pub(crate) fn execute(invocation: SitesInvocation) -> Result<i32, CliError> {
    match invocation {
        SitesInvocation::Selftest => run_selftest(),
        SitesInvocation::Scan(options) => run_scan(options),
    }
}

fn run_scan(options: SitesOptions) -> Result<i32, CliError> {
    let mut scan = scan_current_workspace(!options.no_cache)?;
    crate::config::apply_site_groups(&mut scan.sites);
    let exercised = options
        .exercised
        .as_deref()
        .map(parse_exercised_file)
        .transpose()?;
    let report = build_report(&scan, &options, exercised.as_ref());
    if output::options().is_json() {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| CliError(format!("failed to encode sites JSON: {error}")))?
        );
    } else {
        print_human(&report);
    }
    Ok(0)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SiteRecord {
    pub(crate) id: String,
    pub(crate) kind: String,
    pub(crate) runtime: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) label: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) label_dynamic: bool,
    pub(crate) file: String,
    pub(crate) line: usize,
    #[serde(rename = "crate")]
    pub(crate) crate_name: String,
    pub(crate) module: String,
    pub(crate) context: String,
    pub(crate) groups: Vec<String>,
    pub(crate) macro_path: String,
}

impl SiteRecord {
    fn anonymous_id(file: &str, line: usize, column: usize, kind: &str) -> String {
        format!("{file}:{line}:{column}#{kind}")
    }
}

impl RollupLeaf for SiteRecord {
    fn crate_name(&self) -> &str {
        &self.crate_name
    }

    fn module(&self) -> &str {
        &self.module
    }

    fn groups(&self) -> &[String] {
        &self.groups
    }

    fn bucket(&self) -> &str {
        &self.runtime
    }
}

#[derive(Clone, Debug)]
struct ScanPackage {
    name: String,
    root: PathBuf,
    targets: Vec<TargetHint>,
}

#[derive(Clone, Debug)]
struct TargetHint {
    src_path: PathBuf,
    name: String,
    context: ContextKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContextKind {
    Src,
    Test,
    Example,
    Bench,
}

impl ContextKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Src => "src",
            Self::Test => "test",
            Self::Example => "example",
            Self::Bench => "bench",
        }
    }
}

#[derive(Clone, Debug)]
struct SourceFile {
    path: PathBuf,
    rel_path: String,
    crate_name: String,
    module: String,
    context: ContextKind,
}

#[derive(Clone, Debug)]
struct StaticScan {
    workspace_root: PathBuf,
    sites: Vec<SiteRecord>,
    files_scanned: usize,
    files_unparsed: usize,
    unparsed: Vec<UnparsedFile>,
    cache_state: CacheState,
}

#[derive(Clone, Debug, Serialize)]
struct UnparsedFile {
    file: String,
    error: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CacheState {
    Hit,
    Cold,
}

impl CacheState {
    fn as_str(self) -> &'static str {
        match self {
            CacheState::Hit => "hit",
            CacheState::Cold => "cold",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SitesCache {
    schema: String,
    recognizer_version: String,
    files: BTreeMap<String, CachedFile>,
}

#[derive(Clone, Serialize, Deserialize)]
struct CachedFile {
    sha256: String,
    sites: Vec<SiteRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn scan_current_workspace(use_cache: bool) -> Result<StaticScan, CliError> {
    let (workspace_root, packages) = workspace_packages()?;
    scan_packages(workspace_root, packages, use_cache)
}

fn workspace_packages() -> Result<(PathBuf, Vec<ScanPackage>), CliError> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let output = Command::new(cargo)
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| CliError(format!("failed to run cargo metadata: {error}")))?;
    if !output.status.success() {
        return Err(CliError(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let metadata: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| CliError(format!("cargo metadata returned invalid JSON: {error}")))?;
    let workspace_root = metadata
        .get("workspace_root")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| CliError("cargo metadata omitted workspace_root".into()))?;
    let members: BTreeSet<String> = metadata
        .get("workspace_members")
        .and_then(Value::as_array)
        .ok_or_else(|| CliError("cargo metadata omitted workspace_members".into()))?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    let mut packages = Vec::new();
    for package in metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| CliError("cargo metadata omitted packages".into()))?
    {
        let id = package
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| CliError("cargo metadata package omitted id".into()))?;
        if !members.contains(id) {
            continue;
        }
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| CliError(format!("cargo metadata package {id} omitted name")))?
            .to_string();
        let manifest = package
            .get("manifest_path")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .ok_or_else(|| {
                CliError(format!(
                    "cargo metadata package {name} omitted manifest_path"
                ))
            })?;
        let root = manifest.parent().map(Path::to_path_buf).ok_or_else(|| {
            CliError(format!(
                "manifest path has no parent for package {name}: {}",
                manifest.display()
            ))
        })?;
        let mut targets = Vec::new();
        if let Some(array) = package.get("targets").and_then(Value::as_array) {
            for target in array {
                let Some(src_path) = target.get("src_path").and_then(Value::as_str) else {
                    continue;
                };
                let Some(target_name) = target.get("name").and_then(Value::as_str) else {
                    continue;
                };
                let Some(kinds) = target.get("kind").and_then(Value::as_array) else {
                    continue;
                };
                let context = if kinds.iter().any(|kind| kind.as_str() == Some("test")) {
                    ContextKind::Test
                } else if kinds.iter().any(|kind| kind.as_str() == Some("example")) {
                    ContextKind::Example
                } else if kinds.iter().any(|kind| kind.as_str() == Some("bench")) {
                    ContextKind::Bench
                } else if kinds
                    .iter()
                    .any(|kind| matches!(kind.as_str(), Some("lib" | "bin" | "proc-macro")))
                {
                    ContextKind::Src
                } else {
                    continue;
                };
                targets.push(TargetHint {
                    src_path: PathBuf::from(src_path),
                    name: target_name.to_string(),
                    context,
                });
            }
        }
        packages.push(ScanPackage {
            name,
            root,
            targets,
        });
    }
    packages.sort_by(|left, right| left.name.cmp(&right.name));
    Ok((workspace_root, packages))
}

fn scan_packages(
    workspace_root: PathBuf,
    packages: Vec<ScanPackage>,
    use_cache: bool,
) -> Result<StaticScan, CliError> {
    let mut files = Vec::new();
    let mut seen = BTreeSet::new();
    for package in &packages {
        collect_package_files(&workspace_root, package, &mut seen, &mut files)?;
    }
    files.sort_by(|left, right| left.rel_path.cmp(&right.rel_path));

    let cache_path = workspace_root.join(".patina/out/sites-cache.json");
    let mut cache = if use_cache {
        read_cache(&cache_path).unwrap_or_else(empty_cache)
    } else {
        empty_cache()
    };
    let mut all_cache_hits = use_cache && !files.is_empty();
    let mut updated_files = BTreeMap::new();
    let mut sites = Vec::new();
    let mut unparsed = Vec::new();

    for file in &files {
        let bytes = fs::read(&file.path).map_err(|error| {
            CliError(format!(
                "failed to read Rust source {}: {error}",
                file.path.display()
            ))
        })?;
        let sha = hex_digest(&bytes);
        let cached = use_cache
            .then(|| cache.files.remove(&file.rel_path))
            .flatten()
            .filter(|entry| entry.sha256 == sha);
        let entry = if let Some(entry) = cached {
            entry
        } else {
            all_cache_hits = false;
            scan_file(file, &bytes)
        };
        if let Some(error) = &entry.error {
            unparsed.push(UnparsedFile {
                file: file.rel_path.clone(),
                error: error.clone(),
            });
        }
        sites.extend(entry.sites.clone());
        updated_files.insert(file.rel_path.clone(), entry);
    }

    if use_cache {
        cache.files = updated_files;
        write_cache(&cache_path, &cache)?;
    }

    sites.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then(left.file.cmp(&right.file))
            .then(left.line.cmp(&right.line))
            .then(left.id.cmp(&right.id))
    });

    Ok(StaticScan {
        workspace_root,
        sites,
        files_scanned: files.len(),
        files_unparsed: unparsed.len(),
        unparsed,
        cache_state: if use_cache && all_cache_hits {
            CacheState::Hit
        } else {
            CacheState::Cold
        },
    })
}

fn empty_cache() -> SitesCache {
    SitesCache {
        schema: CACHE_SCHEMA.to_string(),
        recognizer_version: RECOGNIZER_TABLE_VERSION.to_string(),
        files: BTreeMap::new(),
    }
}

fn read_cache(path: &Path) -> Option<SitesCache> {
    let bytes = fs::read(path).ok()?;
    let cache: SitesCache = serde_json::from_slice(&bytes).ok()?;
    if cache.schema == CACHE_SCHEMA && cache.recognizer_version == RECOGNIZER_TABLE_VERSION {
        Some(cache)
    } else {
        None
    }
}

fn write_cache(path: &Path, cache: &SitesCache) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            CliError(format!(
                "failed to create sites cache dir {}: {error}",
                parent.display()
            ))
        })?;
        ensure_patina_gitignore(parent.parent().unwrap_or(parent))?;
    }
    let json = serde_json::to_vec_pretty(cache)
        .map_err(|error| CliError(format!("failed to encode sites cache: {error}")))?;
    fs::write(path, json).map_err(|error| {
        CliError(format!(
            "failed to write sites cache {}: {error}",
            path.display()
        ))
    })
}

fn ensure_patina_gitignore(patina_dir: &Path) -> Result<(), CliError> {
    let path = patina_dir.join(".gitignore");
    if path.exists() {
        let text = fs::read_to_string(&path).map_err(|error| {
            CliError(format!(
                "failed to read {} before updating generated-output ignore: {error}",
                path.display()
            ))
        })?;
        if text.lines().any(|line| line.trim() == "/out/") {
            return Ok(());
        }
        let mut updated = text;
        if !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str("/out/\n");
        fs::write(&path, updated).map_err(|error| {
            CliError(format!(
                "failed to update generated-output ignore {}: {error}",
                path.display()
            ))
        })?;
    } else {
        fs::write(&path, "/out/\n").map_err(|error| {
            CliError(format!(
                "failed to write generated-output ignore {}: {error}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

fn collect_package_files(
    workspace_root: &Path,
    package: &ScanPackage,
    seen: &mut BTreeSet<PathBuf>,
    out: &mut Vec<SourceFile>,
) -> Result<(), CliError> {
    let mut paths = Vec::new();
    collect_rs_paths(&package.root, &mut paths)?;
    paths.sort();
    for path in paths {
        let canonical_key = path.clone();
        if !seen.insert(canonical_key) {
            continue;
        }
        let rel_path = display_path(workspace_root, &path);
        let (module, context) = infer_module_context(package, &path);
        out.push(SourceFile {
            path,
            rel_path,
            crate_name: package.name.clone(),
            module,
            context,
        });
    }
    Ok(())
}

fn collect_rs_paths(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), CliError> {
    let entries = fs::read_dir(dir).map_err(|error| {
        CliError(format!(
            "failed to read directory {}: {error}",
            dir.display()
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError(format!(
                "failed to read directory entry in {}: {error}",
                dir.display()
            ))
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| {
            CliError(format!(
                "failed to stat directory entry {}: {error}",
                path.display()
            ))
        })?;
        if file_type.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if matches!(name.as_ref(), "target" | ".git" | ".jj" | ".patina") {
                continue;
            }
            collect_rs_paths(&path, out)?;
        } else if file_type.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("rs")
        {
            out.push(path);
        }
    }
    Ok(())
}

fn infer_module_context(package: &ScanPackage, path: &Path) -> (String, ContextKind) {
    if let Some(target) = package
        .targets
        .iter()
        .find(|target| target.src_path == path)
    {
        return (rust_ident(&target.name), target.context);
    }
    let rel = path.strip_prefix(&package.root).unwrap_or(path);
    let comps = rel
        .components()
        .filter_map(component_str)
        .collect::<Vec<_>>();
    let crate_ident = rust_ident(&package.name);
    if comps.first().copied() == Some("tests") {
        return (path_module(&comps[1..], None), ContextKind::Test);
    }
    if comps.first().copied() == Some("examples") {
        return (path_module(&comps[1..], None), ContextKind::Example);
    }
    if comps.first().copied() == Some("benches") {
        return (path_module(&comps[1..], None), ContextKind::Bench);
    }
    if comps.first().copied() == Some("src") {
        return (
            path_module(&comps[1..], Some(&crate_ident)),
            ContextKind::Src,
        );
    }
    (path_module(&comps, Some(&crate_ident)), ContextKind::Src)
}

fn component_str(component: Component<'_>) -> Option<&str> {
    match component {
        Component::Normal(value) => value.to_str(),
        _ => None,
    }
}

fn path_module(comps: &[&str], root: Option<&str>) -> String {
    let mut pieces = Vec::new();
    if let Some(root) = root {
        pieces.push(root.to_string());
    }
    for (index, comp) in comps.iter().enumerate() {
        if index + 1 == comps.len() {
            let stem = comp.strip_suffix(".rs").unwrap_or(comp);
            if matches!(stem, "lib" | "main" | "mod") {
                continue;
            }
            pieces.push(rust_ident(stem));
        } else if *comp != "src" {
            pieces.push(rust_ident(comp));
        }
    }
    if pieces.is_empty() {
        "crate".to_string()
    } else {
        pieces.join("::")
    }
}

fn rust_ident(name: &str) -> String {
    let mut out = String::new();
    for (index, ch) in name.chars().enumerate() {
        if ch == '-' || ch == '.' {
            out.push('_');
        } else if (index == 0 && (ch == '_' || ch.is_ascii_alphabetic()))
            || (index > 0 && (ch == '_' || ch.is_ascii_alphanumeric()))
        {
            out.push(ch);
        } else if index == 0 && ch.is_ascii_digit() {
            out.push('_');
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "crate".to_string()
    } else {
        out
    }
}

fn scan_file(file: &SourceFile, bytes: &[u8]) -> CachedFile {
    let text = String::from_utf8_lossy(bytes);
    match syn::parse_file(&text) {
        Ok(parsed) => {
            let mut scanner = FileScanner::new(file);
            scanner.visit_file(&parsed);
            CachedFile {
                sha256: hex_digest(bytes),
                sites: scanner.sites,
                error: None,
            }
        }
        Err(error) => CachedFile {
            sha256: hex_digest(bytes),
            sites: Vec::new(),
            error: Some(error.to_string()),
        },
    }
}

struct FileScanner<'a> {
    file: &'a SourceFile,
    module_stack: Vec<String>,
    test_depth: usize,
    imported_macros: BTreeMap<String, String>,
    sites: Vec<SiteRecord>,
}

impl<'a> FileScanner<'a> {
    fn new(file: &'a SourceFile) -> Self {
        Self {
            file,
            module_stack: Vec::new(),
            test_depth: 0,
            imported_macros: BTreeMap::new(),
            sites: Vec::new(),
        }
    }

    fn current_module(&self) -> String {
        let mut module = self.file.module.clone();
        for segment in &self.module_stack {
            module.push_str("::");
            module.push_str(segment);
        }
        module
    }

    fn current_context(&self) -> String {
        if self.test_depth > 0 {
            "test".to_string()
        } else {
            self.file.context.as_str().to_string()
        }
    }

    fn push_site(
        &mut self,
        kind: &str,
        runtime: &str,
        label: Option<String>,
        label_dynamic: bool,
        macro_path: String,
        span: Span,
    ) {
        let start = span.start();
        let line = start.line;
        let column = start.column + 1;
        let id = label
            .clone()
            .unwrap_or_else(|| SiteRecord::anonymous_id(&self.file.rel_path, line, column, kind));
        self.sites.push(SiteRecord {
            id,
            kind: kind.to_string(),
            runtime: runtime.to_string(),
            label,
            label_dynamic,
            file: self.file.rel_path.clone(),
            line,
            crate_name: self.file.crate_name.clone(),
            module: self.current_module(),
            context: self.current_context(),
            groups: Vec::new(),
            macro_path,
        });
    }
}

impl<'ast> Visit<'ast> for FileScanner<'_> {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        collect_use_aliases(&item.tree, Vec::new(), &mut self.imported_macros);
        visit::visit_item_use(self, item);
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        let was_test = has_cfg_test(&item.attrs);
        if was_test {
            self.test_depth += 1;
        }
        if item.content.is_some() {
            self.module_stack.push(item.ident.to_string());
            visit::visit_item_mod(self, item);
            self.module_stack.pop();
        }
        if was_test {
            self.test_depth -= 1;
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if has_quickcheck_attr(&item.attrs) {
            self.push_site(
                "quickcheck",
                "invisible",
                Some(item.sig.ident.to_string()),
                false,
                "#[quickcheck]".to_string(),
                item.sig.ident.span(),
            );
        }
        visit::visit_item_fn(self, item);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let macro_path = path_to_string(&mac.path);
        let final_segment = mac
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();
        let canonical = self
            .imported_macros
            .get(&final_segment)
            .cloned()
            .unwrap_or_else(|| final_segment.clone());
        if let Some(site) = classify_macro(&macro_path, &canonical, &mac.tokens) {
            match site {
                MacroSite::Single {
                    kind,
                    runtime,
                    label,
                    label_dynamic,
                } => self.push_site(
                    kind,
                    runtime,
                    label,
                    label_dynamic,
                    macro_path,
                    mac.path.span(),
                ),
                MacroSite::Proptest(functions) => {
                    if functions.is_empty() {
                        self.push_site(
                            "proptest",
                            "invisible",
                            None,
                            false,
                            macro_path,
                            mac.path.span(),
                        );
                    } else {
                        for (name, span) in functions {
                            self.push_site(
                                "proptest",
                                "invisible",
                                Some(name),
                                false,
                                macro_path.clone(),
                                span,
                            );
                        }
                    }
                }
            }
        }
        visit::visit_macro(self, mac);
    }
}

fn collect_use_aliases(
    tree: &syn::UseTree,
    prefix: Vec<String>,
    aliases: &mut BTreeMap<String, String>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            let mut prefix = prefix;
            prefix.push(path.ident.to_string());
            collect_use_aliases(&path.tree, prefix, aliases);
        }
        syn::UseTree::Name(name) => {
            if recognized_import_path(&prefix, &name.ident.to_string()) {
                let ident = name.ident.to_string();
                aliases.insert(ident.clone(), ident);
            }
        }
        syn::UseTree::Rename(rename) => {
            let original = rename.ident.to_string();
            if recognized_import_path(&prefix, &original) {
                aliases.insert(rename.rename.to_string(), original);
            }
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_use_aliases(item, prefix.clone(), aliases);
            }
        }
        syn::UseTree::Glob(_) => {}
    }
}

fn recognized_import_path(prefix: &[String], ident: &str) -> bool {
    SDK_SITE_MACROS.contains(&ident)
        || matches!(
            ident,
            "assert_always"
                | "assert_always_or_unreachable"
                | "assert_sometimes"
                | "assert_reachable"
                | "assert_unreachable"
        )
        || prefix.first().is_some_and(|head| head == "antithesis_sdk")
}

fn has_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr.meta.require_list().ok().is_some_and(|list| {
                list.tokens
                    .to_string()
                    .split_whitespace()
                    .any(|token| token == "test")
            })
    })
}

fn has_quickcheck_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "quickcheck")
    })
}

enum MacroSite {
    Single {
        kind: &'static str,
        runtime: &'static str,
        label: Option<String>,
        label_dynamic: bool,
    },
    Proptest(Vec<(String, Span)>),
}

fn classify_macro(macro_path: &str, canonical: &str, tokens: &TokenStream) -> Option<MacroSite> {
    let args = split_args(tokens);
    match canonical {
        "buggify" | "buggify_with_prob" => sdk_label_site("fault", "driven", 0, &args),
        "buggify_delay" => sdk_label_site("delay", "driven", 0, &args),
        "buggify_knob" => sdk_label_site("knob", "driven", 0, &args),
        "always" => sdk_label_site("always", "observed", 1, &args),
        "sometimes" => sdk_label_site("sometimes", "observed", 1, &args),
        "reachable" => sdk_label_site("reachable", "observed", 0, &args),
        "assert" | "assert_eq" | "assert_ne" => Some(MacroSite::Single {
            kind: "assert",
            runtime: "invisible",
            label: None,
            label_dynamic: false,
        }),
        "debug_assert" | "debug_assert_eq" | "debug_assert_ne" => Some(MacroSite::Single {
            kind: "debug_assert",
            runtime: "invisible",
            label: None,
            label_dynamic: false,
        }),
        "unreachable" => Some(MacroSite::Single {
            kind: "unreachable",
            runtime: "invisible",
            label: None,
            label_dynamic: false,
        }),
        "prop_assert" | "prop_assert_eq" | "prop_assert_ne" => Some(MacroSite::Single {
            kind: "prop_assert",
            runtime: "invisible",
            label: None,
            label_dynamic: false,
        }),
        "proptest" => Some(MacroSite::Proptest(proptest_functions(tokens))),
        "quickcheck" => Some(MacroSite::Single {
            kind: "quickcheck",
            runtime: "invisible",
            label: None,
            label_dynamic: false,
        }),
        "assert_always" | "assert_always_or_unreachable" => {
            antithesis_site("antithesis_always", &args)
        }
        "assert_sometimes" => antithesis_site("antithesis_sometimes", &args),
        "assert_reachable" => antithesis_site("antithesis_reachable", &args),
        "assert_unreachable" => antithesis_site("antithesis_unreachable", &args),
        _ if is_antithesis_path(macro_path) => antithesis_site("antithesis_reachable", &args),
        _ => None,
    }
}

fn sdk_label_site(
    kind: &'static str,
    runtime: &'static str,
    label_index: usize,
    args: &[TokenStream],
) -> Option<MacroSite> {
    let label = args.get(label_index).and_then(string_literal_arg);
    Some(MacroSite::Single {
        kind,
        runtime,
        label,
        label_dynamic: args
            .get(label_index)
            .is_some_and(|arg| string_literal_arg(arg).is_none()),
    })
}

fn antithesis_site(kind: &'static str, args: &[TokenStream]) -> Option<MacroSite> {
    Some(MacroSite::Single {
        kind,
        runtime: "invisible",
        label: args.iter().find_map(string_literal_arg),
        label_dynamic: false,
    })
}

fn is_antithesis_path(path: &str) -> bool {
    path == "antithesis_sdk" || path.starts_with("antithesis_sdk::")
}

fn split_args(tokens: &TokenStream) -> Vec<TokenStream> {
    let mut args = Vec::new();
    let mut current = TokenStream::new();
    for token in tokens.clone() {
        match &token {
            TokenTree::Punct(punct) if punct.as_char() == ',' => {
                args.push(current);
                current = TokenStream::new();
            }
            _ => current.extend([token]),
        }
    }
    if !current.is_empty() || tokens.is_empty() {
        args.push(current);
    }
    args
}

fn string_literal_arg(tokens: &TokenStream) -> Option<String> {
    let mut iter = tokens.clone().into_iter();
    let first = iter.next()?;
    if iter.next().is_some() {
        return None;
    }
    let TokenTree::Literal(literal) = first else {
        return None;
    };
    syn::parse_str::<syn::LitStr>(&literal.to_string())
        .ok()
        .map(|lit| lit.value())
}

fn proptest_functions(tokens: &TokenStream) -> Vec<(String, Span)> {
    let mut out = Vec::new();
    collect_proptest_functions(tokens.clone(), &mut out);
    out
}

fn collect_proptest_functions(tokens: TokenStream, out: &mut Vec<(String, Span)>) {
    let mut iter = tokens.into_iter().peekable();
    while let Some(token) = iter.next() {
        match token {
            TokenTree::Ident(ident) if ident == "fn" => {
                if let Some(TokenTree::Ident(name)) = iter.peek() {
                    out.push((name.to_string(), name.span()));
                }
            }
            TokenTree::Group(group) if group.delimiter() != Delimiter::None => {
                collect_proptest_functions(group.stream(), out);
            }
            _ => {}
        }
    }
}

fn path_to_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

#[derive(Clone, Debug)]
struct JoinedSite<'a> {
    site: &'a SiteRecord,
    exercised: Option<&'a ExercisedSite>,
    never_exercised: bool,
}

impl RollupLeaf for JoinedSite<'_> {
    fn crate_name(&self) -> &str {
        &self.site.crate_name
    }

    fn module(&self) -> &str {
        &self.site.module
    }

    fn groups(&self) -> &[String] {
        &self.site.groups
    }

    fn bucket(&self) -> &str {
        &self.site.runtime
    }

    fn is_gap(&self) -> bool {
        self.never_exercised
    }
}

#[derive(Clone, Debug, Default)]
struct JoinResult<'a> {
    by_site_id: BTreeMap<String, &'a ExercisedSite>,
    unmatched: Vec<UnmatchedRuntimeSite>,
}

#[derive(Clone, Debug, Serialize)]
struct UnmatchedRuntimeSite {
    label: String,
    kind: String,
    site: String,
    origin: &'static str,
}

fn build_report(
    scan: &StaticScan,
    options: &SitesOptions,
    exercised: Option<&ExercisedSource>,
) -> Value {
    let join = exercised
        .map(|source| join_exercised(scan, source))
        .unwrap_or_default();
    let filtered = scan
        .sites
        .iter()
        .filter(|site| site_matches(site, options))
        .map(|site| JoinedSite {
            site,
            exercised: join.by_site_id.get(&site.id).copied(),
            never_exercised: exercised.is_some()
                && site.runtime != "invisible"
                && !join.by_site_id.contains_key(&site.id),
        })
        .collect::<Vec<_>>();
    let warnings = exercised
        .filter(|source| source.sites.is_empty())
        .and_then(|_| {
            filtered
                .iter()
                .any(|joined| joined.site.runtime == "driven")
                .then(|| {
                    "WARNING: exercised source contained zero SDK site rows while the static inventory has driven sites; coverage may be vacuous"
                        .to_string()
                })
        })
        .into_iter()
        .collect::<Vec<_>>();
    let rollup = build_rollup(&filtered, RUNTIME_ORDER);
    let static_sites = filtered
        .iter()
        .map(|joined| joined.site.clone())
        .collect::<Vec<_>>();
    let by_kind = count_by_kind(&static_sites);

    let mut totals = json!({
        "sites": filtered.len(),
        "by_runtime": rollup.by_bucket,
        "by_kind": by_kind,
    });
    if exercised.is_some() {
        totals["exercised"] = exercised_totals(&filtered, &join);
    }

    let mut root = Map::new();
    root.insert("schema".to_string(), json!(SITES_SCHEMA));
    root.insert("verb".to_string(), json!("sites"));
    root.insert(
        "scan".to_string(),
        json!({
            "workspace_root": scan.workspace_root.display().to_string(),
            "files_scanned": scan.files_scanned,
            "files_unparsed": scan.files_unparsed,
            "cache": scan.cache_state.as_str(),
            "recognizers": RECOGNIZER_NAMES.len(),
            "recognizer_version": RECOGNIZER_TABLE_VERSION,
            "unparsed": scan.unparsed,
        }),
    );
    if let Some(source) = exercised {
        root.insert(
            "exercised_source".to_string(),
            json!({
                "kind": source.kind,
                "path": source.path,
                "reports": source.reports,
                "generations_observed": source.generations_observed,
            }),
        );
    }
    if !warnings.is_empty() {
        root.insert("warnings".to_string(), json!(warnings));
    }
    if let Some(config) = crate::config::provenance_json() {
        root.insert("config".to_string(), config);
    }
    root.insert("totals".to_string(), totals);
    root.insert(
        "crates".to_string(),
        crate_rollups_json(&rollup.crates, exercised.is_some()),
    );
    root.insert(
        "groups".to_string(),
        group_rollups_json(&rollup.groups, exercised.is_some()),
    );
    root.insert(
        "unmatched_runtime_labels".to_string(),
        json!(join.unmatched.len()),
    );
    if !join.unmatched.is_empty() {
        root.insert("unmatched".to_string(), json!(join.unmatched));
    }
    if options.scoped() {
        root.insert("sites".to_string(), site_rows_json(&filtered));
        root.insert(
            "detail".to_string(),
            json!({
                "mode": if exercised.is_some() { "static+exercised" } else { "static" },
                "honesty": if exercised.is_some() {
                    "Runtime rows are joined to static SDK labels or dynamic-label file:line sites; invisible sites remain inventory-only and carry no exercised object."
                } else {
                    "Static-only report has no exercised source; invisible sites are inventoried but Patina cannot observe their execution."
                },
            }),
        );
    } else {
        root.insert(
            "detail".to_string(),
            json!({
                "hint": "Per-site rows are omitted from this index.",
                "command_template": "cargo patina sites --module {module} --format json",
            }),
        );
    }
    Value::Object(root)
}

fn join_exercised<'a>(scan: &StaticScan, source: &'a ExercisedSource) -> JoinResult<'a> {
    let mut by_label: BTreeMap<&str, &SiteRecord> = BTreeMap::new();
    let mut dynamic_by_location: BTreeMap<String, &SiteRecord> = BTreeMap::new();
    for site in &scan.sites {
        if matches!(site.runtime.as_str(), "driven" | "observed") {
            if let Some(label) = &site.label {
                by_label.insert(label, site);
            } else if site.label_dynamic {
                dynamic_by_location.insert(format!("{}:{}", site.file, site.line), site);
            }
        }
    }

    let mut joined = JoinResult::default();
    for exercised in source.sites.values() {
        if let Some(site) = by_label.get(exercised.label.as_str()) {
            joined.by_site_id.insert(site.id.clone(), exercised);
            continue;
        }
        if let Some(location) = normalize_runtime_site(&scan.workspace_root, &exercised.site) {
            if let Some(site) = dynamic_by_location.get(&location) {
                joined.by_site_id.insert(site.id.clone(), exercised);
                continue;
            }
        }
        joined.unmatched.push(UnmatchedRuntimeSite {
            label: exercised.label.clone(),
            kind: exercised.kind.clone(),
            site: exercised.site.clone(),
            origin: "expanded",
        });
    }
    joined
}

fn normalize_runtime_site(workspace_root: &Path, site: &str) -> Option<String> {
    let (file, line) = site.rsplit_once(':')?;
    if line.parse::<usize>().is_err() {
        return None;
    }
    let mut file = file.replace('\\', "/");
    let root = workspace_root.to_string_lossy().replace('\\', "/");
    if let Some(stripped) = file.strip_prefix(root.trim_end_matches('/')) {
        file = stripped.trim_start_matches('/').to_string();
    }
    Some(format!("{file}:{line}"))
}

fn exercised_totals(filtered: &[JoinedSite<'_>], join: &JoinResult<'_>) -> Value {
    let mut joined_runtime_labels = 0_u64;
    let mut driven_fired = 0_u64;
    let mut observed_satisfied = 0_u64;
    let mut never_exercised = 0_u64;
    for joined in filtered {
        if joined.never_exercised {
            never_exercised += 1;
        }
        let Some(exercised) = joined.exercised else {
            continue;
        };
        joined_runtime_labels += 1;
        match joined.site.kind.as_str() {
            "fault" | "delay" if exercised.fires > 0 => driven_fired += 1,
            "knob" if exercised.knob_min.is_some() => driven_fired += 1,
            "always" if exercised.evals > 0 && exercised.always_violated_runs == 0 => {
                observed_satisfied += 1;
            }
            "sometimes" if exercised.sometimes_satisfied_runs > 0 => observed_satisfied += 1,
            "reachable" if exercised.reachable_runs > 0 => observed_satisfied += 1,
            _ => {}
        }
    }
    json!({
        "runtime_labels": joined_runtime_labels + join.unmatched.len() as u64,
        "joined_runtime_labels": joined_runtime_labels,
        "unmatched_runtime_labels": join.unmatched.len(),
        "driven_fired": driven_fired,
        "observed_satisfied": observed_satisfied,
        "never_exercised": never_exercised,
    })
}

fn site_rows_json(sites: &[JoinedSite<'_>]) -> Value {
    Value::Array(
        sites
            .iter()
            .map(|joined| {
                let mut value = serde_json::to_value(joined.site)
                    .expect("site records are JSON-serializable objects");
                if let (Some(object), Some(exercised)) = (value.as_object_mut(), joined.exercised) {
                    if joined.site.runtime != "invisible" {
                        object.insert("exercised".to_string(), json!(exercised));
                    }
                }
                value
            })
            .collect(),
    )
}

fn site_matches(site: &SiteRecord, options: &SitesOptions) -> bool {
    if let Some(crate_filter) = &options.crate_filter {
        if &site.crate_name != crate_filter {
            return false;
        }
    }
    if let Some(module_filter) = &options.module_filter {
        if &site.module != module_filter {
            return false;
        }
    }
    if let Some(group_filter) = &options.group_filter {
        if !site.groups.iter().any(|group| group == group_filter) {
            return false;
        }
    }
    if let Some(site_filter) = &options.site_filter {
        if &site.id != site_filter && site.label.as_ref() != Some(site_filter) {
            return false;
        }
    }
    if let Some(kind_filter) = &options.kind_filter {
        if &site.kind != kind_filter {
            return false;
        }
    }
    if let Some(runtime_filter) = &options.runtime_filter {
        if &site.runtime != runtime_filter {
            return false;
        }
    }
    true
}

fn count_by_kind(sites: &[SiteRecord]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for kind in KIND_ORDER {
        counts.insert((*kind).to_string(), 0);
    }
    for site in sites {
        *counts.entry(site.kind.clone()).or_insert(0) += 1;
    }
    counts
}

fn crate_rollups_json(crates: &[crate::rollup::CrateRollup], include_gaps: bool) -> Value {
    Value::Array(
        crates
            .iter()
            .map(|krate| {
                let mut value = json!({
                    "name": krate.name,
                    "sites": krate.total,
                    "by_runtime": krate.by_bucket,
                    "modules": krate.modules.iter().map(|module| {
                        let mut module_value = json!({
                            "module": module.module,
                            "sites": module.total,
                            "by_runtime": module.by_bucket,
                        });
                        if include_gaps {
                            module_value["never_exercised"] = json!(module.gaps);
                        }
                        module_value
                    }).collect::<Vec<_>>(),
                });
                if include_gaps {
                    value["never_exercised"] = json!(krate.gaps);
                }
                value
            })
            .collect(),
    )
}

fn group_rollups_json(groups: &[crate::rollup::GroupRollup], include_gaps: bool) -> Value {
    Value::Array(
        groups
            .iter()
            .map(|group| {
                let mut value = json!({
                    "name": group.name,
                    "sites": group.total,
                    "by_runtime": group.by_bucket,
                });
                if include_gaps {
                    value["never_exercised"] = json!(group.gaps);
                }
                value
            })
            .collect(),
    )
}

fn print_human(report: &Value) {
    let scan = &report["scan"];
    let totals = &report["totals"];
    println!("== sites static inventory ==");
    println!(
        "workspace={} files_scanned={} files_unparsed={} cache={} recognizers={}",
        scan["workspace_root"].as_str().unwrap_or("?"),
        scan["files_scanned"].as_u64().unwrap_or(0),
        scan["files_unparsed"].as_u64().unwrap_or(0),
        scan["cache"].as_str().unwrap_or("?"),
        scan["recognizers"].as_u64().unwrap_or(0),
    );
    println!(
        "sites={} driven={} observed={} invisible={}",
        totals["sites"].as_u64().unwrap_or(0),
        totals["by_runtime"]["driven"].as_u64().unwrap_or(0),
        totals["by_runtime"]["observed"].as_u64().unwrap_or(0),
        totals["by_runtime"]["invisible"].as_u64().unwrap_or(0),
    );
    if let Some(source) = report.get("exercised_source") {
        println!(
            "exercised_source={} kind={} reports={} generations_observed={} joined={} unmatched={} never_exercised={}",
            source["path"].as_str().unwrap_or("?"),
            source["kind"].as_str().unwrap_or("?"),
            source["reports"].as_u64().unwrap_or(0),
            source["generations_observed"].as_u64().unwrap_or(0),
            totals["exercised"]["joined_runtime_labels"]
                .as_u64()
                .unwrap_or(0),
            totals["exercised"]["unmatched_runtime_labels"]
                .as_u64()
                .unwrap_or(0),
            totals["exercised"]["never_exercised"].as_u64().unwrap_or(0),
        );
    }
    if let Some(warnings) = report.get("warnings").and_then(Value::as_array) {
        for warning in warnings {
            println!(
                "{}",
                warning.as_str().unwrap_or("WARNING: unknown sites warning")
            );
        }
    }
    if scan["files_unparsed"].as_u64().unwrap_or(0) > 0 {
        println!("WARNING: unparsed Rust files were counted and omitted from site totals:");
        if let Some(unparsed) = scan["unparsed"].as_array() {
            for row in unparsed {
                println!(
                    "  {}: {}",
                    row["file"].as_str().unwrap_or("?"),
                    row["error"].as_str().unwrap_or("?")
                );
            }
        }
    }
    if let Some(sites) = report.get("sites").and_then(Value::as_array) {
        println!("\n== sites ==");
        for site in sites {
            let label = site.get("label").and_then(Value::as_str).unwrap_or("-");
            let dynamic = if site
                .get("label_dynamic")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                " dynamic-label"
            } else {
                ""
            };
            let exercised = site.get("exercised").map_or_else(String::new, |row| {
                format!(
                    " exercised(reg={} evals={} fires={} satisfied={} reached={})",
                    row["registered_gens"].as_u64().unwrap_or(0),
                    row["evals"].as_u64().unwrap_or(0),
                    row["fires"].as_u64().unwrap_or(0),
                    row["satisfied_gens"].as_u64().unwrap_or(0),
                    row["reachable_runs"].as_u64().unwrap_or(0),
                )
            });
            println!(
                "{}:{} {} {} id={} label={} module={} context={} macro={}{}{}",
                site["file"].as_str().unwrap_or("?"),
                site["line"].as_u64().unwrap_or(0),
                site["kind"].as_str().unwrap_or("?"),
                site["runtime"].as_str().unwrap_or("?"),
                site["id"].as_str().unwrap_or("?"),
                label,
                site["module"].as_str().unwrap_or("?"),
                site["context"].as_str().unwrap_or("?"),
                site["macro_path"].as_str().unwrap_or("?"),
                dynamic,
                exercised,
            );
        }
        if report.get("exercised_source").is_some() {
            println!(
                "\nRuntime rows are joined by label (or dynamic-label file:line); invisible sites remain inventory-only."
            );
        } else {
            println!(
                "\nStatic-only report: exercised data is absent; invisible sites render as inventory only."
            );
        }
    } else {
        println!(
            "\n{:<32} {:>6} {:>7} {:>8} {:>9} {:>7}",
            "crate/module", "sites", "driven", "observed", "invisible", "never"
        );
        if let Some(crates) = report["crates"].as_array() {
            for krate in crates {
                print_rollup_row("", krate, "name");
                if let Some(modules) = krate["modules"].as_array() {
                    for module in modules {
                        print_rollup_row("  ", module, "module");
                    }
                }
            }
        }
        println!(
            "\nPer-site rows omitted. Drill down with `cargo patina sites --module <PATH>` or `--all`."
        );
    }
}

fn print_rollup_row(prefix: &str, row: &Value, name_key: &str) {
    let name = row[name_key].as_str().unwrap_or("?");
    let sites = row["sites"].as_u64().unwrap_or(0);
    let driven = row["by_runtime"]["driven"].as_u64().unwrap_or(0);
    let observed = row["by_runtime"]["observed"].as_u64().unwrap_or(0);
    let invisible = row["by_runtime"]["invisible"].as_u64().unwrap_or(0);
    let never = row["never_exercised"].as_u64().unwrap_or(0);
    println!(
        "{:<32} {:>6} {:>7} {:>8} {:>9} {:>7}",
        format!("{prefix}{name}"),
        sites,
        pct(driven, sites),
        pct(observed, sites),
        pct(invisible, sites),
        never,
    );
}

fn pct(count: u64, total: u64) -> String {
    count
        .checked_mul(100)
        .and_then(|percent| percent.checked_div(total))
        .map(|percent| format!("{percent}%"))
        .unwrap_or_else(|| "0%".to_string())
}

fn run_selftest() -> Result<i32, CliError> {
    let result = run_selftest_inner()?;
    println!("== sites recognizer selftest ==");
    println!(
        "fixture_sites={} files_scanned={} files_unparsed={} recognizers={}",
        result.sites.len(),
        result.files_scanned,
        result.files_unparsed,
        RECOGNIZER_NAMES.len()
    );
    for kind in KIND_ORDER {
        let count = result
            .sites
            .iter()
            .filter(|site| site.kind == *kind)
            .count();
        if count > 0 {
            println!("  {kind}: {count}");
        }
    }
    println!(
        "sites selftest passed: recognizers fired and wrapper macro stayed an expected static miss"
    );
    Ok(0)
}

fn run_selftest_inner() -> Result<StaticScan, CliError> {
    let dir = tempfile::tempdir()
        .map_err(|error| CliError(format!("failed to create sites selftest fixture: {error}")))?;
    let root = dir.path().to_path_buf();
    fs::create_dir_all(root.join("src")).map_err(|error| {
        CliError(format!(
            "failed to create sites selftest source dir: {error}"
        ))
    })?;
    fs::write(
        root.join("Cargo.toml"),
        r#"[package]
name = "sites-fixture"
version = "0.0.0"
edition = "2024"
"#,
    )
    .map_err(|error| CliError(format!("failed to write sites selftest manifest: {error}")))?;
    fs::write(root.join("src/lib.rs"), SELFTEST_LIB).map_err(|error| {
        CliError(format!(
            "failed to write sites selftest source fixture: {error}"
        ))
    })?;
    fs::create_dir_all(root.join("tests")).map_err(|error| {
        CliError(format!(
            "failed to create sites selftest tests dir: {error}"
        ))
    })?;
    fs::write(root.join("tests/prop.rs"), SELFTEST_TEST).map_err(|error| {
        CliError(format!(
            "failed to write sites selftest test fixture: {error}"
        ))
    })?;
    let package = ScanPackage {
        name: "sites-fixture".to_string(),
        root: root.clone(),
        targets: vec![TargetHint {
            src_path: root.join("src/lib.rs"),
            name: "sites_fixture".to_string(),
            context: ContextKind::Src,
        }],
    };
    let scan = scan_packages(root, vec![package], false)?;
    assert_selftest_counts(&scan)?;
    Ok(scan)
}

const SELFTEST_LIB: &str = r#"
use patina_dst::always as renamed_always;
use antithesis_sdk::assert_sometimes as renamed_antithesis_sometimes;

macro_rules! wrapper_fault {
    () => { patina_dst::buggify!("wrapped-static-miss") };
}

pub fn exercise(input: i32) {
    let dynamic = format!("dyn-{input}");
    let _ = patina_dst::buggify!("fq-fault");
    let _ = buggify_with_prob!("bare-fault", 0.5);
    let _ = patina_dst::buggify_delay!("fq-delay");
    let _ = patina_dst::buggify_knob!("fq-knob", 3, 1, 9);
    patina_dst::always!(input >= 0, "fq-always");
    sometimes!(input == 1, "bare-sometimes");
    patina_dst::reachable!("fq-reachable");
    renamed_always!(input != 99, "renamed-always");
    let _ = patina_dst::buggify!(dynamic);

    assert!(input >= 0);
    assert_eq!(input, input);
    assert_ne!(input, -1);
    debug_assert!(input < 1000);
    debug_assert_eq!(input + 1, input + 1);
    debug_assert_ne!(input, -2);
    unreachable!("std unreachable inventory only");

    prop_assert!(input >= 0);
    prop_assert_eq!(input, input);
    prop_assert_ne!(input, -1);
    quickcheck! { fn qc_macro(x: u8) -> bool { x == x } }

    antithesis_sdk::assert_always!(input >= 0, "anti-always");
    assert_always_or_unreachable!(input >= 0, "anti-always-or-unreachable");
    renamed_antithesis_sometimes!(input == 1, "anti-sometimes");
    antithesis_sdk::assert_reachable!("anti-reachable");
    assert_unreachable!("anti-unreachable");

    let _ = wrapper_fault!();
}

#[cfg(test)]
mod tests {
    pub fn test_context() {
        reachable!("cfg-test-reachable");
    }
}
"#;

const SELFTEST_TEST: &str = r#"
#[quickcheck]
fn attr_quickcheck(x: u8) -> bool { x == x }

proptest! {
    #[test]
    fn proptest_case(a in 0u8..10) {
        prop_assert!(a < 10);
    }
}
"#;

fn assert_selftest_counts(scan: &StaticScan) -> Result<(), CliError> {
    if scan.files_unparsed != 0 {
        return Err(CliError(format!(
            "sites selftest fixture failed to parse: {:?}",
            scan.unparsed
        )));
    }
    let counts = count_by_kind(&scan.sites);
    let expected = BTreeMap::from([
        ("fault", 3usize),
        ("delay", 1),
        ("knob", 1),
        ("always", 2),
        ("sometimes", 1),
        ("reachable", 2),
        ("assert", 3),
        ("debug_assert", 3),
        ("prop_assert", 3),
        ("proptest", 1),
        ("quickcheck", 2),
        ("antithesis_always", 2),
        ("antithesis_sometimes", 1),
        ("antithesis_reachable", 1),
        ("antithesis_unreachable", 1),
        ("unreachable", 1),
    ]);
    for (kind, expected) in expected {
        let actual = counts.get(kind).copied().unwrap_or(0);
        if actual != expected {
            return Err(CliError(format!(
                "sites selftest kind {kind} expected {expected}, got {actual}; sites={:#?}",
                scan.sites
            )));
        }
    }
    let dynamic = scan
        .sites
        .iter()
        .find(|site| site.label_dynamic)
        .ok_or_else(|| CliError("sites selftest did not find dynamic-label SDK site".into()))?;
    if dynamic.label.is_some() || dynamic.runtime != "driven" {
        return Err(CliError(format!(
            "sites selftest dynamic label row malformed: {dynamic:#?}"
        )));
    }
    let cfg_test = scan
        .sites
        .iter()
        .find(|site| site.label.as_deref() == Some("cfg-test-reachable"))
        .ok_or_else(|| CliError("sites selftest missed #[cfg(test)] module site".into()))?;
    if cfg_test.context != "test" {
        return Err(CliError(format!(
            "sites selftest expected cfg(test) context, got {}",
            cfg_test.context
        )));
    }
    if scan
        .sites
        .iter()
        .any(|site| site.label.as_deref() == Some("wrapped-static-miss"))
    {
        return Err(CliError(
            "sites selftest wrapper macro was counted; wrapper expansions must remain an expected static miss"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn recognized_sdk_site_macros() -> BTreeSet<&'static str> {
    SDK_SITE_MACROS.iter().copied().collect()
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selftest_fixture_proves_recognizers() {
        run_selftest_inner().expect("sites selftest fixture should pass");
    }

    #[test]
    fn cache_reuses_clean_file_and_invalidates_on_recognizer_version() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn f() { assert!(true); }\n").unwrap();
        let package = ScanPackage {
            name: "cache-fixture".to_string(),
            root: root.clone(),
            targets: vec![TargetHint {
                src_path: root.join("src/lib.rs"),
                name: "cache_fixture".to_string(),
                context: ContextKind::Src,
            }],
        };
        let first = scan_packages(root.clone(), vec![package.clone()], true).unwrap();
        assert_eq!(first.cache_state, CacheState::Cold);
        assert_eq!(first.sites.len(), 1);
        let ignore = fs::read_to_string(root.join(".patina/.gitignore")).unwrap();
        assert!(ignore.lines().any(|line| line.trim() == "/out/"));
        let second = scan_packages(root.clone(), vec![package.clone()], true).unwrap();
        assert_eq!(second.cache_state, CacheState::Hit);
        fs::write(
            root.join(".patina/out/sites-cache.json"),
            b"{\"schema\":\"patina.sites-cache/v1\",\"recognizer_version\":\"old\",\"files\":{}}",
        )
        .unwrap();
        let third = scan_packages(root, vec![package], true).unwrap();
        assert_eq!(third.cache_state, CacheState::Cold);
    }

    #[test]
    fn scoped_json_carries_site_rows() {
        let scan = StaticScan {
            workspace_root: PathBuf::from("/w"),
            sites: vec![SiteRecord {
                id: "label".to_string(),
                kind: "always".to_string(),
                runtime: "observed".to_string(),
                label: Some("label".to_string()),
                label_dynamic: false,
                file: "src/lib.rs".to_string(),
                line: 1,
                crate_name: "pkg".to_string(),
                module: "pkg".to_string(),
                context: "src".to_string(),
                groups: Vec::new(),
                macro_path: "always".to_string(),
            }],
            files_scanned: 1,
            files_unparsed: 0,
            unparsed: Vec::new(),
            cache_state: CacheState::Cold,
        };
        let report = build_report(
            &scan,
            &SitesOptions {
                module_filter: Some("pkg".to_string()),
                ..SitesOptions::default()
            },
            None,
        );
        assert_eq!(report["schema"], SITES_SCHEMA);
        assert_eq!(report["sites"].as_array().unwrap().len(), 1);
        assert_eq!(report["unmatched_runtime_labels"], 0);
    }

    #[test]
    fn exercised_source_joins_labels_and_dynamic_file_line_sites() {
        let scan = StaticScan {
            workspace_root: PathBuf::from("/workspace"),
            sites: vec![
                SiteRecord {
                    id: "static-label".to_string(),
                    kind: "fault".to_string(),
                    runtime: "driven".to_string(),
                    label: Some("static-label".to_string()),
                    label_dynamic: false,
                    file: "src/main.rs".to_string(),
                    line: 10,
                    crate_name: "pkg".to_string(),
                    module: "pkg".to_string(),
                    context: "src".to_string(),
                    groups: Vec::new(),
                    macro_path: "buggify".to_string(),
                },
                SiteRecord {
                    id: "src/main.rs:12:5#fault".to_string(),
                    kind: "fault".to_string(),
                    runtime: "driven".to_string(),
                    label: None,
                    label_dynamic: true,
                    file: "src/main.rs".to_string(),
                    line: 12,
                    crate_name: "pkg".to_string(),
                    module: "pkg".to_string(),
                    context: "src".to_string(),
                    groups: Vec::new(),
                    macro_path: "buggify".to_string(),
                },
            ],
            files_scanned: 1,
            files_unparsed: 0,
            unparsed: Vec::new(),
            cache_state: CacheState::Cold,
        };
        let mut exercised_sites = BTreeMap::new();
        exercised_sites.insert(
            "static-label".to_string(),
            ExercisedSite {
                label: "static-label".to_string(),
                kind: "fault".to_string(),
                site: "src/main.rs:10".to_string(),
                first_registered_gen: Some(0),
                last_registered_gen: Some(0),
                registered_gens: 1,
                runs_active: 1,
                evals: 2,
                fires: 1,
                runs_fired: 1,
                ..ExercisedSite::default()
            },
        );
        exercised_sites.insert(
            "dynamic-at-runtime".to_string(),
            ExercisedSite {
                label: "dynamic-at-runtime".to_string(),
                kind: "fault".to_string(),
                site: "/workspace/src/main.rs:12".to_string(),
                first_registered_gen: Some(0),
                last_registered_gen: Some(0),
                registered_gens: 1,
                evals: 1,
                ..ExercisedSite::default()
            },
        );
        let source = ExercisedSource {
            kind: "sdk_report".to_string(),
            path: "stderr.log".to_string(),
            reports: 1,
            generations_observed: 1,
            sites: exercised_sites,
        };
        let report = build_report(
            &scan,
            &SitesOptions {
                all: true,
                ..SitesOptions::default()
            },
            Some(&source),
        );
        assert_eq!(report["unmatched_runtime_labels"], 0);
        assert_eq!(report["totals"]["exercised"]["joined_runtime_labels"], 2);
        let rows = report["sites"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["exercised"]["fires"], 1);
        assert_eq!(rows[1]["exercised"]["label"], "dynamic-at-runtime");
    }

    #[test]
    fn unmatched_runtime_labels_are_visible_not_dropped() {
        let scan = StaticScan {
            workspace_root: PathBuf::from("/workspace"),
            sites: Vec::new(),
            files_scanned: 0,
            files_unparsed: 0,
            unparsed: Vec::new(),
            cache_state: CacheState::Cold,
        };
        let mut exercised_sites = BTreeMap::new();
        exercised_sites.insert(
            "wrapped".to_string(),
            ExercisedSite {
                label: "wrapped".to_string(),
                kind: "fault".to_string(),
                site: "src/lib.rs:1".to_string(),
                first_registered_gen: Some(0),
                last_registered_gen: Some(0),
                registered_gens: 1,
                ..ExercisedSite::default()
            },
        );
        let source = ExercisedSource {
            kind: "sdk_report".to_string(),
            path: "stderr.log".to_string(),
            reports: 1,
            generations_observed: 1,
            sites: exercised_sites,
        };
        let report = build_report(&scan, &SitesOptions::default(), Some(&source));
        assert_eq!(report["unmatched_runtime_labels"], 1);
        assert_eq!(report["unmatched"][0]["origin"], "expanded");
    }

    #[test]
    fn empty_exercised_source_warns_when_static_driven_sites_exist() {
        let scan = StaticScan {
            workspace_root: PathBuf::from("/workspace"),
            sites: vec![SiteRecord {
                id: "static-label".to_string(),
                kind: "fault".to_string(),
                runtime: "driven".to_string(),
                label: Some("static-label".to_string()),
                label_dynamic: false,
                file: "src/main.rs".to_string(),
                line: 10,
                crate_name: "pkg".to_string(),
                module: "pkg".to_string(),
                context: "src".to_string(),
                groups: Vec::new(),
                macro_path: "buggify".to_string(),
            }],
            files_scanned: 1,
            files_unparsed: 0,
            unparsed: Vec::new(),
            cache_state: CacheState::Cold,
        };
        let source = ExercisedSource {
            kind: "campaign".to_string(),
            path: "out".to_string(),
            reports: 3,
            generations_observed: 3,
            sites: BTreeMap::new(),
        };
        let report = build_report(&scan, &SitesOptions::default(), Some(&source));
        assert!(
            report["warnings"][0]
                .as_str()
                .unwrap()
                .contains("zero SDK site rows"),
            "expected vacuity warning: {report:#}"
        );
    }

    #[test]
    fn sdk_recognizer_table_matches_exported_runtime_site_macros() {
        let sdk = Path::new(env!("CARGO_MANIFEST_DIR")).join("../patina/src/lib.rs");
        let source = fs::read_to_string(&sdk).expect("read SDK source");
        let parsed = syn::parse_file(&source).expect("parse SDK source");
        let mut exported_runtime_macros = BTreeSet::new();
        for item in parsed.items {
            let syn::Item::Macro(mac) = item else {
                continue;
            };
            if !mac
                .attrs
                .iter()
                .any(|attr| attr.path().is_ident("macro_export"))
            {
                continue;
            }
            let Some(ident) = mac.ident else {
                continue;
            };
            let tokens = mac.mac.tokens.to_string();
            if site_runtime_shim_calls()
                .iter()
                .any(|needle| tokens.contains(needle))
            {
                exported_runtime_macros.insert(ident.to_string());
            }
        }
        let recognized = recognized_sdk_site_macros();
        let missing = exported_runtime_macros
            .iter()
            .filter(|name| !recognized.contains(name.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "SDK macros call runtime site shims but are absent from the sites recognizer table: {missing:?}"
        );
    }

    fn site_runtime_shim_calls() -> &'static [&'static str] {
        &[
            "__rt :: buggify",
            "__rt :: buggify_delay",
            "__rt :: buggify_knob",
            "__rt :: always",
            "__rt :: sometimes",
            "__rt :: reachable",
        ]
    }
}
