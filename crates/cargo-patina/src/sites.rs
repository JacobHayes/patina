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

mod recognize;
mod report;
mod scan;
mod selftest;

use recognize::recognizer_count;
use recognize::scan_file;
use report::KIND_ORDER;
use report::build_report;
use report::count_by_kind;
use report::duplicate_label_marker_line;
use report::find_duplicate_labels;
use report::print_human;
#[cfg(test)]
use scan::CacheState;
use scan::CachedFile;
use scan::ContextKind;
use scan::RECOGNIZER_TABLE_VERSION;
use scan::ScanPackage;
use scan::SourceFile;
use scan::StaticScan;
use scan::TargetHint;
use scan::hex_digest;
use scan::scan_current_workspace;
use scan::scan_packages;
use selftest::run_selftest;

pub(crate) const SITES_SCHEMA: &str = "patina.sites/v1";

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
    if arguments.iter().any(|argument| argument == "--") {
        return Err(CliError::usage(
            "sites takes no guest arguments or `--` separator",
        ));
    }
    let args = crate::cli::parse("sites", crate::help::Family::Sole, arguments)?;
    let options = SitesOptions {
        crate_filter: args.string("--crate"),
        module_filter: args.string("--module"),
        group_filter: args.string("--group"),
        site_filter: args.string("--site"),
        all: args.flag("--all"),
        exercised: args.path("--exercised"),
        kind_filter: args.string("--kind"),
        runtime_filter: args.string("--runtime"),
        no_cache: args.flag("--no-cache"),
    };
    if !args.flag("--selftest") {
        return Ok(SitesInvocation::Scan(options));
    }
    if options != SitesOptions::default() {
        return Err(CliError::usage(
            "sites --selftest does not accept report filters",
        ));
    }
    Ok(SitesInvocation::Selftest)
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
    let duplicate_labels = find_duplicate_labels(&scan.sites);
    let exercised = options
        .exercised
        .as_deref()
        .map(parse_exercised_file)
        .transpose()?;
    let report = build_report(&scan, &options, exercised.as_ref(), &duplicate_labels);
    if output::options().is_json() {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| CliError(format!("failed to encode sites JSON: {error}")))?
        );
    } else {
        print_human(&report);
    }
    // Stderr carries the marker in BOTH modes: stdout is the report (the JSON
    // envelope, or the human table), and a wrapper that discards stdout must
    // still see WHICH label collided, not just a nonzero exit.
    for finding in &duplicate_labels {
        eprintln!("{}", duplicate_label_marker_line(finding));
    }
    Ok(if duplicate_labels.is_empty() { 0 } else { 1 })
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
