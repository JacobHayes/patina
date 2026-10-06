//! Native yield-point coverage map parsing, campaign accumulation, and the
//! `cargo patina coverage` offline report verb.
//!
//! This is the single parser for `patina.covmap/v1`. `run --coverage-out`, the
//! campaign accumulator, and the read-only coverage verb all come through this
//! module so the binary format has one validation path.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use object::{Object, ObjectSymbol, SymbolKind};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::CliError;
use crate::aux_store::{AuxFoldDecision, fold_decision, validate_resume_watermark};
use crate::cli;
use crate::help;
use crate::output;
use crate::rollup::{Rollup, RollupLeaf, build_rollup};

mod campaign;
mod covmap;
pub(crate) use campaign::*;
mod detectors;
mod input;
mod report;
mod symbols;

pub(crate) use covmap::CAMPAIGN_COVERAGE_SCHEMA;
use covmap::COVERAGE_ENVELOPE_SCHEMA;
#[cfg(test)]
use covmap::COVERAGE_MAP_MAGIC;
#[cfg(test)]
use covmap::COVERAGE_MAP_VERSION;
use covmap::COVERED_BUCKETS;
pub(crate) use covmap::Covmap;
pub(crate) use covmap::CovmapRange;
pub(crate) use covmap::coverage_summary_from_map;
#[cfg(test)]
use covmap::parse_covmap_bytes;
pub(crate) use covmap::read_covmap;
pub(crate) use detectors::campaign_detector_selftest;
#[cfg(test)]
use detectors::synthetic_covmap;
use input::CoverageData;
use input::load_coverage_input;
use input::validate_coverage_binary;
use report::coverage_json;
use report::print_coverage_human;
pub(crate) use report::top_uncovered_crates;
use symbols::CoverageReportTree;
use symbols::symbolize_coverage;

fn permille(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        ((numerator as u128 * 1000) / denominator as u128) as u64
    }
}

fn percent_string_permille(permille: u64) -> String {
    format!("{}.{:01}%", permille / 10, permille % 10)
}

fn percent_string(numerator: u64, denominator: u64) -> String {
    percent_string_permille(permille(numerator, denominator))
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CoverageOptions {
    focus: Option<String>,
    top: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoverageInvocation {
    binary: PathBuf,
    input: PathBuf,
    options: CoverageOptions,
}

/// Parse `coverage <BINARY> <MAP|CAMPAIGN-OUT-DIR> [--focus PATH] [--top N]`.
pub(crate) fn parse(arguments: Vec<OsString>) -> Result<CoverageInvocation, CliError> {
    let scan = crate::locate_positionals("coverage", &arguments, 2);
    if scan.positionals.len() != 2 {
        return Err(CliError::usage(
            "coverage requires a binary path and a coverage map or campaign out-dir",
        ));
    }
    let args = cli::parse("coverage", help::Family::Sole, scan.rest)?;
    Ok(CoverageInvocation {
        binary: PathBuf::from(&scan.positionals[0]),
        input: PathBuf::from(&scan.positionals[1]),
        options: CoverageOptions {
            focus: args.string("--focus"),
            top: args.usize("--top"),
        },
    })
}

pub(crate) fn execute(invocation: CoverageInvocation) -> Result<i32, CliError> {
    let data = load_coverage_input(&invocation.input)?;
    validate_coverage_binary(&invocation.binary, &data)?;
    let report = symbolize_coverage(&invocation.binary, &data)?;
    if output::options().is_json() {
        println!(
            "{}",
            serde_json::to_string_pretty(&coverage_json(&invocation, &data, &report))
                .map_err(|error| CliError(format!("failed to encode coverage JSON: {error}")))?
        );
    } else {
        print_coverage_human(&invocation, &data, &report);
    }
    Ok(0)
}

#[cfg(test)]
mod tests;
