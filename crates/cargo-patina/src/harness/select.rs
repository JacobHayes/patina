//! Which packages and libtest targets an invocation covers, decided from
//! Cargo's own metadata the way `cargo test` decides them.

use super::{CargoFeatures, Selection, TestInvocation};
use crate::CliError;
use crate::shim_build::{RustcInvocation, apply_rustc_env};
use serde_json::Value;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

/// A libtest target's kind: the `cargo` flag that selects it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum TargetKind {
    Lib,
    Bin,
    Test,
}

impl TargetKind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Lib => "lib",
            Self::Bin => "bin",
            Self::Test => "test",
        }
    }
}

/// One libtest target of one package.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Target {
    pub(crate) package: String,
    pub(crate) kind: TargetKind,
    pub(crate) name: String,
}

impl Target {
    /// The `cargo` arguments that select this target alone.
    pub(crate) fn cargo_args(&self) -> Vec<String> {
        match self.kind {
            TargetKind::Lib => vec!["--lib".to_string()],
            TargetKind::Bin => vec!["--bin".to_string(), self.name.clone()],
            TargetKind::Test => vec!["--test".to_string(), self.name.clone()],
        }
    }

    /// How a reader is shown the target: its package and its selection flag.
    pub(crate) fn label(&self) -> String {
        format!("{} {}", self.package, self.cargo_args().join(" "))
    }
}

/// A target the selection covers that is not run, and why.
pub(crate) struct SkippedTarget {
    pub(crate) target: Target,
    pub(crate) reason: String,
}

pub(super) struct Selected {
    pub(super) targets: Vec<Target>,
    pub(super) skipped: Vec<SkippedTarget>,
    pub(super) target_dir: PathBuf,
}

/// `cargo metadata --no-deps` for `manifest`: the workspace members only.
pub(crate) fn cargo_metadata(
    manifest: &Path,
    rustc: Option<&RustcInvocation>,
) -> Result<Value, CliError> {
    let cargo = rustc
        .map(|r| r.cargo_command.clone())
        .unwrap_or_else(|| env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo")));
    let mut command = Command::new(&cargo);
    if let Some(rustc) = rustc {
        apply_rustc_env(&mut command, rustc);
    }
    let output = command
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .arg("--manifest-path")
        .arg(manifest)
        .output()
        .map_err(|error| CliError(format!("failed to run cargo metadata: {error}")))?;
    if !output.status.success() {
        return Err(CliError(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| CliError(format!("failed to parse cargo metadata: {error}")))
}

pub(crate) fn metadata_target_dir(metadata: &Value) -> Result<PathBuf, CliError> {
    metadata
        .get("target_directory")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| CliError("cargo metadata did not report target_directory".into()))
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn strings<'a>(value: &'a Value, key: &str) -> Vec<&'a str> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

pub(super) fn select(invocation: &TestInvocation, metadata: &Value) -> Result<Selected, CliError> {
    let packages = select_packages(metadata, &invocation.manifest, &invocation.selection)?;
    let (targets, skipped) =
        select_targets(&packages, &invocation.selection, &invocation.features)?;
    if targets.is_empty() && skipped.is_empty() {
        return Err(CliError::usage(format!(
            "no libtest target to test in {}",
            packages
                .iter()
                .filter_map(|package| text(package, "name"))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    Ok(Selected {
        targets,
        skipped,
        target_dir: metadata_target_dir(metadata)?,
    })
}

/// The packages `cargo test` would test: `--workspace`'s every member, the
/// `-p` names, or else the package whose manifest was named, and for a
/// virtual manifest the workspace's default members.
pub(super) fn select_packages<'a>(
    metadata: &'a Value,
    manifest: &Path,
    selection: &Selection,
) -> Result<Vec<&'a Value>, CliError> {
    let all: Vec<&Value> = metadata
        .get("packages")
        .and_then(Value::as_array)
        .map(|packages| packages.iter().collect())
        .unwrap_or_default();
    let members: BTreeSet<&str> = strings(metadata, "workspace_members").into_iter().collect();
    let members: Vec<&Value> = all
        .into_iter()
        .filter(|package| text(package, "id").is_some_and(|id| members.contains(id)))
        .collect();
    if selection.workspace {
        return Ok(members);
    }
    if !selection.packages.is_empty() {
        let mut chosen = Vec::new();
        for name in &selection.packages {
            let found = members
                .iter()
                .find(|package| text(package, "name") == Some(name.as_str()))
                .ok_or_else(|| {
                    CliError::usage(format!(
                        "package {name:?} is not a member of the workspace; its members: {}",
                        members
                            .iter()
                            .filter_map(|package| text(package, "name"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                })?;
            if !chosen
                .iter()
                .any(|package: &&Value| text(package, "id") == text(found, "id"))
            {
                chosen.push(*found);
            }
        }
        return Ok(chosen);
    }
    let canonical = |path: &Path| fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let wanted = canonical(manifest);
    if let Some(package) = members.iter().find(|package| {
        text(package, "manifest_path").is_some_and(|path| canonical(Path::new(path)) == wanted)
    }) {
        return Ok(vec![*package]);
    }
    let defaults: BTreeSet<&str> = strings(metadata, "workspace_default_members")
        .into_iter()
        .collect();
    Ok(members
        .into_iter()
        .filter(|package| {
            defaults.is_empty() || text(package, "id").is_some_and(|id| defaults.contains(id))
        })
        .collect())
}

/// A metadata target's libtest kind, if it has a libtest harness at all. A
/// `[lib]` reports its crate types as its kinds, so a dependency-style
/// `crate-type = ["rlib", "cdylib"]` library is still a library; build
/// scripts, examples and benches are not tested.
fn libtest_kind(target: &Value) -> Option<TargetKind> {
    let kinds = strings(target, "kind");
    if !kinds.is_empty()
        && kinds.iter().all(|kind| {
            matches!(
                *kind,
                "lib" | "rlib" | "dylib" | "cdylib" | "staticlib" | "proc-macro"
            )
        })
    {
        Some(TargetKind::Lib)
    } else if kinds == ["test"] {
        Some(TargetKind::Test)
    } else if kinds == ["bin"] {
        Some(TargetKind::Bin)
    } else {
        None
    }
}

/// Whether `wanted` names the target `name`: its own name, or the crate name
/// Cargo derives from it (`-` as `_`), which is all a compiled test knows of
/// itself.
fn names(wanted: &str, name: &str) -> bool {
    wanted == name || wanted == name.replace('-', "_")
}

pub(super) fn select_targets(
    packages: &[&Value],
    selection: &Selection,
    features: &CargoFeatures,
) -> Result<(Vec<Target>, Vec<SkippedTarget>), CliError> {
    let mut targets = Vec::new();
    let mut skipped = Vec::new();
    let mut unmatched_bins: Vec<&String> = selection.bins.iter().collect();
    let mut unmatched_tests: Vec<&String> = selection.tests.iter().collect();
    let mut unmatched_skips: Vec<&String> = selection.skip_targets.iter().collect();
    let mut available = BTreeSet::new();
    for package in packages {
        let package_name = text(package, "name").unwrap_or_default().to_string();
        let enabled = enabled_features(package, features);
        let package_targets = package
            .get("targets")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for entry in package_targets {
            let Some(kind) = libtest_kind(entry) else {
                continue;
            };
            let name = text(entry, "name").unwrap_or_default().to_string();
            available.insert(format!("{package_name} {} {name}", kind.name()));
            let explicit = match kind {
                TargetKind::Lib => selection.lib,
                TargetKind::Bin => selection.bins.iter().any(|wanted| names(wanted, &name)),
                TargetKind::Test => selection.tests.iter().any(|wanted| names(wanted, &name)),
            };
            unmatched_bins.retain(|wanted| !(kind == TargetKind::Bin && names(wanted, &name)));
            unmatched_tests.retain(|wanted| !(kind == TargetKind::Test && names(wanted, &name)));
            let chosen = if selection.names_targets() {
                explicit
                    || (kind == TargetKind::Bin && selection.all_bins)
                    || (kind == TargetKind::Test && selection.all_tests)
            } else {
                // `cargo test`'s default: every target whose `test` is on.
                entry.get("test").and_then(Value::as_bool) != Some(false)
            };
            if !chosen {
                continue;
            }
            let target = Target {
                package: package_name.clone(),
                kind,
                name,
            };
            if selection
                .skip_targets
                .iter()
                .any(|skip| names(skip, &target.name))
            {
                unmatched_skips.retain(|skip| !names(skip, &target.name));
                skipped.push(SkippedTarget {
                    target,
                    reason: "--skip-target".to_string(),
                });
                continue;
            }
            let missing: Vec<&str> = strings(entry, "required-features")
                .into_iter()
                .filter(|feature| {
                    !enabled
                        .as_ref()
                        .is_none_or(|enabled| enabled.contains(*feature))
                })
                .collect();
            if !missing.is_empty() {
                let reason = format!("requires the features: {}", missing.join(", "));
                if explicit {
                    return Err(CliError::usage(format!(
                        "target {} {reason}; consider --features {}",
                        target.label(),
                        missing.join(",")
                    )));
                }
                skipped.push(SkippedTarget { target, reason });
                continue;
            }
            targets.push(target);
        }
    }
    if let Some(wanted) = unmatched_bins.first().or(unmatched_tests.first()) {
        let kind = if unmatched_bins.is_empty() {
            "test"
        } else {
            "bin"
        };
        return Err(CliError::usage(format!(
            "no {kind} target named {wanted:?} in the selected packages; their libtest targets: {}",
            if available.is_empty() {
                "<none>".to_string()
            } else {
                available.into_iter().collect::<Vec<_>>().join(", ")
            }
        )));
    }
    // A skip that names nothing selected is a typo, not a smaller suite.
    if let Some(skip) = unmatched_skips.first() {
        return Err(CliError::usage(format!(
            "--skip-target {skip:?} names no selected target; the selected targets: {}",
            targets
                .iter()
                .chain(skipped.iter().map(|skipped| &skipped.target))
                .map(Target::label)
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    if selection.lib && !targets.iter().any(|target| target.kind == TargetKind::Lib) {
        return Err(CliError::usage("--lib: no selected package has a library"));
    }
    targets.sort();
    targets.dedup();
    Ok((targets, skipped))
}

/// The package's features the invocation enables, closed over the features
/// each one enables in turn; `None` for all of them. Only the package's own
/// feature names are followed (`dep:`/`pkg/feature` entries enable nothing
/// here), which is all `required-features` can name of it.
fn enabled_features(package: &Value, features: &CargoFeatures) -> Option<BTreeSet<String>> {
    if features.all_features {
        return None;
    }
    let table = package.get("features").and_then(Value::as_object);
    let package_name = text(package, "name").unwrap_or_default();
    let mut pending: Vec<String> = features
        .features
        .iter()
        .flat_map(|list| list.split([',', ' ']))
        .filter(|feature| !feature.is_empty())
        .filter_map(|feature| match feature.split_once('/') {
            Some((package, feature)) if package == package_name => Some(feature.to_string()),
            Some(_) => None,
            None => Some(feature.to_string()),
        })
        .collect();
    if !features.no_default_features && table.is_some_and(|table| table.contains_key("default")) {
        pending.push("default".to_string());
    }
    let mut enabled = BTreeSet::new();
    while let Some(feature) = pending.pop() {
        if !enabled.insert(feature.clone()) {
            continue;
        }
        if let Some(implied) = table
            .and_then(|table| table.get(&feature))
            .and_then(Value::as_array)
        {
            pending.extend(
                implied
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|entry| !entry.contains(':') && !entry.contains('/'))
                    .map(str::to_owned),
            );
        }
    }
    Some(enabled)
}
