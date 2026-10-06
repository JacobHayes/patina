//! Campaign state persistence, artifact identity, and out-dir locking.

use super::observe::{DepthState, EdgeCoverageState};
use super::spec::classify_rules_to_json;
use super::{
    AllowUnmetSometimes, CampaignClass, CampaignSpec, FAULT_SCALE_FULL, STARVE_SCALE_FULL,
    VerdictFacts,
};
use crate::CliError;
use crate::aux_store::validate_resume_watermark;
use crate::sdk_report::CoverageTally;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// The out-dir's resumable state. `v2` adds `verdicts` to every notable run: the
/// `(kind, label)` set the generation reported through the verdict ABI, which is
/// what `minimize --generation N` targets when no `--marker` is given. It is a
/// required field, not an optional one — a v1 out-dir is refused by name rather
/// than resumed with a silently empty verdict set that would make an auto-target
/// minimize look like "this generation reported nothing".
const CAMPAIGN_STATE_SCHEMA: &str = "patina.campaign.state/v2";
const CAMPAIGN_SIGNATURES_SCHEMA: &str = "patina.campaign.signatures/v1";

// ===========================================================================
// Signature store
// ===========================================================================

/// One accumulated failure signature and its provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SignatureRecord {
    pub(super) class: CampaignClass,
    pub(super) shape: String,
    pub(super) policy: String,
    pub(super) first_seen_gen: u64,
    pub(super) count: u64,
    pub(super) seed: u64,
    pub(super) reproduce: String,
    pub(super) trace: Option<String>,
    /// `failures/generation-N.log` — the child's streams, kept only for a failure
    /// that left no replayable trace. Stored RELATIVE to the campaign's output
    /// directory: the store lives in that directory, and an absolute path would
    /// make two runs of the same campaign into two different output directories
    /// produce different stores, when the whole purpose of a dedup record is
    /// that identical failures produce identical records. (`trace` and `report`
    /// above predate this and are still absolute.)
    pub(super) log: Option<String>,
    pub(super) report: Option<String>,
}

impl SignatureRecord {
    fn to_json(&self, key: &str) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert("signature".into(), key.into());
        map.insert("class".into(), self.class.as_str().into());
        map.insert("shape".into(), self.shape.clone().into());
        if !self.policy.is_empty() {
            map.insert("policy".into(), self.policy.clone().into());
        }
        map.insert("first_seen_gen".into(), self.first_seen_gen.into());
        map.insert("count".into(), self.count.into());
        map.insert("seed".into(), self.seed.into());
        map.insert("reproduce".into(), self.reproduce.clone().into());
        if let Some(trace) = &self.trace {
            map.insert("trace".into(), trace.clone().into());
        }
        if let Some(log) = &self.log {
            map.insert("log".into(), log.clone().into());
        }
        if let Some(report) = &self.report {
            map.insert("report".into(), report.clone().into());
        }
        serde_json::Value::Object(map)
    }

    fn from_json(value: &serde_json::Value) -> Result<(String, Self), String> {
        let object = value
            .as_object()
            .ok_or_else(|| "signature record must be an object".to_string())?;
        let key = json_required_str(object, "signature")?.to_string();
        let class_text = json_required_str(object, "class")?;
        let class = CampaignClass::parse(class_text)
            .ok_or_else(|| format!("unknown campaign class {class_text:?}"))?;
        let shape = json_required_str(object, "shape")?.to_string();
        let policy = json_optional_str(object, "policy")?.unwrap_or_default();
        let record = SignatureRecord {
            class,
            shape,
            policy,
            first_seen_gen: json_required_u64(object, "first_seen_gen")?,
            count: json_required_u64(object, "count")?,
            seed: json_required_u64(object, "seed")?,
            reproduce: json_required_str(object, "reproduce")?.to_string(),
            trace: json_optional_str(object, "trace")?,
            log: json_optional_str(object, "log")?,
            report: json_optional_str(object, "report")?,
        };
        let expected_key = format!(
            "{}|{}|{}",
            record.class.as_str(),
            record.shape,
            record.policy
        );
        if key != expected_key {
            return Err(format!(
                "signature key {key:?} does not match canonical key {expected_key:?}"
            ));
        }
        if record.to_json(&key) != *value {
            return Err("signature record is not in canonical lossless form".to_string());
        }
        Ok((key, record))
    }
}

// ===========================================================================
// Campaign driver
// ===========================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct GenerationOutcome {
    pub(super) generation: u64,
    pub(super) seed: u64,
    pub(super) class: CampaignClass,
    pub(super) flags: Vec<String>,
    pub(super) novel: bool,
    pub(super) signature_key: Option<String>,
    /// What this generation reported through the verdict ABI, from
    /// [`recognize_verdicts`]. Persisted because it is the campaign's own record
    /// of WHICH failure the generation was, and `minimize --generation N` needs
    /// exactly that to build its oracle without being handed a `--marker`: the
    /// campaign already recognized the failure, so re-deriving it from a fresh
    /// run would only ask minimize to target whatever a re-run happens to
    /// produce. The recorded set is the target; the seed re-run must then still
    /// contain it, which is what makes an unreproducible target a refusal rather
    /// than a tautology.
    pub(super) verdicts: Vec<VerdictFacts>,
}

impl GenerationOutcome {
    pub(super) fn is_notable(&self) -> bool {
        self.novel || self.class.is_failure()
    }

    pub(super) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "generation": self.generation,
            "seed": self.seed,
            "class": self.class.as_str(),
            "novel": self.novel,
            "signature": self.signature_key.clone(),
            "flags": self.flags.clone(),
            "verdicts": self.verdicts.iter().map(VerdictFacts::to_json).collect::<Vec<_>>(),
        })
    }

    fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "notable run must be an object".to_string())?;
        let class_text = json_required_str(object, "class")?;
        let class = CampaignClass::parse(class_text)
            .ok_or_else(|| format!("unknown campaign class {class_text:?}"))?;
        let flags = object
            .get("flags")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| "notable run flags must be an array".to_string())?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| "notable run flags entries must be strings".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let signature_key = match object.get("signature") {
            Some(serde_json::Value::Null) => None,
            Some(value) => Some(
                value
                    .as_str()
                    .ok_or_else(|| "notable run signature must be a string or null".to_string())?
                    .to_string(),
            ),
            None => return Err("notable run missing signature".to_string()),
        };
        let verdicts = object
            .get("verdicts")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| "notable run verdicts must be an array".to_string())?
            .iter()
            .map(VerdictFacts::from_json)
            .collect::<Result<Vec<_>, _>>()?;
        let outcome = GenerationOutcome {
            generation: json_required_u64(object, "generation")?,
            seed: json_required_u64(object, "seed")?,
            class,
            flags,
            novel: json_required_bool(object, "novel")?,
            signature_key,
            verdicts,
        };
        if outcome.to_json() != *value {
            return Err("notable run is not in canonical lossless form".to_string());
        }
        Ok(outcome)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ArtifactIdentity {
    pub(super) path: String,
    pub(super) sha256: String,
    pub(super) family: &'static str,
}

impl ArtifactIdentity {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "path": self.path.clone(),
            "sha256": self.sha256.clone(),
            "family": self.family,
        })
    }

    fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "artifact identity must be an object".to_string())?;
        let family_text = json_required_str(object, "family")?;
        let family = parse_artifact_family(family_text)
            .ok_or_else(|| format!("unknown artifact family {family_text:?}"))?;
        let identity = ArtifactIdentity {
            path: json_required_str(object, "path")?.to_string(),
            sha256: json_required_str(object, "sha256")?.to_string(),
            family,
        };
        if identity.to_json() != *value {
            return Err("artifact identity is not in canonical lossless form".to_string());
        }
        Ok(identity)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct InvocationRecord {
    pub(super) cli: String,
    pub(super) from_gen: u64,
    pub(super) gens_run: u64,
    pub(super) timeout_secs: u64,
    pub(super) elapsed_secs: u64,
}

impl InvocationRecord {
    pub(super) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "cli": self.cli.clone(),
            "from_gen": self.from_gen,
            "gens_run": self.gens_run,
            "timeout_secs": self.timeout_secs,
            "elapsed_secs": self.elapsed_secs,
        })
    }

    fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "invocation record must be an object".to_string())?;
        let record = InvocationRecord {
            cli: json_required_str(object, "cli")?.to_string(),
            from_gen: json_required_u64(object, "from_gen")?,
            gens_run: json_required_u64(object, "gens_run")?,
            timeout_secs: json_required_u64(object, "timeout_secs")?,
            elapsed_secs: json_required_u64(object, "elapsed_secs")?,
        };
        if record.to_json() != *value {
            return Err("invocation record is not in canonical lossless form".to_string());
        }
        Ok(record)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CampaignState {
    pub(super) artifact: ArtifactIdentity,
    pub(super) spec: CampaignSpec,
    pub(super) generations_done: u64,
    pub(super) classes: BTreeMap<String, u64>,
    pub(super) signatures: BTreeMap<String, SignatureRecord>,
    pub(super) notable_runs: Vec<GenerationOutcome>,
    pub(super) invocations: Vec<InvocationRecord>,
}

impl CampaignState {
    pub(super) fn fresh(artifact: ArtifactIdentity, spec: CampaignSpec) -> Self {
        Self {
            artifact,
            spec,
            generations_done: 0,
            classes: BTreeMap::new(),
            signatures: BTreeMap::new(),
            notable_runs: Vec::new(),
            invocations: Vec::new(),
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": CAMPAIGN_STATE_SCHEMA,
            "artifact": self.artifact.to_json(),
            "spec": spec_to_json(&self.spec),
            "generations_done": self.generations_done,
            "classes": self.classes.clone(),
            "signatures": signatures_to_json(&self.signatures),
            "notable_runs": self.notable_runs.iter().map(GenerationOutcome::to_json).collect::<Vec<_>>(),
            "invocations": self.invocations.iter().map(InvocationRecord::to_json).collect::<Vec<_>>(),
        })
    }

    fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "campaign state must be a JSON object".to_string())?;
        let schema = json_required_str(object, "schema")?;
        if schema != CAMPAIGN_STATE_SCHEMA {
            return Err(format!("unsupported schema {schema:?}"));
        }
        let artifact = ArtifactIdentity::from_json(
            object
                .get("artifact")
                .ok_or_else(|| "campaign state missing artifact".to_string())?,
        )?;
        let spec = spec_from_state_json(
            object
                .get("spec")
                .ok_or_else(|| "campaign state missing spec".to_string())?,
        )?;
        let generations_done = json_required_u64(object, "generations_done")?;
        let classes = parse_class_counts(
            object
                .get("classes")
                .ok_or_else(|| "campaign state missing classes".to_string())?,
        )?;
        let signatures = parse_signature_records(
            object
                .get("signatures")
                .ok_or_else(|| "campaign state missing signatures".to_string())?,
        )?;
        let notable_runs = parse_notable_runs(
            object
                .get("notable_runs")
                .ok_or_else(|| "campaign state missing notable_runs".to_string())?,
        )?;
        let invocations = parse_invocations(
            object
                .get("invocations")
                .ok_or_else(|| "campaign state missing invocations".to_string())?,
        )?;
        let state = CampaignState {
            artifact,
            spec,
            generations_done,
            classes,
            signatures,
            notable_runs,
            invocations,
        };
        state.validate()?;
        if state.to_json() != *value {
            return Err("campaign state is not in canonical lossless form".to_string());
        }
        Ok(state)
    }

    fn validate(&self) -> Result<(), String> {
        if self.generations_done > self.spec.generations {
            return Err(format!(
                "generations_done={} exceeds target generations={}",
                self.generations_done, self.spec.generations
            ));
        }
        let counted: u64 = self.classes.values().sum();
        if counted != self.generations_done {
            return Err(format!(
                "class histogram counts {counted} generations but cursor is {}",
                self.generations_done
            ));
        }
        let signature_total: u64 = self.signatures.values().map(|record| record.count).sum();
        let failures = class_counts_failures(&self.classes);
        if signature_total != failures {
            return Err(format!(
                "signature counts {signature_total} failures but class histogram has {failures}"
            ));
        }
        for run in &self.notable_runs {
            if run.generation >= self.generations_done {
                return Err(format!(
                    "notable run generation {} is beyond cursor {}",
                    run.generation, self.generations_done
                ));
            }
            if !run.is_notable() {
                return Err(format!(
                    "non-notable OK generation {} was persisted as notable",
                    run.generation
                ));
            }
        }
        Ok(())
    }
}

pub(super) fn json_required_str<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'a str, String> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("{key} must be a string"))
}

fn json_optional_str(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<String>, String> {
    match object.get(key) {
        Some(value) => value
            .as_str()
            .map(|text| Some(text.to_string()))
            .ok_or_else(|| format!("{key} must be a string")),
        None => Ok(None),
    }
}

fn json_required_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64, String> {
    object
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("{key} must be an unsigned integer"))
}

fn json_required_bool(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<bool, String> {
    object
        .get(key)
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| format!("{key} must be a boolean"))
}

pub(super) fn spec_to_json(spec: &CampaignSpec) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("generations".into(), spec.generations.into());
    map.insert("seed_base".into(), spec.seed_base.into());
    map.insert("timeout_secs".into(), spec.timeout_secs.into());
    map.insert("guest_args".into(), spec.guest_args.clone().into());
    map.insert("buggify".into(), spec.buggify.into());
    map.insert("swarm".into(), spec.swarm.into());
    map.insert("pct".into(), spec.pct.into());
    map.insert("faults".into(), spec.faults.into());
    // Default-omitted for the same reason as the keys below: a spec that does
    // not declare custom-op faults records exactly the JSON it did before this
    // key existed, so an out-dir written by an earlier build still round-trips
    // on `--resume`.
    // Written only when it differs from the default, exactly like the optional
    // keys around it: `spec_from_state_json` rebuilds from `CampaignSpec::default()`
    // and then demands `spec_to_json` reproduce the file byte for byte, so an
    // unconditional key would make every out-dir recorded before this flag
    // existed fail its canonical-form check on `--resume`.
    if spec.fault_scale_permille != FAULT_SCALE_FULL {
        map.insert(
            "fault_scale_permille".into(),
            spec.fault_scale_permille.into(),
        );
    }
    if spec.custom_op_faults {
        map.insert("custom_op_faults".into(), true.into());
    }
    // Default-omitted for the same round-trip reason as the keys around it: a
    // campaign that does not explore starvation records exactly the JSON it did
    // before this key existed, so an out-dir written by an earlier build still
    // passes the canonical-form check on `--resume`.
    if spec.starve {
        map.insert("starve".into(), true.into());
    }
    // Default-omitted for the same reason as every optional key around it: the
    // canonical-form gate `--resume` reloads through demands `spec_to_json`
    // reproduce the recorded file exactly, so an unconditional key would break
    // every out-dir written before this flag existed.
    if spec.starve_scale_permille != STARVE_SCALE_FULL {
        map.insert(
            "starve_scale_permille".into(),
            spec.starve_scale_permille.into(),
        );
    }
    // Emitted only when the campaign HAS a host table, so a DNS-free spec's
    // recorded JSON is byte-identical to what it was before the key existed and
    // an out-dir written by an earlier build still round-trips on `--resume`.
    if !spec.dns_entries.is_empty() {
        map.insert("dns_entries".into(), spec.dns_entries.clone().into());
    }
    // Same default-omit rule as the host table above: a campaign that forwards
    // none of the native harness/gate surface records exactly the JSON it did
    // before these keys existed, so an out-dir written by an earlier build still
    // round-trips through the canonical-form check on `--resume`.
    if spec.harness {
        map.insert("harness".into(), true.into());
    }
    if !spec.allow_symbols.is_empty() {
        map.insert("allow_symbols".into(), spec.allow_symbols.clone().into());
    }
    if let Some(value) = &spec.allow_unsupported_symbols {
        map.insert("allow_unsupported_symbols".into(), value.clone().into());
    }
    if let Some(value) = spec.watchdog_nanos {
        map.insert("watchdog_nanos".into(), value.into());
    }
    if let Some(value) = spec.converge_nanos {
        map.insert("converge_nanos".into(), value.into());
    }
    if let Some(value) = spec.compute_watchdog_ms {
        map.insert("compute_watchdog_ms".into(), value.into());
    }
    if let Some(value) = spec.heal_after_nanos {
        map.insert("heal_after_nanos".into(), value.into());
    }
    map.insert("report".into(), spec.report.into());
    map.insert("plateau_after".into(), spec.plateau_after.into());
    map.insert("guided".into(), spec.guided.into());
    if let Some(value) = spec.allow_unmet_sometimes {
        map.insert("allow_unmet_sometimes".into(), allow_unmet_to_json(value));
    }
    // Default-omit, like the host table above: a spec with no declared rules
    // records exactly the JSON it did before this key existed, so an out-dir
    // written by an earlier build still round-trips on `--resume`.
    if !spec.classify.is_empty() {
        map.insert("classify".into(), classify_rules_to_json(&spec.classify));
    }
    serde_json::Value::Object(map)
}

pub(super) fn allow_unmet_to_json(value: AllowUnmetSometimes) -> serde_json::Value {
    match value {
        AllowUnmetSometimes::Always => serde_json::Value::Bool(true),
        AllowUnmetSometimes::BelowGenerations(min) => serde_json::Value::from(min),
    }
}

pub(super) fn spec_from_state_json(value: &serde_json::Value) -> Result<CampaignSpec, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "spec must be an object".to_string())?;
    for key in [
        "generations",
        "seed_base",
        "timeout_secs",
        "guest_args",
        "buggify",
        "swarm",
        "pct",
        "faults",
        "report",
        "plateau_after",
    ] {
        if !object.contains_key(key) {
            return Err(format!("spec missing required key {key:?}"));
        }
    }
    let mut spec = CampaignSpec::default();
    spec.apply_json(value).map_err(|error| error.to_string())?;
    if spec_to_json(&spec) != *value {
        return Err("spec is not in canonical lossless form".to_string());
    }
    Ok(spec)
}

pub(super) fn signatures_to_json(
    signatures: &BTreeMap<String, SignatureRecord>,
) -> Vec<serde_json::Value> {
    signatures
        .iter()
        .map(|(key, record)| record.to_json(key))
        .collect()
}

fn parse_signature_records(
    value: &serde_json::Value,
) -> Result<BTreeMap<String, SignatureRecord>, String> {
    let entries = value
        .as_array()
        .ok_or_else(|| "signatures must be an array".to_string())?;
    let mut signatures = BTreeMap::new();
    for entry in entries {
        let (key, record) = SignatureRecord::from_json(entry)?;
        if signatures.insert(key.clone(), record).is_some() {
            return Err(format!("duplicate signature record {key:?}"));
        }
    }
    Ok(signatures)
}

fn parse_notable_runs(value: &serde_json::Value) -> Result<Vec<GenerationOutcome>, String> {
    value
        .as_array()
        .ok_or_else(|| "notable_runs must be an array".to_string())?
        .iter()
        .map(GenerationOutcome::from_json)
        .collect()
}

fn parse_invocations(value: &serde_json::Value) -> Result<Vec<InvocationRecord>, String> {
    value
        .as_array()
        .ok_or_else(|| "invocations must be an array".to_string())?
        .iter()
        .map(InvocationRecord::from_json)
        .collect()
}

fn parse_class_counts(value: &serde_json::Value) -> Result<BTreeMap<String, u64>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "classes must be an object".to_string())?;
    let mut classes = BTreeMap::new();
    for (class, count) in object {
        CampaignClass::parse(class).ok_or_else(|| format!("unknown campaign class {class:?}"))?;
        let count = count
            .as_u64()
            .ok_or_else(|| format!("class count for {class:?} must be an unsigned integer"))?;
        classes.insert(class.clone(), count);
    }
    Ok(classes)
}

pub(super) fn class_counts_failures(class_counts: &BTreeMap<String, u64>) -> u64 {
    class_counts
        .iter()
        .filter_map(|(class, count)| {
            CampaignClass::parse(class)
                .filter(CampaignClass::is_failure)
                .map(|_| *count)
        })
        .sum()
}

fn parse_artifact_family(value: &str) -> Option<&'static str> {
    match value {
        "native" => Some("native"),
        "wasi" => Some("wasi"),
        _ => None,
    }
}

fn artifact_family_from_bytes(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"\0asm") {
        "wasi"
    } else {
        "native"
    }
}

pub(super) fn artifact_identity(path: &Path) -> Result<ArtifactIdentity, CliError> {
    let bytes = fs::read(path)
        .map_err(|e| CliError(format!("failed to read artifact {}: {e}", path.display())))?;
    Ok(ArtifactIdentity {
        path: path.display().to_string(),
        sha256: sha256_hex(&bytes),
        family: artifact_family_from_bytes(&bytes),
    })
}

pub(super) fn verify_artifact_identity(recorded: &ArtifactIdentity) -> Result<(), CliError> {
    let path = PathBuf::from(&recorded.path);
    let current = artifact_identity(&path).map_err(|error| {
        CliError(format!(
            "campaign out-dir records artifact {} but it cannot be read: {error}; start a new out-dir if the artifact moved",
            recorded.path
        ))
    })?;
    if current.sha256 != recorded.sha256 {
        return Err(CliError(format!(
            "campaign out-dir records artifact sha256 {} but {} now hashes {}; the artifact changed since this campaign started. Signatures from different builds are not comparable — start a new out-dir for the new build.",
            recorded.sha256, recorded.path, current.sha256
        )));
    }
    if current.family != recorded.family {
        return Err(CliError(format!(
            "campaign out-dir records artifact family {} but {} is now {}; start a new out-dir for the new build",
            recorded.family, recorded.path, current.family
        )));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(super) fn write_campaign_checkpoint(
    state_path: &Path,
    store_path: &Path,
    sites_path: &Path,
    state: &CampaignState,
    coverage: &CoverageTally,
    edge_coverage: &EdgeCoverageState,
    depth: &DepthState,
) -> Result<(), CliError> {
    // The state cursor is the checkpoint readers poll. Write the derived stores
    // first, then the state file, so an observed advanced cursor has matching
    // signatures/sites/native-coverage artifacts. Native coverage writes before
    // the cursor on purpose: if a crash tears here, generations_applied may be
    // one ahead and resume will re-run then watermark-skip that generation.
    if let Some(store) = edge_coverage.active() {
        store.write_checkpoint()?;
    }
    if let Some(store) = depth.active() {
        store.write_checkpoint()?;
    }
    write_sites_store(sites_path, coverage)?;
    write_signature_store(store_path, &state.signatures)?;
    write_campaign_state(state_path, state)
}

fn write_campaign_state(path: &Path, state: &CampaignState) -> Result<(), CliError> {
    state
        .validate()
        .map_err(|error| CliError(format!("refusing to write invalid campaign state: {error}")))?;
    atomic_write_json(path, &state.to_json(), "campaign state")
}

pub(super) fn load_campaign_state(path: &Path) -> Result<CampaignState, CliError> {
    let text = fs::read_to_string(path).map_err(|e| {
        CliError(format!(
            "failed to read campaign state {}: {e}",
            path.display()
        ))
    })?;
    let json: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        CliError(format!(
            "campaign state {} is invalid JSON: {e}",
            path.display()
        ))
    })?;
    match CampaignState::from_json(&json) {
        Ok(state) => Ok(state),
        Err(error) if error.starts_with("unsupported schema") => Err(CliError(format!(
            "campaign state {} has {error}; this out-dir was written by a different cargo-patina version; finish it with that version or start a new out-dir",
            path.display()
        ))),
        Err(error) => Err(CliError(format!(
            "campaign state {} is corrupt: {error}; refusing to resume partially",
            path.display()
        ))),
    }
}

pub(super) fn load_coverage_tally(
    path: &Path,
    generations_done: u64,
) -> Result<CoverageTally, CliError> {
    if !path.exists() {
        return Err(CliError(format!(
            "campaign out-dir is missing sites store {} for {} already-recorded generations; refusing to resume partially",
            path.display(),
            generations_done
        )));
    }
    let text = fs::read_to_string(path).map_err(|error| {
        CliError(format!(
            "failed to read campaign sites store {}: {error}",
            path.display()
        ))
    })?;
    let json: serde_json::Value = serde_json::from_str(&text).map_err(|error| {
        CliError(format!(
            "campaign sites store {} is invalid JSON: {error}",
            path.display()
        ))
    })?;
    let tally = CoverageTally::from_json(&json).map_err(|error| {
        CliError(format!(
            "campaign sites store {} is corrupt: {error}; refusing to resume partially",
            path.display()
        ))
    })?;
    let label = format!("campaign sites store {}", path.display());
    validate_resume_watermark(
        &label,
        "generations_observed",
        tally.generations_observed,
        generations_done,
        "per-generation SDK reports are transient, so refusing to resume with missing sites folds",
    )?;
    Ok(tally)
}

fn write_signature_store(
    path: &Path,
    signatures: &BTreeMap<String, SignatureRecord>,
) -> Result<(), CliError> {
    let store = serde_json::json!({
        "schema": CAMPAIGN_SIGNATURES_SCHEMA,
        "signatures": signatures_to_json(signatures),
    });
    atomic_write_json(path, &store, "signature store")
}

fn write_sites_store(path: &Path, coverage: &CoverageTally) -> Result<(), CliError> {
    atomic_write_json(path, &coverage.to_json(), "campaign sites store")
}

fn atomic_write_json(path: &Path, value: &serde_json::Value, label: &str) -> Result<(), CliError> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|e| CliError(format!("failed to serialize {label}: {e}")))?;
    atomic_write(path, text.as_bytes(), label)
}

fn atomic_write(path: &Path, bytes: &[u8], label: &str) -> Result<(), CliError> {
    let parent = path
        .parent()
        .ok_or_else(|| CliError(format!("{label} path {} has no parent", path.display())))?;
    fs::create_dir_all(parent).map_err(|e| {
        CliError(format!(
            "failed to create {label} dir {}: {e}",
            parent.display()
        ))
    })?;
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(OsStr::to_str).unwrap_or("json")
    ));
    {
        let mut file = File::create(&tmp).map_err(|e| {
            CliError(format!(
                "failed to create temporary {label} {}: {e}",
                tmp.display()
            ))
        })?;
        file.write_all(bytes).map_err(|e| {
            CliError(format!(
                "failed to write temporary {label} {}: {e}",
                tmp.display()
            ))
        })?;
        file.sync_all().map_err(|e| {
            CliError(format!(
                "failed to sync temporary {label} {}: {e}",
                tmp.display()
            ))
        })?;
    }
    fs::rename(&tmp, path).map_err(|e| {
        CliError(format!(
            "failed to atomically replace {label} {}: {e}",
            path.display()
        ))
    })
}

/// The campaign out-dir as an absolute path. Nothing is created or canonicalized
/// — a fresh campaign's out-dir need not exist yet, and resolving symlinks would
/// rewrite a path the operator typed — the cwd is simply folded in once, at the
/// only moment the campaign's cwd is known to be the operator's.
pub(super) fn absolute_out_dir(out_dir: &Path) -> Result<PathBuf, CliError> {
    if out_dir.is_absolute() {
        return Ok(out_dir.to_path_buf());
    }
    let cwd = std::env::current_dir().map_err(|e| {
        CliError(format!(
            "failed to resolve campaign out-dir {}: {e}",
            out_dir.display()
        ))
    })?;
    Ok(cwd.join(out_dir))
}

#[derive(Debug)]
pub(super) struct CampaignLock {
    _file: File,
}

impl CampaignLock {
    pub(super) fn acquire(out_dir: &Path) -> Result<Self, CliError> {
        fs::create_dir_all(out_dir)
            .map_err(|e| CliError(format!("failed to create campaign output dir: {e}")))?;
        let path = out_dir.join("campaign.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| {
                CliError(format!(
                    "failed to open campaign lock {}: {e}",
                    path.display()
                ))
            })?;
        acquire_flock(&file, out_dir)?;
        Ok(Self { _file: file })
    }
}

fn acquire_flock(file: &File, out_dir: &Path) -> Result<(), CliError> {
    crate::lock_exclusive(file, false).map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            CliError(format!(
                "another campaign is writing this out-dir: {}",
                out_dir.display()
            ))
        } else {
            CliError(format!(
                "failed to lock campaign out-dir {}: {error}",
                out_dir.display()
            ))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::super::{CampaignClass, CampaignSpec, VerdictFacts};
    use super::*;
    use crate::sdk_report::CoverageTally;
    use std::fs;

    #[test]
    fn sites_load_validates_resume_watermark() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sites.json");
        let coverage = CoverageTally {
            generations_observed: 2,
            ..CoverageTally::default()
        };
        write_sites_store(&path, &coverage).unwrap();

        load_coverage_tally(&path, 1).expect("one-generation tear ahead is resumable");
        load_coverage_tally(&path, 2).expect("aligned cursor is resumable");

        let behind = load_coverage_tally(&path, 3).unwrap_err();
        assert!(
            behind.0.contains("missing sites folds"),
            "unexpected error: {behind}"
        );
        let ahead = load_coverage_tally(&path, 0).unwrap_err();
        assert!(
            ahead
                .0
                .contains("at most one checkpoint-tear generation ahead"),
            "unexpected error: {ahead}"
        );

        let mut bad_schema = coverage.to_json();
        bad_schema["schema"] = "patina.campaign.sites/v999".into();
        fs::write(&path, serde_json::to_string_pretty(&bad_schema).unwrap()).unwrap();
        let schema = load_coverage_tally(&path, 2).unwrap_err();
        assert!(
            schema.0.contains("unsupported schema"),
            "unexpected error: {schema}"
        );

        fs::remove_file(&path).unwrap();
        let missing = load_coverage_tally(&path, 0).unwrap_err();
        assert!(
            missing.0.contains("missing sites store"),
            "unexpected error: {missing}"
        );
    }

    #[test]
    fn campaign_state_round_trips_byte_stably_and_rejects_corruption() {
        let mut state = CampaignState::fresh(
            ArtifactIdentity {
                path: "guest".to_string(),
                sha256: "abc".to_string(),
                family: "native",
            },
            CampaignSpec {
                generations: 3,
                timeout_secs: 9,
                buggify: true,
                watchdog_nanos: Some(5),
                ..CampaignSpec::default()
            },
        );
        state.generations_done = 2;
        state.classes.insert("OK".to_string(), 1);
        state.classes.insert("LIVENESS".to_string(), 1);
        let key = "LIVENESS|PATINA_VIOLATION liveness #|".to_string();
        state.signatures.insert(
            key.clone(),
            SignatureRecord {
                class: CampaignClass::Liveness,
                shape: "PATINA_VIOLATION liveness #".to_string(),
                policy: String::new(),
                first_seen_gen: 1,
                count: 1,
                seed: 42,
                reproduce: "cargo patina run guest --seed 42".to_string(),
                trace: None,
                log: None,
                report: None,
            },
        );
        state.notable_runs.push(GenerationOutcome {
            generation: 1,
            seed: 42,
            class: CampaignClass::Liveness,
            flags: vec!["--liveness-watchdog".to_string(), "5".to_string()],
            novel: true,
            signature_key: Some(key),
            verdicts: vec![VerdictFacts {
                kind: "violation".to_string(),
                label: "no-loss".to_string(),
            }],
        });
        state.invocations.push(InvocationRecord {
            cli: "campaign guest --gens 3".to_string(),
            from_gen: 0,
            gens_run: 2,
            timeout_secs: 9,
            elapsed_secs: 1,
        });
        let pretty = serde_json::to_string_pretty(&state.to_json()).unwrap();
        let parsed_json: serde_json::Value = serde_json::from_str(&pretty).unwrap();
        let loaded = CampaignState::from_json(&parsed_json).unwrap();
        assert_eq!(
            pretty,
            serde_json::to_string_pretty(&loaded.to_json()).unwrap(),
            "state serialize -> load -> serialize must be byte-stable"
        );

        // The notable run's verdicts are what `minimize --generation` targets
        // without a --marker, so they have to survive the round trip by name.
        assert_eq!(
            parsed_json["notable_runs"][0]["verdicts"],
            serde_json::json!([{"kind": "violation", "label": "no-loss"}]),
        );
        assert_eq!(
            loaded.notable_runs[0].verdicts,
            state.notable_runs[0].verdicts
        );

        let mut bad_schema = parsed_json.clone();
        bad_schema["schema"] = "patina.campaign.state/v999".into();
        assert!(CampaignState::from_json(&bad_schema).is_err());
        // A v1 out-dir has no `verdicts` on its notable runs. It is refused by
        // name rather than read as "this generation reported nothing", which
        // would make an auto-target minimize refuse for the wrong reason.
        let mut v1 = parsed_json.clone();
        v1["schema"] = "patina.campaign.state/v1".into();
        v1["notable_runs"][0]
            .as_object_mut()
            .unwrap()
            .remove("verdicts");
        let error = CampaignState::from_json(&v1).unwrap_err();
        assert!(
            error.starts_with("unsupported schema"),
            "unexpected error: {error}"
        );
        let mut missing_verdicts = parsed_json.clone();
        missing_verdicts["notable_runs"][0]
            .as_object_mut()
            .unwrap()
            .remove("verdicts");
        assert!(CampaignState::from_json(&missing_verdicts).is_err());
        let mut bad_class = parsed_json;
        bad_class["classes"] = serde_json::json!({"MYSTERY": 1, "OK": 1});
        assert!(CampaignState::from_json(&bad_class).is_err());
    }

    #[test]
    fn campaign_lock_refuses_a_second_writer() {
        let dir = tempfile::tempdir().unwrap();
        let _first = CampaignLock::acquire(dir.path()).unwrap();
        let error = CampaignLock::acquire(dir.path()).unwrap_err().to_string();
        assert!(
            error.contains("another campaign is writing this out-dir")
                || error.contains("failed to lock campaign out-dir"),
            "{error}"
        );
    }
}
