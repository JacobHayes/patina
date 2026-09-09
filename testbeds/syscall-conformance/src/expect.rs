//! The harness half: normalizer, expectation files, `divergences.toml`, the
//! differ, the host gate, and the planted-failure selftest. Pure Rust so the
//! `conform` binary builds on every platform the runner can be invoked from.

use crate::observe::{parse_stream, Event, Norm, ParsedNorm};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const SCHEMA: &str = "patina.conformance/v1";

// ---- expectation files ------------------------------------------------------

/// The first line of an expectation file: what blessed it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Header {
    pub schema: String,
    pub probe: String,
    pub os: String,
    pub arch: String,
    /// `uname -r` of the oracle kernel that blessed the events.
    pub kernel: String,
    /// glibc version on the blessing host.
    pub glibc: String,
    /// The kernel ABI level patina's virtual kernel claims
    /// (`registry::VIRTUAL_ABI`, read from `cargo patina syscalls --format json`).
    pub virtual_abi: String,
}

#[derive(Serialize, Deserialize)]
struct HeaderLine {
    header: Header,
}

pub struct Expectation {
    pub header: Header,
    pub events: Vec<Event>,
}

pub fn parse_expectation(text: &str) -> Result<Expectation, String> {
    let first = text
        .lines()
        .find(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .ok_or("empty expectation file")?;
    let header: HeaderLine = serde_json::from_str(first)
        .map_err(|error| format!("expectation header is not {{\"header\":…}}: {error}"))?;
    if header.header.schema != SCHEMA {
        return Err(format!(
            "expectation schema {:?} is not {SCHEMA:?}",
            header.header.schema
        ));
    }
    let events = parse_stream(text)?;
    Ok(Expectation {
        header: header.header,
        events,
    })
}

pub fn render_expectation(header: &Header, events: &[Event]) -> String {
    let mut out = String::new();
    out.push_str(
        &serde_json::to_string(&HeaderLine {
            header: header.clone(),
        })
        .expect("header serializes"),
    );
    out.push('\n');
    for event in events {
        out.push_str(&serde_json::to_string(event).expect("event serializes"));
        out.push('\n');
    }
    out
}

// ---- normalization ----------------------------------------------------------

#[derive(Default)]
struct Normalizer {
    /// namespace → raw value → label (`fd@57`: the event that introduced it).
    labels: HashMap<String, HashMap<i64, String>>,
    monotonic: HashMap<String, i64>,
}

impl Normalizer {
    /// The label of `value` in `namespace`: the seq of the event that first
    /// showed it (plus `.k` for the k-th new value within one event). Keyed by
    /// the introducing event rather than by a running count so an extra
    /// allocation on one side (a call that succeeds under patina and fails on
    /// the host, or the reverse) shifts nothing downstream.
    fn label(
        &mut self,
        namespace: &str,
        value: i64,
        seq: u64,
        fresh_in_event: &mut usize,
    ) -> String {
        let table = self.labels.entry(namespace.to_string()).or_default();
        if let Some(label) = table.get(&value) {
            return label.clone();
        }
        let label = if *fresh_in_event == 0 {
            format!("{namespace}@{seq}")
        } else {
            format!("{namespace}@{seq}.{fresh_in_event}")
        };
        *fresh_in_event += 1;
        table.insert(value, label.clone());
        label
    }

    fn apply(&mut self, event: &mut Event) {
        let norms: Vec<(String, String)> = event
            .norm
            .iter()
            .map(|(path, tag)| (path.clone(), tag.clone()))
            .collect();
        let mut retire: Option<i64> = None;
        let mut fresh: HashMap<String, usize> = HashMap::new();
        for (path, tag) in norms {
            let Some(norm) = Norm::parse(&tag) else {
                continue;
            };
            // Monotonic relations are per clock: consecutive reads of different
            // clock ids have unrelated epochs, so the key carries `args.clock`
            // when the event has one (clock_gettime, clock_nanosleep, ...).
            let key = match event.args.get("clock") {
                Some(clock) => format!("{}.{path}.clock={clock}", event.op),
                None => format!("{}.{path}", event.op),
            };
            let slot: Option<&mut Value> = if path == "ret" {
                Some(&mut event.ret)
            } else if let Some(name) = path.strip_prefix("args.") {
                event.args.get_mut(name)
            } else if let Some(name) = path.strip_prefix("fields.") {
                event.fields.get_mut(name)
            } else {
                None
            };
            let Some(slot) = slot else { continue };
            let Some(number) = slot.as_i64() else {
                continue; // already normalized (a string), or not a number
            };
            *slot = match norm {
                ParsedNorm::Relative(namespace) => {
                    if number < 0 {
                        continue;
                    }
                    if namespace == "fd" && event.op == "close" && path == "args.fd" {
                        retire = Some(number);
                    }
                    let fresh_in_event = fresh.entry(namespace.clone()).or_insert(0);
                    Value::from(self.label(&namespace, number, event.seq, fresh_in_event))
                }
                ParsedNorm::Inode => {
                    let fresh_in_event = fresh.entry("ino".to_string()).or_insert(0);
                    Value::from(self.label("ino", number, event.seq, fresh_in_event))
                }
                ParsedNorm::Identity => {
                    let fresh_in_event = fresh.entry("id".to_string()).or_insert(0);
                    Value::from(self.label("id", number, event.seq, fresh_in_event))
                }
                ParsedNorm::Monotonic => {
                    let relation = match self.monotonic.get(&key) {
                        None => "mono:first",
                        Some(previous) if number >= *previous => "mono:>=",
                        Some(_) => "mono:-",
                    };
                    self.monotonic.insert(key, number);
                    Value::from(relation)
                }
                ParsedNorm::Mask(bits) => Value::from((number as u64) & bits),
            };
        }
        if let Some(number) = retire {
            if let Some(table) = self.labels.get_mut("fd") {
                table.remove(&number);
            }
        }
    }
}

/// Apply every event's declared normalizations, in stream order (ordinal and
/// monotonic state carries across events). Idempotent: an already-normalized
/// value is a string and is left alone.
pub fn normalize(mut events: Vec<Event>) -> Vec<Event> {
    let mut normalizer = Normalizer::default();
    for event in &mut events {
        normalizer.apply(event);
    }
    events
}

// ---- divergences.toml -------------------------------------------------------

#[derive(Deserialize, Clone, Debug)]
pub struct Divergence {
    pub probe: String,
    /// Absent = the divergence holds for every vehicle.
    #[serde(default)]
    pub vehicle: Option<String>,
    /// `field` (default): one field path at matching events differs.
    /// `abort`: the probe dies under patina at event `seq` (a fatal trap or a
    /// refusal inside that call); the recorded stream must be exactly the
    /// blessed prefix before `seq` (compared field-wise as usual). A probe that
    /// records more events than that is stale.
    /// `probe`: the whole probe fails under patina (aborts or its stream cannot
    /// be compared); a declared failing probe that now passes is stale.
    #[serde(default = "default_kind")]
    pub kind: String,
    /// Event op the field divergence applies to (`*` = any op).
    #[serde(default)]
    pub op: Option<String>,
    /// Field path: `op`, `ret`, `errno`, `args.<k>`, `fields.<k>`.
    #[serde(default)]
    pub field: Option<String>,
    /// Narrow to one event index.
    #[serde(default)]
    pub seq: Option<u64>,
    /// Narrow to a set of event indices.
    #[serde(default)]
    pub seqs: Vec<u64>,
    /// Narrow to `check` events with this label (`args.label`).
    #[serde(default)]
    pub label: Option<String>,
    pub reason: String,
}

fn default_kind() -> String {
    "field".to_string()
}

#[derive(Deserialize)]
struct DivergenceFile {
    #[serde(default)]
    divergence: Vec<Divergence>,
}

pub fn load_divergences(text: &str) -> Result<Vec<Divergence>, String> {
    let file: DivergenceFile =
        toml::from_str(text).map_err(|error| format!("divergences.toml: {error}"))?;
    for (index, divergence) in file.divergence.iter().enumerate() {
        let at = format!("divergences.toml [[divergence]] #{}", index + 1);
        if divergence.reason.trim().is_empty() {
            return Err(format!("{at}: reason is required"));
        }
        match divergence.kind.as_str() {
            "field" => {
                if divergence.op.is_none() || divergence.field.is_none() {
                    return Err(format!("{at}: kind = \"field\" needs op and field"));
                }
            }
            "abort" => {
                if divergence.seq.is_none() {
                    return Err(format!("{at}: kind = \"abort\" needs seq"));
                }
            }
            "probe" => {}
            other => return Err(format!("{at}: unknown kind {other:?}")),
        }
    }
    Ok(file.divergence)
}

impl Divergence {
    fn applies_to(&self, probe: &str, vehicle: &str) -> bool {
        self.probe == probe && self.vehicle.as_deref().is_none_or(|v| v == vehicle)
    }

    fn matches(&self, event: &Event, path: &str) -> bool {
        self.kind == "field"
            && self
                .op
                .as_deref()
                .is_some_and(|op| op == "*" || op == event.op)
            && self.field.as_deref() == Some(path)
            && self.seq.is_none_or(|seq| seq == event.seq)
            && (self.seqs.is_empty() || self.seqs.contains(&event.seq))
            && self
                .label
                .as_deref()
                .is_none_or(|label| event.args.get("label").and_then(Value::as_str) == Some(label))
    }

    pub fn describe(&self) -> String {
        match self.kind.as_str() {
            "abort" => format!(
                "probe {} vehicle={} kind=abort seq={}: {}",
                self.probe,
                self.vehicle.as_deref().unwrap_or("*"),
                self.seq.unwrap_or(0),
                self.reason
            ),
            "probe" => format!(
                "probe {} vehicle={} kind=probe: {}",
                self.probe,
                self.vehicle.as_deref().unwrap_or("*"),
                self.reason
            ),
            _ => format!(
                "probe {} vehicle={} op={} field={}{}{}{}: {}",
                self.probe,
                self.vehicle.as_deref().unwrap_or("*"),
                self.op.as_deref().unwrap_or("?"),
                self.field.as_deref().unwrap_or("?"),
                self.seq.map(|s| format!(" seq={s}")).unwrap_or_default(),
                if self.seqs.is_empty() {
                    String::new()
                } else {
                    format!(" seqs={:?}", self.seqs)
                },
                self.label
                    .as_deref()
                    .map(|l| format!(" label={l:?}"))
                    .unwrap_or_default(),
                self.reason
            ),
        }
    }
}

/// The declaration under which `(probe, vehicle)` does not run to completion
/// under patina — a probe-level one (refused, or its stream lost) or an abort
/// at a known event — if any. Either way the run leaves no trace to replay.
pub fn declared_failing<'a>(
    divergences: &'a [Divergence],
    probe: &str,
    vehicle: &str,
) -> Option<&'a Divergence> {
    divergences
        .iter()
        .find(|d| (d.kind == "probe" || d.kind == "abort") && d.applies_to(probe, vehicle))
}

// ---- probes.toml and the registry -------------------------------------------

/// One probe's coverage. Unknown keys are refused so a stale table cannot sit
/// in the manifest unread.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct ProbeSpec {
    /// Rows the probe exercises: the native leg is host-unavailable when the
    /// host kernel predates one.
    #[serde(default)]
    pub syscalls: Vec<String>,
    /// Rows the probe asserts `ENOSYS` for (their `since` is past the virtual
    /// ABI level): the native leg is host-unavailable when the host kernel
    /// IMPLEMENTS one, since it then cannot be the oracle for absence.
    #[serde(default)]
    pub absent: Vec<String>,
    /// The libc spellings the `libc` vehicle goes through.
    #[serde(default)]
    pub symbols: Vec<String>,
}

/// `probes.toml`: probe id → coverage. The virtual ABI level and each row's
/// first kernel are the registry's ([`Registry`]), not the manifest's.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub probe: BTreeMap<String, ProbeSpec>,
}

pub fn load_manifest(text: &str) -> Result<Manifest, String> {
    let manifest: Manifest =
        toml::from_str(text).map_err(|error| format!("probes.toml: {error}"))?;
    if manifest.probe.is_empty() {
        return Err("probes.toml: no [probe.\"…\"] tables".to_string());
    }
    for (id, spec) in &manifest.probe {
        if spec.syscalls.is_empty() && spec.absent.is_empty() {
            return Err(format!(
                "probes.toml: probe {id:?} lists no syscalls and no absent rows"
            ));
        }
    }
    Ok(manifest)
}

/// The registry as `cargo patina syscalls --format json` (schema
/// `patina.syscalls/v1`) reports it for the host arch: the virtual ABI level,
/// every row's disposition kind and `since`, and the symbol rows.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    pub virtual_abi: String,
    /// row name → disposition kind (`modeled`, `absent`, …).
    pub dispositions: BTreeMap<String, String>,
    /// row name → first mainline kernel carrying the number (rows past the
    /// table's baseline only).
    pub since: BTreeMap<String, String>,
    pub symbols: BTreeSet<String>,
}

pub const REGISTRY_SCHEMA: &str = "patina.syscalls/v1";

pub fn load_registry(text: &str) -> Result<Registry, String> {
    let json: Value =
        serde_json::from_str(text).map_err(|error| format!("registry json: {error}"))?;
    if json["schema"] != REGISTRY_SCHEMA {
        return Err(format!(
            "registry json: schema {} is not {REGISTRY_SCHEMA:?}",
            json["schema"]
        ));
    }
    let virtual_abi = json["virtual_abi"]
        .as_str()
        .ok_or("registry json: no virtual_abi")?
        .to_string();
    if kernel_version(&virtual_abi).is_none() {
        return Err(format!(
            "registry json: virtual_abi {virtual_abi:?} is not a kernel release"
        ));
    }
    let mut registry = Registry {
        virtual_abi,
        ..Registry::default()
    };
    for row in json["rows"].as_array().ok_or("registry json: no rows")? {
        let name = row["name"]
            .as_str()
            .ok_or("registry json: a row has no name")?
            .to_string();
        let kind = row["disposition"]["kind"]
            .as_str()
            .ok_or_else(|| format!("registry json: row {name} has no disposition kind"))?
            .to_string();
        if let Some(since) = row["since"].as_str() {
            if kernel_version(since).is_none() {
                return Err(format!(
                    "registry json: row {name} since {since:?} is not a kernel release"
                ));
            }
            registry.since.insert(name.clone(), since.to_string());
        }
        registry.dispositions.insert(name, kind);
    }
    for symbol in json["symbols"]
        .as_array()
        .ok_or("registry json: no symbols")?
    {
        let name = symbol["name"]
            .as_str()
            .ok_or("registry json: a symbol has no name")?;
        registry.symbols.insert(name.to_string());
    }
    if registry.dispositions.is_empty() {
        return Err("registry json: no rows".to_string());
    }
    Ok(registry)
}

/// Every name the manifest uses is a registry row of the right kind: an
/// exercised row exists and is not `absent`, an `absent` row is `absent` and
/// dated, a symbol is a symbol row. Fails closed before any leg runs; the
/// cargo cross-gate (`cargo-patina/tests/syscall_registry.rs`) holds the other
/// direction (every registry `probe` id is a probe here).
pub fn validate_manifest(manifest: &Manifest, registry: &Registry) -> Result<(), String> {
    let mut problems = Vec::new();
    for (id, spec) in &manifest.probe {
        for name in &spec.syscalls {
            match registry.dispositions.get(name).map(String::as_str) {
                None => problems.push(format!("{id}: {name} is not a registry row")),
                Some("absent") => problems.push(format!(
                    "{id}: exercises {name}, which the registry dispositions absent (list it under `absent`)"
                )),
                Some(_) => {}
            }
        }
        for name in &spec.absent {
            match registry.dispositions.get(name).map(String::as_str) {
                None => problems.push(format!("{id}: {name} is not a registry row")),
                Some("absent") => {
                    if !registry.since.contains_key(name) {
                        problems.push(format!(
                            "{id}: absent row {name} has no `since` in the registry; the host gate cannot date it"
                        ));
                    }
                }
                Some(kind) => problems.push(format!(
                    "{id}: asserts {name} absent, which the registry dispositions {kind}"
                )),
            }
        }
        for name in &spec.symbols {
            if !registry.symbols.contains(name) {
                problems.push(format!("{id}: {name} is not a symbol row"));
            }
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "probes.toml disagrees with the registry:\n  {}",
            problems.join("\n  ")
        ))
    }
}

// ---- the differ -------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The host oracle leg: the stream must equal the blessing exactly.
    Native,
    /// The patina (or record) leg: differences must be declared, and every
    /// declaration must still be needed.
    Patina,
}

impl Mode {
    pub fn parse(text: &str) -> Option<Mode> {
        match text {
            "native" => Some(Mode::Native),
            "patina" => Some(Mode::Patina),
            _ => None,
        }
    }
}

pub struct Outcome {
    pub ok: bool,
    pub lines: Vec<String>,
}

fn flatten(event: &Event) -> BTreeMap<String, Value> {
    let mut map = BTreeMap::new();
    map.insert("op".to_string(), Value::from(event.op.as_str()));
    map.insert("ret".to_string(), event.ret.clone());
    map.insert(
        "errno".to_string(),
        event.errno.as_deref().map_or(Value::Null, Value::from),
    );
    for (key, value) in &event.args {
        map.insert(format!("args.{key}"), value.clone());
    }
    for (key, value) in &event.fields {
        map.insert(format!("fields.{key}"), value.clone());
    }
    // `norm` tags are the probe's declarations, identical on both sides unless
    // the annotated field is absent — and that absence is already a `fields.*`
    // divergence, so the tags themselves are not compared.
    map
}

fn describe_event(event: &Event) -> String {
    let args: Vec<String> = event
        .args
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    format!("seq {} {}({})", event.seq, event.op, args.join(", "))
}

/// Compare an actual (raw) stream with the blessing.
pub fn diff(
    mode: Mode,
    probe: &str,
    vehicle: &str,
    expected: &Expectation,
    actual_raw: Vec<Event>,
    divergences: &[Divergence],
    probe_ok: bool,
) -> Outcome {
    let actual = normalize(actual_raw);
    let mut lines = Vec::new();
    let mut failures = 0usize;
    let mut fail = |lines: &mut Vec<String>, text: String| {
        failures += 1;
        lines.push(format!("FAIL {text}"));
    };

    let applicable: Vec<&Divergence> = divergences
        .iter()
        .filter(|d| d.applies_to(probe, vehicle))
        .collect();

    if mode == Mode::Patina {
        if let Some(declared) = applicable.iter().find(|d| d.kind == "probe") {
            // A probe-kind declaration covers a probe that DIES (or loses events)
            // under patina. Once it runs to completion with the blessed event
            // shape, the declaration is stale even if individual fields still
            // diverge: those are field-kind declarations of their own, and the
            // ordinary diff below must judge them.
            let completed = probe_ok && actual.len() == expected.events.len();
            if completed {
                fail(
                    &mut lines,
                    format!(
                        "STALE: the probe is declared failing under patina but now runs to completion with the blessed event count; delete the declaration (field divergences need their own): {}",
                        declared.describe()
                    ),
                );
            } else {
                lines.push(format!(
                    "declared failing probe (probe_ok={probe_ok}, {} events vs {} blessed): {}",
                    actual.len(),
                    expected.events.len(),
                    declared.describe()
                ));
            }
            return Outcome {
                ok: failures == 0,
                lines,
            };
        }
    }

    // A declared abort: the stream must be exactly the prefix before `seq`.
    let abort_at = if mode == Mode::Patina {
        applicable
            .iter()
            .find(|d| d.kind == "abort")
            .map(|d| (d.seq.unwrap_or(0) as usize, d.describe()))
    } else {
        None
    };
    let expected_len = match &abort_at {
        Some((seq, description)) => {
            if probe_ok || actual.len() > *seq {
                fail(
                    &mut lines,
                    format!(
                        "STALE: the probe is declared to abort at seq {seq} but recorded {} events{}; move or delete the declaration: {description}",
                        actual.len(),
                        if probe_ok { " and exited 0" } else { "" }
                    ),
                );
            } else if actual.len() < *seq {
                fail(
                    &mut lines,
                    format!(
                        "the probe died before its declared abort (seq {seq}): {} events recorded; see its stderr",
                        actual.len()
                    ),
                );
            } else {
                lines.push(format!(
                    "declared abort observed at seq {seq}: {description}"
                ));
            }
            (*seq).min(expected.events.len())
        }
        None => {
            if !probe_ok {
                fail(
                    &mut lines,
                    format!(
                        "the probe did not exit 0 ({} events recorded, {} blessed); see its stderr",
                        actual.len(),
                        expected.events.len()
                    ),
                );
            }
            expected.events.len()
        }
    };

    if abort_at.is_none() && actual.len() != expected_len {
        let first_divergent = actual
            .iter()
            .zip(expected.events.iter())
            .find(|(a, e)| a != e)
            .map(|(a, _)| describe_event(a));
        fail(
            &mut lines,
            format!(
                "event-count drift: {} blessed events, {} actual{}",
                expected.events.len(),
                actual.len(),
                first_divergent
                    .map(|d| format!("; first divergent event: {d}"))
                    .unwrap_or_else(|| "; the shorter stream is a prefix of the longer".to_string())
            ),
        );
    }

    let mut used = vec![false; applicable.len()];
    let mut reported = 0usize;
    for (actual_event, expected_event) in
        actual.iter().zip(expected.events.iter().take(expected_len))
    {
        if actual_event == expected_event {
            continue;
        }
        let a = flatten(actual_event);
        let e = flatten(expected_event);
        let mut paths: Vec<&String> = a.keys().chain(e.keys()).collect();
        paths.sort();
        paths.dedup();
        for path in paths {
            let av = a.get(path).cloned().unwrap_or(Value::Null);
            let ev = e.get(path).cloned().unwrap_or(Value::Null);
            if av == ev {
                continue;
            }
            let declared = if mode == Mode::Patina {
                applicable
                    .iter()
                    .enumerate()
                    .find(|(_, d)| d.matches(expected_event, path))
                    .map(|(index, _)| index)
            } else {
                None
            };
            match declared {
                Some(index) => used[index] = true,
                None => {
                    if reported < 40 {
                        fail(
                            &mut lines,
                            format!(
                                "{} divergence at {}: {path} blessed {ev} vs actual {av}",
                                if mode == Mode::Patina {
                                    "undeclared"
                                } else {
                                    "host-oracle"
                                },
                                describe_event(expected_event)
                            ),
                        );
                    }
                    reported += 1;
                }
            }
        }
    }
    if reported > 40 {
        lines.push(format!(
            "… {} more divergent fields not listed",
            reported - 40
        ));
    }

    if mode == Mode::Patina {
        for (index, divergence) in applicable.iter().enumerate() {
            if divergence.kind == "field" && !used[index] {
                fail(
                    &mut lines,
                    format!(
                        "STALE: declared divergence no longer diverges; delete it (or narrow it): {}",
                        divergence.describe()
                    ),
                );
            }
        }
        let declared_used = used.iter().filter(|u| **u).count();
        if declared_used > 0 {
            lines.push(format!(
                "{declared_used} declared divergence(s) observed and still needed"
            ));
        }
    }

    Outcome {
        ok: failures == 0,
        lines,
    }
}

// ---- the host gate ----------------------------------------------------------

/// `6.8.0-139-generic` → `(6, 8, 0)`; `5.10` → `(5, 10, 0)`.
pub fn kernel_version(text: &str) -> Option<(u64, u64, u64)> {
    let numeric: String = text
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let mut parts = numeric.split('.').filter(|p| !p.is_empty());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().map_or(Some(0), |p| p.parse().ok())?;
    let patch = parts.next().map_or(Some(0), |p| p.parse().ok())?;
    Some((major, minor, patch))
}

#[derive(Debug, PartialEq, Eq)]
pub enum HostGate {
    Ok,
    /// The host kernel cannot be the oracle for this probe: it lacks a number
    /// the probe exercises, or implements a number the probe asserts absent.
    /// Not a failure.
    Unavailable(String),
    /// The host kernel is older than the one that blessed the expectation: the
    /// oracle cannot be trusted to agree; fail.
    TooOld(String),
    Error(String),
}

pub fn host_gate(
    manifest: &Manifest,
    registry: &Registry,
    probe: &str,
    blessed: &Header,
    host_kernel: &str,
) -> HostGate {
    let Some(host) = kernel_version(host_kernel) else {
        return HostGate::Error(format!("cannot parse host kernel version {host_kernel:?}"));
    };
    let Some(blessed_version) = kernel_version(&blessed.kernel) else {
        return HostGate::Error(format!(
            "cannot parse blessed kernel version {:?}",
            blessed.kernel
        ));
    };
    let Some(spec) = manifest.probe.get(probe) else {
        return HostGate::Error(format!("probe {probe:?} is not in probes.toml"));
    };
    // An undated row predates every host the harness runs on.
    let since_of = |name: &str| {
        registry
            .since
            .get(name)
            .and_then(|s| kernel_version(s))
            .unwrap_or((0, 0, 0))
    };
    for syscall in &spec.syscalls {
        let since = since_of(syscall);
        if host < since {
            return HostGate::Unavailable(format!(
                "host kernel {host_kernel} lacks {syscall} (since {}.{})",
                since.0, since.1
            ));
        }
    }
    for syscall in &spec.absent {
        let Some(since) = registry.since.get(syscall).and_then(|s| kernel_version(s)) else {
            return HostGate::Error(format!(
                "absent row {syscall} has no `since` in the registry; the host gate cannot date it"
            ));
        };
        if host >= since {
            return HostGate::Unavailable(format!(
                "host kernel {host_kernel} implements {syscall} (since {}.{}); it cannot be the \
                 oracle for a number the virtual ABI {} lacks",
                since.0, since.1, registry.virtual_abi
            ));
        }
    }
    if host < blessed_version {
        return HostGate::TooOld(format!(
            "host kernel {host_kernel} is older than the blessing kernel {}",
            blessed.kernel
        ));
    }
    HostGate::Ok
}

// ---- the selftest -----------------------------------------------------------

fn synthetic_header() -> Header {
    Header {
        schema: SCHEMA.to_string(),
        probe: "selftest/synthetic".to_string(),
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
        kernel: "6.8.0".to_string(),
        glibc: "2.39".to_string(),
        virtual_abi: "6.8".to_string(),
    }
}

/// A small raw stream with every normalization kind in play.
fn synthetic_raw() -> Vec<Event> {
    let mut events = Vec::new();
    let mut push = |op: &str,
                    ret: i64,
                    errno: Option<&str>,
                    args: &[(&str, Value)],
                    fields: &[(&str, Value)],
                    norm: &[(&str, Norm)]| {
        let seq = events.len() as u64;
        events.push(Event {
            seq,
            op: op.to_string(),
            args: args
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
            ret: Value::from(ret),
            errno: errno.map(str::to_string),
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
            norm: norm.iter().map(|(k, n)| (k.to_string(), n.tag())).collect(),
        });
    };
    push(
        "openat",
        17,
        None,
        &[("path", Value::from("/tmp/x")), ("flags", Value::from(66))],
        &[],
        &[("ret", Norm::Relative("fd"))],
    );
    push(
        "write",
        5,
        None,
        &[("fd", Value::from(17)), ("len", Value::from(5))],
        &[],
        &[("args.fd", Norm::Relative("fd"))],
    );
    push(
        "fstat",
        0,
        None,
        &[("fd", Value::from(17))],
        &[
            ("kind", Value::from("reg")),
            ("perm", Value::from(0o644)),
            ("uid", Value::from(1000)),
            ("ino", Value::from(998877)),
        ],
        &[
            ("args.fd", Norm::Relative("fd")),
            ("fields.uid", Norm::Identity),
            ("fields.ino", Norm::Inode),
        ],
    );
    push(
        "clock_gettime",
        0,
        None,
        &[("clock", Value::from(1))],
        &[("ns", Value::from(1_700_000_000_000_i64))],
        &[("fields.ns", Norm::Monotonic)],
    );
    push(
        "clock_gettime",
        0,
        None,
        &[("clock", Value::from(1))],
        &[("ns", Value::from(1_700_000_000_500_i64))],
        &[("fields.ns", Norm::Monotonic)],
    );
    push(
        "openat",
        -1,
        Some("ENOENT"),
        &[
            ("path", Value::from("/tmp/missing")),
            ("flags", Value::from(0)),
        ],
        &[],
        &[("ret", Norm::Relative("fd"))],
    );
    push(
        "check",
        1,
        None,
        &[("label", Value::from("write returned len"))],
        &[],
        &[],
    );
    events
}

fn divergence(op: &str, field: &str, vehicle: Option<&str>) -> Divergence {
    Divergence {
        probe: "selftest/synthetic".to_string(),
        vehicle: vehicle.map(str::to_string),
        kind: "field".to_string(),
        op: Some(op.to_string()),
        field: Some(field.to_string()),
        seq: None,
        seqs: Vec::new(),
        label: None,
        reason: "selftest: planted".to_string(),
    }
}

/// Prove every differ gate can fail: a planted divergence, a planted stale
/// divergence, a planted event-count drift (both directions), a planted stale
/// probe-level declaration, plus the controls that must pass, plus the host
/// gate's two refusals. Returns `ok` only if every case behaved.
pub fn selftest() -> Outcome {
    let header = synthetic_header();
    let raw = synthetic_raw();
    let expected = Expectation {
        header: header.clone(),
        events: normalize(raw.clone()),
    };
    let mut lines = Vec::new();
    let mut all_ok = true;
    let mut case = |name: &str, want_ok: bool, outcome: Outcome, must_mention: &str| {
        let behaved = outcome.ok == want_ok
            && (must_mention.is_empty() || outcome.lines.iter().any(|l| l.contains(must_mention)));
        all_ok &= behaved;
        lines.push(format!(
            "SELFTEST {}: {name} (expected {}, got {}{})",
            if behaved { "ok" } else { "FAILED" },
            if want_ok { "pass" } else { "fail" },
            if outcome.ok { "pass" } else { "fail" },
            if must_mention.is_empty() || !behaved {
                String::new()
            } else {
                format!("; fired: {must_mention:?}")
            }
        ));
        if !behaved {
            for line in outcome.lines {
                lines.push(format!("    {line}"));
            }
        }
    };

    let probe = "selftest/synthetic";

    // Controls: an identical stream passes natively and under patina, and the
    // normalizer erases host magnitudes (a different fd/inode/uid/clock still
    // matches).
    case(
        "control: identical stream passes (native)",
        true,
        diff(
            Mode::Native,
            probe,
            "libc",
            &expected,
            raw.clone(),
            &[],
            true,
        ),
        "",
    );
    case(
        "control: identical stream passes (patina)",
        true,
        diff(
            Mode::Patina,
            probe,
            "libc",
            &expected,
            raw.clone(),
            &[],
            true,
        ),
        "",
    );
    let mut renumbered = raw.clone();
    renumbered[0].ret = Value::from(3);
    renumbered[1].args.insert("fd".to_string(), Value::from(3));
    renumbered[2].args.insert("fd".to_string(), Value::from(3));
    renumbered[2]
        .fields
        .insert("uid".to_string(), Value::from(0));
    renumbered[2]
        .fields
        .insert("ino".to_string(), Value::from(42));
    renumbered[3]
        .fields
        .insert("ns".to_string(), Value::from(10));
    renumbered[4]
        .fields
        .insert("ns".to_string(), Value::from(11));
    case(
        "control: normalized magnitudes (fd/uid/ino/clock) match",
        true,
        diff(
            Mode::Patina,
            probe,
            "libc",
            &expected,
            renumbered,
            &[],
            true,
        ),
        "",
    );

    // Planted divergence: the write returns a different count.
    let mut planted = raw.clone();
    planted[1].ret = Value::from(4);
    case(
        "planted divergence is refused (patina, undeclared)",
        false,
        diff(
            Mode::Patina,
            probe,
            "libc",
            &expected,
            planted.clone(),
            &[],
            true,
        ),
        "undeclared divergence",
    );
    case(
        "planted divergence is refused (native oracle)",
        false,
        diff(
            Mode::Native,
            probe,
            "libc",
            &expected,
            planted.clone(),
            &[],
            true,
        ),
        "host-oracle divergence",
    );
    case(
        "planted divergence passes once declared",
        true,
        diff(
            Mode::Patina,
            probe,
            "libc",
            &expected,
            planted.clone(),
            &[divergence("write", "ret", None)],
            true,
        ),
        "still needed",
    );
    case(
        "a declaration for another vehicle does not cover it",
        false,
        diff(
            Mode::Patina,
            probe,
            "libc",
            &expected,
            planted.clone(),
            &[divergence("write", "ret", Some("raw"))],
            true,
        ),
        "undeclared divergence",
    );

    // Planted stale divergence: declared, but the stream agrees.
    case(
        "planted stale divergence is refused",
        false,
        diff(
            Mode::Patina,
            probe,
            "libc",
            &expected,
            raw.clone(),
            &[divergence("write", "ret", None)],
            true,
        ),
        "STALE",
    );

    // Planted event-count drift, both directions.
    let mut short = raw.clone();
    short.pop();
    case(
        "planted event-count drift (missing event) is refused",
        false,
        diff(Mode::Patina, probe, "libc", &expected, short, &[], true),
        "event-count drift",
    );
    let mut long = raw.clone();
    let mut extra = raw[6].clone();
    extra.seq = 7;
    long.push(extra);
    case(
        "planted event-count drift (extra event) is refused",
        false,
        diff(Mode::Patina, probe, "libc", &expected, long, &[], true),
        "event-count drift",
    );

    // A failed check under patina is a field divergence, not an abort.
    let mut failed_check = raw.clone();
    failed_check[6].ret = Value::from(0);
    case(
        "a failed check is an undeclared divergence",
        false,
        diff(
            Mode::Patina,
            probe,
            "libc",
            &expected,
            failed_check.clone(),
            &[],
            true,
        ),
        "check(label=",
    );
    let labelled = Divergence {
        label: Some("write returned len".to_string()),
        ..divergence("check", "ret", None)
    };
    case(
        "a failed check passes once declared by label",
        true,
        diff(
            Mode::Patina,
            probe,
            "libc",
            &expected,
            failed_check,
            &[labelled],
            true,
        ),
        "still needed",
    );

    // Probe-level declarations.
    let failing_probe = Divergence {
        kind: "probe".to_string(),
        op: None,
        field: None,
        ..divergence("", "", None)
    };
    case(
        "a probe that dies is refused when undeclared",
        false,
        diff(
            Mode::Patina,
            probe,
            "libc",
            &expected,
            raw[..2].to_vec(),
            &[],
            false,
        ),
        "did not exit 0",
    );
    case(
        "a probe that dies passes when declared failing",
        true,
        diff(
            Mode::Patina,
            probe,
            "libc",
            &expected,
            raw[..2].to_vec(),
            std::slice::from_ref(&failing_probe),
            false,
        ),
        "declared failing probe",
    );
    case(
        "planted stale probe-level declaration is refused",
        false,
        diff(
            Mode::Patina,
            probe,
            "libc",
            &expected,
            raw.clone(),
            std::slice::from_ref(&failing_probe),
            true,
        ),
        "STALE",
    );
    case(
        "a dying probe never passes the native oracle",
        false,
        diff(
            Mode::Native,
            probe,
            "libc",
            &expected,
            raw.clone(),
            &[],
            false,
        ),
        "did not exit 0",
    );

    // Abort-level declarations: exact prefix, stale when the probe outlives it.
    let abort_at_3 = Divergence {
        kind: "abort".to_string(),
        op: None,
        field: None,
        seq: Some(3),
        ..divergence("", "", None)
    };
    case(
        "a declared abort with the exact prefix passes",
        true,
        diff(
            Mode::Patina,
            probe,
            "libc",
            &expected,
            raw[..3].to_vec(),
            std::slice::from_ref(&abort_at_3),
            false,
        ),
        "declared abort observed",
    );
    case(
        "a declared abort still compares the prefix",
        false,
        diff(
            Mode::Patina,
            probe,
            "libc",
            &expected,
            planted[..3].to_vec(),
            std::slice::from_ref(&abort_at_3),
            false,
        ),
        "undeclared divergence",
    );
    case(
        "planted stale abort (the probe outlived it) is refused",
        false,
        diff(
            Mode::Patina,
            probe,
            "libc",
            &expected,
            raw[..5].to_vec(),
            std::slice::from_ref(&abort_at_3),
            false,
        ),
        "STALE",
    );
    case(
        "planted stale abort (the probe now passes) is refused",
        false,
        diff(
            Mode::Patina,
            probe,
            "libc",
            &expected,
            raw.clone(),
            std::slice::from_ref(&abort_at_3),
            true,
        ),
        "STALE",
    );
    case(
        "a probe dying before its declared abort is refused",
        false,
        diff(
            Mode::Patina,
            probe,
            "libc",
            &expected,
            raw[..1].to_vec(),
            std::slice::from_ref(&abort_at_3),
            false,
        ),
        "died before its declared abort",
    );

    // The host gate.
    let absent_probe = "selftest/absent";
    let manifest = Manifest {
        probe: BTreeMap::from([
            (
                probe.to_string(),
                ProbeSpec {
                    syscalls: vec!["openat".to_string(), "statx".to_string()],
                    ..ProbeSpec::default()
                },
            ),
            (
                absent_probe.to_string(),
                ProbeSpec {
                    absent: vec!["fchroot".to_string()],
                    ..ProbeSpec::default()
                },
            ),
        ]),
    };
    let registry = Registry {
        virtual_abi: "6.8".to_string(),
        dispositions: BTreeMap::from([
            ("openat".to_string(), "modeled".to_string()),
            ("statx".to_string(), "modeled".to_string()),
            ("fchroot".to_string(), "absent".to_string()),
        ]),
        since: BTreeMap::from([
            ("statx".to_string(), "4.11".to_string()),
            ("fchroot".to_string(), "7.3".to_string()),
        ]),
        symbols: BTreeSet::new(),
    };
    let gate_case = |host: &str, want: fn(&HostGate) -> bool| -> Outcome {
        let gate = host_gate(&manifest, &registry, probe, &header, host);
        Outcome {
            ok: want(&gate),
            lines: vec![format!("{gate:?}")],
        }
    };
    let absent_case = |host: &str, want: fn(&HostGate) -> bool| -> Outcome {
        let gate = host_gate(&manifest, &registry, absent_probe, &header, host);
        Outcome {
            ok: want(&gate),
            lines: vec![format!("{gate:?}")],
        }
    };
    case(
        "host gate: a current kernel passes",
        true,
        gate_case("6.8.0-139-generic", |g| *g == HostGate::Ok),
        "",
    );
    case(
        "host gate: a kernel lacking statx is host-unavailable",
        true,
        gate_case("4.4.0", |g| matches!(g, HostGate::Unavailable(_))),
        "",
    );
    case(
        "host gate: a kernel older than the blessing is refused",
        true,
        gate_case("5.15.0", |g| matches!(g, HostGate::TooOld(_))),
        "",
    );
    case(
        "host gate: an absent-row probe runs on a kernel that lacks the number",
        true,
        absent_case("6.8.0-139-generic", |g| *g == HostGate::Ok),
        "",
    );
    case(
        "host gate: an absent-row probe is host-unavailable on a kernel that implements the number",
        true,
        absent_case("7.3.0", |g| matches!(g, HostGate::Unavailable(_))),
        "",
    );
    let planted = validate_manifest(
        &Manifest {
            probe: BTreeMap::from([(
                "selftest/bad".to_string(),
                ProbeSpec {
                    syscalls: vec!["nonesuch".to_string(), "fchroot".to_string()],
                    absent: vec!["openat".to_string()],
                    symbols: vec!["nonesuch".to_string()],
                },
            )]),
        },
        &registry,
    );
    case(
        "manifest check: an unknown row, an exercised absent row, an absent modeled row, and an unknown symbol are refused",
        true,
        Outcome {
            ok: matches!(&planted, Err(text) if text.matches("selftest/bad").count() == 4),
            lines: vec![format!("{planted:?}")],
        },
        "",
    );
    case(
        "manifest check: the control passes",
        true,
        Outcome {
            ok: validate_manifest(&manifest, &registry).is_ok(),
            lines: vec![],
        },
        "",
    );

    Outcome { ok: all_ok, lines }
}
