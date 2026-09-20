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

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Divergence {
    pub probe: String,
    /// Absent = the divergence holds for every vehicle.
    #[serde(default)]
    pub vehicle: Option<String>,
    /// `field` (default): one field path at matching events differs.
    /// `abort`: the probe dies under patina at event `seq` (a fatal trap or a
    /// refusal inside that call); the recorded stream must be exactly the
    /// blessed prefix before `seq` (compared field-wise as usual), the
    /// termination must be a signal death, and `stderr`, when given, must
    /// appear in the leg's stderr (the exact named diagnostic). A probe that
    /// records more events than that is stale.
    /// `probe`: the whole probe cannot be compared under patina (an audit
    /// refusal, a stream lost before its first event); stale once it runs to
    /// completion with the blessed event count.
    /// `pending`: the probe is not conformant yet — any death, event loss, field
    /// or termination divergence is covered, and the leg still lists every
    /// difference it found; stale the moment the probe passes cleanly. It is
    /// the only kind a frozen oracle probe may carry besides its by-design
    /// aborts, and the family gate requires every one gone.
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
    /// `abort` only: a substring the leg's stderr must carry (the trap's named
    /// diagnostic), so a declared abort pins WHY the probe died, not just where.
    #[serde(default)]
    pub stderr: Option<String>,
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
        divergence
            .validate()
            .map_err(|error| format!("{at}: {error}"))?;
    }
    Ok(file.divergence)
}

impl Divergence {
    /// The shape rules of one declaration (shared by `divergences.toml` and the
    /// frozen manifest, which lists declarations in the same form).
    pub fn validate(&self) -> Result<(), String> {
        if self.reason.trim().is_empty() {
            return Err("reason is required".to_string());
        }
        match self.kind.as_str() {
            "field" => {
                if self.op.is_none() || self.field.is_none() {
                    return Err("kind = \"field\" needs op and field".to_string());
                }
            }
            "abort" => {
                if self.seq.is_none() {
                    return Err("kind = \"abort\" needs seq".to_string());
                }
            }
            "probe" | "pending" => {}
            other => return Err(format!("unknown kind {other:?}")),
        }
        if self.stderr.is_some() && self.kind != "abort" {
            return Err("stderr is only meaningful on kind = \"abort\"".to_string());
        }
        if let Some(vehicle) = &self.vehicle {
            if !VEHICLES.contains(&vehicle.as_str()) {
                return Err(format!("unknown vehicle {vehicle:?}"));
            }
        }
        Ok(())
    }

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

    /// A declaration the design makes permanent (a process-lifecycle trap the
    /// probe's native oracle needs), never a gap to close.
    pub fn by_design(&self) -> bool {
        self.reason.starts_with("by design:")
    }

    pub fn describe(&self) -> String {
        match self.kind.as_str() {
            "abort" => format!(
                "probe {} vehicle={} kind=abort seq={}{}: {}",
                self.probe,
                self.vehicle.as_deref().unwrap_or("*"),
                self.seq.unwrap_or(0),
                self.stderr
                    .as_deref()
                    .map(|s| format!(" stderr={s:?}"))
                    .unwrap_or_default(),
                self.reason
            ),
            "probe" | "pending" => format!(
                "probe {} vehicle={} kind={}: {}",
                self.probe,
                self.vehicle.as_deref().unwrap_or("*"),
                self.kind,
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
/// under patina — a probe-level one (refused, or its stream lost), a pending
/// one (not conformant yet), or an abort at a known event — if any. Either way
/// the run leaves no trace to replay.
pub fn declared_failing<'a>(
    divergences: &'a [Divergence],
    probe: &str,
    vehicle: &str,
) -> Option<&'a Divergence> {
    divergences.iter().find(|d| {
        (d.kind == "probe" || d.kind == "abort" || d.kind == "pending")
            && d.applies_to(probe, vehicle)
    })
}

// ---- probes.toml and the registry -------------------------------------------

pub const VEHICLES: [&str; 3] = ["libc", "syscall", "raw"];

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
    pub os: String,
    pub arch: String,
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
        os: json["os"]
            .as_str()
            .ok_or("registry json: no os")?
            .to_string(),
        arch: json["arch"]
            .as_str()
            .ok_or("registry json: no arch")?
            .to_string(),
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

/// Required target-local inventories. Adding an architecture requires its report here
/// and in the runner; an incomplete inventory is never a permissive fallback.
pub const REGISTRY_ARCHES: &[&str] = &["x86_64", "aarch64"];

pub fn validate_platforms(host: &Registry, references: &[Registry]) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for registry in std::iter::once(host).chain(references) {
        if registry.os != "linux" || !REGISTRY_ARCHES.contains(&registry.arch.as_str()) {
            return Err(format!(
                "unsupported registry target {}-{}",
                registry.os, registry.arch
            ));
        }
        if registry.virtual_abi != host.virtual_abi {
            return Err("registry virtual ABI mismatch".into());
        }
        if !seen.insert(registry.arch.as_str()) {
            return Err(format!(
                "duplicate registry target {}-{}",
                registry.os, registry.arch
            ));
        }
    }
    if seen.len() != REGISTRY_ARCHES.len() {
        return Err("missing reference registry target".into());
    }
    Ok(())
}

/// Every name the manifest uses is a registry row of the right kind: an
/// exercised row exists and is not `absent`, an `absent` row is `absent` and
/// dated, a symbol is a symbol row. Fails closed before any leg runs; the
/// cargo cross-gate (`cargo-patina/tests/syscall_registry.rs`) holds the other
/// direction (every registry `probe` id is a probe here).
pub fn validate_manifest(
    manifest: &Manifest,
    registry: &Registry,
    references: &[Registry],
) -> Result<Vec<String>, String> {
    validate_platforms(registry, references)?;
    let mut nonhost = Vec::new();
    let mut problems = Vec::new();
    for (id, spec) in &manifest.probe {
        let row_registry = |name: &str| {
            if registry.dispositions.contains_key(name) {
                registry
            } else {
                references
                    .iter()
                    .find(|r| r.dispositions.contains_key(name))
                    .unwrap_or(registry)
            }
        };
        for name in spec.syscalls.iter().chain(&spec.absent) {
            let owner = row_registry(name);
            if owner.arch != registry.arch {
                nonhost.push(format!("{id}: {name} nonhost on {}-{} (known on {}-{}; not executed or observed absent)", registry.os, registry.arch, owner.os, owner.arch));
            }
        }
        for name in &spec.syscalls {
            let registry = row_registry(name);
            match registry.dispositions.get(name).map(String::as_str) {
                None => problems.push(format!("{id}: {name} is not a registry row")),
                Some("absent") => problems.push(format!(
                    "{id}: exercises {name}, which the registry dispositions absent (list it under `absent`)"
                )),
                Some(_) => {}
            }
        }
        for name in &spec.absent {
            let registry = row_registry(name);
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
        Ok(nonhost)
    } else {
        Err(format!(
            "probes.toml disagrees with the registry:\n  {}",
            problems.join("\n  ")
        ))
    }
}

// ---- termination ------------------------------------------------------------

/// The op of the one event the harness itself appends to every leg's stream:
/// how the probe process ended, as the SUPERVISOR observed it — the native
/// leg's `waitpid` status, or the `guest_exit` the `cargo patina` envelope
/// reports. It is compared like any other event, so a probe whose last act is
/// `kill(getpid(), SIGTERM)` with `SIG_DFL` is blessed as "signaled 15" and a
/// virtual kernel that does not die the same way diverges on it. The runner
/// never writes this line from the expectation.
pub const TERMINATION_OP: &str = "__termination";

/// The op a probe records right before it dies on purpose (`Probe::dies_by`):
/// the blessing accepts a signal termination only when the last recorded event
/// announces that very signal, so a probe that dies by accident (a stray
/// SIGSEGV) is refused at bless time, never recorded as an expectation.
pub const EXPECT_DEATH_OP: &str = "expect_death";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Termination {
    Exited(i32),
    /// `core` is `None` when the supervisor does not report the core flag
    /// (the `cargo patina` envelope today), and a blessed `true`/`false` then
    /// diverges on `fields.core` — a gap the runtime closes, never the harness.
    Signaled {
        signal: i32,
        core: Option<bool>,
    },
    /// The leg's wall-clock timeout killed the process group.
    Timeout,
    /// The supervisor reported no process outcome (a refusal before the guest
    /// ran, or an envelope without `guest_exit`).
    Absent,
}

impl Termination {
    pub fn event(&self, seq: u64) -> Event {
        let mut fields = BTreeMap::new();
        match self {
            Termination::Exited(code) => {
                fields.insert("kind".to_string(), Value::from("exited"));
                fields.insert("code".to_string(), Value::from(*code));
            }
            Termination::Signaled { signal, core } => {
                fields.insert("kind".to_string(), Value::from("signaled"));
                fields.insert("signal".to_string(), Value::from(*signal));
                fields.insert("core".to_string(), core.map_or(Value::Null, Value::from));
            }
            Termination::Timeout => {
                fields.insert("kind".to_string(), Value::from("timeout"));
            }
            Termination::Absent => {
                fields.insert("kind".to_string(), Value::from("absent"));
            }
        }
        Event {
            seq,
            op: TERMINATION_OP.to_string(),
            args: BTreeMap::new(),
            ret: Value::from(0),
            errno: None,
            fields,
            norm: BTreeMap::new(),
        }
    }

    pub fn from_event(event: &Event) -> Option<Termination> {
        if event.op != TERMINATION_OP {
            return None;
        }
        match event.fields.get("kind").and_then(Value::as_str)? {
            "exited" => Some(Termination::Exited(
                event.fields.get("code")?.as_i64()? as i32
            )),
            "signaled" => Some(Termination::Signaled {
                signal: event.fields.get("signal")?.as_i64()? as i32,
                core: event.fields.get("core").and_then(Value::as_bool),
            }),
            "timeout" => Some(Termination::Timeout),
            "absent" => Some(Termination::Absent),
            _ => None,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Termination::Exited(code) => format!("exited {code}"),
            Termination::Signaled { signal, core } => format!(
                "signaled {signal}{}",
                match core {
                    Some(true) => " (core dumped)",
                    Some(false) => "",
                    None => " (core flag unreported)",
                }
            ),
            Termination::Timeout => "killed by the leg timeout".to_string(),
            Termination::Absent => "no process outcome reported".to_string(),
        }
    }
}

/// Split a stream into its events and its trailing termination line (if any).
pub fn split_termination(mut events: Vec<Event>) -> (Vec<Event>, Option<Event>) {
    let termination = match events.last() {
        Some(last) if last.op == TERMINATION_OP => events.pop(),
        _ => None,
    };
    (events, termination)
}

/// The blessed termination of an expectation, for the legs that observe the
/// process outcome directly (the leak leg under strace).
pub fn blessed_termination(expected: &Expectation) -> Result<Termination, String> {
    let (_, termination) = split_termination(expected.events.clone());
    let event = termination.ok_or("expectation has no termination line; re-bless")?;
    Termination::from_event(&event).ok_or_else(|| "malformed termination line".to_string())
}

/// Whether a raw native stream is blessable: every check passed, and the
/// termination is `exited 0` or a signal death the probe announced with
/// `expect_death` as its last event.
pub fn blessable(events: &[Event]) -> Result<(), String> {
    let (events, termination) = split_termination(events.to_vec());
    let termination = termination.ok_or("the stream has no termination line")?;
    let termination = Termination::from_event(&termination).ok_or("malformed termination line")?;
    if let Some(failed) = events
        .iter()
        .find(|event| event.op == "check" && event.ret != Value::from(1))
    {
        return Err(format!(
            "a check failed natively: {}",
            failed
                .args
                .get("label")
                .and_then(Value::as_str)
                .unwrap_or("?")
        ));
    }
    match termination {
        Termination::Exited(0) => Ok(()),
        Termination::Signaled { signal, .. } => {
            let announced = events
                .last()
                .filter(|event| event.op == EXPECT_DEATH_OP)
                .and_then(|event| event.args.get("signal"))
                .and_then(Value::as_i64);
            if announced == Some(i64::from(signal)) {
                Ok(())
            } else {
                Err(format!(
                    "the probe died on signal {signal} without announcing it (Probe::dies_by as its last act)"
                ))
            }
        }
        other => Err(format!(
            "the probe did not pass natively: {}",
            other.describe()
        )),
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

/// Compare an actual (raw) stream with the blessing. `stderr` is the leg's
/// captured stderr, consulted by abort declarations that pin a diagnostic.
pub fn diff(
    mode: Mode,
    probe: &str,
    vehicle: &str,
    expected: &Expectation,
    actual_raw: Vec<Event>,
    divergences: &[Divergence],
    stderr: Option<&str>,
) -> Outcome {
    let mut lines = Vec::new();
    let mut failures = 0usize;
    let mut fail = |lines: &mut Vec<String>, text: String| {
        failures += 1;
        lines.push(format!("FAIL {text}"));
    };

    let (expected_events, expected_term) = split_termination(expected.events.clone());
    let Some(expected_term) = expected_term else {
        fail(
            &mut lines,
            "the expectation has no termination line; re-bless it on this host".to_string(),
        );
        return Outcome { ok: false, lines };
    };
    let (actual_events, actual_term) = split_termination(actual_raw);
    let actual = normalize(actual_events);
    let Some(actual_term) = actual_term else {
        fail(
            &mut lines,
            format!(
                "no termination line observed ({} events): the supervisor did not append the \
                 process outcome, and a stream is never compared without one",
                actual.len()
            ),
        );
        return Outcome { ok: false, lines };
    };
    let Some(termination) = Termination::from_event(&actual_term) else {
        fail(&mut lines, "malformed termination line".to_string());
        return Outcome { ok: false, lines };
    };
    let probe_ok = termination == Termination::Exited(0);

    let applicable: Vec<&Divergence> = divergences
        .iter()
        .filter(|d| d.applies_to(probe, vehicle))
        .collect();
    let pending = if mode == Mode::Patina {
        applicable.iter().find(|d| d.kind == "pending").copied()
    } else {
        None
    };

    if mode == Mode::Patina {
        if let Some(declared) = applicable.iter().find(|d| d.kind == "probe") {
            // A probe-kind declaration covers a probe that DIES (or loses events)
            // under patina. Once it runs to completion with the blessed event
            // shape, the declaration is stale even if individual fields still
            // diverge: those are field-kind declarations of their own, and the
            // ordinary diff below must judge them.
            let completed = probe_ok && actual.len() == expected_events.len();
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
                    "declared failing probe ({}, {} events vs {} blessed): {}",
                    termination.describe(),
                    actual.len(),
                    expected_events.len(),
                    declared.describe()
                ));
            }
            return Outcome {
                ok: failures == 0,
                lines,
            };
        }
    }

    // A declared abort: the stream must be exactly the prefix before `seq`, the
    // probe must have died on a signal, and the pinned diagnostic (if any) must
    // be in its stderr.
    let abort_at = if mode == Mode::Patina {
        applicable
            .iter()
            .find(|d| d.kind == "abort")
            .map(|d| (d.seq.unwrap_or(0) as usize, d.describe(), d.stderr.clone()))
    } else {
        None
    };
    let expected_len = match &abort_at {
        Some((seq, description, pinned)) => {
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
                        "the probe died before its declared abort (seq {seq}): {} events recorded, {}; see its stderr",
                        actual.len(),
                        termination.describe()
                    ),
                );
            } else {
                if !matches!(termination, Termination::Signaled { .. }) {
                    fail(
                        &mut lines,
                        format!(
                            "declared abort at seq {seq}, but the probe did not die on a signal ({}): {description}",
                            termination.describe()
                        ),
                    );
                }
                if let Some(pinned) = pinned {
                    let observed = stderr.unwrap_or("");
                    if observed.contains(pinned.as_str()) {
                        lines.push(format!("declared abort diagnostic observed: {pinned:?}"));
                    } else {
                        fail(
                            &mut lines,
                            format!(
                                "declared abort diagnostic not observed in the leg's stderr: {pinned:?}: {description}"
                            ),
                        );
                    }
                }
                lines.push(format!(
                    "declared abort observed at seq {seq} ({}): {description}",
                    termination.describe()
                ));
            }
            (*seq).min(expected_events.len())
        }
        None => expected_events.len(),
    };

    if abort_at.is_none() && actual.len() != expected_len {
        let first_divergent = actual
            .iter()
            .zip(expected_events.iter())
            .find(|(a, e)| a != e)
            .map(|(a, _)| describe_event(a));
        fail(
            &mut lines,
            format!(
                "event-count drift: {} blessed events, {} actual{}",
                expected_events.len(),
                actual.len(),
                first_divergent
                    .map(|d| format!("; first divergent event: {d}"))
                    .unwrap_or_else(|| "; the shorter stream is a prefix of the longer".to_string())
            ),
        );
    }

    let mut used = vec![false; applicable.len()];
    let mut reported = 0usize;
    // The termination is compared like any other event (declarable as
    // `op = "__termination"`), except under a declared abort, which already
    // required a signal death.
    let termination_pair = if abort_at.is_none() {
        Some((actual_term, expected_term))
    } else {
        None
    };
    let pairs = actual
        .iter()
        .zip(expected_events.iter().take(expected_len))
        .map(|(a, e)| (a.clone(), e.clone()))
        .chain(termination_pair);
    for (actual_event, expected_event) in pairs {
        if actual_event == expected_event {
            continue;
        }
        let a = flatten(&actual_event);
        let e = flatten(&expected_event);
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
                    .find(|(_, d)| d.matches(&expected_event, path))
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
                                describe_event(&expected_event)
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
    if abort_at.is_none() && !probe_ok && lines.iter().any(|line| line.starts_with("FAIL ")) {
        lines.push(format!(
            "the probe did not exit 0 ({}); see its stderr",
            termination.describe()
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

    if let Some(pending) = pending {
        if failures == 0 {
            lines.push(format!(
                "FAIL STALE: the probe is declared pending but now passes cleanly; delete the declaration: {}",
                pending.describe()
            ));
            return Outcome { ok: false, lines };
        }
        // Every failure above is the gap the declaration names; the leg still
        // lists them so the builder sees exactly what remains.
        let covered: Vec<String> = lines
            .iter()
            .map(|line| match line.strip_prefix("FAIL ") {
                Some(rest) => format!("  pending: {rest}"),
                None => format!("  {line}"),
            })
            .collect();
        let mut out = vec![format!(
            "declared pending ({failures} difference(s) covered, {}): {}",
            termination.describe(),
            pending.describe()
        )];
        out.extend(covered);
        return Outcome {
            ok: true,
            lines: out,
        };
    }

    Outcome {
        ok: failures == 0,
        lines,
    }
}

// ---- the frozen oracle (family gate) ----------------------------------------

/// `frozen.toml`: per family, the oracle a builder may not touch and what the
/// runtime must show beyond green probes. Version control is the
/// tamper evidence: `gate.sh` requires `paths` to carry no uncommitted change.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Frozen {
    pub family: BTreeMap<String, FrozenFamily>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct FrozenFamily {
    /// The probe ids the family owns; their declarations are gated.
    pub probes: Vec<String>,
    /// The oracle's paths (files or directories, from the repo root).
    pub paths: Vec<String>,
    /// The exact declarations the family's probes may carry, in the
    /// `divergences.toml` shape.
    #[serde(default)]
    pub declaration: Vec<Divergence>,
    /// What the runtime must show that green probes cannot: a shallow model
    /// can satisfy behaviour-only probes.
    #[serde(default)]
    pub obligation: Vec<Obligation>,
}

/// One design obligation:
///
/// * `unit-test` — `krate` + `test`: exactly one test of that crate has the
///   path `test` (or a path ending in `::test`), is not ignored, and passes
///   when run alone. `asserts` says what it must assert; the gate checks
///   existence and passing, the code review checks substance.
/// * `trace` — `probe` (+ `vehicles`): the trace the probe's replay leg
///   RECORDED has `format_version >= format_version_min`, its
///   `signal_generated` ops are exactly `signal_generated` (in order, `<sig>:p`
///   process-directed or `<sig>:t` thread-directed), and no generation is
///   directly followed by more than `max_wakes_per_generation` `task_wake` ops.
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Obligation {
    pub kind: String,
    #[serde(default, rename = "crate")]
    pub krate: Option<String>,
    #[serde(default)]
    pub test: Option<String>,
    #[serde(default)]
    pub asserts: Option<String>,
    #[serde(default)]
    pub probe: Option<String>,
    #[serde(default)]
    pub vehicles: Vec<String>,
    #[serde(default)]
    pub format_version_min: Option<u64>,
    #[serde(default)]
    pub signal_generated: Option<Vec<String>>,
    #[serde(default)]
    pub max_wakes_per_generation: Option<usize>,
}

impl Obligation {
    fn validate(&self) -> Result<(), String> {
        let ok = match self.kind.as_str() {
            "unit-test" => {
                self.krate.is_some()
                    && self.test.is_some()
                    && self
                        .asserts
                        .as_deref()
                        .is_some_and(|a| !a.trim().is_empty())
            }
            "trace" => {
                self.probe.is_some()
                    && self.signal_generated.iter().flatten().all(|generation| {
                        generation.rsplit_once(':').is_some_and(|(sig, target)| {
                            sig.parse::<u32>().is_ok() && (target == "p" || target == "t")
                        })
                    })
                    && self.vehicles.iter().all(|v| VEHICLES.contains(&v.as_str()))
            }
            other => return Err(format!("unknown obligation kind {other:?}")),
        };
        if ok {
            Ok(())
        } else {
            Err(format!("a malformed {:?} obligation", self.kind))
        }
    }

    fn vehicles(&self) -> Vec<&str> {
        if self.vehicles.is_empty() {
            VEHICLES.to_vec()
        } else {
            self.vehicles.iter().map(String::as_str).collect()
        }
    }
}

pub fn load_frozen(text: &str) -> Result<Frozen, String> {
    let frozen: Frozen = toml::from_str(text).map_err(|error| format!("frozen.toml: {error}"))?;
    for (family, spec) in &frozen.family {
        if spec.probes.is_empty() || spec.paths.is_empty() {
            return Err(format!(
                "frozen.toml: family {family:?} needs probes and paths"
            ));
        }
        for declaration in &spec.declaration {
            declaration
                .validate()
                .map_err(|error| format!("frozen.toml: family {family:?}: {error}"))?;
            let pending = declaration.kind == "pending";
            if !spec.probes.contains(&declaration.probe) || !(pending || declaration.by_design()) {
                return Err(format!(
                    "frozen.toml: family {family:?}: the declaration for {:?} must be for an owned probe and be `pending` or `by design:`",
                    declaration.probe
                ));
            }
        }
        for obligation in &spec.obligation {
            obligation
                .validate()
                .map_err(|error| format!("frozen.toml: family {family:?}: {error}"))?;
        }
    }
    Ok(frozen)
}

/// The declaration rule of the family gate: the family's probes may carry
/// only frozen declarations (a new or relabeled one fails), every by-design
/// one must still be there, and every pending one must be gone. One line per
/// violation; none means the rule holds.
pub fn gate_declarations(frozen: &FrozenFamily, current: &[Divergence]) -> Vec<String> {
    let mut violations = Vec::new();
    for declaration in current {
        if frozen.probes.contains(&declaration.probe) && !frozen.declaration.contains(declaration) {
            violations.push(format!(
                "declaration not in the frozen set (new, relabeled or re-scoped): {}",
                declaration.describe()
            ));
        }
    }
    for declaration in &frozen.declaration {
        let present = current.contains(declaration);
        if declaration.by_design() && !present {
            violations.push(format!(
                "by-design declaration removed: {}",
                declaration.describe()
            ));
        } else if !declaration.by_design() && present {
            violations.push(format!(
                "still pending: {}{}",
                declaration.probe,
                declaration
                    .vehicle
                    .as_deref()
                    .map(|v| format!("[{v}]"))
                    .unwrap_or_default()
            ));
        }
    }
    violations
}

/// One recorded trace as the supervisor reports it: `trace info --format json`
/// and the `trace events --format json` lines (`patina.trace.events/v1`).
pub struct RecordedTrace {
    pub format_version: Option<u64>,
    pub events: Vec<Value>,
}

pub fn parse_recorded_trace(info_text: &str, events_text: &str) -> Result<RecordedTrace, String> {
    let info: Value = serde_json::from_str(info_text)
        .map_err(|error| format!("trace info is not JSON: {error}"))?;
    let info = if info["trace_info"].is_object() {
        info["trace_info"].clone()
    } else {
        info
    };
    let mut events = Vec::new();
    for (index, line) in events_text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .map_err(|error| format!("trace events line {}: {error}", index + 1))?;
        if value["kind"].is_string() {
            events.push(value);
        }
    }
    Ok(RecordedTrace {
        format_version: info["format_version"].as_u64(),
        events,
    })
}

/// A `signal_generated` op as `<sig>:p|t`: process-directed when the op's
/// `target` is the string `process`, thread-directed otherwise (`{"task": N}`).
fn generation_of(event: &Value) -> Option<String> {
    if event["kind"] != "signal_generated" {
        return None;
    }
    let sig = event["operation"]["sig"].as_u64()?;
    let process = event["operation"]["target"]
        .as_str()
        .is_some_and(|t| t.eq_ignore_ascii_case("process"));
    Some(format!("{sig}:{}", if process { "p" } else { "t" }))
}

/// One trace obligation against one recorded trace: a work-order line per
/// unmet fact. `leg` names the probe and vehicle.
pub fn check_trace_obligation(
    obligation: &Obligation,
    leg: &str,
    trace: &RecordedTrace,
) -> Vec<String> {
    let mut unmet = Vec::new();
    if let Some(min) = obligation.format_version_min {
        if trace.format_version.is_none_or(|version| version < min) {
            unmet.push(format!(
                "trace fact unmet: {leg}: the recorded trace is format {}, required >= {min}",
                trace
                    .format_version
                    .map_or("?".to_string(), |v| v.to_string())
            ));
        }
    }
    if let Some(expected) = &obligation.signal_generated {
        let observed: Vec<String> = trace.events.iter().filter_map(generation_of).collect();
        if &observed != expected {
            unmet.push(format!(
                "trace fact unmet: {leg}: signal_generated ops recorded [{}], the probe generates [{}]",
                observed.join(" "),
                expected.join(" ")
            ));
        }
    }
    if let Some(max) = obligation.max_wakes_per_generation {
        for (index, event) in trace.events.iter().enumerate() {
            let wakes = trace.events[index + 1..]
                .iter()
                .take_while(|next| next["kind"] == "task_wake")
                .count();
            if event["kind"] == "signal_generated" && wakes > max {
                unmet.push(format!(
                    "trace fact unmet: {leg}: a generation woke {wakes} tasks (at most {max}: only the chosen target is unlinked and woken)"
                ));
            }
        }
    }
    unmet
}

/// Every trace obligation against the replay legs' dumped traces under
/// `out_dir` (`<bin>/replay.<vehicle>.trace-info.json` and
/// `.trace-events.jsonl`, written by `run.sh`). A missing dump is unmet: the
/// probe's replay leg did not run (it is still declared, or it failed).
pub fn check_trace_obligations(due: &[Obligation], out_dir: &std::path::Path) -> Vec<String> {
    let mut unmet = Vec::new();
    for obligation in due.iter().filter(|o| o.kind == "trace") {
        let probe = obligation.probe.as_deref().unwrap_or("?");
        let base = out_dir.join(probe.replace('/', "-"));
        let mut missing = Vec::new();
        for vehicle in obligation.vehicles() {
            let leg = format!("{probe}[{vehicle}]");
            let read = |suffix: &str| {
                std::fs::read_to_string(base.join(format!("replay.{vehicle}.{suffix}")))
            };
            match (read("trace-info.json"), read("trace-events.jsonl")) {
                (Ok(info), Ok(events)) => match parse_recorded_trace(&info, &events) {
                    Ok(trace) => unmet.extend(check_trace_obligation(obligation, &leg, &trace)),
                    Err(error) => unmet.push(format!("trace fact unmet: {leg}: {error}")),
                },
                _ => missing.push(vehicle),
            }
        }
        if !missing.is_empty() {
            unmet.push(format!(
                "trace fact unmet: {probe}[{}]: no recorded trace (the probe's replay leg did not run)",
                missing.join(",")
            ));
        }
    }
    unmet
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
    references: &[Registry],
    probe: &str,
    blessed: &Header,
    host_kernel: &str,
) -> HostGate {
    if let Err(error) = validate_manifest(manifest, registry, references) {
        return HostGate::Error(error);
    }
    if blessed.os != registry.os
        || blessed.arch != registry.arch
        || blessed.virtual_abi != registry.virtual_abi
    {
        return HostGate::Error("blessing target/virtual ABI does not match host registry".into());
    }
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
    for syscall in spec
        .syscalls
        .iter()
        .filter(|name| registry.dispositions.contains_key(*name))
    {
        let since = since_of(syscall);
        if host < since {
            return HostGate::Unavailable(format!(
                "host kernel {host_kernel} lacks {syscall} (since {}.{})",
                since.0, since.1
            ));
        }
    }
    for syscall in spec
        .absent
        .iter()
        .filter(|name| registry.dispositions.contains_key(*name))
    {
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

/// A small raw stream with every normalization kind in play (no termination
/// line; `with_term` appends one the way the supervisor does).
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

/// Append the supervisor's termination line to a stream.
fn with_term(mut events: Vec<Event>, termination: Termination) -> Vec<Event> {
    let seq = events.len() as u64;
    events.push(termination.event(seq));
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
        stderr: None,
        reason: "selftest: planted".to_string(),
    }
}

fn pending_declaration(reason: &str) -> Divergence {
    Divergence {
        kind: "pending".to_string(),
        op: None,
        field: None,
        reason: reason.to_string(),
        ..divergence("", "", None)
    }
}

/// Prove every differ gate can fail: a planted divergence, a planted stale
/// divergence, a planted event-count drift (both directions), a planted stale
/// probe-level declaration, a planted wrong / missing termination, a pending
/// declaration that covers and one that went stale, an abort whose pinned
/// diagnostic is absent, the frozen declaration rule's four refusals, plus the
/// controls that must pass, plus the host gate's two refusals. Returns `ok`
/// only if every case behaved.
pub fn selftest() -> Outcome {
    let header = synthetic_header();
    let raw = with_term(synthetic_raw(), Termination::Exited(0));
    let expected = Expectation {
        header: header.clone(),
        events: with_term(normalize(synthetic_raw()), Termination::Exited(0)),
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
    let d = |mode, actual: Vec<Event>, divs: &[Divergence], stderr: Option<&str>| {
        diff(mode, probe, "libc", &expected, actual, divs, stderr)
    };

    // Controls: an identical stream passes natively and under patina, and the
    // normalizer erases host magnitudes (a different fd/inode/uid/clock still
    // matches).
    case(
        "control: identical stream passes (native)",
        true,
        d(Mode::Native, raw.clone(), &[], None),
        "",
    );
    case(
        "control: identical stream passes (patina)",
        true,
        d(Mode::Patina, raw.clone(), &[], None),
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
        d(Mode::Patina, renumbered, &[], None),
        "",
    );

    // Planted divergence: the write returns a different count.
    let mut planted = raw.clone();
    planted[1].ret = Value::from(4);
    case(
        "planted divergence is refused (patina, undeclared)",
        false,
        d(Mode::Patina, planted.clone(), &[], None),
        "undeclared divergence",
    );
    case(
        "planted divergence is refused (native oracle)",
        false,
        d(Mode::Native, planted.clone(), &[], None),
        "host-oracle divergence",
    );
    case(
        "planted divergence passes once declared",
        true,
        d(
            Mode::Patina,
            planted.clone(),
            &[divergence("write", "ret", None)],
            None,
        ),
        "still needed",
    );
    case(
        "a declaration for another vehicle does not cover it",
        false,
        d(
            Mode::Patina,
            planted.clone(),
            &[divergence("write", "ret", Some("raw"))],
            None,
        ),
        "undeclared divergence",
    );

    // Planted stale divergence: declared, but the stream agrees.
    case(
        "planted stale divergence is refused",
        false,
        d(
            Mode::Patina,
            raw.clone(),
            &[divergence("write", "ret", None)],
            None,
        ),
        "STALE",
    );

    // Planted event-count drift, both directions.
    let short = with_term(synthetic_raw()[..6].to_vec(), Termination::Exited(0));
    case(
        "planted event-count drift (missing event) is refused",
        false,
        d(Mode::Patina, short, &[], None),
        "event-count drift",
    );
    let mut long = synthetic_raw();
    let mut extra = long[6].clone();
    extra.seq = 7;
    long.push(extra);
    case(
        "planted event-count drift (extra event) is refused",
        false,
        d(
            Mode::Patina,
            with_term(long, Termination::Exited(0)),
            &[],
            None,
        ),
        "event-count drift",
    );

    // A failed check under patina is a field divergence, not an abort.
    let mut failed_check = raw.clone();
    failed_check[6].ret = Value::from(0);
    case(
        "a failed check is an undeclared divergence",
        false,
        d(Mode::Patina, failed_check.clone(), &[], None),
        "check(label=",
    );
    let labelled = Divergence {
        label: Some("write returned len".to_string()),
        ..divergence("check", "ret", None)
    };
    case(
        "a failed check passes once declared by label",
        true,
        d(Mode::Patina, failed_check, &[labelled], None),
        "still needed",
    );

    // The termination line: the supervisor's observation, never synthesized.
    let died = with_term(
        synthetic_raw(),
        Termination::Signaled {
            signal: 15,
            core: Some(false),
        },
    );
    case(
        "a planted wrong termination (signal death vs blessed exit 0) is refused",
        false,
        d(Mode::Patina, died.clone(), &[], None),
        "__termination",
    );
    case(
        "a planted wrong termination never passes the native oracle",
        false,
        d(Mode::Native, died.clone(), &[], None),
        "__termination",
    );
    let term_kind = divergence("__termination", "fields.kind", None);
    let term_code = divergence("__termination", "fields.code", None);
    let term_signal = divergence("__termination", "fields.signal", None);
    let term_core = divergence("__termination", "fields.core", None);
    case(
        "a wrong termination passes once every differing field is declared",
        true,
        d(
            Mode::Patina,
            died,
            &[
                term_kind.clone(),
                term_code.clone(),
                term_signal.clone(),
                term_core.clone(),
            ],
            None,
        ),
        "still needed",
    );
    case(
        "a stream without a termination line is refused (it cannot be filled in)",
        false,
        d(Mode::Patina, synthetic_raw(), &[], None),
        "no termination line observed",
    );
    let unblessed = Expectation {
        header: header.clone(),
        events: normalize(synthetic_raw()),
    };
    case(
        "an expectation without a termination line is refused",
        false,
        diff(
            Mode::Patina,
            probe,
            "libc",
            &unblessed,
            raw.clone(),
            &[],
            None,
        ),
        "no termination line; re-bless",
    );
    let unreported = with_term(
        synthetic_raw(),
        Termination::Signaled {
            signal: 6,
            core: None,
        },
    );
    let blessed_core = Expectation {
        header: header.clone(),
        events: with_term(
            normalize(synthetic_raw()),
            Termination::Signaled {
                signal: 6,
                core: Some(true),
            },
        ),
    };
    case(
        "an unreported core flag diverges from a blessed one",
        false,
        diff(
            Mode::Patina,
            probe,
            "libc",
            &blessed_core,
            unreported.clone(),
            &[],
            None,
        ),
        "fields.core",
    );
    case(
        "an unreported core flag passes once declared",
        true,
        diff(
            Mode::Patina,
            probe,
            "libc",
            &blessed_core,
            unreported,
            std::slice::from_ref(&term_core),
            None,
        ),
        "still needed",
    );
    case(
        "blessing refuses a signal death the probe did not announce",
        true,
        Outcome {
            ok: blessable(&with_term(
                synthetic_raw(),
                Termination::Signaled {
                    signal: 15,
                    core: Some(false),
                },
            ))
            .is_err(),
            lines: vec![],
        },
        "",
    );
    let mut announced = synthetic_raw();
    announced.push(Event {
        seq: announced.len() as u64,
        op: EXPECT_DEATH_OP.to_string(),
        args: BTreeMap::from([("signal".to_string(), Value::from(15))]),
        ret: Value::from(0),
        errno: None,
        fields: BTreeMap::new(),
        norm: BTreeMap::new(),
    });
    case(
        "blessing accepts an announced signal death",
        true,
        Outcome {
            ok: blessable(&with_term(
                announced,
                Termination::Signaled {
                    signal: 15,
                    core: Some(false),
                },
            ))
            .is_ok(),
            lines: vec![],
        },
        "",
    );
    case(
        "blessing refuses a failed check and a nonzero exit",
        true,
        Outcome {
            ok: blessable(&with_term(synthetic_raw(), Termination::Exited(101))).is_err()
                && blessable(&{
                    let mut failed = synthetic_raw();
                    failed[6].ret = Value::from(0);
                    with_term(failed, Termination::Exited(0))
                })
                .is_err(),
            lines: vec![],
        },
        "",
    );

    // Probe-level declarations.
    let failing_probe = Divergence {
        kind: "probe".to_string(),
        op: None,
        field: None,
        ..divergence("", "", None)
    };
    let abort_stream = with_term(
        synthetic_raw()[..2].to_vec(),
        Termination::Signaled {
            signal: 6,
            core: Some(true),
        },
    );
    case(
        "a probe that dies is refused when undeclared",
        false,
        d(Mode::Patina, abort_stream.clone(), &[], None),
        "event-count drift",
    );
    case(
        "a probe that dies passes when declared failing",
        true,
        d(
            Mode::Patina,
            abort_stream.clone(),
            std::slice::from_ref(&failing_probe),
            None,
        ),
        "declared failing probe",
    );
    case(
        "planted stale probe-level declaration is refused",
        false,
        d(
            Mode::Patina,
            raw.clone(),
            std::slice::from_ref(&failing_probe),
            None,
        ),
        "STALE",
    );
    case(
        "a dying probe never passes the native oracle",
        false,
        d(Mode::Native, abort_stream.clone(), &[], None),
        "",
    );

    // Pending declarations: cover any difference, stale once none remains.
    let pending = pending_declaration("pending: selftest — M1: planted");
    case(
        "a pending declaration covers a dying probe and lists the gap",
        true,
        d(
            Mode::Patina,
            abort_stream.clone(),
            std::slice::from_ref(&pending),
            None,
        ),
        "pending: event-count drift",
    );
    case(
        "a pending declaration covers a field divergence",
        true,
        d(
            Mode::Patina,
            planted.clone(),
            std::slice::from_ref(&pending),
            None,
        ),
        "pending: undeclared divergence",
    );
    case(
        "planted stale pending declaration (the probe passes) is refused",
        false,
        d(
            Mode::Patina,
            raw.clone(),
            std::slice::from_ref(&pending),
            None,
        ),
        "STALE",
    );

    // Abort-level declarations: exact prefix, a signal death, the pinned
    // diagnostic, stale when the probe outlives it.
    let abort_at_3 = Divergence {
        kind: "abort".to_string(),
        op: None,
        field: None,
        seq: Some(3),
        ..divergence("", "", None)
    };
    let died_at_3 = with_term(
        synthetic_raw()[..3].to_vec(),
        Termination::Signaled {
            signal: 6,
            core: Some(true),
        },
    );
    case(
        "a declared abort with the exact prefix passes",
        true,
        d(
            Mode::Patina,
            died_at_3.clone(),
            std::slice::from_ref(&abort_at_3),
            None,
        ),
        "declared abort observed",
    );
    let mut planted_prefix = died_at_3.clone();
    planted_prefix[1].ret = Value::from(4);
    case(
        "a declared abort still compares the prefix",
        false,
        d(
            Mode::Patina,
            planted_prefix,
            std::slice::from_ref(&abort_at_3),
            None,
        ),
        "undeclared divergence",
    );
    case(
        "a declared abort whose probe exited instead of dying is refused",
        false,
        d(
            Mode::Patina,
            with_term(synthetic_raw()[..3].to_vec(), Termination::Exited(1)),
            std::slice::from_ref(&abort_at_3),
            None,
        ),
        "did not die on a signal",
    );
    case(
        "planted stale abort (the probe outlived it) is refused",
        false,
        d(
            Mode::Patina,
            with_term(
                synthetic_raw()[..5].to_vec(),
                Termination::Signaled {
                    signal: 6,
                    core: Some(true),
                },
            ),
            std::slice::from_ref(&abort_at_3),
            None,
        ),
        "STALE",
    );
    case(
        "planted stale abort (the probe now passes) is refused",
        false,
        d(
            Mode::Patina,
            raw.clone(),
            std::slice::from_ref(&abort_at_3),
            None,
        ),
        "STALE",
    );
    case(
        "a probe dying before its declared abort is refused",
        false,
        d(
            Mode::Patina,
            with_term(
                synthetic_raw()[..1].to_vec(),
                Termination::Signaled {
                    signal: 6,
                    core: Some(true),
                },
            ),
            std::slice::from_ref(&abort_at_3),
            None,
        ),
        "died before its declared abort",
    );
    let pinned_abort = Divergence {
        stderr: Some("patina: process spawn reached under patina: fork".to_string()),
        ..abort_at_3.clone()
    };
    case(
        "a declared abort whose pinned diagnostic is absent from stderr is refused",
        false,
        d(
            Mode::Patina,
            died_at_3.clone(),
            std::slice::from_ref(&pinned_abort),
            Some("patina: something else entirely\n"),
        ),
        "diagnostic not observed",
    );
    case(
        "a declared abort whose pinned diagnostic is in stderr passes",
        true,
        d(
            Mode::Patina,
            died_at_3.clone(),
            std::slice::from_ref(&pinned_abort),
            Some("patina: process spawn reached under patina: fork; failing closed\n"),
        ),
        "declared abort diagnostic observed",
    );

    // The frozen declaration rule.
    let by_design = Divergence {
        kind: "abort".to_string(),
        op: None,
        field: None,
        seq: Some(1),
        reason: "by design: fork is a process-lifecycle trap".to_string(),
        ..divergence("", "", None)
    };
    let pending = pending_declaration("pending: selftest — planted");
    let trace_obligation = Obligation {
        kind: "trace".to_string(),
        krate: None,
        test: None,
        asserts: None,
        probe: Some(probe.to_string()),
        vehicles: Vec::new(),
        format_version_min: Some(9),
        signal_generated: Some(vec!["10:p".to_string(), "10:t".to_string()]),
        max_wakes_per_generation: Some(1),
    };
    let frozen = FrozenFamily {
        probes: vec!["selftest/synthetic".to_string()],
        paths: vec!["probes".to_string()],
        declaration: vec![by_design.clone(), pending.clone()],
        obligation: vec![trace_obligation.clone()],
    };
    let gate = |current: &[Divergence], mention: &str| {
        let lines = gate_declarations(&frozen, current);
        Outcome {
            ok: if mention.is_empty() {
                lines.is_empty()
            } else {
                lines.iter().any(|l| l.contains(mention))
            },
            lines,
        }
    };
    case(
        "frozen rule: only the by-design declarations left passes",
        true,
        gate(std::slice::from_ref(&by_design), ""),
        "",
    );
    case(
        "frozen rule: a pending declaration still present is refused",
        true,
        gate(&[by_design.clone(), pending.clone()], "still pending"),
        "",
    );
    case(
        "frozen rule: a new or relabeled declaration is refused",
        true,
        gate(
            &[
                by_design.clone(),
                pending_declaration("pending: selftest — relabeled"),
            ],
            "not in the frozen set",
        ),
        "",
    );
    case(
        "frozen rule: a removed by-design declaration is refused",
        true,
        gate(&[], "by-design declaration removed"),
        "",
    );

    // Trace obligations: what a behaviour-only pass skips.
    let op =
        |kind: &str, operation: Value| serde_json::json!({"kind": kind, "operation": operation});
    let generated = |sig: u64, target: Value| {
        op(
            "signal_generated",
            serde_json::json!({"sig": sig, "target": target}),
        )
    };
    let wake = || op("task_wake", serde_json::json!({"task": 1}));
    let next = || op("scheduler_next", Value::Null);
    let trace_case = |format: u64, events: Vec<Value>, mention: &str| {
        let unmet = check_trace_obligation(
            &trace_obligation,
            "selftest/synthetic[libc]",
            &RecordedTrace {
                format_version: Some(format),
                events,
            },
        );
        Outcome {
            ok: if mention.is_empty() {
                unmet.is_empty()
            } else {
                unmet.iter().any(|line| line.contains(mention))
            },
            lines: unmet,
        }
    };
    let faithful = vec![
        generated(10, Value::from("process")),
        wake(),
        next(),
        generated(10, serde_json::json!({"task": 2})),
    ];
    case(
        "obligation: a trace with the probe's generations, in order, at the required format is met",
        true,
        trace_case(9, faithful.clone(), ""),
        "",
    );
    case(
        "obligation: a recorded trace with no signal_generated op for a generating probe is unmet",
        true,
        trace_case(
            9,
            vec![next(), wake(), next()],
            "signal_generated ops recorded []",
        ),
        "",
    );
    case(
        "obligation: generations in the wrong order or with the wrong target are unmet",
        true,
        trace_case(
            9,
            vec![
                generated(10, serde_json::json!({"task": 2})),
                generated(10, Value::from("process")),
            ],
            "recorded [10:t 10:p]",
        ),
        "",
    );
    case(
        "obligation: a trace below the required format version is unmet",
        true,
        trace_case(8, faithful.clone(), "is format 8"),
        "",
    );
    case(
        "obligation: a generation that wakes every parked task is unmet",
        true,
        trace_case(
            9,
            vec![
                generated(10, Value::from("process")),
                wake(),
                wake(),
                generated(10, serde_json::json!({"task": 2})),
            ],
            "woke 2 tasks",
        ),
        "",
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
        os: "linux".into(),
        arch: "x86_64".into(),
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
    let references = [Registry {
        arch: "aarch64".into(),
        ..registry.clone()
    }];
    let gate_case = |host: &str, want: fn(&HostGate) -> bool| -> Outcome {
        let gate = host_gate(&manifest, &registry, &references, probe, &header, host);
        Outcome {
            ok: want(&gate),
            lines: vec![format!("{gate:?}")],
        }
    };
    let absent_case = |host: &str, want: fn(&HostGate) -> bool| -> Outcome {
        let gate = host_gate(
            &manifest,
            &registry,
            &references,
            absent_probe,
            &header,
            host,
        );
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
        &references,
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
            ok: validate_manifest(&manifest, &registry, &references).is_ok(),
            lines: vec![],
        },
        "",
    );

    // Class pairing: architecture-local coverage and host metadata isolation.
    // Synthetic future dates distinguish inventory knowledge from host availability.
    let mut foreign = references[0].clone();
    foreign
        .dispositions
        .insert("foreign_call".into(), "modeled".into());
    foreign
        .dispositions
        .insert("foreign_absent".into(), "absent".into());
    foreign.since.insert("foreign_call".into(), "99.0".into());
    foreign.since.insert("foreign_absent".into(), "1.0".into());
    let mut mixed = manifest.clone();
    mixed
        .probe
        .get_mut(probe)
        .unwrap()
        .syscalls
        .push("foreign_call".into());
    mixed
        .probe
        .get_mut(probe)
        .unwrap()
        .absent
        .push("foreign_absent".into());
    let refs = [foreign];
    let coverage = validate_manifest(&mixed, &registry, &refs);
    case(
        "manifest platforms: foreign names explicitly nonhost",
        true,
        Outcome {
            ok: matches!(&coverage, Ok(rows) if rows.len() == 2 && rows.iter().any(|r| r.contains("foreign_call")) && rows.iter().any(|r| r.contains("foreign_absent"))),
            lines: vec![format!("{coverage:?}")],
        },
        "",
    );
    let gate = host_gate(&mixed, &registry, &refs, probe, &header, "6.8");
    case(
        "manifest platforms: foreign future and absent dates never gate the host",
        true,
        Outcome {
            ok: gate == HostGate::Ok,
            lines: vec![format!("{gate:?}")],
        },
        "",
    );
    for (label, bad_refs) in [
        ("missing reference", vec![]),
        ("misidentified reference", vec![registry.clone()]),
        (
            "wrong OS",
            vec![Registry {
                os: "darwin".into(),
                ..refs[0].clone()
            }],
        ),
        (
            "wrong ABI",
            vec![Registry {
                virtual_abi: "99.0".into(),
                ..refs[0].clone()
            }],
        ),
    ] {
        let result = validate_manifest(&mixed, &registry, &bad_refs);
        case(
            &format!("manifest platforms: refuses {label}"),
            true,
            Outcome {
                ok: result.is_err(),
                lines: vec![format!("{result:?}")],
            },
            "",
        );
    }
    for (label, name, absent) in [
        ("foreign wrong kind", "foreign_absent", false),
        ("foreign modeled as absent", "foreign_call", true),
        ("typo", "foreign_typo", false),
    ] {
        let mut bad = mixed.clone();
        let spec = bad.probe.get_mut(probe).unwrap();
        if absent {
            spec.absent.push(name.into());
        } else {
            spec.syscalls.push(name.into());
        }
        let result = validate_manifest(&bad, &registry, &refs);
        case(
            &format!("manifest platforms: refuses {label}"),
            true,
            Outcome {
                ok: result.is_err(),
                lines: vec![format!("{result:?}")],
            },
            "",
        );
    }
    let mut future_host = registry.clone();
    future_host.since.insert("openat".into(), "99.0".into());
    let gate = host_gate(&mixed, &future_host, &refs, probe, &header, "6.8");
    case(
        "manifest platforms: host future date still gates",
        true,
        Outcome {
            ok: matches!(gate, HostGate::Unavailable(_)),
            lines: vec![format!("{gate:?}")],
        },
        "",
    );

    Outcome { ok: all_ok, lines }
}
