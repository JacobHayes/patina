//! The live comparison: a scenario's native observation is the oracle for its
//! patina observation of the same run.
//!
//! Both streams are normalized independently (the scenario's declared
//! [`Norm`](crate::observe::Norm)s), then compared field by field. Exact by
//! default: the only accepted differences are the ones a scenario's gaps name,
//! and a gap that no longer matches is itself a failure, so the declarations
//! are always exactly the current gap.

use crate::observe::{CHECK_OP, EXPECT_DEATH_OP, EXPECT_EXIT_OP, Event, ParsedNorm};
use crate::vehicle::Vehicle;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::time::Duration;

/// How a process ended, as its supervisor observed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Termination {
    Exited(i32),
    /// `core` is `None` when the supervisor does not report the flag.
    Signaled {
        signal: i32,
        core: Option<bool>,
    },
    /// The supervisor reported no guest outcome (a refusal before the guest ran).
    Unreported,
    /// The run was confirmed stuck and killed: the guest had started (its
    /// journal's start marker), and then neither its recorded events nor its
    /// scheduling state changed for a whole no-progress window (see
    /// `crates/cargo-patina/tests/native_conformance.rs`, `HangWatch`). A run
    /// that is merely slow is never this: it keeps the normal deadline.
    Hung,
}

impl fmt::Display for Termination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Termination::Exited(code) => write!(f, "exited {code}"),
            Termination::Signaled { signal, core } => write!(
                f,
                "signaled {signal}{}",
                match core {
                    Some(true) => " (core dumped)",
                    Some(false) => "",
                    None => " (core flag unreported)",
                }
            ),
            Termination::Unreported => write!(f, "no guest outcome reported"),
            Termination::Hung => write!(f, "hung (confirmed stuck, killed)"),
        }
    }
}

/// Which side of the differential a run is: the host kernel, or patina.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leg {
    Native,
    Patina,
}

impl Leg {
    fn name(self) -> &'static str {
        match self {
            Leg::Native => "native",
            Leg::Patina => "patina",
        }
    }
}

/// What produced an observation, set by the runner that produced it; every
/// comparison message names its sides from this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origin {
    pub leg: Leg,
    pub vehicle: Vehicle,
}

impl Origin {
    /// This side's name against `other`: what tells the two apart.
    fn name_against(self, other: Origin) -> &'static str {
        if self.leg == other.leg {
            self.vehicle.name()
        } else {
            self.leg.name()
        }
    }
}

/// One run of a scenario through one vehicle.
#[derive(Clone, Debug)]
pub struct Observation {
    pub origin: Origin,
    /// The raw (unnormalized) event stream.
    pub events: Vec<Event>,
    pub termination: Termination,
    pub stderr: String,
}

// ---- normalization ----------------------------------------------------------

#[derive(Default)]
struct Normalizer {
    /// table → raw value → label (`fd@57`: the event that introduced it). A
    /// namespace's table, except `port`'s, which has one per IP protocol.
    labels: HashMap<String, HashMap<i64, String>>,
    monotonic: HashMap<String, i64>,
    /// The IP protocol of each descriptor an AF_INET or AF_INET6 `socket` or
    /// an `accept` on one produced, until another event produces the number.
    protocols: HashMap<i64, i64>,
}

/// The IP protocol an AF_INET or AF_INET6 `socket` event created: its
/// protocol argument, or the type's default (TCP for a stream, UDP for a
/// datagram) for 0. The numbers are Linux's, as the streams record them,
/// whatever host compares them.
fn inet_protocol(event: &Event) -> Option<i64> {
    const AF_INET: i64 = 2;
    const AF_INET6: i64 = 10;
    const SOCK_STREAM: i64 = 1;
    const SOCK_DGRAM: i64 = 2;
    const SOCK_TYPE_MASK: i64 = 0xf;
    const IPPROTO_TCP: i64 = 6;
    const IPPROTO_UDP: i64 = 17;
    let arg = |name| event.args.get(name).and_then(Value::as_i64);
    if !matches!(arg("domain"), Some(AF_INET | AF_INET6)) {
        return None;
    }
    match (arg("protocol")?, arg("type")? & SOCK_TYPE_MASK) {
        (0, SOCK_STREAM) => Some(IPPROTO_TCP),
        (0, SOCK_DGRAM) => Some(IPPROTO_UDP),
        (0, _) => None,
        (protocol, _) => Some(protocol),
    }
}

impl Normalizer {
    /// The label of `value` in `table`: `namespace@` the seq of the event
    /// that first showed it (plus `.k` for the k-th new value of the
    /// namespace within one event). Keyed by the introducing event rather
    /// than a running count, so an extra allocation on one side shifts
    /// nothing downstream.
    fn label(
        &mut self,
        table: &str,
        namespace: &str,
        value: i64,
        seq: u64,
        fresh: &mut usize,
    ) -> String {
        let table = self.labels.entry(table.to_string()).or_default();
        if let Some(label) = table.get(&value) {
            return label.clone();
        }
        let label = if *fresh == 0 {
            format!("{namespace}@{seq}")
        } else {
            format!("{namespace}@{seq}.{fresh}")
        };
        *fresh += 1;
        table.insert(value, label.clone());
        label
    }

    fn apply(&mut self, event: &mut Event) {
        let norms: Vec<(String, String)> = event
            .norm
            .iter()
            .map(|(path, tag)| (path.clone(), tag.clone()))
            .collect();
        let mut retire = None;
        let mut fresh: HashMap<String, usize> = HashMap::new();
        // A port's identity is per IP protocol, as the kernel's port tables
        // are: a UDP port and a TCP port that share a number are unrelated.
        // The protocol is the descriptor's the event names (a destination
        // or source is the sender's or receiver's protocol); an event naming
        // no inet socket labels in the plain `port` table.
        let fd = event.args.get("fd").and_then(Value::as_i64);
        let port_table = match fd.and_then(|fd| self.protocols.get(&fd)) {
            Some(protocol) => format!("port/{protocol}"),
            None => "port".to_string(),
        };
        self.track_protocols(event, fd);
        for (path, tag) in norms {
            let Some(norm) = ParsedNorm::parse(&tag) else {
                continue;
            };
            // Monotonic relations are per clock: reads of different clock ids
            // have unrelated epochs.
            let key = match event.args.get("clock") {
                Some(clock) => format!("{}.{path}.clock={clock}", event.op),
                None => format!("{}.{path}", event.op),
            };
            if matches!(norm, ParsedNorm::Alternatives(_)) {
                // A comparison relation (`alternative`), not a rewrite: the
                // raw value stays for the comparison and for a gap to pin.
                continue;
            }
            let slot = match path.as_str() {
                "ret" => Some(&mut event.ret),
                _ => path
                    .strip_prefix("args.")
                    .and_then(|name| event.args.get_mut(name))
                    .or_else(|| {
                        path.strip_prefix("fields.")
                            .and_then(|name| event.fields.get_mut(name))
                    }),
            };
            let Some(slot) = slot else { continue };
            let Some(number) = slot.as_i64() else {
                continue;
            };
            *slot = match norm {
                ParsedNorm::Relative(namespace) => {
                    if number < 0 {
                        continue;
                    }
                    if namespace == "fd" && event.op == "close" && path == "args.fd" {
                        retire = Some(number);
                    }
                    let table = if namespace == "port" {
                        &port_table
                    } else {
                        &namespace
                    };
                    let fresh = fresh.entry(namespace.clone()).or_insert(0);
                    Value::from(self.label(table, &namespace, number, event.seq, fresh))
                }
                ParsedNorm::Inode => {
                    let fresh = fresh.entry("ino".to_string()).or_insert(0);
                    Value::from(self.label("ino", "ino", number, event.seq, fresh))
                }
                ParsedNorm::Identity(id) => {
                    let fresh = fresh.entry(id.clone()).or_insert(0);
                    Value::from(self.label(&id, &id, number, event.seq, fresh))
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
                ParsedNorm::Alternatives(_) => unreachable!("skipped above"),
            };
        }
        if let Some(number) = retire
            && let Some(table) = self.labels.get_mut("fd")
        {
            table.remove(&number);
        }
    }

    /// Record the protocol of the descriptors `event` produces (its `ret` or
    /// a field labeled in the `fd` namespace), from the raw values: an inet
    /// `socket`'s, an `accept`'s listener's (`fd`), or none.
    fn track_protocols(&mut self, event: &Event, fd: Option<i64>) {
        let protocol = match event.op.as_str() {
            "socket" => inet_protocol(event),
            "accept" | "accept4" => fd.and_then(|fd| self.protocols.get(&fd).copied()),
            _ => None,
        };
        for (path, tag) in &event.norm {
            if tag != "relative:fd" {
                continue;
            }
            let value = match path.as_str() {
                "ret" => Some(&event.ret),
                _ => path
                    .strip_prefix("fields.")
                    .and_then(|name| event.fields.get(name)),
            };
            let Some(number) = value.and_then(Value::as_i64).filter(|number| *number >= 0) else {
                continue;
            };
            match protocol.filter(|_| path == "ret") {
                Some(protocol) => self.protocols.insert(number, protocol),
                None => self.protocols.remove(&number),
            };
        }
    }
}

/// Apply every event's declared normalizations, in stream order (label and
/// monotonic state carries across events).
pub fn normalize(mut events: Vec<Event>) -> Vec<Event> {
    let mut normalizer = Normalizer::default();
    for event in &mut events {
        normalizer.apply(event);
    }
    events
}

// ---- a run's own verdict ----------------------------------------------------

/// Whether a run passes the scenario on its own: it recorded something,
/// every check passed, and the process exited 0, exited with the status its
/// last event announced, or died by the signal its last event announced. A
/// native run that does is an oracle.
pub fn verdict(run: &Observation) -> Result<(), String> {
    if run.events.is_empty() {
        return Err(format!("recorded no event ({})", run.termination));
    }
    if let Some(label) = failed_check(run) {
        return Err(format!("a check failed: {label}"));
    }
    let announced_exit = run
        .events
        .last()
        .filter(|event| event.op == EXPECT_EXIT_OP)
        .and_then(|event| event.args.get("code"))
        .and_then(Value::as_i64);
    if let Some(code) = announced_exit {
        return if run.termination == Termination::Exited(code as i32) {
            Ok(())
        } else {
            Err(format!(
                "announced exiting {code} (Probe::exits_with) but {}",
                run.termination
            ))
        };
    }
    match run.termination {
        Termination::Exited(0) => Ok(()),
        Termination::Signaled { signal, .. } => {
            let announced = run
                .events
                .last()
                .filter(|event| event.op == EXPECT_DEATH_OP)
                .and_then(|event| event.args.get("signal"))
                .and_then(Value::as_i64);
            if announced == Some(i64::from(signal)) {
                Ok(())
            } else {
                Err(format!(
                    "died on signal {signal} without announcing it (Probe::dies_by as its last act)"
                ))
            }
        }
        other => Err(format!("did not pass: {other}")),
    }
}

/// The label of the first check `observation` records as failed.
pub fn failed_check(observation: &Observation) -> Option<&str> {
    observation
        .events
        .iter()
        .find(|event| event.op == CHECK_OP && event.ret != 1)
        .map(|failed| label_of(failed).unwrap_or("?"))
}

fn label_of(event: &Event) -> Option<&str> {
    event.args.get("label").and_then(Value::as_str)
}

// ---- differences ------------------------------------------------------------

/// A value a gap pins on the patina side of a difference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observed {
    Str(&'static str),
    Int(i64),
    Bool(bool),
    Null,
    /// Any other JSON value, as JSON text (an array, say).
    Json(&'static str),
}

impl Observed {
    fn value(self) -> Value {
        match self {
            Observed::Str(text) => Value::from(text),
            Observed::Int(number) => Value::from(number),
            Observed::Bool(flag) => Value::from(flag),
            Observed::Null => Value::Null,
            Observed::Json(text) => serde_json::from_str(text)
                .unwrap_or_else(|error| panic!("gap value {text:?} is not JSON: {error}")),
        }
    }
}

/// One difference a gap declares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Difference {
    /// Event `seq` (an `op` event) differs at `path` (`ret`, `errno`,
    /// `args.<k>`, `fields.<k>`), where patina observes `patina` (the
    /// normalized value).
    Field {
        seq: u64,
        op: &'static str,
        path: &'static str,
        patina: Observed,
    },
    /// The check at event `seq`, with this label, fails under patina.
    Check { seq: u64, label: &'static str },
}

impl Difference {
    pub const fn check(seq: u64, label: &'static str) -> Self {
        Difference::Check { seq, label }
    }

    pub const fn field(seq: u64, op: &'static str, path: &'static str, patina: Observed) -> Self {
        Difference::Field {
            seq,
            op,
            path,
            patina,
        }
    }
}

/// How a scenario's patina run fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The patina run completes and ends like the native one; exactly these
    /// observations differ (the union of every applicable gap's).
    Differs(&'static [Difference]),
    /// The patina run records `events` events — the native run's first, but for
    /// the differences the vehicle's differing gaps declare — then ends
    /// `ending` with `diagnostic` in its stderr.
    Stops {
        events: usize,
        ending: Ending,
        diagnostic: &'static str,
    },
    /// The patina run records `events` events — the native run's first, but
    /// for the declared differences, as for `Stops`; read back from the
    /// probe's in-memory journal (`crate::journal`), since a killed run has
    /// no envelope — and then makes no progress: the harness starts watching
    /// `within` after the run began, confirms the hang positively
    /// ([`Termination::Hung`]) and kills it, so a declared hang costs about
    /// `within`, not the full run deadline. `within` is the smallest bound
    /// reliably past what a completed run needs (at most
    /// `catalog::MAX_HANG_WITHIN`).
    Hangs { events: usize, within: Duration },
}

impl Failure {
    /// Whether the patina run ends before the native one does (`Stops`,
    /// `Hangs`): at most one such gap per vehicle, and no record, replay or
    /// strace run after it.
    pub fn ends_early(&self) -> bool {
        matches!(self, Failure::Stops { .. } | Failure::Hangs { .. })
    }

    /// When the harness starts confirming a declared hang.
    pub fn hang_deadline(&self) -> Option<Duration> {
        match self {
            Failure::Hangs { within, .. } => Some(*within),
            _ => None,
        }
    }
}

/// How a stopping patina run ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ending {
    Signal(i32),
    Exit(i32),
}

/// A difference as observed, in the shape a gap declares.
#[derive(Clone, Debug, PartialEq)]
enum Found {
    Field {
        seq: u64,
        op: String,
        path: String,
        native: Value,
        patina: Value,
    },
    Check {
        seq: u64,
        label: String,
    },
}

impl Found {
    /// The difference, its sides named `reference` and `other`.
    fn describe(&self, reference: &str, other: &str) -> String {
        match self {
            Found::Field {
                seq,
                op,
                path,
                native,
                patina,
            } => format!("seq {seq} {op} {path}: {reference} {native}, {other} {patina}"),
            Found::Check { seq, label } => format!("seq {seq} check {label:?} fails under {other}"),
        }
    }
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
    // `norm` tags are the scenario's declarations, identical on both sides
    // unless the annotated field is absent — itself a `fields.*` difference.
    map
}

/// Whether the native event declares `native` and `patina` interchangeable
/// answers at `path` (`Norm::Alternatives`): both are among the values.
fn alternative(native: &Event, path: &str, native_value: &Value, patina_value: &Value) -> bool {
    let Some(ParsedNorm::Alternatives(values)) =
        native.norm.get(path).and_then(|tag| ParsedNorm::parse(tag))
    else {
        return false;
    };
    let among = |value: &Value| {
        value
            .as_str()
            .is_some_and(|text| values.iter().any(|allowed| allowed == text))
    };
    among(native_value) && among(patina_value)
}

/// The field differences between two aligned, normalized event prefixes.
fn found(native: &[Event], patina: &[Event]) -> Vec<Found> {
    let mut out = Vec::new();
    for (native, patina) in native.iter().zip(patina) {
        if native == patina {
            continue;
        }
        if native.op == CHECK_OP
            && patina.op == CHECK_OP
            && native.args == patina.args
            && native.ret != patina.ret
        {
            out.push(Found::Check {
                seq: native.seq,
                label: label_of(native).unwrap_or("?").to_string(),
            });
            continue;
        }
        let a = flatten(native);
        let b = flatten(patina);
        let mut paths: Vec<&String> = a.keys().chain(b.keys()).collect();
        paths.sort();
        paths.dedup();
        for path in paths {
            let native_value = a.get(path).cloned().unwrap_or(Value::Null);
            let patina_value = b.get(path).cloned().unwrap_or(Value::Null);
            if native_value != patina_value
                && !alternative(native, path, &native_value, &patina_value)
            {
                out.push(Found::Field {
                    seq: native.seq,
                    op: native.op.clone(),
                    path: path.clone(),
                    native: native_value,
                    patina: patina_value,
                });
            }
        }
    }
    out
}

fn declared_matches(declared: &Difference, found: &Found) -> bool {
    match (declared, found) {
        (
            Difference::Field {
                seq,
                op,
                path,
                patina,
            },
            Found::Field {
                seq: found_seq,
                op: found_op,
                path: found_path,
                patina: found_patina,
                ..
            },
        ) => {
            seq == found_seq
                && op == found_op
                && path == found_path
                && patina.value() == *found_patina
        }
        (
            Difference::Check { seq, label },
            Found::Check {
                seq: found_seq,
                label: found_label,
            },
        ) => seq == found_seq && label == found_label,
        _ => false,
    }
}

/// A gap as the comparison sees it: why, and how patina fails.
#[derive(Clone, Copy, Debug)]
pub struct Expected<'a> {
    pub reason: &'a str,
    pub failure: &'a Failure,
}

/// What a comparison that held saw: one line per gap confirmed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Verdict {
    pub confirmed: Vec<String>,
}

/// Compare a patina observation with its native oracle under the applicable
/// gaps. At most one gap stops the run; the differing gaps then name every
/// difference before the stop. `Err` carries every failure.
pub fn judge(
    native: &Observation,
    patina: &Observation,
    gaps: &[Expected<'_>],
) -> Result<Verdict, Vec<String>> {
    let (from, to) = (native.origin, patina.origin);
    if from.leg != Leg::Native || to.leg != Leg::Patina || from.vehicle != to.vehicle {
        return Err(vec![format!(
            "judge compares a native and a patina run of one vehicle, not {from:?} and {to:?}"
        )]);
    }
    compare(native, patina, gaps)
}

/// The comparison itself; its messages name each side from its origin.
fn compare(
    native: &Observation,
    patina: &Observation,
    gaps: &[Expected<'_>],
) -> Result<Verdict, Vec<String>> {
    let reference = native.origin.name_against(patina.origin);
    let other = patina.origin.name_against(native.origin);
    let native_events = normalize(native.events.clone());
    let patina_events = normalize(patina.events.clone());
    let (stops, differs): (Vec<&Expected<'_>>, Vec<&Expected<'_>>) =
        gaps.iter().partition(|gap| gap.failure.ends_early());
    let mut failures = Vec::new();
    let mut confirmed = Vec::new();
    let compared = match stops.as_slice() {
        [] => {
            if native_events.len() != patina_events.len() {
                let first = found(&native_events, &patina_events);
                failures.push(format!(
                    "event count: {reference} {}, {other} {}{}",
                    native_events.len(),
                    patina_events.len(),
                    first
                        .first()
                        .map(|found| format!(
                            "; first difference: {}",
                            found.describe(reference, other)
                        ))
                        .unwrap_or_default()
                ));
            }
            if native.termination != patina.termination {
                failures.push(format!(
                    "termination: {reference} {}, {other} {}",
                    native.termination, patina.termination
                ));
            }
            &native_events[..]
        }
        [stop] => {
            let events = check_stop(
                patina,
                patina_events.len(),
                stop,
                &mut confirmed,
                &mut failures,
            );
            &native_events[..events.min(native_events.len())]
        }
        _ => {
            return Err(vec![format!(
                "{} stopping gaps for one vehicle; a run stops once",
                stops.len()
            )]);
        }
    };
    let observed = found(compared, &patina_events);
    for gap in &differs {
        let Failure::Differs(declared) = gap.failure else {
            unreachable!("partitioned above")
        };
        let mut matched = 0;
        for difference in declared.iter() {
            if observed
                .iter()
                .any(|found| declared_matches(difference, found))
            {
                matched += 1;
            } else {
                failures.push(format!(
                    "declared difference not observed (stale, or a different patina value): {difference:?} ({})",
                    gap.reason
                ));
            }
        }
        if matched > 0 && matched == declared.len() {
            confirmed.push(format!(
                "{matched} difference(s) as declared: {}",
                gap.reason
            ));
        }
    }
    for found in &observed {
        let declared = differs.iter().any(|gap| match gap.failure {
            Failure::Differs(declared) => declared.iter().any(|d| declared_matches(d, found)),
            Failure::Stops { .. } | Failure::Hangs { .. } => false,
        });
        if !declared {
            failures.push(format!(
                "undeclared difference: {}",
                found.describe(reference, other)
            ));
        }
    }
    if failures.is_empty() {
        Ok(Verdict { confirmed })
    } else {
        Err(failures)
    }
}

/// The declared stop's own conditions: the event count, the ending and the
/// diagnostic. Returns the number of native events the stopped run is compared
/// against.
fn check_stop(
    observation: &Observation,
    recorded: usize,
    gap: &Expected<'_>,
    confirmed: &mut Vec<String>,
    failures: &mut Vec<String>,
) -> usize {
    let (events, ending, diagnostic) = match *gap.failure {
        Failure::Stops {
            events,
            ending,
            diagnostic,
        } => (events, Some(ending), diagnostic),
        Failure::Hangs { events, within } => {
            let before = failures.len();
            if observation.termination != Termination::Hung {
                failures.push(format!(
                    "declared to hang after {events} events (watched from {within:?}), but patina {} with {recorded} events; the gap is stale: {}",
                    observation.termination, gap.reason
                ));
                return events;
            }
            if recorded != events {
                failures.push(format!(
                    "declared to hang after {events} events, hung after {recorded}: {}",
                    gap.reason
                ));
            }
            if failures.len() == before {
                confirmed.push(format!(
                    "hangs after {events} events as declared (confirmed stuck from {within:?}): {}",
                    gap.reason
                ));
            }
            return events;
        }
        Failure::Differs(_) => unreachable!("check_stop takes a stopping gap"),
    };
    let ending = ending.expect("a stop declares its ending");
    let before = failures.len();
    if observation.termination == Termination::Exited(0) {
        failures.push(format!(
            "declared to stop after {events} events but patina exited 0 with {recorded} events; the gap is stale: {}",
            gap.reason
        ));
        return events;
    }
    if recorded != events {
        failures.push(format!(
            "declared to stop after {events} events, stopped after {recorded}: {}",
            gap.reason
        ));
    }
    let ended = match observation.termination {
        Termination::Signaled { signal, .. } => Some(Ending::Signal(signal)),
        Termination::Exited(code) => Some(Ending::Exit(code)),
        Termination::Unreported | Termination::Hung => None,
    };
    if ended != Some(ending) {
        failures.push(format!(
            "declared to end {ending:?}, ended {}: {}",
            observation.termination, gap.reason
        ));
    }
    if !observation.stderr.contains(diagnostic) {
        failures.push(format!(
            "declared diagnostic {diagnostic:?} not in the patina stderr: {}",
            gap.reason
        ));
    }
    if failures.len() == before {
        confirmed.push(format!(
            "stops after {events} events as declared: {}",
            gap.reason
        ));
    }
    events
}

/// Compare two native observations of one scenario through different
/// vehicles: the host kernel answers every vehicle the same way.
pub fn vehicles_agree(reference: &Observation, other: &Observation) -> Result<(), Vec<String>> {
    let (from, to) = (reference.origin, other.origin);
    if from.leg != Leg::Native || to.leg != Leg::Native || from.vehicle == to.vehicle {
        return Err(vec![format!(
            "vehicles_agree compares native runs of two vehicles, not {from:?} and {to:?}"
        )]);
    }
    compare(reference, other, &[]).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::Norm;

    const NATIVE: Origin = Origin {
        leg: Leg::Native,
        vehicle: Vehicle::Syscall,
    };

    /// `super::judge` with each side's origin set as its runner would.
    fn judge(
        native: &Observation,
        patina: &Observation,
        gaps: &[Expected<'_>],
    ) -> Result<Verdict, Vec<String>> {
        let patina = Observation {
            origin: Origin {
                leg: Leg::Patina,
                ..NATIVE
            },
            ..patina.clone()
        };
        super::judge(native, &patina, gaps)
    }

    /// A comparison of the wrong pair of runs is refused, whatever the
    /// streams: a native run against another, a patina run against its own
    /// vehicle's or another vehicle's native one as `vehicles_agree`.
    #[test]
    fn comparisons_refuse_the_wrong_pair_of_runs() {
        let on = |leg, vehicle| Observation {
            origin: Origin { leg, vehicle },
            ..native()
        };
        let (syscall, libc) = (
            on(Leg::Native, Vehicle::Syscall),
            on(Leg::Native, Vehicle::Libc),
        );
        let patina = on(Leg::Patina, Vehicle::Syscall);
        assert!(super::judge(&syscall, &patina, &[]).is_ok());
        assert!(super::judge(&syscall, &syscall, &[]).is_err());
        assert!(super::judge(&patina, &syscall, &[]).is_err());
        assert!(super::judge(&libc, &patina, &[]).is_err());
        assert!(vehicles_agree(&syscall, &libc).is_ok());
        assert!(vehicles_agree(&syscall, &syscall).is_err());
        assert!(vehicles_agree(&syscall, &patina).is_err());
    }

    fn event(seq: u64, op: &str, ret: i64) -> Event {
        Event {
            seq,
            op: op.to_string(),
            args: BTreeMap::new(),
            ret: Value::from(ret),
            errno: None,
            fields: BTreeMap::new(),
            norm: BTreeMap::new(),
        }
    }

    fn failed(seq: u64, op: &str, errno: &str) -> Event {
        Event {
            errno: Some(errno.to_string()),
            ..event(seq, op, -1)
        }
    }

    fn check(seq: u64, label: &str, ok: bool) -> Event {
        let mut event = event(seq, CHECK_OP, i64::from(ok));
        event.args.insert("label".to_string(), Value::from(label));
        event
    }

    fn observation(events: Vec<Event>) -> Observation {
        Observation {
            origin: NATIVE,
            events,
            termination: Termination::Exited(0),
            stderr: String::new(),
        }
    }

    fn native() -> Observation {
        observation(vec![
            event(0, "openat", 3),
            failed(1, "newfstatat", "EINVAL"),
            check(2, "an unknown flag is EINVAL", true),
        ])
    }

    fn patina_enosys() -> Observation {
        observation(vec![
            event(0, "openat", 3),
            failed(1, "newfstatat", "ENOSYS"),
            check(2, "an unknown flag is EINVAL", false),
        ])
    }

    const ENOSYS_GAP: Failure = Failure::Differs(&[
        Difference::Field {
            seq: 1,
            op: "newfstatat",
            path: "errno",
            patina: Observed::Str("ENOSYS"),
        },
        Difference::check(2, "an unknown flag is EINVAL"),
    ]);

    fn gap(failure: &Failure) -> Expected<'_> {
        Expected {
            reason: "pending: test",
            failure,
        }
    }

    /// Patina conforms when its stream and ending equal the native run's,
    /// or differ exactly as a declared gap says: each declared difference
    /// observed at its event with its patina value, and nothing else.
    #[test]
    fn a_stream_conforms_only_as_declared() {
        const ELSEWHERE: Failure = Failure::Differs(&[
            Difference::Field {
                seq: 1,
                op: "newfstatat",
                path: "errno",
                patina: Observed::Str("ENOSYS"),
            },
            Difference::check(0, "an unknown flag is EINVAL"),
        ]);
        let mut other_value = patina_enosys();
        other_value.events[1].errno = Some("EPERM".to_string());
        let mut shorter = native();
        shorter.events.pop();
        let ended = |termination| Observation {
            termination,
            ..native()
        };
        let signaled = |core| Termination::Signaled { signal: 6, core };
        let cases = [
            ("identical streams", native(), native(), vec![], true),
            (
                "an undeclared difference",
                native(),
                patina_enosys(),
                vec![],
                false,
            ),
            (
                "a declared difference",
                native(),
                patina_enosys(),
                vec![gap(&ENOSYS_GAP)],
                true,
            ),
            (
                "a check declared at another event",
                native(),
                patina_enosys(),
                vec![gap(&ELSEWHERE)],
                false,
            ),
            (
                "another patina value",
                native(),
                other_value,
                vec![gap(&ENOSYS_GAP)],
                false,
            ),
            (
                "fewer patina events",
                native(),
                shorter.clone(),
                vec![],
                false,
            ),
            ("fewer native events", shorter, native(), vec![], false),
            (
                "another termination",
                native(),
                ended(Termination::Signaled {
                    signal: 15,
                    core: Some(false),
                }),
                vec![],
                false,
            ),
            (
                "another core flag",
                ended(signaled(Some(true))),
                ended(signaled(None)),
                vec![],
                false,
            ),
        ];
        for (case, native, patina, gaps, holds) in cases {
            assert_eq!(judge(&native, &patina, &gaps).is_ok(), holds, "{case}");
        }
        let verdict = judge(&native(), &patina_enosys(), &[gap(&ENOSYS_GAP)]).unwrap();
        assert_eq!(verdict.confirmed.len(), 1, "the one gap is confirmed");
    }

    /// A gap patina no longer shows fails, once per declared difference.
    #[test]
    fn a_stale_gap_fails_once_patina_conforms() {
        let Failure::Differs(declared) = ENOSYS_GAP else {
            unreachable!("ENOSYS_GAP declares differences")
        };
        let failures = judge(&native(), &native(), &[gap(&ENOSYS_GAP)]).unwrap_err();
        assert_eq!(failures.len(), declared.len(), "{failures:?}");
    }

    const STOP: Failure = Failure::Stops {
        events: 1,
        ending: Ending::Signal(6),
        diagnostic: "trapped fork",
    };

    fn stopped(stderr: &str) -> Observation {
        Observation {
            origin: NATIVE,
            events: vec![event(0, "openat", 3)],
            termination: Termination::Signaled {
                signal: 6,
                core: Some(true),
            },
            stderr: stderr.to_string(),
        }
    }

    /// A declared stop holds only when patina stops at the declared point,
    /// with the declared ending and diagnostic, after a prefix that conforms
    /// (or differs only as declared); a run that completes makes it stale.
    #[test]
    fn a_declared_stop_holds_only_as_declared() {
        let exited = Observation {
            termination: Termination::Exited(101),
            ..stopped("trapped fork")
        };
        let mut differing = stopped("trapped fork");
        differing.events[0].ret = Value::from(4);
        let early = Observation {
            events: vec![],
            ..stopped("trapped fork")
        };
        const BEFORE: Failure = Failure::Differs(&[Difference::Field {
            seq: 0,
            op: "openat",
            path: "ret",
            patina: Observed::Int(4),
        }]);
        let cases = [
            (
                "the declared stop",
                stopped("patina: trapped fork"),
                vec![gap(&STOP)],
                true,
            ),
            (
                "another diagnostic",
                stopped("other"),
                vec![gap(&STOP)],
                false,
            ),
            ("another ending", exited, vec![gap(&STOP)], false),
            ("a completed run", native(), vec![gap(&STOP)], false),
            ("a hang", hung(1), vec![gap(&STOP)], false),
            (
                "a differing prefix",
                differing.clone(),
                vec![gap(&STOP)],
                false,
            ),
            (
                "a declared difference before it",
                differing,
                vec![gap(&STOP), gap(&BEFORE)],
                true,
            ),
            (
                "two stops for one vehicle",
                stopped("trapped fork"),
                vec![gap(&STOP), gap(&STOP)],
                false,
            ),
            ("an early stop", early, vec![gap(&STOP)], false),
        ];
        for (case, patina, gaps, holds) in cases {
            assert_eq!(judge(&native(), &patina, &gaps).is_ok(), holds, "{case}");
        }
    }

    const HANG: Failure = Failure::Hangs {
        events: 1,
        within: Duration::from_secs(5),
    };

    fn hung(events: usize) -> Observation {
        Observation {
            origin: NATIVE,
            events: native().events.into_iter().take(events).collect(),
            termination: Termination::Hung,
            stderr: String::new(),
        }
    }

    /// A declared hang holds only when patina hangs after the declared number
    /// of events, the prefix conforming; a run that ends makes it stale.
    #[test]
    fn a_declared_hang_holds_only_as_declared() {
        const AT_START: Failure = Failure::Hangs {
            events: 0,
            within: Duration::from_secs(5),
        };
        let mut differing = hung(1);
        differing.events[0].ret = Value::from(4);
        let cases = [
            ("the declared hang", hung(1), &HANG, true),
            (
                "a hang at the start, by its marker alone",
                hung(0),
                &AT_START,
                true,
            ),
            (
                "a hang after an event, declared at the start",
                hung(1),
                &AT_START,
                false,
            ),
            ("a hang after another count", hung(0), &HANG, false),
            ("a completed run", native(), &HANG, false),
            ("a stop", stopped("trapped fork"), &HANG, false),
            ("a differing prefix", differing, &HANG, false),
        ];
        for (case, patina, failure, holds) in cases {
            assert_eq!(
                judge(&native(), &patina, &[gap(failure)]).is_ok(),
                holds,
                "{case}"
            );
        }
    }

    fn renamed(errno: &str) -> Observation {
        let mut event = failed(0, "renameat", errno);
        event.norm.insert(
            "errno".to_string(),
            Norm::Alternatives(&["EEXIST", "ENOTEMPTY"]).tag(),
        );
        observation(vec![event])
    }

    #[test]
    fn documented_alternatives_compare_equal_and_nothing_else_does() {
        assert!(judge(&renamed("EEXIST"), &renamed("ENOTEMPTY"), &[]).is_ok());
        assert!(judge(&renamed("EEXIST"), &renamed("ENOTDIR"), &[]).is_err());
    }

    fn masked(mask: u64, relevant: u64) -> Observation {
        let mut event = event(0, "statx", 0);
        event.fields.insert("mask".to_string(), Value::from(mask));
        event
            .norm
            .insert("fields.mask".to_string(), Norm::Mask(relevant).tag());
        observation(vec![event])
    }

    #[test]
    fn a_mask_compares_only_the_bits_inside_it() {
        assert!(judge(&masked(0x7ff, 0x0ff), &masked(0x0ff, 0x0ff), &[]).is_ok());
        assert!(judge(&masked(0x7ff, 0x7ff), &masked(0x3ff, 0x7ff), &[]).is_err());
    }

    fn opened(fd: i64, seq: u64) -> Event {
        let mut event = event(seq, "openat", fd);
        event
            .norm
            .insert("ret".to_string(), Norm::Relative("fd").tag());
        event
    }

    #[test]
    fn relative_descriptors_compare_by_identity() {
        let host = observation(vec![opened(7, 0), opened(9, 1)]);
        let virtual_kernel = observation(vec![opened(3, 0), opened(4, 1)]);
        assert!(judge(&host, &virtual_kernel, &[]).is_ok());
        let shared = observation(vec![opened(3, 0), opened(3, 1)]);
        assert!(judge(&host, &shared, &[]).is_err());
    }

    #[test]
    fn a_gap_pins_the_raw_alternative() {
        let found = found(&renamed("ENOTDIR").events, &renamed("EEXIST").events);
        assert_eq!(
            found,
            [Found::Field {
                seq: 0,
                op: "renameat".to_string(),
                path: "errno".to_string(),
                native: Value::from("ENOTDIR"),
                patina: Value::from("EEXIST"),
            }]
        );
    }

    fn exit_announced(code: i64) -> Event {
        let mut announced = event(3, EXPECT_EXIT_OP, 0);
        announced.args.insert("code".to_string(), Value::from(code));
        announced
    }

    /// A native run is an oracle when every check passed and it ended as it
    /// announced (or exited 0 announcing nothing); any other is not.
    #[test]
    fn a_native_run_is_an_oracle_only_when_it_passed_and_ended_as_announced() {
        let ended = |announced: Option<Event>, termination| {
            let mut run = native();
            run.events.extend(announced);
            run.termination = termination;
            run
        };
        let death_announced = |signal: i64| {
            let mut announced = event(3, EXPECT_DEATH_OP, 0);
            announced
                .args
                .insert("signal".to_string(), Value::from(signal));
            announced
        };
        let signaled = |signal, core| Termination::Signaled {
            signal,
            core: Some(core),
        };
        let cases = [
            ("a passing run", native(), true),
            ("an empty stream", observation(vec![]), false),
            ("a failed check", patina_enosys(), false),
            (
                "an announced signal death",
                ended(Some(death_announced(15)), signaled(15, false)),
                true,
            ),
            (
                "an unannounced signal death",
                ended(None, signaled(11, true)),
                false,
            ),
            (
                "an announced exit",
                ended(Some(exit_announced(3)), Termination::Exited(3)),
                true,
            ),
            (
                "an unannounced nonzero exit",
                ended(None, Termination::Exited(3)),
                false,
            ),
            (
                "an exit 0 where 3 was announced",
                ended(Some(exit_announced(3)), Termination::Exited(0)),
                false,
            ),
            (
                "an exit 4 where 3 was announced",
                ended(Some(exit_announced(3)), Termination::Exited(4)),
                false,
            ),
        ];
        for (case, run, oracle) in cases {
            assert_eq!(verdict(&run).is_ok(), oracle, "{case}");
        }
    }

    /// A socket event: `domain`, `type`, protocol 0, the descriptor `fd`.
    fn socket(seq: u64, domain: i64, kind: i64, fd: i64) -> Event {
        let mut event = event(seq, "socket", fd);
        event.args.insert("domain".to_string(), Value::from(domain));
        event.args.insert("type".to_string(), Value::from(kind));
        event.args.insert("protocol".to_string(), Value::from(0));
        event
            .norm
            .insert("ret".to_string(), Norm::Relative("fd").tag());
        event
    }

    /// An `op` on `fd` showing `port` in `fields.{key}_port`.
    fn port(seq: u64, op: &str, fd: i64, key: &str, port: i64) -> Event {
        let mut event = event(seq, op, 0);
        event.args.insert("fd".to_string(), Value::from(fd));
        event
            .norm
            .insert("args.fd".to_string(), Norm::Relative("fd").tag());
        let path = format!("{key}_port");
        event.fields.insert(path.clone(), Value::from(port));
        event
            .norm
            .insert(format!("fields.{path}"), Norm::Relative("port").tag());
        event
    }

    /// An `accept4` on `listener` returning `fd` from peer port `peer`.
    fn accept(seq: u64, listener: i64, fd: i64, peer: i64) -> Event {
        let mut event = port(seq, "accept4", listener, "peer", peer);
        event.ret = Value::from(fd);
        event
            .norm
            .insert("ret".to_string(), Norm::Relative("fd").tag());
        event
    }

    const AF_INET: i64 = 2;
    const AF_INET6: i64 = 10;
    const STREAM: i64 = 1;
    const DGRAM: i64 = 2;

    /// A UDP socket at `udp`, then a TCP client at `client` whose listener
    /// is at `listener`, and the peer the listener accepts.
    fn udp_then_tcp(udp: i64, listener: i64, client: i64, peer: i64) -> Vec<Event> {
        vec![
            socket(0, AF_INET6, DGRAM, 3),
            port(1, "getsockname", 3, "addr", udp),
            socket(2, AF_INET, STREAM, 4),
            port(3, "getsockname", 4, "addr", listener),
            socket(4, AF_INET6, STREAM, 5),
            port(5, "getsockname", 5, "addr", client),
            accept(6, 4, 6, peer),
            port(7, "getpeername", 6, "addr", peer),
        ]
    }

    #[test]
    fn a_host_coincidence_across_protocols_conforms() {
        // The host drew the TCP client's port equal to the UDP socket's;
        // patina never repeats a number.
        let native = observation(udp_then_tcp(40000, 50001, 40000, 40000));
        let patina = observation(udp_then_tcp(32768, 32769, 32770, 32770));
        assert_eq!(judge(&native, &patina, &[]), Ok(Verdict::default()));
    }

    #[test]
    fn port_identity_within_a_protocol_is_still_compared() {
        let native = observation(udp_then_tcp(40000, 50001, 50002, 50002));
        // The accepted peer is not the client (a wrong peer port), and the
        // client shows the listener's port.
        let wrong_peer = observation(udp_then_tcp(32768, 32769, 32770, 32771));
        let failures = judge(&native, &wrong_peer, &[]).unwrap_err();
        assert!(failures.iter().any(|line| line.contains("accept4")));
        let shared = observation(udp_then_tcp(32768, 32769, 32769, 32769));
        assert!(judge(&native, &shared, &[]).is_err());
    }
}
