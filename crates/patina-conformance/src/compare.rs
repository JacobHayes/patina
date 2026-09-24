//! The live comparison: a scenario's native observation is the oracle for its
//! patina observation of the same run.
//!
//! Both streams are normalized independently (the scenario's declared
//! [`Norm`](crate::observe::Norm)s), then compared field by field. Exact by
//! default: the only accepted differences are the ones a scenario's gaps name,
//! and a gap that no longer matches is itself a failure, so the declarations
//! are always exactly the current gap.

use crate::observe::{CHECK_OP, EXPECT_DEATH_OP, Event, ParsedNorm};
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

/// One run of a scenario through one vehicle.
#[derive(Clone, Debug)]
pub struct Observation {
    /// The raw (unnormalized) event stream.
    pub events: Vec<Event>,
    pub termination: Termination,
    pub stderr: String,
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
    /// the introducing event rather than a running count, so an extra
    /// allocation on one side shifts nothing downstream.
    fn label(&mut self, namespace: &str, value: i64, seq: u64, fresh: &mut usize) -> String {
        let table = self.labels.entry(namespace.to_string()).or_default();
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
                    let fresh = fresh.entry(namespace.clone()).or_insert(0);
                    Value::from(self.label(&namespace, number, event.seq, fresh))
                }
                ParsedNorm::Inode => {
                    let fresh = fresh.entry("ino".to_string()).or_insert(0);
                    Value::from(self.label("ino", number, event.seq, fresh))
                }
                ParsedNorm::Identity(id) => {
                    let fresh = fresh.entry(id.clone()).or_insert(0);
                    Value::from(self.label(&id, number, event.seq, fresh))
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
        if let Some(number) = retire {
            if let Some(table) = self.labels.get_mut("fd") {
                table.remove(&number);
            }
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

// ---- the native oracle ------------------------------------------------------

/// Whether a native observation is an oracle at all: it recorded something,
/// every check passed, and the process exited 0 or died by the signal its
/// last event announced.
pub fn native_verdict(native: &Observation) -> Result<(), String> {
    if native.events.is_empty() {
        return Err(format!("recorded no event ({})", native.termination));
    }
    if let Some(failed) = native
        .events
        .iter()
        .find(|event| event.op == CHECK_OP && event.ret != 1)
    {
        return Err(format!(
            "a check failed natively: {}",
            label_of(failed).unwrap_or("?")
        ));
    }
    match native.termination {
        Termination::Exited(0) => Ok(()),
        Termination::Signaled { signal, .. } => {
            let announced = native
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
        other => Err(format!("did not pass natively: {other}")),
    }
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

impl fmt::Display for Found {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Found::Field {
                seq,
                op,
                path,
                native,
                patina,
            } => write!(f, "seq {seq} {op} {path}: native {native}, patina {patina}"),
            Found::Check { seq, label } => {
                write!(f, "seq {seq} check {label:?} fails under patina")
            }
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

/// Compare a patina observation with its native oracle under the applicable
/// gaps. At most one gap stops the run; the differing gaps then name every
/// difference before the stop. `Ok` carries one line per gap confirmed; `Err`
/// every failure.
pub fn judge(
    native: &Observation,
    patina: &Observation,
    gaps: &[Expected<'_>],
) -> Result<Vec<String>, Vec<String>> {
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
                    "event count: native {}, patina {}{}",
                    native_events.len(),
                    patina_events.len(),
                    first
                        .first()
                        .map(|found| format!("; first difference: {found}"))
                        .unwrap_or_default()
                ));
            }
            if native.termination != patina.termination {
                failures.push(format!(
                    "termination: native {}, patina {}",
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
        if matched == declared.len() {
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
            failures.push(format!("undeclared difference: {found}"));
        }
    }
    if failures.is_empty() {
        Ok(confirmed)
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
    judge(reference, other, &[]).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::Norm;

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

    #[test]
    fn identical_streams_conform() {
        assert_eq!(judge(&native(), &native(), &[]), Ok(vec![]));
    }

    #[test]
    fn an_undeclared_difference_fails() {
        let failures = judge(&native(), &patina_enosys(), &[]).unwrap_err();
        assert!(
            failures
                .iter()
                .any(|line| line.contains("seq 1 newfstatat errno"))
        );
        assert!(
            failures
                .iter()
                .any(|line| line.contains("an unknown flag is EINVAL"))
        );
    }

    #[test]
    fn a_declared_difference_is_confirmed() {
        let lines = judge(&native(), &patina_enosys(), &[gap(&ENOSYS_GAP)]).unwrap();
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn a_stale_gap_fails_once_patina_conforms() {
        let failures = judge(&native(), &native(), &[gap(&ENOSYS_GAP)]).unwrap_err();
        assert_eq!(failures.len(), 2, "{failures:?}");
        assert!(failures.iter().all(|line| line.contains("not observed")));
    }

    #[test]
    fn a_declared_check_pins_its_event() {
        const ELSEWHERE: Failure = Failure::Differs(&[
            Difference::Field {
                seq: 1,
                op: "newfstatat",
                path: "errno",
                patina: Observed::Str("ENOSYS"),
            },
            Difference::check(0, "an unknown flag is EINVAL"),
        ]);
        let failures = judge(&native(), &patina_enosys(), &[gap(&ELSEWHERE)]).unwrap_err();
        assert!(failures.iter().any(|line| line.contains("not observed")));
        assert!(
            failures
                .iter()
                .any(|line| line.contains("undeclared difference: seq 2 check"))
        );
    }

    #[test]
    fn a_declared_difference_pins_the_patina_value() {
        let mut patina = patina_enosys();
        patina.events[1].errno = Some("EPERM".to_string());
        let failures = judge(&native(), &patina, &[gap(&ENOSYS_GAP)]).unwrap_err();
        assert!(failures.iter().any(|line| line.contains("not observed")));
        assert!(
            failures
                .iter()
                .any(|line| line.contains("undeclared difference: seq 1"))
        );
    }

    #[test]
    fn event_count_drift_fails_in_both_directions() {
        let mut shorter = native();
        shorter.events.pop();
        assert!(judge(&native(), &shorter, &[]).is_err());
        assert!(judge(&shorter, &native(), &[]).is_err());
    }

    #[test]
    fn a_termination_difference_fails() {
        let mut died = native();
        died.termination = Termination::Signaled {
            signal: 15,
            core: Some(false),
        };
        let failures = judge(&native(), &died, &[]).unwrap_err();
        assert!(failures[0].starts_with("termination:"), "{failures:?}");
    }

    #[test]
    fn a_core_flag_difference_fails() {
        let signaled = |core| Observation {
            termination: Termination::Signaled { signal: 6, core },
            ..native()
        };
        assert!(judge(&signaled(Some(true)), &signaled(None), &[]).is_err());
    }

    const STOP: Failure = Failure::Stops {
        events: 1,
        ending: Ending::Signal(6),
        diagnostic: "trapped fork",
    };

    fn stopped(stderr: &str) -> Observation {
        Observation {
            events: vec![event(0, "openat", 3)],
            termination: Termination::Signaled {
                signal: 6,
                core: Some(true),
            },
            stderr: stderr.to_string(),
        }
    }

    #[test]
    fn a_declared_stop_is_confirmed() {
        assert!(judge(&native(), &stopped("patina: trapped fork"), &[gap(&STOP)]).is_ok());
    }

    #[test]
    fn a_declared_stop_pins_its_diagnostic() {
        let failures = judge(&native(), &stopped("other"), &[gap(&STOP)]).unwrap_err();
        assert!(failures[0].contains("diagnostic"), "{failures:?}");
    }

    #[test]
    fn a_declared_stop_pins_its_ending() {
        let mut exited = stopped("trapped fork");
        exited.termination = Termination::Exited(101);
        assert!(judge(&native(), &exited, &[gap(&STOP)]).is_err());
    }

    #[test]
    fn a_declared_stop_is_stale_once_patina_completes() {
        let failures = judge(&native(), &native(), &[gap(&STOP)]).unwrap_err();
        assert!(failures[0].contains("stale"), "{failures:?}");
    }

    const HANG: Failure = Failure::Hangs {
        events: 1,
        within: Duration::from_secs(5),
    };

    fn hung(events: usize) -> Observation {
        Observation {
            events: native().events.into_iter().take(events).collect(),
            termination: Termination::Hung,
            stderr: String::new(),
        }
    }

    #[test]
    fn a_declared_hang_is_confirmed() {
        assert!(judge(&native(), &hung(1), &[gap(&HANG)]).is_ok());
    }

    #[test]
    fn a_hang_with_no_event_is_confirmed_by_its_marker_alone() {
        const AT_START: Failure = Failure::Hangs {
            events: 0,
            within: Duration::from_secs(5),
        };
        assert!(judge(&native(), &hung(0), &[gap(&AT_START)]).is_ok());
        assert!(judge(&native(), &hung(1), &[gap(&AT_START)]).is_err());
    }

    #[test]
    fn a_declared_hang_pins_its_event_count() {
        let failures = judge(&native(), &hung(0), &[gap(&HANG)]).unwrap_err();
        assert!(failures[0].contains("hung after 0"), "{failures:?}");
    }

    #[test]
    fn a_declared_hang_is_stale_once_patina_ends() {
        let failures = judge(&native(), &native(), &[gap(&HANG)]).unwrap_err();
        assert!(failures[0].contains("stale"), "{failures:?}");
        let failures = judge(&native(), &stopped("trapped fork"), &[gap(&HANG)]).unwrap_err();
        assert!(failures[0].contains("stale"), "{failures:?}");
    }

    #[test]
    fn an_undeclared_hang_fails_a_stop() {
        let failures = judge(&native(), &hung(1), &[gap(&STOP)]).unwrap_err();
        assert!(
            failures.iter().any(|f| f.contains("declared to end")),
            "{failures:?}"
        );
    }

    #[test]
    fn a_hang_compares_the_prefix_before_it() {
        let mut hung = hung(1);
        hung.events[0].ret = Value::from(4);
        assert!(judge(&native(), &hung, &[gap(&HANG)]).is_err());
    }

    #[test]
    fn a_stop_compares_the_prefix_before_it() {
        let mut stopped = stopped("trapped fork");
        stopped.events[0].ret = Value::from(4);
        assert!(judge(&native(), &stopped, &[gap(&STOP)]).is_err());
    }

    #[test]
    fn a_stop_admits_the_declared_differences_before_it() {
        let mut stopped = stopped("trapped fork");
        stopped.events[0].ret = Value::from(4);
        const BEFORE: Failure = Failure::Differs(&[Difference::Field {
            seq: 0,
            op: "openat",
            path: "ret",
            patina: Observed::Int(4),
        }]);
        assert!(judge(&native(), &stopped, &[gap(&STOP), gap(&BEFORE)]).is_ok());
    }

    #[test]
    fn two_stops_for_one_vehicle_fail() {
        assert!(
            judge(
                &native(),
                &stopped("trapped fork"),
                &[gap(&STOP), gap(&STOP)]
            )
            .is_err()
        );
    }

    #[test]
    fn an_early_stop_fails() {
        let mut early = stopped("trapped fork");
        early.events.clear();
        assert!(judge(&native(), &early, &[gap(&STOP)]).is_err());
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
    fn documented_alternatives_compare_equal() {
        assert!(judge(&renamed("EEXIST"), &renamed("ENOTEMPTY"), &[]).is_ok());
    }

    #[test]
    fn a_value_outside_the_alternatives_still_differs() {
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
    fn a_mask_ignores_bits_outside_it() {
        assert!(judge(&masked(0x7ff, 0x0ff), &masked(0x0ff, 0x0ff), &[]).is_ok());
    }

    #[test]
    fn a_mask_keeps_bits_inside_it() {
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
    fn an_empty_native_stream_is_not_an_oracle() {
        assert!(native_verdict(&observation(vec![])).is_err());
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

    #[test]
    fn a_passing_native_run_is_an_oracle() {
        assert_eq!(native_verdict(&native()), Ok(()));
    }

    #[test]
    fn a_native_failed_check_is_not_an_oracle() {
        assert!(native_verdict(&patina_enosys()).is_err());
    }

    #[test]
    fn an_unannounced_native_signal_death_is_not_an_oracle() {
        let died = Observation {
            termination: Termination::Signaled {
                signal: 11,
                core: Some(true),
            },
            ..native()
        };
        assert!(native_verdict(&died).is_err());
    }

    #[test]
    fn an_announced_native_signal_death_is_an_oracle() {
        let mut announced = event(3, EXPECT_DEATH_OP, 0);
        announced.args.insert("signal".to_string(), Value::from(15));
        let mut died = native();
        died.events.push(announced);
        died.termination = Termination::Signaled {
            signal: 15,
            core: Some(false),
        };
        assert_eq!(native_verdict(&died), Ok(()));
    }
}
