//! Bounded event recording and allocation-free borrowed prefix export.

use std::fmt;
use std::io::Write;
use std::path::Path;

use patina_dst_abi::{Operation, Outcome};
use serde::Serialize;

use crate::bundle::{Decision, Decisions};
use crate::{
    BuggifyConfigRecord, ComputeStop, LifecycleEvent, LifecycleEventKind, MAIN_TIMELINE,
    MAX_TIMELINE_EVENTS, MAX_TRACE_BYTES, ProcessEnd, ProcessTrace, RunMetadata,
    TRACE_FORMAT_VERSION, TraceBundle, TraceError, TraceEvent,
};

/// A `Write` sink that counts bytes instead of keeping them, so a value can be
/// measured in its serialized encoding without ever materializing it.
struct ByteCounter(u64);

impl Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len() as u64);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Exactly how many bytes `event` occupies inside a serialized bundle, or
/// `None` when it does not serialize at all.
///
/// A `None` is deliberately NOT a budget event: an event that will not
/// serialize means a broken recorder, and the loud finalization failure that
/// diagnoses it must be reached rather than pre-empted by a graceful budget
/// refusal. The ledger charges nothing for such an event and lets finalization
/// fail the run (see [`EventLedger::admit`]).
fn serialized_event_len(event: &TraceEvent) -> Option<u64> {
    let mut counter = ByteCounter(0);
    // A recorder's events follow one another, so none carries its order.
    serde_json::to_writer(
        &mut counter,
        &Decision::of(event, event.order.wrapping_sub(1)),
    )
    .ok()?;
    Some(counter.0)
}

/// A budget refusal decided in flight, kept as the parts of the
/// [`TraceError::ResourceLimit`] it becomes: `TraceError` is not `Clone`, and
/// the refusal has to be reproducible at every finalization entry point.
#[derive(Clone, Debug)]
struct Overflow {
    message: String,
    bytes: Option<(u64, u64)>,
}

impl Overflow {
    fn to_error(&self) -> TraceError {
        TraceError::ResourceLimit {
            message: self.message.clone(),
            bytes: self.bytes,
        }
    }
}

/// What the events a recorder is holding will cost in the serialized bundle,
/// tallied as they arrive, and the budget they are held against.
///
/// A recorder used to learn it had outgrown [`MAX_TRACE_BYTES`] only when it
/// serialized at finalization — by which time the entire run was already in
/// memory (gigabytes for a long guest) and the artifact was lost anyway. The
/// ledger moves that discovery to the event that crosses the budget, so a
/// doomed recording costs a bounded amount of RAM instead of an unbounded one.
/// The run itself is untouched: recording is write-only, so a recorder that
/// goes inert cannot change what the guest does or what verdict it reaches.
///
/// An event is charged its EXACT serialized length plus the one separator byte
/// that will precede it in the `decisions` array, so the running total is a
/// true count of the events' share of the bundle. It deliberately excludes the
/// bundle's framing and metadata, which makes the total a strict UNDER-estimate
/// of the file: a recording that would have fit can therefore never be
/// abandoned in flight, and a trace under budget is byte-identical to one
/// recorded without a ledger at all. The exact, authoritative check still
/// happens at serialization ([`TraceBundle::to_bytes_with_limit`]) — this is a
/// bound on memory, not a second opinion about the limit.
///
/// The decision is a pure function of the recorded event stream: the same run
/// records the same events in the same order and therefore overflows at exactly
/// the same event, on every host and on every re-run. Nothing here consults the
/// clock, the allocator, or how much memory the machine has.
pub(super) struct EventLedger {
    /// Serialized bytes of the events admitted so far, separators included.
    bytes: u64,
    /// Events admitted so far, including the one that overflowed.
    events: u64,
    max_bytes: u64,
    max_events: u64,
    overflow: Option<Overflow>,
}

impl EventLedger {
    const fn with_limits(max_bytes: u64, max_events: u64) -> Self {
        Self {
            bytes: 0,
            events: 0,
            max_bytes,
            max_events,
            overflow: None,
        }
    }

    pub(super) const fn overflowed(&self) -> bool {
        self.overflow.is_some()
    }

    pub(super) fn overflow_error(&self) -> Option<TraceError> {
        self.overflow.as_ref().map(Overflow::to_error)
    }

    /// Charge one more event. `true` if the caller may go on holding it;
    /// `false` once the budget is spent, which means the caller must drop
    /// everything it holds and record nothing further — the trace is abandoned.
    ///
    /// Both of the bundle's recorded budgets are enforced here, the byte budget
    /// and [`MAX_TIMELINE_EVENTS`], because either one reached at finalization
    /// costs the artifact anyway; reaching them in flight at least stops paying
    /// for it in memory.
    pub(super) fn admit(&mut self, event: &TraceEvent, timeline: &str) -> bool {
        if self.overflowed() {
            return false;
        }
        let separator = u64::from(self.events > 0);
        self.bytes = self
            .bytes
            .saturating_add(separator)
            .saturating_add(serialized_event_len(event).unwrap_or(0));
        self.events += 1;
        if self.events > self.max_events {
            self.overflow = Some(Overflow {
                message: format!(
                    "timeline {timeline} reached {} events while recording; limit is {}; the \
                     recorder abandoned the trace rather than hold more",
                    self.events, self.max_events
                ),
                bytes: None,
            });
            return false;
        }
        if self.bytes > self.max_bytes {
            self.overflow = Some(Overflow {
                message: format!(
                    "recorded trace reached {} bytes of events at event {} of timeline \
                     {timeline}; limit is {}; the recorder abandoned the trace rather than hold \
                     more; reduce recorded event count or payload volume, or split the run",
                    self.bytes, self.events, self.max_bytes
                ),
                bytes: Some((self.bytes, self.max_bytes)),
            });
            return false;
        }
        true
    }
}

/// Borrowed-prefix export status. An abandoned recorder is a plain enum value,
/// not a boxed serde I/O error: the terminal caller may hold its allocator.
#[derive(Debug)]
pub enum PrefixWriteError {
    Overflow,
    Serialization(serde_json::Error),
}
impl fmt::Display for PrefixWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow => f.write_str("recorded prefix was abandoned after trace overflow"),
            Self::Serialization(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for PrefixWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Overflow => None,
            Self::Serialization(error) => Some(error),
        }
    }
}

pub struct Recorder {
    metadata: RunMetadata,
    incarnation: u64,
    decisions: Vec<TraceEvent>,
    /// The guest's child processes, by pid ([`Recorder::begin_process`]).
    processes: std::collections::BTreeMap<i32, ProcessTrace>,
    ledger: EventLedger,
}

impl Recorder {
    pub fn new(metadata: RunMetadata) -> Self {
        Self::with_limit(metadata, MAX_TRACE_BYTES)
    }

    /// A recorder that abandons after `max_bytes` of recorded events instead of
    /// [`MAX_TRACE_BYTES`], so the in-flight budget is testable without
    /// recording a quarter of a gigabyte.
    fn with_limit(metadata: RunMetadata, max_bytes: u64) -> Self {
        Self::with_limits(metadata, max_bytes, MAX_TIMELINE_EVENTS as u64)
    }

    fn with_limits(metadata: RunMetadata, max_bytes: u64, max_events: u64) -> Self {
        Self {
            metadata,
            incarnation: 0,
            decisions: Vec::new(),
            processes: std::collections::BTreeMap::new(),
            ledger: EventLedger::with_limits(max_bytes, max_events),
        }
    }

    /// Record the operations of `incarnation` of a crash-restart run; every
    /// other recording is incarnation 0.
    #[must_use]
    pub fn with_incarnation(mut self, incarnation: u64) -> Self {
        self.incarnation = incarnation;
        self
    }

    /// Record one boundary decision — unless this trace has already been
    /// abandoned for outgrowing its budget, after which the recorder is inert
    /// and holds nothing. See [`EventLedger`] for why abandoning early is safe.
    pub fn observe(&mut self, operation: Operation, outcome: Outcome) {
        if self.ledger.overflowed() {
            return;
        }
        let mut event = TraceEvent::new(self.decisions.len() as u64, operation, outcome);
        event.incarnation = self.incarnation;
        if self.ledger.admit(&event, MAIN_TIMELINE) {
            self.decisions.push(event);
        } else {
            // Release the held events AND their capacity the moment the trace
            // is abandoned: the whole point is that a doomed recording stops
            // costing memory here rather than at finalization.
            self.decisions = Vec::new();
        }
    }

    /// Number of committed decisions. None means the recorder abandoned its
    /// storage on overflow, NOT that it has a valid empty prefix. Allocation-free.
    pub fn committed_prefix_len(&self) -> Option<u64> {
        (!self.ledger.overflowed()).then_some(self.decisions.len() as u64)
    }

    /// Set the terminal native refusal before exporting its prefix.
    pub fn set_compute_stop(&mut self, stop: ComputeStop) {
        self.metadata.compute_stop = Some(stop);
    }

    /// Overwrite the recorded buggify configuration at finalization.
    pub fn set_buggify(&mut self, buggify: Option<BuggifyConfigRecord>) {
        self.metadata.buggify = buggify;
    }

    pub fn finish(self, path: impl AsRef<Path>) -> Result<(), TraceError> {
        let max_bytes = self.ledger.max_bytes;
        self.finish_with_limit(path, max_bytes)
    }

    pub(super) fn finish_with_limit(
        self,
        path: impl AsRef<Path>,
        max_bytes: u64,
    ) -> Result<(), TraceError> {
        self.into_bundle()?.write_atomic_with_limit(path, max_bytes)
    }

    /// Convert the recorded decisions into a bundle without touching storage,
    /// or refuse with the budget error when the trace was abandoned in flight.
    ///
    /// The refusal is the SAME [`TraceError::ResourceLimit`] the serialization
    /// check would have raised, so every consumer of the graceful budget path —
    /// the shim's shutdown downgrade, the abandoned-trace marker, the
    /// `PATINA_INFRA` line — behaves exactly as it did when the overflow was
    /// only discovered at finalization. An abandoned recorder must never yield
    /// a bundle: it holds no events, and a structurally valid trace claiming
    /// zero decisions would replay as a lie.
    pub fn into_bundle(self) -> Result<TraceBundle, TraceError> {
        match self.ledger.overflow_error() {
            Some(error) => Err(error),
            None => {
                let mut bundle =
                    TraceBundle::linear(self.metadata, self.incarnation, self.decisions);
                bundle.processes = self.processes.into_values().collect();
                Ok(bundle)
            }
        }
    }

    /// Serialize a borrowed linear prefix without allocating or cloning events.
    /// Native asynchronous stops cannot call the guest's allocator: its owner
    /// may be the very thread that stopped making progress. The initial buggify
    /// configuration is retained; end-of-run site-report enrichment is omitted.
    pub fn write_prefix(&self, writer: impl std::io::Write) -> Result<(), PrefixWriteError> {
        #[derive(Serialize)]
        struct Prefix<'a> {
            format_version: u32,
            metadata: &'a RunMetadata,
            timelines: [PrefixTimeline<'a>; 1],
            #[serde(skip_serializing_if = "<[_]>::is_empty")]
            processes: &'a [ProcessPrefix<'a>],
        }
        // A child process as the bundle stores it ([`ProcessTrace`]),
        // borrowed.
        #[derive(Serialize)]
        struct ProcessPrefix<'a> {
            pid: i32,
            parent: i32,
            program: &'a str,
            argv: &'a [String],
            status: Option<i32>,
            end: Option<ProcessEnd>,
            metadata: &'a RunMetadata,
            timeline: PrefixTimeline<'a>,
        }
        #[derive(Serialize)]
        struct PrefixTimeline<'a> {
            id: &'static str,
            parent: Option<&'static str>,
            from_sequence: Option<u64>,
            branch_seed: Option<u64>,
            lifecycle: [LifecycleEvent; 2],
            decisions: Decisions<'a>,
        }
        if self.ledger.overflowed() {
            return Err(PrefixWriteError::Overflow);
        }
        // The children, borrowed: a stop with none allocates nothing here.
        let processes: Vec<ProcessPrefix<'_>> = self
            .processes
            .values()
            .map(|process| {
                let start = 0;
                let end = process
                    .decisions
                    .last()
                    .map_or(start + 1, |event| event.order.saturating_add(1));
                ProcessPrefix {
                    pid: process.pid,
                    parent: process.parent,
                    program: &process.program,
                    argv: &process.argv,
                    status: process.end.map(|(status, _)| status),
                    end: process.end.map(|(_, end)| end),
                    metadata: &process.metadata,
                    timeline: PrefixTimeline {
                        id: MAIN_TIMELINE,
                        parent: None,
                        from_sequence: None,
                        branch_seed: None,
                        lifecycle: [
                            LifecycleEvent {
                                order: start,
                                kind: LifecycleEventKind::Start { incarnation: 0 },
                            },
                            LifecycleEvent {
                                order: end,
                                kind: LifecycleEventKind::End { incarnation: 0 },
                            },
                        ],
                        decisions: Decisions {
                            start_order: start,
                            events: &process.decisions,
                        },
                    },
                }
            })
            .collect();
        let start = self
            .decisions
            .first()
            .map_or(0, |event| event.order.saturating_sub(1));
        let end = self
            .decisions
            .last()
            .map_or(start + 1, |event| event.order.saturating_add(1));
        serde_json::to_writer(
            writer,
            &Prefix {
                format_version: TRACE_FORMAT_VERSION,
                metadata: &self.metadata,
                timelines: [PrefixTimeline {
                    id: MAIN_TIMELINE,
                    parent: None,
                    from_sequence: None,
                    branch_seed: None,
                    lifecycle: [
                        LifecycleEvent {
                            order: start,
                            kind: LifecycleEventKind::Start {
                                incarnation: self.incarnation,
                            },
                        },
                        LifecycleEvent {
                            order: end,
                            kind: LifecycleEventKind::End {
                                incarnation: self.incarnation,
                            },
                        },
                    ],
                    decisions: Decisions {
                        start_order: start,
                        events: &self.decisions,
                    },
                }],
                processes: &processes,
            },
        )
        .map_err(PrefixWriteError::Serialization)
    }

    /// The metadata this recording runs under.
    pub fn metadata(&self) -> &RunMetadata {
        &self.metadata
    }

    /// A child process of the guest began: `process` (no decisions yet,
    /// no end), whose recording the root holds from now on.
    pub fn begin_process(&mut self, process: ProcessTrace) {
        self.processes.insert(process.pid, process);
    }

    /// Child `pid` made `decisions`, in its order, after those it shipped
    /// before. They count against the trace's budgets as the root's own do.
    pub fn extend_process(&mut self, pid: i32, decisions: Vec<(Operation, Outcome)>) {
        let Some(process) = self.processes.get_mut(&pid) else {
            return;
        };
        for (operation, outcome) in decisions {
            if self.ledger.overflowed() {
                return;
            }
            let event = TraceEvent::new(process.decisions.len() as u64, operation, outcome);
            if self.ledger.admit(&event, "process") {
                process.decisions.push(event);
            } else {
                self.decisions = Vec::new();
                self.processes.clear();
                return;
            }
        }
    }

    /// Child `pid` ended, with wait status `status`, as `end` says.
    pub fn end_process(&mut self, pid: i32, status: i32, end: ProcessEnd) {
        if let Some(process) = self.processes.get_mut(&pid)
            && process.end.is_none()
        {
            process.end = Some((status, end));
        }
    }

    /// A bundle of the decisions recorded SO FAR, leaving the recorder usable.
    /// The runtime writes one of these when a run is stopped mid-flight (step
    /// budget exhausted, the no-progress horizon) and the consuming
    /// [`Recorder::into_bundle`] at finalization is never reached — a truncated
    /// but structurally valid trace beats the empty file the abort would leave.
    /// An abandoned trace refuses here too, for the reason above.
    pub fn to_bundle(&self) -> Result<TraceBundle, TraceError> {
        match self.ledger.overflow_error() {
            Some(error) => Err(error),
            None => {
                let mut bundle = TraceBundle::linear(
                    self.metadata.clone(),
                    self.incarnation,
                    self.decisions.clone(),
                );
                bundle.processes = self.processes.values().cloned().collect();
                Ok(bundle)
            }
        }
    }
}

#[cfg(test)]
mod tests;
