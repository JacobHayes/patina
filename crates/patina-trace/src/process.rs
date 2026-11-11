//! The child processes of a multi-process run: one recording each.
//!
//! A run whose guest spawned processes records one timeline per child
//! process beside its own: who the child was (its pid, its parent, the
//! program and arguments it ran), how it ended, and its own recording, the
//! metadata its runtime started with and the decisions it made, which a
//! replay hands that child as a trace of its own ([`ProcessTrace::bundle`]).
//! The root's own timeline holds the machine's decisions about the child:
//! each switch to it, its spawn (a runnable foreign task) and its end (a
//! gone one).

use serde::{Deserialize, Serialize};

use crate::{MAIN_TIMELINE, RunMetadata, Timeline, TraceBundle, TraceError, TraceEvent};

/// How a child process ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessEnd {
    /// It exited, or a signal's default action ended it.
    Exit,
    /// It was sent `SIGKILL`.
    Killed,
    /// The root's end killed it.
    Teardown,
}

/// One child process of the run and its recording.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "ProcessRecord", try_from = "ProcessRecord")]
pub struct ProcessTrace {
    pub pid: i32,
    pub parent: i32,
    /// The program, as the spawn named it.
    pub program: String,
    /// Its arguments, `argv[0]` included.
    pub argv: Vec<String>,
    /// Its wait status and how it ended, once it did.
    pub end: Option<(i32, ProcessEnd)>,
    /// The metadata its runtime recorded under.
    pub metadata: RunMetadata,
    /// Its decisions, in its own order.
    pub decisions: Vec<TraceEvent>,
}

impl ProcessTrace {
    /// This child's recording as a trace of its own, as its runtime would
    /// have written it: what a replay hands the child.
    pub fn bundle(&self) -> TraceBundle {
        TraceBundle::linear(self.metadata.clone(), 0, self.decisions.clone())
    }
}

/// A [`ProcessTrace`] as a bundle stores it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessRecord {
    pid: i32,
    parent: i32,
    program: String,
    argv: Vec<String>,
    status: Option<i32>,
    end: Option<ProcessEnd>,
    metadata: RunMetadata,
    timeline: Timeline,
}

impl From<ProcessTrace> for ProcessRecord {
    fn from(process: ProcessTrace) -> Self {
        let mut bundle = TraceBundle::linear(process.metadata, 0, process.decisions);
        Self {
            pid: process.pid,
            parent: process.parent,
            program: process.program,
            argv: process.argv,
            status: process.end.map(|(status, _)| status),
            end: process.end.map(|(_, end)| end),
            metadata: bundle.metadata,
            timeline: bundle.timelines.remove(0),
        }
    }
}

impl TryFrom<ProcessRecord> for ProcessTrace {
    type Error = String;

    fn try_from(record: ProcessRecord) -> Result<Self, String> {
        let end = match (record.status, record.end) {
            (Some(status), Some(end)) => Some((status, end)),
            (None, None) => None,
            _ => {
                return Err(format!(
                    "process {} has a status or an end alone",
                    record.pid
                ));
            }
        };
        if record.timeline.id != MAIN_TIMELINE || record.timeline.parent.is_some() {
            return Err(format!("process {}'s timeline is not linear", record.pid));
        }
        let bundle = TraceBundle {
            format_version: crate::TRACE_FORMAT_VERSION,
            metadata: record.metadata,
            timelines: vec![record.timeline],
            processes: Vec::new(),
        };
        bundle
            .validate()
            .map_err(|error: TraceError| format!("process {}: {error}", record.pid))?;
        let decisions = bundle
            .resolved_timeline(MAIN_TIMELINE)
            .map_err(|error| format!("process {}: {error}", record.pid))?;
        Ok(Self {
            pid: record.pid,
            parent: record.parent,
            program: record.program,
            argv: record.argv,
            end,
            metadata: bundle.metadata,
            decisions,
        })
    }
}
