//! Trace events, timelines, bundle validation and persistence.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use patina_dst_abi::{Operation, Outcome};
use serde::{Deserialize, Serialize};

use crate::lifecycle::{
    linear_lifecycle_from_start_and_incarnation, validate_lifecycle_events,
    validate_timeline_lifecycle,
};
use crate::{
    ABANDONED_TRACE_KEY, AbandonedTrace, LifecycleEvent, LifecycleEventKind, MAIN_TIMELINE,
    MAX_TIMELINE_EVENTS, MAX_TRACE_BYTES, RunMetadata, TRACE_FORMAT_VERSION, TraceError,
    create_scratch, remove_dead_scratch,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceEvent {
    /// Operation sequence number, contiguous among boundary operations only.
    pub sequence: u64,
    /// Global order slot shared with lifecycle markers.
    pub order: u64,
    /// Guest incarnation that issued this operation.
    pub incarnation: u64,
    pub operation: Operation,
    pub outcome: Outcome,
}

impl TraceEvent {
    pub fn new(sequence: u64, operation: Operation, outcome: Outcome) -> Self {
        Self {
            sequence,
            order: sequence.saturating_add(1),
            incarnation: 0,
            operation,
            outcome,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timeline {
    pub id: String,
    pub parent: Option<String>,
    pub from_sequence: Option<u64>,
    pub branch_seed: Option<u64>,
    pub lifecycle: Vec<LifecycleEvent>,
    pub decisions: Vec<TraceEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceBundle {
    pub format_version: u32,
    pub metadata: RunMetadata,
    pub timelines: Vec<Timeline>,
}

impl TraceBundle {
    pub fn new(metadata: RunMetadata, decisions: Vec<TraceEvent>) -> Self {
        Self::linear(metadata, 0, decisions)
    }

    /// A trace of one incarnation from start to end: every decision belongs to
    /// `incarnation`, between its `Start` and `End` markers.
    pub fn linear(metadata: RunMetadata, incarnation: u64, mut decisions: Vec<TraceEvent>) -> Self {
        for event in &mut decisions {
            event.incarnation = incarnation;
        }
        let start_order = decisions
            .first()
            .map(|event| event.order.saturating_sub(1))
            .unwrap_or(0);
        Self {
            format_version: TRACE_FORMAT_VERSION,
            metadata,
            timelines: vec![Timeline {
                id: MAIN_TIMELINE.into(),
                parent: None,
                from_sequence: None,
                branch_seed: None,
                lifecycle: linear_lifecycle_from_start_and_incarnation(
                    start_order,
                    incarnation,
                    &decisions,
                ),
                decisions,
            }],
        }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, TraceError> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|source| TraceError::Io {
            action: format!("open trace {}", path.display()),
            source,
        })?;
        let size = file
            .metadata()
            .map_err(|source| TraceError::Io {
                action: format!("inspect trace {}", path.display()),
                source,
            })?
            .len();
        enforce_trace_byte_limit(size, MAX_TRACE_BYTES, "trace file")?;
        if size == 0 {
            return Err(TraceError::Incomplete {
                path: path.to_path_buf(),
                reason: "empty trace file; record finalization did not complete".into(),
            });
        }
        let value: serde_json::Value =
            serde_json::from_reader(BufReader::new(file)).map_err(|source| {
                if source.is_eof() {
                    TraceError::Incomplete {
                        path: path.to_path_buf(),
                        reason: format!("truncated JSON trace: {source}"),
                    }
                } else {
                    TraceError::Parse {
                        path: path.to_path_buf(),
                        source,
                    }
                }
            })?;
        Self::decode(value, path.to_path_buf())
    }

    /// Parse and validate a bundle from in-memory bytes, enforcing the same
    /// size limit as file loading.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, TraceError> {
        enforce_trace_byte_limit(
            bytes.len() as u64,
            MAX_TRACE_BYTES,
            "trace transport payload",
        )?;
        let path = PathBuf::from("<trace-transport>");
        if bytes.is_empty() {
            return Err(TraceError::Incomplete {
                path,
                reason: "empty trace transport payload; record finalization did not complete"
                    .into(),
            });
        }
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|source| {
            if source.is_eof() {
                TraceError::Incomplete {
                    path: path.clone(),
                    reason: format!("truncated JSON trace: {source}"),
                }
            } else {
                TraceError::Parse {
                    path: path.clone(),
                    source,
                }
            }
        })?;
        Self::decode(value, path)
    }

    /// Check a decoded bundle's version, then deserialize and validate it.
    ///
    /// Only a bundle at [`TRACE_FORMAT_VERSION`] is deserialized; any other
    /// declared version is refused before any structural interpretation.
    fn decode(value: serde_json::Value, path: PathBuf) -> Result<Self, TraceError> {
        // An abandoned-trace marker is a valid JSON document that is not a
        // bundle. Recognize it FIRST so the refusal names what actually
        // happened — the recorder gave up on this trace, and why — instead of
        // the "missing format_version" confusion the version check would
        // otherwise report for a file that is not corrupt at all.
        if let Some(abandoned) = value
            .get(ABANDONED_TRACE_KEY)
            .and_then(|marker| serde_json::from_value::<AbandonedTrace>(marker.clone()).ok())
        {
            return Err(TraceError::Incomplete {
                path,
                reason: format!(
                    "the recorder abandoned this trace ({}): {}; it holds no events and cannot be \
                     replayed",
                    abandoned.reason, abandoned.detail
                ),
            });
        }
        if let Some(found) = format_version_of(&value)
            && found != TRACE_FORMAT_VERSION
        {
            return Err(TraceError::UnsupportedVersion { found });
        }
        require_complete_current_bundle(&value, &path)?;
        let bundle: Self =
            serde_json::from_value(value).map_err(|source| TraceError::Parse { path, source })?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Validate and serialize this bundle to the canonical byte encoding.
    ///
    /// The canonical form is compact (single-line) JSON with base64 byte
    /// payloads - the format 3 encoding. It stays valid JSON, so a bundle can be
    /// inspected with any JSON tool (`jq . run.patina`,
    /// `python3 -m json.tool run.patina`) when a human-readable view is wanted;
    /// nothing here is a bespoke binary framing that would need a dedicated
    /// dump command.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TraceError> {
        self.to_bytes_with_limit(MAX_TRACE_BYTES)
    }

    fn to_bytes_with_limit(&self, max_bytes: u64) -> Result<Vec<u8>, TraceError> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(self).map_err(TraceError::Serialize)?;
        bytes.push(b'\n');
        enforce_trace_byte_limit(bytes.len() as u64, max_bytes, "serialized trace")?;
        Ok(bytes)
    }

    pub fn write_atomic(&self, path: impl AsRef<Path>) -> Result<(), TraceError> {
        self.write_atomic_with_limit(path, MAX_TRACE_BYTES)
    }

    pub(super) fn write_atomic_with_limit(
        &self,
        path: impl AsRef<Path>,
        max_bytes: u64,
    ) -> Result<(), TraceError> {
        let bytes = self.to_bytes_with_limit(max_bytes)?;
        let path = path.as_ref();
        let parent = path.parent().filter(|value| !value.as_os_str().is_empty());
        if let Some(parent) = parent {
            fs::create_dir_all(parent).map_err(|source| TraceError::Io {
                action: format!("create trace directory {}", parent.display()),
                source,
            })?;
        }
        remove_dead_scratch(path);
        let (temp_path, file) = create_scratch(path).map_err(|source| TraceError::Io {
            action: format!("create temporary trace beside {}", path.display()),
            source,
        })?;

        let write_result = (|| {
            let mut writer = BufWriter::new(&file);
            writer.write_all(&bytes).map_err(|source| TraceError::Io {
                action: format!("write temporary trace {}", temp_path.display()),
                source,
            })?;
            writer.flush().map_err(|source| TraceError::Io {
                action: format!("flush temporary trace {}", temp_path.display()),
                source,
            })?;
            writer
                .get_ref()
                .sync_all()
                .map_err(|source| TraceError::Io {
                    action: format!("sync temporary trace {}", temp_path.display()),
                    source,
                })
        })();

        if let Err(error) = write_result {
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }

        if let Err(source) = fs::rename(&temp_path, path) {
            let _ = fs::remove_file(&temp_path);
            return Err(TraceError::Io {
                action: format!(
                    "atomically rename {} to {}",
                    temp_path.display(),
                    path.display()
                ),
                source,
            });
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), TraceError> {
        if self.format_version != TRACE_FORMAT_VERSION {
            return Err(TraceError::UnsupportedVersion {
                found: self.format_version,
            });
        }
        if self.metadata.fingerprint.is_empty() {
            return Err(TraceError::Invalid(
                "trace compatibility fingerprint is empty".into(),
            ));
        }
        if self.metadata.decision_policy.is_empty() {
            return Err(TraceError::Invalid(
                "trace decision policy identifier is empty".into(),
            ));
        }
        if fingerprint_declares_component(&self.metadata.fingerprint, "buggify")
            && self.metadata.buggify.is_none()
        {
            return Err(TraceError::Invalid(
                "fingerprint declares +buggify but trace metadata has no buggify config".into(),
            ));
        }
        // The swarm record must partition cleanly: every selected class was a
        // candidate, and no class is listed twice. Consumers derive "swarm
        // dropped this class" as the complement of the two lists, so a record
        // that is not a clean partition would make that derivation lie.
        if let Some(swarm) = &self.metadata.swarm {
            let mut candidates = BTreeSet::new();
            for class in &swarm.candidate_classes {
                if !candidates.insert(class.as_str()) {
                    return Err(TraceError::Invalid(format!(
                        "swarm candidate class {class:?} is listed more than once"
                    )));
                }
            }
            let mut selected = BTreeSet::new();
            for class in &swarm.selected_classes {
                if !selected.insert(class.as_str()) {
                    return Err(TraceError::Invalid(format!(
                        "swarm selected class {class:?} is listed more than once"
                    )));
                }
                if !candidates.contains(class.as_str()) {
                    return Err(TraceError::Invalid(format!(
                        "swarm selected class {class:?} was not a candidate; \
                         the selection must be a subset of the candidates"
                    )));
                }
            }
        }
        let Some(main) = self.timelines.first() else {
            return Err(TraceError::Invalid("trace has no main timeline".into()));
        };
        if main.id != MAIN_TIMELINE
            || main.parent.is_some()
            || main.from_sequence.is_some()
            || main.branch_seed.is_some()
        {
            return Err(TraceError::Invalid(
                "the first timeline must be an unbranched main timeline".into(),
            ));
        }

        let mut ids = BTreeSet::new();
        for (timeline_index, timeline) in self.timelines.iter().enumerate() {
            if timeline.decisions.len() > MAX_TIMELINE_EVENTS {
                return Err(TraceError::ResourceLimit {
                    message: format!(
                        "timeline {} has {} events; limit is {MAX_TIMELINE_EVENTS}",
                        timeline.id,
                        timeline.decisions.len()
                    ),
                    bytes: None,
                });
            }
            if timeline.id.is_empty() || !ids.insert(timeline.id.clone()) {
                return Err(TraceError::Invalid(format!(
                    "timeline id is empty or duplicated: {:?}",
                    timeline.id
                )));
            }
            let start = if timeline_index == 0 {
                0
            } else {
                let parent = timeline.parent.as_ref().ok_or_else(|| {
                    TraceError::Invalid(format!("timeline {} has no parent", timeline.id))
                })?;
                let parent_index = self.timelines[..timeline_index]
                    .iter()
                    .position(|candidate| &candidate.id == parent)
                    .ok_or_else(|| {
                        TraceError::Invalid(format!(
                            "timeline {} refers to missing or later parent {parent}",
                            timeline.id
                        ))
                    })?;
                let from = timeline.from_sequence.ok_or_else(|| {
                    TraceError::Invalid(format!("timeline {} has no branch sequence", timeline.id))
                })?;
                if timeline.branch_seed.is_none() {
                    return Err(TraceError::Invalid(format!(
                        "timeline {} has no branch seed",
                        timeline.id
                    )));
                }
                let parent_len = self.resolve_by_index(parent_index)?.len() as u64;
                if from > parent_len {
                    return Err(TraceError::Invalid(format!(
                        "timeline {} branches at {from}, beyond parent length {parent_len}",
                        timeline.id
                    )));
                }
                from
            };
            validate_timeline_lifecycle(timeline)?;
            for (index, event) in timeline.decisions.iter().enumerate() {
                let expected = start + index as u64;
                if event.sequence != expected {
                    return Err(TraceError::Invalid(format!(
                        "event {index} in timeline {} has sequence {}, expected {expected}",
                        timeline.id, event.sequence
                    )));
                }
                if index > 0 && event.order <= timeline.decisions[index - 1].order {
                    return Err(TraceError::Invalid(format!(
                        "event {index} in timeline {} has non-increasing global order {}",
                        timeline.id, event.order
                    )));
                }
            }
        }
        for index in 0..self.timelines.len() {
            self.validate_resolved_orders_by_index(index)?;
        }
        Ok(())
    }

    fn validate_resolved_orders_by_index(&self, index: usize) -> Result<(), TraceError> {
        let timeline = &self.timelines[index];
        let decisions = self.resolve_by_index(index)?;
        let lifecycle = self.resolve_lifecycle_by_index(index)?;
        validate_lifecycle_events(
            &format!("resolved timeline {}", timeline.id),
            &lifecycle,
            &decisions,
        )?;
        let mut previous_order = None;
        for event in &decisions {
            if previous_order.is_some_and(|previous| event.order <= previous) {
                return Err(TraceError::Invalid(format!(
                    "resolved timeline {} operation sequence {} has non-increasing global order {}",
                    timeline.id, event.sequence, event.order
                )));
            }
            previous_order = Some(event.order);
        }
        Ok(())
    }

    pub fn resolved_timeline(&self, id: &str) -> Result<Vec<TraceEvent>, TraceError> {
        self.validate()?;
        let index = self
            .timelines
            .iter()
            .position(|timeline| timeline.id == id)
            .ok_or_else(|| TraceError::UnknownTimeline(id.into()))?;
        self.resolve_by_index(index)
    }

    fn resolve_by_index(&self, index: usize) -> Result<Vec<TraceEvent>, TraceError> {
        let timeline = &self.timelines[index];
        let Some(parent) = &timeline.parent else {
            return Ok(timeline.decisions.clone());
        };
        let parent_index = self.timelines[..index]
            .iter()
            .position(|candidate| &candidate.id == parent)
            .ok_or_else(|| TraceError::UnknownTimeline(parent.clone()))?;
        let mut decisions = self.resolve_by_index(parent_index)?;
        decisions.truncate(timeline.from_sequence.unwrap_or(0) as usize);
        decisions.extend(timeline.decisions.clone());
        Ok(decisions)
    }

    pub fn resolved_lifecycle(&self, id: &str) -> Result<Vec<LifecycleEvent>, TraceError> {
        self.validate()?;
        let index = self
            .timelines
            .iter()
            .position(|timeline| timeline.id == id)
            .ok_or_else(|| TraceError::UnknownTimeline(id.into()))?;
        self.resolve_lifecycle_by_index(index)
    }

    fn resolve_lifecycle_by_index(&self, index: usize) -> Result<Vec<LifecycleEvent>, TraceError> {
        let timeline = &self.timelines[index];
        let Some(parent) = &timeline.parent else {
            return Ok(timeline.lifecycle.clone());
        };
        let parent_index = self.timelines[..index]
            .iter()
            .position(|candidate| &candidate.id == parent)
            .ok_or_else(|| TraceError::UnknownTimeline(parent.clone()))?;
        let parent_lifecycle = self.resolve_lifecycle_by_index(parent_index)?;
        let parent_prefix = self.resolve_by_index(parent_index)?;
        let from = timeline.from_sequence.unwrap_or(0) as usize;
        let prefix_last = parent_prefix.get(from.saturating_sub(1));
        let prefix_end_order = prefix_last
            .map(|event| event.order.saturating_add(1))
            .unwrap_or(0);
        let parent_active = prefix_last.map(|event| event.incarnation);
        let mut lifecycle: Vec<_> = parent_lifecycle
            .into_iter()
            .filter(|marker| marker.order < prefix_end_order)
            .collect();
        let mut suffix_lifecycle = timeline.lifecycle.clone();
        if let (Some(active), Some(first)) = (parent_active, suffix_lifecycle.first())
            && matches!(first.kind, LifecycleEventKind::Start { incarnation } if incarnation == active)
        {
            suffix_lifecycle.remove(0);
        }
        lifecycle.extend(suffix_lifecycle);
        Ok(lifecycle)
    }
}

fn fingerprint_declares_component(fingerprint: &str, component: &str) -> bool {
    fingerprint.split('+').skip(1).any(|part| part == component)
}

/// Read the declared format version from a decoded bundle when it is present as
/// a non-negative integer. A missing or non-integer field yields `None`, so the
/// caller defers to typed deserialization for a precise parse error rather than
/// guessing a version.
fn format_version_of(value: &serde_json::Value) -> Option<u32> {
    u32::try_from(value.get("format_version")?.as_u64()?).ok()
}

fn require_complete_current_bundle(
    value: &serde_json::Value,
    path: &Path,
) -> Result<(), TraceError> {
    let object = value
        .as_object()
        .ok_or_else(|| TraceError::Invalid("trace bundle must be a JSON object".into()))?;
    for field in ["format_version", "metadata", "timelines"] {
        if !object.contains_key(field) {
            return Err(TraceError::Incomplete {
                path: path.to_path_buf(),
                reason: format!("trace bundle is missing required field `{field}`"),
            });
        }
    }
    let metadata = object["metadata"]
        .as_object()
        .ok_or_else(|| TraceError::Incomplete {
            path: path.to_path_buf(),
            reason: "trace metadata is missing or not an object".into(),
        })?;
    for field in ["root_seed", "decision_policy", "fingerprint"] {
        if !metadata.contains_key(field) {
            return Err(TraceError::Incomplete {
                path: path.to_path_buf(),
                reason: format!("trace metadata is missing required field `{field}`"),
            });
        }
    }
    Ok(())
}

fn enforce_trace_byte_limit(
    size: u64,
    max_bytes: u64,
    description: &'static str,
) -> Result<(), TraceError> {
    if size <= max_bytes {
        return Ok(());
    }
    Err(TraceError::ResourceLimit {
        message: format!(
            "{description} is {size} bytes; limit is {max_bytes}; reduce recorded event count or payload volume, or split the run"
        ),
        bytes: Some((size, max_bytes)),
    })
}

#[cfg(test)]
mod tests;
