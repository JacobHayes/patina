//! Reading a trace file without holding its decisions.
//!
//! [`TraceBundle::load`] holds every decision of every timeline at once, so a
//! reader of a large trace needs memory in proportion to it. A [`TraceStream`]
//! reads the file twice instead. The first read checks it exactly as `load`
//! does, keeping only its structure: metadata, lifecycle markers, and for each
//! timeline a decision count and the orders that do not follow the previous
//! decision's (which a recorded trace only has around lifecycle markers). The
//! second read hands one resolved timeline's decisions to a callback, one at a
//! time. Either way, memory is bounded by the largest single decision and the
//! trace's structure, not by how many decisions it holds.

use std::fmt;
use std::fs::File;
use std::io::{BufReader, Seek, SeekFrom};
use std::marker::PhantomData;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};

use crate::bundle::{
    DecisionRecord, Mark, TimelineShape, enforce_trace_byte_limit, resolve_lifecycle,
    resolve_segments, timeline_index, validate_shape,
};
use crate::lifecycle::active_incarnation_at_order;
use crate::{LifecycleEvent, MAX_TRACE_BYTES, RunMetadata, TraceBundle, TraceError, TraceEvent};

const READ_BUFFER_BYTES: usize = 1 << 16;

/// A strictly checked trace file whose resolved timelines are read on demand,
/// one decision at a time.
#[derive(Debug)]
pub struct TraceStream {
    source: Source,
}

#[derive(Debug)]
enum Source {
    Streamed {
        file: File,
        path: PathBuf,
        timelines: Vec<SpineTimeline>,
    },
    /// A trace the streaming read refused but [`TraceBundle::load`] accepts.
    /// The streaming read accepts every bundle the recorder writes, so this is
    /// only a fallback that keeps the two readers' verdicts the same.
    Loaded(Box<TraceBundle>),
}

impl TraceStream {
    /// Open and check `path`, accepting exactly what [`TraceBundle::load`]
    /// accepts and refusing the rest with `load`'s error.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, TraceError> {
        let path = path.as_ref();
        match Self::open_streamed(path) {
            Ok(source) => Ok(Self { source }),
            Err(_) => {
                let bundle = TraceBundle::load(path)?;
                Ok(Self {
                    source: Source::Loaded(Box::new(bundle)),
                })
            }
        }
    }

    fn open_streamed(path: &Path) -> Result<Source, TraceError> {
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
            return Err(TraceError::Invalid("empty trace file".into()));
        }
        let mut pass = Pass::Shape(Box::default());
        read_bundle(&file, path, &mut pass)?;
        let Pass::Shape(shape) = pass else {
            unreachable!("the shape pass stays a shape pass")
        };
        let (Some(format_version), Some(metadata)) = (shape.format_version, shape.metadata) else {
            unreachable!("the bundle visitor requires both fields")
        };
        validate_shape(format_version, &metadata, &shape.timelines)?;
        Ok(Source::Streamed {
            file,
            path: path.to_path_buf(),
            timelines: shape.timelines,
        })
    }

    /// How many decisions timeline `id` holds once resolved.
    pub fn resolved_len(&self, id: &str) -> Result<usize, TraceError> {
        match &self.source {
            Source::Streamed { timelines, .. } => {
                Ok(resolve_segments(timelines, timeline_index(timelines, id)?)?
                    .iter()
                    .map(|(_, count)| count)
                    .sum())
            }
            Source::Loaded(bundle) => Ok(bundle.resolved_timeline(id)?.len()),
        }
    }

    /// Timeline `id`'s resolved lifecycle markers, as
    /// [`TraceBundle::resolved_lifecycle`] gives them.
    pub fn resolved_lifecycle(&self, id: &str) -> Result<Vec<LifecycleEvent>, TraceError> {
        match &self.source {
            Source::Streamed { timelines, .. } => {
                resolve_lifecycle(timelines, timeline_index(timelines, id)?)
            }
            Source::Loaded(bundle) => bundle.resolved_lifecycle(id),
        }
    }

    /// Hand timeline `id`'s resolved decisions to `each`, in order, as
    /// [`TraceBundle::resolved_timeline`] gives them. Stops at the first error
    /// `each` returns and gives it back as the inner error.
    pub fn for_each_resolved<E>(
        &mut self,
        id: &str,
        mut each: impl FnMut(TraceEvent) -> Result<(), E>,
    ) -> Result<Result<(), E>, TraceError> {
        let (file, path, timelines) = match &mut self.source {
            Source::Streamed {
                file,
                path,
                timelines,
            } => (file, path, timelines),
            Source::Loaded(bundle) => {
                return Ok(bundle.resolved_timeline(id)?.into_iter().try_for_each(each));
            }
        };
        let mut wanted = vec![0; timelines.len()];
        for (timeline, count) in resolve_segments(timelines, timeline_index(timelines, id)?)? {
            wanted[timeline] = count;
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|source| TraceError::Io {
                action: format!("rewind trace {}", path.display()),
                source,
            })?;
        let mut failure = None;
        let mut sink = |event| match each(event) {
            Ok(()) => ControlFlow::Continue(()),
            Err(error) => {
                failure = Some(error);
                ControlFlow::Break(())
            }
        };
        let mut pass = Pass::Emit(Emit {
            timelines,
            wanted,
            sink: &mut sink,
        });
        let read = read_bundle(file, path, &mut pass);
        match (failure, read) {
            (Some(error), _) => Ok(Err(error)),
            (None, read) => read.map(Ok),
        }
    }
}

/// One timeline as the shape pass keeps it: everything but its decisions'
/// operations and outcomes.
#[derive(Debug)]
struct SpineTimeline {
    id: String,
    parent: Option<String>,
    from_sequence: Option<u64>,
    branch_seed: Option<u64>,
    lifecycle: Vec<LifecycleEvent>,
    decision_count: usize,
    /// `(index, order)` of each decision whose order does not follow the
    /// previous decision's; the first decision's when it is stored at all.
    order_breaks: Vec<(usize, u64)>,
}

impl SpineTimeline {
    /// Each decision's order and incarnation, derived as a loaded timeline
    /// derives them: a stored order, else the one after the previous
    /// decision's (the first decision's: after the first lifecycle marker's),
    /// and the incarnation the lifecycle has active there.
    fn derived(&self) -> impl Iterator<Item = (u64, Option<u64>)> + '_ {
        let mut previous = self.lifecycle.first().map_or(0, |marker| marker.order);
        let mut breaks = self.order_breaks.iter().peekable();
        (0..self.decision_count).map(move |index| {
            let order = match breaks.next_if(|(at, _)| *at == index) {
                Some(&(_, order)) => order,
                None => previous.wrapping_add(1),
            };
            previous = order;
            (order, active_incarnation_at_order(&self.lifecycle, order))
        })
    }
}

impl TimelineShape for SpineTimeline {
    fn id(&self) -> &str {
        &self.id
    }
    fn parent(&self) -> Option<&str> {
        self.parent.as_deref()
    }
    fn branch_sequence(&self) -> Option<u64> {
        self.from_sequence
    }
    fn branch_seed(&self) -> Option<u64> {
        self.branch_seed
    }
    fn lifecycle(&self) -> &[LifecycleEvent] {
        &self.lifecycle
    }
    fn decision_count(&self) -> usize {
        self.decision_count
    }
    fn marks(&self) -> impl Iterator<Item = Mark> + '_ {
        let start = self.from_sequence.unwrap_or(0);
        self.derived()
            .enumerate()
            .map(move |(index, (order, incarnation))| Mark {
                sequence: start + index as u64,
                order,
                // The shape pass refused any decision outside an incarnation.
                incarnation: incarnation.unwrap_or_default(),
            })
    }
}

enum Pass<'a> {
    /// The first read: check every field and keep the trace's structure.
    Shape(Box<Shape>),
    /// The second read: hand the wanted decisions to a sink.
    Emit(Emit<'a>),
}

#[derive(Default)]
struct Shape {
    format_version: Option<u32>,
    metadata: Option<RunMetadata>,
    timelines: Vec<SpineTimeline>,
}

struct Emit<'a> {
    timelines: &'a [SpineTimeline],
    /// How many of each timeline's decisions, from its first, to hand on.
    wanted: Vec<usize>,
    sink: &'a mut dyn FnMut(TraceEvent) -> ControlFlow<()>,
}

/// Deserialize the bundle in `file` through `pass`.
fn read_bundle(file: &File, path: &Path, pass: &mut Pass<'_>) -> Result<(), TraceError> {
    let parse = |source| TraceError::Parse {
        path: path.to_path_buf(),
        source,
    };
    let reader = BufReader::with_capacity(READ_BUFFER_BYTES, file);
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    de::Deserializer::deserialize_struct(
        &mut deserializer,
        "TraceBundle",
        BUNDLE_FIELDS,
        BundleVisitor(pass),
    )
    .map_err(parse)?;
    deserializer.end().map_err(parse)
}

/// A struct's field values, whether it is written as an object or, as derived
/// deserializers also accept, as an array of its fields in order.
trait FieldValues<'de> {
    type Error: de::Error;
    fn value<S: DeserializeSeed<'de>>(&mut self, seed: S) -> Result<S::Value, Self::Error>;
}

struct MapValues<A>(A);

impl<'de, A: MapAccess<'de>> FieldValues<'de> for MapValues<A> {
    type Error = A::Error;
    fn value<S: DeserializeSeed<'de>>(&mut self, seed: S) -> Result<S::Value, A::Error> {
        self.0.next_value_seed(seed)
    }
}

struct SeqValues<A> {
    seq: A,
    read: usize,
    expecting: &'static str,
}

impl<'de, A: SeqAccess<'de>> FieldValues<'de> for SeqValues<A> {
    type Error = A::Error;
    fn value<S: DeserializeSeed<'de>>(&mut self, seed: S) -> Result<S::Value, A::Error> {
        let value = self
            .seq
            .next_element_seed(seed)?
            .ok_or_else(|| de::Error::invalid_length(self.read, &self.expecting))?;
        self.read += 1;
        Ok(value)
    }
}

fn typed<'de, T: Deserialize<'de>, V: FieldValues<'de>>(values: &mut V) -> Result<T, V::Error> {
    values.value(PhantomData::<T>)
}

/// Read an object's keys as field indexes, refusing unknown and repeated
/// ones as derived deserializers do, and the missing ones `required` names.
fn visit_fields<'de, A: MapAccess<'de>>(
    mut map: A,
    fields: &'static [&'static str],
    required: &[usize],
    mut field: impl FnMut(usize, &mut MapValues<A>) -> Result<(), A::Error>,
) -> Result<(), A::Error> {
    let mut seen = vec![false; fields.len()];
    while let Some(key) = map.next_key::<String>()? {
        let Some(index) = fields.iter().position(|name| *name == key) else {
            return Err(de::Error::unknown_field(&key, fields));
        };
        if std::mem::replace(&mut seen[index], true) {
            return Err(de::Error::duplicate_field(fields[index]));
        }
        let mut values = MapValues(map);
        field(index, &mut values)?;
        map = values.0;
    }
    match required.iter().find(|&&index| !seen[index]) {
        Some(&index) => Err(de::Error::missing_field(fields[index])),
        None => Ok(()),
    }
}

struct BundleVisitor<'p, 'a>(&'p mut Pass<'a>);

const BUNDLE_FIELDS: &[&str] = &["format_version", "metadata", "timelines"];

impl BundleVisitor<'_, '_> {
    fn field<'de, V: FieldValues<'de>>(
        &mut self,
        field: usize,
        values: &mut V,
    ) -> Result<(), V::Error> {
        match (field, &mut *self.0) {
            (0, Pass::Shape(shape)) => shape.format_version = Some(typed(values)?),
            (0, Pass::Emit(_)) => drop(typed::<u32, _>(values)?),
            (1, Pass::Shape(shape)) => shape.metadata = Some(typed(values)?),
            (1, Pass::Emit(_)) => drop(typed::<IgnoredAny, _>(values)?),
            _ => values.value(TimelinesSeed(&mut *self.0))?,
        }
        Ok(())
    }
}

impl<'de> Visitor<'de> for BundleVisitor<'_, '_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("struct TraceBundle")
    }

    fn visit_map<A: MapAccess<'de>>(mut self, map: A) -> Result<(), A::Error> {
        visit_fields(map, BUNDLE_FIELDS, &[0, 1, 2], |field, values| {
            self.field(field, values)
        })
    }

    fn visit_seq<A: SeqAccess<'de>>(mut self, seq: A) -> Result<(), A::Error> {
        let mut values = SeqValues {
            seq,
            read: 0,
            expecting: "struct TraceBundle with 3 elements",
        };
        (0..BUNDLE_FIELDS.len()).try_for_each(|field| self.field(field, &mut values))
    }
}

struct TimelinesSeed<'p, 'a>(&'p mut Pass<'a>);

impl<'de> DeserializeSeed<'de> for TimelinesSeed<'_, '_> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for TimelinesSeed<'_, '_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a list of timelines")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let mut index = 0;
        while seq
            .next_element_seed(TimelineSeed {
                pass: &mut *self.0,
                index,
                fields: TimelineFields::default(),
            })?
            .is_some()
        {
            index += 1;
        }
        if let Pass::Emit(emit) = self.0
            && index != emit.timelines.len()
        {
            return Err(de::Error::custom("the trace changed between reads"));
        }
        Ok(())
    }
}

struct TimelineSeed<'p, 'a> {
    pass: &'p mut Pass<'a>,
    index: usize,
    fields: TimelineFields,
}

/// What the shape pass has read of a timeline so far.
#[derive(Default)]
struct TimelineFields {
    id: Option<String>,
    parent: Option<String>,
    from_sequence: Option<u64>,
    branch_seed: Option<u64>,
    lifecycle: Option<Vec<LifecycleEvent>>,
    decisions: Option<(usize, Vec<(usize, u64)>)>,
}

const TIMELINE_FIELDS: &[&str] = &[
    "id",
    "parent",
    "from_sequence",
    "branch_seed",
    "lifecycle",
    "decisions",
];
const DECISIONS: usize = 5;

impl<'de> DeserializeSeed<'de> for TimelineSeed<'_, '_> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_struct("TimelineRecord", TIMELINE_FIELDS, self)
    }
}

impl TimelineSeed<'_, '_> {
    fn field<'de, V: FieldValues<'de>>(
        &mut self,
        field: usize,
        values: &mut V,
    ) -> Result<(), V::Error> {
        let fields = &mut self.fields;
        match &mut *self.pass {
            Pass::Emit(emit) if field == DECISIONS => {
                let timelines = emit.timelines;
                let Some(timeline) = timelines.get(self.index) else {
                    return Err(de::Error::custom("the trace changed between reads"));
                };
                values.value(EmitDecisions {
                    marks: timeline.marks(),
                    wanted: emit.wanted[self.index],
                    sink: &mut *emit.sink,
                })?;
            }
            Pass::Emit(_) => drop(typed::<IgnoredAny, _>(values)?),
            Pass::Shape(_) => match field {
                0 => fields.id = Some(typed(values)?),
                1 => fields.parent = typed(values)?,
                2 => fields.from_sequence = typed(values)?,
                3 => fields.branch_seed = typed(values)?,
                4 => fields.lifecycle = Some(typed(values)?),
                _ => fields.decisions = Some(values.value(ShapeDecisions)?),
            },
        }
        Ok(())
    }

    /// Keep the timeline the shape pass read, refusing what a loaded
    /// timeline's derivation refuses.
    fn finish<E: de::Error>(self) -> Result<(), E> {
        let Pass::Shape(shape) = self.pass else {
            return Ok(());
        };
        let fields = self.fields;
        let (Some(id), Some(lifecycle), Some((decision_count, order_breaks))) =
            (fields.id, fields.lifecycle, fields.decisions)
        else {
            unreachable!("every timeline form requires its id, lifecycle and decisions")
        };
        let timeline = SpineTimeline {
            id,
            parent: fields.parent,
            from_sequence: fields.from_sequence,
            branch_seed: fields.branch_seed,
            lifecycle,
            decision_count,
            order_breaks,
        };
        if let Some((index, (order, _))) = timeline
            .derived()
            .enumerate()
            .find(|(_, (_, incarnation))| incarnation.is_none())
        {
            return Err(de::Error::custom(format!(
                "timeline {} decision {index} at order {order} is outside any active incarnation",
                timeline.id
            )));
        }
        shape.timelines.push(timeline);
        Ok(())
    }
}

impl<'de> Visitor<'de> for TimelineSeed<'_, '_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("struct TimelineRecord")
    }

    fn visit_map<A: MapAccess<'de>>(mut self, map: A) -> Result<(), A::Error> {
        // A missing optional field is `None`, as derived deserializers read it.
        visit_fields(map, TIMELINE_FIELDS, &[0, 4, DECISIONS], |field, values| {
            self.field(field, values)
        })?;
        self.finish()
    }

    fn visit_seq<A: SeqAccess<'de>>(mut self, seq: A) -> Result<(), A::Error> {
        let mut values = SeqValues {
            seq,
            read: 0,
            expecting: "struct TimelineRecord with 6 elements",
        };
        (0..TIMELINE_FIELDS.len()).try_for_each(|field| self.field(field, &mut values))?;
        self.finish()
    }
}

/// The shape pass's read of a timeline's decisions: each is decoded in full,
/// so a malformed one is refused, then dropped, keeping its count and the
/// orders that break the run of consecutive ones.
struct ShapeDecisions;

impl<'de> DeserializeSeed<'de> for ShapeDecisions {
    type Value = (usize, Vec<(usize, u64)>);

    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for ShapeDecisions {
    type Value = (usize, Vec<(usize, u64)>);

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a list of decisions")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut count = 0;
        let mut breaks = Vec::new();
        // The previous decision's order, once it no longer depends on the
        // lifecycle markers (which may come later in the object).
        let mut previous: Option<u64> = None;
        while let Some(record) = seq.next_element::<DecisionRecord>()? {
            match record.order {
                Some(order) => {
                    if previous.is_none_or(|previous| previous.wrapping_add(1) != order) {
                        breaks.push((count, order));
                    }
                    previous = Some(order);
                }
                None => previous = previous.map(|previous| previous.wrapping_add(1)),
            }
            count += 1;
        }
        Ok((count, breaks))
    }
}

/// The emit pass's read of a timeline's decisions: the first `wanted` are
/// decoded and handed on with their derived fields; the rest are skipped.
struct EmitDecisions<'a, M> {
    marks: M,
    wanted: usize,
    sink: &'a mut dyn FnMut(TraceEvent) -> ControlFlow<()>,
}

impl<'de, M: Iterator<Item = Mark>> DeserializeSeed<'de> for EmitDecisions<'_, M> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, M: Iterator<Item = Mark>> Visitor<'de> for EmitDecisions<'_, M> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a list of decisions")
    }

    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<(), A::Error> {
        for _ in 0..self.wanted {
            let (Some(record), Some(mark)) =
                (seq.next_element::<DecisionRecord>()?, self.marks.next())
            else {
                return Err(de::Error::custom("the trace changed between reads"));
            };
            let event = TraceEvent {
                sequence: mark.sequence,
                order: mark.order,
                incarnation: mark.incarnation,
                operation: record.operation,
                outcome: record.outcome,
            };
            if (self.sink)(event).is_break() {
                return Err(de::Error::custom("stopped by the reader"));
            }
        }
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(())
    }
}

#[cfg(test)]
mod tests;
