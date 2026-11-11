//! `--progress`: what a long verb is doing while it runs, as JSON Lines on
//! stderr under `--format json`. stdout keeps its one result envelope.
//!
//! Every line is one object: the schema, the verb, the event's name, the
//! seconds since the tool started, and the event's own fields. Human output
//! keeps its own progress lines and never prints these.
//!
//! A `patina` child (a campaign generation, a test's run) never inherits the
//! request: it is spawned with explicit argv and without the operator's
//! `PATINA_<FLAG>` defaults (`supervisor_identity::expect_this_supervisor`),
//! so its stderr, which its parent captures and classifies, stays its own.

use std::io::Write;
use std::sync::OnceLock;
use std::time::Instant;

use serde_json::{Map, Value};

/// The schema stamped on every progress line. Bump the version suffix only on
/// a breaking change to the documented shape.
pub const PROGRESS_SCHEMA: &str = "patina.progress/v1";

static STARTED: OnceLock<Instant> = OnceLock::new();

/// Start the clock `elapsed_secs` counts from: when the options are installed.
pub(super) fn start_clock() {
    STARTED.get_or_init(Instant::now);
}

/// Whether progress lines were asked for: `--progress` under `--format json`.
pub fn wanted() -> bool {
    let options = super::options();
    options.progress && options.is_json()
}

/// Write one progress event to stderr, when asked for. `fields` is an object
/// of the event's own fields.
pub fn emit(event: &str, fields: Value) {
    if !wanted() {
        return;
    }
    let elapsed = STARTED.get_or_init(Instant::now).elapsed().as_secs_f64();
    let mut line = Map::new();
    line.insert("schema".into(), PROGRESS_SCHEMA.into());
    line.insert(
        "verb".into(),
        super::options().verb.as_deref().unwrap_or("").into(),
    );
    line.insert("event".into(), event.into());
    line.insert(
        "elapsed_secs".into(),
        ((elapsed * 1000.0).round() / 1000.0).into(),
    );
    if let Value::Object(fields) = fields {
        line.extend(fields);
    }
    let mut text = Value::Object(line).to_string();
    text.push('\n');
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(text.as_bytes());
    let _ = stderr.flush();
}
