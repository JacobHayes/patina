//! Typed observation events: what a scenario writes, one JSON line per
//! observed call, on stdout.
//!
//! `{"seq","op","args","ret","errno","fields","norm"}`: `args` are the inputs
//! the scenario chose to show, `ret` is the kernel result (`-1` with `errno`
//! named on failure), `fields` are the struct members the scenario pulled out,
//! and `norm` maps a field path (`ret`, `errno`, `args.fd`, `fields.ino`) to
//! the typed normalization the comparison applies before it compares the
//! native and patina streams (see [`Norm`]). Asserts and panics go to stderr,
//! so a stream stays machine-readable even when the scenario dies.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Event {
    pub seq: u64,
    pub op: String,
    pub args: BTreeMap<String, Value>,
    pub ret: Value,
    pub errno: Option<String>,
    pub fields: BTreeMap<String, Value>,
    pub norm: BTreeMap<String, String>,
}

/// The op of a semantic property the scenario asserts (`ret` 1 or 0, the
/// property in `args.label`).
pub const CHECK_OP: &str = "check";

/// The op a scenario records right before it ends the process on purpose
/// (`Probe::dies_by`): a signal death passes natively only when the last
/// recorded event announces that very signal.
pub const EXPECT_DEATH_OP: &str = "expect_death";

/// The op a scenario records right before the process exits with a status
/// other than 0 on purpose (`Probe::exits_with`): such an exit passes
/// natively only when the last recorded event announces that very status.
pub const EXPECT_EXIT_OP: &str = "expect_exit";

/// Per-field normalization, declared by the scenario, never regex over text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Norm {
    /// The value is an allocated number (a descriptor, a port) whose identity
    /// matters but whose magnitude is the host's business: replaced by the
    /// label of the event that introduced it (`fd@57`), so sharing relations
    /// survive and absolute numbers do not. In the `fd` namespace a `close`
    /// retires the number, so a later reuse is a NEW identity on both sides;
    /// the lowest-free reuse policy itself is a scenario `check`. In the
    /// `port` namespace a number's identity is per IP protocol: the protocol
    /// of the AF_INET/AF_INET6 socket the event's `fd` names, as its
    /// `socket` or `accept` event showed it.
    Relative(&'static str),
    /// An inode number: labeled by first appearance (identity relations only).
    Inode,
    /// Host identity of one kind: labeled by first appearance within its kind,
    /// so the virtual identities compare with the host's by relation, not
    /// value, and a host whose uid and gid differ compares with a virtual
    /// kernel whose are equal.
    Identity(Id),
    /// A clock reading: replaced by its order relation to the previous reading
    /// of the same `(op, field, clock)` (`mono:first`, `mono:>=`, `mono:-`).
    /// Strict advance is not a kernel guarantee (coarse clocks, a virtual clock
    /// that moves only on sleeps), so "advanced" is a scenario `check`.
    Monotonic,
    /// Keep only these bits.
    Mask(u64),
    /// Linux documents these values as interchangeable answers to the call
    /// (e.g. `rename(2)` onto a nonempty directory: `EEXIST` or `ENOTEMPTY`):
    /// any of them compares equal to any other. A comparison relation, not a
    /// rewrite: the raw value is what a gap pins.
    Alternatives(&'static [&'static str]),
}

impl Norm {
    pub fn tag(&self) -> String {
        match self {
            Norm::Relative(namespace) => format!("relative:{namespace}"),
            Norm::Inode => "inode".to_string(),
            Norm::Identity(id) => format!("identity:{}", id.name()),
            Norm::Monotonic => "monotonic".to_string(),
            Norm::Mask(bits) => format!("mask:0o{bits:o}"),
            Norm::Alternatives(values) => format!("alternatives:{}", values.join("|")),
        }
    }
}

/// The kind of an identity [`Norm::Identity`] labels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Id {
    /// Process, thread, process-group and session ids (one namespace: the
    /// main thread's tid is the pid).
    Process,
    User,
    Group,
}

impl Id {
    pub fn name(self) -> &'static str {
        match self {
            Id::Process => "pid",
            Id::User => "uid",
            Id::Group => "gid",
        }
    }
}

/// [`Norm`] as read back from a stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParsedNorm {
    Relative(String),
    Inode,
    Identity(String),
    Monotonic,
    Mask(u64),
    Alternatives(Vec<String>),
}

impl ParsedNorm {
    pub fn parse(tag: &str) -> Option<ParsedNorm> {
        if let Some(namespace) = tag.strip_prefix("relative:") {
            return Some(ParsedNorm::Relative(namespace.to_string()));
        }
        if let Some(octal) = tag.strip_prefix("mask:0o") {
            return u64::from_str_radix(octal, 8).ok().map(ParsedNorm::Mask);
        }
        if let Some(id) = tag.strip_prefix("identity:") {
            return Some(ParsedNorm::Identity(id.to_string()));
        }
        if let Some(values) = tag.strip_prefix("alternatives:") {
            return Some(ParsedNorm::Alternatives(
                values.split('|').map(str::to_string).collect(),
            ));
        }
        match tag {
            "inode" => Some(ParsedNorm::Inode),
            "monotonic" => Some(ParsedNorm::Monotonic),
            _ => None,
        }
    }
}

/// Parse a stream: one JSON event per line; blank lines are ignored.
pub fn parse_stream(text: &str) -> Result<Vec<Event>, String> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str(line)
                .map_err(|error| format!("line {}: not an event: {error}: {line}", index + 1))
        })
        .collect()
}
