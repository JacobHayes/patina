//! Operation summaries, notable markers, and durations.

use super::*;

/// A one-line human summary of an event, avoiding raw byte payloads (shown as a
/// length instead). Reads fields generically from JSON so it never panics on an
/// unfamiliar operation shape.
pub fn summarize(kind: &str, op: &Value, out: &Value) -> String {
    let mut parts: Vec<String> = Vec::new();
    for key in [
        "path",
        // The resolved host name; without it a `dns_resolve` event renders as a
        // bare byte count, saying nothing about WHICH name was looked up.
        "name",
        "from",
        "to",
        "target",
        "link_path",
        "address",
        "label",
        "reason",
        "clock",
        "fd",
        "socket",
        "listener",
        "task",
        "offset",
        "len",
        "max_len",
        "deadline_nanos",
        "now_nanos",
        "backlog",
        "how",
        // The inode a FIFO `fstat` names.
        "ino",
    ] {
        if let Some(v) = op.get(key)
            && let Some(text) = scalar(v)
        {
            parts.push(format!("{key}={text}"));
        }
    }
    // A permission mode is only readable in octal: `mode=0o644` says what
    // `mode=420` does not. Rendered separately for that reason alone.
    //
    // `fs_open` keeps its mode inside `flags`, where the generic scan above
    // cannot see it — and an open's creation mode is exactly as load-bearing as
    // `mkdir`'s, so the flag word is rendered here too: the set flags in POSIX
    // spelling, then the mode when the open actually creates. A reader who
    // cannot see `O_PATH` in the trace cannot tell the descriptor that resolves
    // paths from the one that reads the directory.
    if let Some(flags) = op.get("flags").and_then(Value::as_object) {
        let named = [
            ("read", "read"),
            ("write", "write"),
            ("create", "create"),
            ("truncate", "truncate"),
            ("append", "append"),
            ("exclusive", "exclusive"),
            ("path_only", "path_only"),
        ]
        .into_iter()
        .filter(|(key, _)| flags.get(*key).and_then(Value::as_bool).unwrap_or(false))
        .map(|(_, label)| label)
        .collect::<Vec<_>>();
        if !named.is_empty() {
            parts.push(format!("flags={}", named.join("|")));
        }
        if let Some(mode) = flags.get("mode").and_then(Value::as_u64)
            && flags
                .get("create")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        {
            parts.push(format!("mode=0o{mode:o}"));
        }
    }
    if let Some(mode) = op.get("mode").and_then(Value::as_u64) {
        parts.push(format!("mode=0o{mode:o}"));
    }
    if let Some(Value::String(s)) = op.get("bytes") {
        parts.push(format!("bytes≈{}", base64_len(s)));
    }
    if let Some(k) = out.get("kind").and_then(Value::as_str) {
        match k {
            "unit" => {}
            "error" => {
                if let Some(v) = out.get("value") {
                    let code = v
                        .get("code")
                        .and_then(Value::as_str)
                        .unwrap_or("error")
                        .to_string();
                    parts.push(format!("→ error:{code}"));
                }
            }
            "bytes" => {
                if let Some(Value::String(s)) = out.get("value") {
                    parts.push(format!("→ {} bytes", base64_len(s)));
                }
            }
            "optional_task" | "task" => {
                if let Some(v) = out.get("value") {
                    parts.push(format!(
                        "→ task {}",
                        scalar(v).unwrap_or_else(|| "-".into())
                    ));
                }
            }
            "handle" | "socket" | "u64" | "usize" | "optional_u64" => {
                if let Some(v) = out.get("value")
                    && let Some(text) = scalar(v)
                {
                    parts.push(format!("→ {text}"));
                }
            }
            "send_report" => {
                if let Some(v) = out.get("value") {
                    let disp = v
                        .get("disposition")
                        .and_then(Value::as_str)
                        .unwrap_or("queued");
                    parts.push(format!("→ {disp}"));
                }
            }
            "datagram" => {
                let present = out.get("value").map(|v| !v.is_null()).unwrap_or(false);
                parts.push(if present {
                    "→ datagram".into()
                } else {
                    "→ none".into()
                });
            }
            other => parts.push(format!("→ {other}")),
        }
    }
    let _ = kind;
    parts.join(" ")
}

pub fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

pub fn base64_len(s: &str) -> usize {
    let padding = s.bytes().rev().take_while(|&b| b == b'=').count();
    (s.len() / 4).saturating_mul(3).saturating_sub(padding)
}

pub(super) fn bytes_in(op: &Value) -> usize {
    op.get("bytes")
        .and_then(Value::as_str)
        .map(base64_len)
        .unwrap_or(0)
}

pub(super) fn bytes_out(out: &Value) -> usize {
    match out.get("kind").and_then(Value::as_str) {
        Some("bytes") => out
            .get("value")
            .and_then(Value::as_str)
            .map(base64_len)
            .unwrap_or(0),
        Some("optional_bytes") => out
            .get("value")
            .and_then(Value::as_str)
            .map(base64_len)
            .unwrap_or(0),
        Some("datagram") => out
            .get("value")
            .and_then(|value| value.get("bytes"))
            .and_then(Value::as_str)
            .map(base64_len)
            .unwrap_or(0),
        _ => 0,
    }
}

pub fn detect_notable(kind: &str, op: &Value, out: &Value) -> Option<Notable> {
    if kind == "fs_crash" {
        return Some(Notable::Crash);
    }
    if out.get("kind").and_then(Value::as_str) == Some("error") {
        let v = out.get("value")?;
        return Some(Notable::Error {
            code: v
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("error")
                .to_string(),
            message: v
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        });
    }
    if out.get("kind").and_then(Value::as_str) == Some("send_report") {
        let disp = out
            .get("value")
            .and_then(|v| v.get("disposition"))
            .and_then(Value::as_str)
            .unwrap_or("queued");
        if disp != "queued" {
            return Some(Notable::Drop {
                to: op
                    .get("to")
                    .and_then(Value::as_str)
                    .unwrap_or("?")
                    .to_string(),
                reason: disp.to_string(),
            });
        }
    }
    None
}

/// Render a nanosecond count in a compact human unit.
pub fn human_nanos(n: u64) -> String {
    if n == 0 {
        return "0 ns".to_string();
    }
    const UNITS: [(u64, &str); 5] = [
        (1_000_000_000 * 60, "min"),
        (1_000_000_000, "s"),
        (1_000_000, "ms"),
        (1_000, "µs"),
        (1, "ns"),
    ];
    for (scale, unit) in UNITS {
        if n >= scale {
            let whole = n / scale;
            let frac = (n % scale) * 100 / scale;
            if frac == 0 {
                return format!("{whole} {unit}");
            }
            return format!("{whole}.{frac:02} {unit}");
        }
    }
    format!("{n} ns")
}

#[cfg(test)]
mod tests;
