//! A run's signature: a stable name for what failed, so that a sweep or a report can count
//! one bug once however many seeds hit it. It is `outcome stop: primary`, where `primary` is
//! what failed: the failed `always` label; the waits the blocked threads were parked in; the
//! first panic or assertion line the guest printed on stderr, then the signal name or the exit
//! status; the unsupported call. Digit and hex runs are collapsed, so addresses, thread ids,
//! line numbers and counts that vary by seed do not split a group. Fault settings are not part
//! of it. Written into `result.json` when the run ends; readers take it from there.

use serde_json::Value;
use std::path::Path;

/// Longest `primary` kept (characters).
const PRIMARY_MAX: usize = 200;

/// The signature of a finished run (`null` for `ok`). `dir` is its run directory: the last
/// incarnation's stderr is read there for a panic or assertion line.
pub fn of(r: &Value, dir: &Path) -> Value {
    let s = |k: &str| r[k].as_str().unwrap_or("").to_string();
    let (outcome, stop) = (s("outcome"), s("stop"));
    if outcome == "ok" || outcome.is_empty() {
        return Value::Null;
    }
    let inc = r["incarnations"].as_u64().unwrap_or(1).max(1) - 1;
    let stderr = std::fs::read(dir.join(format!("inc-{inc}")).join("stderr"))
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let p = primary(r, &stderr);
    Value::String(if p.is_empty() {
        format!("{outcome} {stop}")
    } else {
        format!("{outcome} {stop}: {p}")
    })
}

fn primary(r: &Value, stderr: &str) -> String {
    let message = r["message"].as_str().unwrap_or("");
    let p = match r["outcome"].as_str().unwrap_or("") {
        "violation" => match r["sdk"]["violation"]["label"].as_str() {
            Some(l) => l.to_string(),
            None => message.to_string(),
        },
        "liveness" => {
            let w = waits(message);
            if w.is_empty() {
                message.to_string()
            } else {
                format!("parked in {w}")
            }
        }
        "crash" | "failure" => {
            let mut parts = vec![];
            if let Some(l) = guest_line(stderr) {
                parts.push(l);
            } else if message.starts_with("INVARIANT ") {
                parts.push(message.to_string());
            }
            let g = &r["guest"];
            match (g["signal"].as_i64(), g["exit"].as_i64()) {
                (Some(sig), _) => parts.push(crate::outcome::signal_name(sig)),
                (None, Some(x)) => parts.push(format!("exit {x}")),
                _ => {}
            }
            return parts.join("; ").chars().take(PRIMARY_MAX).collect();
        }
        "unsupported" => {
            let w = waits(message);
            if r["stop"] == "compute-stall" {
                // The detail names threads and counts; the stall itself is the finding.
                w
            } else {
                message.to_string()
            }
        }
        // Not a finding about the guest: the stop token is the whole name (the messages carry
        // paths and times).
        _ => String::new(),
    };
    normalise(&p)
}

/// The distinct `wait=` tokens of a parked-threads detail, sorted, normalised.
fn waits(detail: &str) -> String {
    let mut w: Vec<String> = detail
        .split_whitespace()
        .filter_map(|t| t.strip_prefix("wait="))
        .map(|t| normalise(t.trim_end_matches([';', ','])))
        .collect();
    w.sort();
    w.dedup();
    w.join(",")
}

/// The guest's own first statement of what went wrong on stderr: a Rust panic (from
/// `panicked at`, with the message line that follows it), a Go `panic:`, a C `assert`, a
/// Python exception after a traceback, or an `INVARIANT` line.
pub fn guest_line(stderr: &str) -> Option<String> {
    let lines: Vec<&str> = stderr.lines().collect();
    for (i, l) in lines.iter().enumerate() {
        let l = l.trim_end();
        if let Some(at) = l.find("panicked at") {
            let mut s = l[at..].to_string();
            if s.ends_with(':') {
                if let Some(next) = lines.get(i + 1) {
                    s.push(' ');
                    s.push_str(next.trim());
                }
            }
            return Some(normalise(&s));
        }
        if l.starts_with("panic: ")
            || l.starts_with("INVARIANT ")
            || l.contains("Assertion `")
            || l.contains("assertion failed")
        {
            return Some(normalise(l));
        }
        if l.starts_with("Traceback (most recent call last)") {
            if let Some(e) = lines[i + 1..]
                .iter()
                .find(|x| !x.is_empty() && !x.starts_with(char::is_whitespace))
            {
                return Some(normalise(e));
            }
        }
    }
    None
}

/// Collapse what varies between seeds: `0x` hex to `0x_`, digit runs to `N`, other runs of
/// six or more hex digits containing a digit to `H`; whitespace runs to one space.
pub fn normalise(s: &str) -> String {
    let mut out = String::new();
    for word in s.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        let c: Vec<char> = word.chars().collect();
        let mut i = 0;
        while i < c.len() {
            let hex_run = |from: usize| {
                c[from..]
                    .iter()
                    .take_while(|x| x.is_ascii_hexdigit())
                    .count()
            };
            let boundary = i == 0 || !c[i - 1].is_ascii_alphanumeric();
            if c[i] == '0' && c.get(i + 1) == Some(&'x') && hex_run(i + 2) > 0 {
                out.push_str("0x_");
                i += 2 + hex_run(i + 2);
            } else if boundary
                && hex_run(i) >= 6
                && c[i..i + hex_run(i)].iter().any(|x| x.is_ascii_digit())
                && c.get(i + hex_run(i))
                    .is_none_or(|x| !x.is_ascii_alphanumeric())
            {
                out.push('H');
                i += hex_run(i);
            } else if c[i].is_ascii_digit() {
                out.push('N');
                while i < c.len() && c[i].is_ascii_digit() {
                    i += 1;
                }
            } else {
                out.push(c[i]);
                i += 1;
            }
        }
    }
    out.chars().take(PRIMARY_MAX).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sig(r: Value, stderr: &str) -> String {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("patina-sig-{}-{n}", std::process::id()));
        std::fs::create_dir_all(dir.join("inc-0")).unwrap();
        std::fs::write(dir.join("inc-0/stderr"), stderr).unwrap();
        let s = of(&r, &dir);
        std::fs::remove_dir_all(&dir).unwrap();
        s.as_str().unwrap_or("").to_string()
    }

    #[test]
    fn what_varies_by_seed_does_not_split_and_what_failed_does() {
        let fail = |exit: i64| {
            json!({"outcome": "failure", "stop": "exit", "message": "x", "incarnations": 1,
                   "guest": {"exit": exit, "signal": null}})
        };
        let panic = |thread: &str, line: u32, msg: &str| {
            format!("thread '{thread}' panicked at src/lib.rs:{line}:9:\n{msg} 0x7ffd1234\n")
        };
        // The same panic on another thread, line and address: one signature.
        assert_eq!(
            sig(fail(101), &panic("main", 10, "index 3 out of range")),
            sig(fail(101), &panic("worker-7", 12, "index 41 out of range"))
        );
        // Another message, or another exit status: another signature.
        assert_ne!(
            sig(fail(101), &panic("main", 10, "index 3 out of range")),
            sig(fail(101), &panic("main", 10, "called unwrap on None"))
        );
        assert_ne!(sig(fail(3), ""), sig(fail(4), ""));
        // A violation is named by its label, not its detail.
        let v = |detail: &str| {
            json!({"outcome": "violation", "stop": "always", "message": detail,
                   "sdk": {"violation": {"label": "balance", "detail": detail}}})
        };
        assert_eq!(
            sig(v("balance -1"), ""),
            sig(v("balance -7 at 0xdead00"), "")
        );
        // Ok has none.
        assert!(of(&json!({"outcome": "ok"}), Path::new("/nonexistent")).is_null());
    }

    #[test]
    fn deadlocks_are_named_by_their_waits() {
        let d = |a: &str, b: &str| {
            json!({"outcome": "liveness", "stop": "deadlock",
                   "message": format!("every thread is blocked with no deadline: slot=0 tid={a} wait=futex deadline=none; slot=1 tid={b} wait=read(pipe) deadline=none")})
        };
        assert_eq!(sig(d("4", "9"), ""), sig(d("12", "3"), ""));
        assert!(sig(d("4", "9"), "").contains("futex"));
    }
}
