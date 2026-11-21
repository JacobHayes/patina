//! A run's signature: a stable name for what failed, so that a sweep or a report can count
//! one bug once however many seeds hit it. It is `outcome stop: primary`, where `primary` is
//! what failed: the failed `always` label; the waits the blocked threads were parked in; the
//! first panic or assertion line the guest printed on stderr, then the signal name or the exit
//! status; the unsupported call. Fault settings are not part of it. Written into `result.json`
//! when the run ends; readers take it from there.
//!
//! A violation is named by its label and the first line of its detail: a program that reports
//! every failure under one label still gets one group per bug. A checker that names its finding
//! `LABEL [KEY]` (`check::finding`) chose its grouping itself: the label and key, verbatim,
//! are the whole name, and the detail is left to the report to show.
//!
//! The rule for numbers: what names the failure is kept as it is (the exit status, the signal
//! name, an SDK label, a call's name); numbers in text the guest or the supervisor wrote are
//! collapsed (`normalise`), because addresses, line and column numbers, thread and process
//! ids, counts and durations vary by seed and build while the bug stays the same. Absolute
//! paths keep their last three components (`checkout_free`), so a label made from a source
//! file's path is the same in every checkout.
//!
//! The rule for nodes: a node's own end (`node_end`) is named `[node NAME]` with NAME's
//! digits collapsed, so replicas numbered alike (`n1`, `n2`, `n3`) that end the same way are
//! one bug while nodes named for their roles (`primary`, `backup`) stay apart. Which node
//! crashed, and where, is a fault setting's effect and not part of it: a lost write found by
//! the driver after b's crash and after a's has one name.

use serde_json::Value;
use std::path::Path;

/// Longest `primary` kept (characters).
const PRIMARY_MAX: usize = 200;
/// Longest part of a violation's detail kept in its signature (characters): enough to tell
/// one message from another, short enough that context a program appends (state dumps,
/// counters) does not split one bug.
const DETAIL_MAX: usize = 64;
/// A checker's detail is its whole first line, which its author wrote to name the finding
/// (context goes on later lines, in `check.out`): cut only at the signature's length.
const CHECK_DETAIL_MAX: usize = PRIMARY_MAX;
/// Components an absolute path keeps (`checkout_free`).
const PATH_KEEP: usize = 3;

/// The signature of a finished run (`null` for `ok`). `dir` is its run directory: the last
/// incarnation's stderr is read there for a panic or assertion line.
pub fn of(r: &Value, dir: &Path) -> Value {
    let s = |k: &str| r[k].as_str().unwrap_or("").to_string();
    let (outcome, stop) = (s("outcome"), s("stop"));
    if outcome == "ok" || outcome.is_empty() {
        return Value::Null;
    }
    // A node's own end (`node_end`): its stderr, its exit or signal, and its name, which
    // tells it from the same end of another node's command (digits collapsed: replicas).
    let (stderr_at, at) = match r["node_end"]["node"].as_str() {
        Some(n) => (
            dir.join("node").join(n).join(format!(
                "inc-{}",
                r["node_end"]["incarnation"].as_u64().unwrap_or(0)
            )),
            format!(" [node {}]", normalise(n)),
        ),
        None => {
            let inc = r["incarnations"].as_u64().unwrap_or(1).max(1) - 1;
            (dir.join(format!("inc-{inc}")), String::new())
        }
    };
    let stderr = std::fs::read(stderr_at.join("stderr"))
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let p = primary(r, &stderr);
    Value::String(if p.is_empty() {
        format!("{outcome} {stop}{at}")
    } else {
        format!("{outcome} {stop}{at}: {p}")
    })
}

fn primary(r: &Value, stderr: &str) -> String {
    let message = r["message"].as_str().unwrap_or("");
    let p = match r["outcome"].as_str().unwrap_or("") {
        // A failed `always`, or a `--check` finding: the same rule.
        "violation" => {
            let v = if r["stop"] == "check" {
                &r["check"]
            } else {
                &r["sdk"]["violation"]
            };
            match v["label"].as_str() {
                Some(l) => {
                    return violation(l, v["detail"].as_str().unwrap_or(""), r["stop"] == "check")
                }
                None => message.to_string(),
            }
        }
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
            } else if let Some(l) = last_line(stderr) {
                parts.push(l);
            }
            let g = if r["node_end"].is_object() {
                &r["node_end"]
            } else {
                &r["guest"]
            };
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

/// A checker's label split into its name and its key: `LABEL [KEY]` (`check::finding`).
pub fn keyed(label: &str) -> Option<(&str, &str)> {
    let (name, rest) = label.split_once(" [")?;
    let key = rest.strip_suffix(']')?;
    (!name.is_empty() && !name.contains(char::is_whitespace)).then_some((name, key))
}

/// A violation's name: its label kept as written (but checkout-free; its digits are kept),
/// then the first line of its detail, normalised and cut at `max` characters, which tells
/// apart bugs reported under one label. A checker's keyed label (`LABEL [KEY]`) is the whole
/// name: the key as written, the detail left out.
fn violation(label: &str, detail: &str, check: bool) -> String {
    let max = if check { CHECK_DETAIL_MAX } else { DETAIL_MAX };
    if check {
        if let Some((name, key)) = keyed(label) {
            let p = format!("{} [{key}]", checkout_free(name));
            return p.chars().take(PRIMARY_MAX).collect();
        }
    }
    let mut p = checkout_free(label);
    let first = detail.lines().find(|x| !x.trim().is_empty()).unwrap_or("");
    let d: String = normalise(&checkout_free(first)).chars().take(max).collect();
    if !d.is_empty() {
        p = format!("{p}: {}", d.trim_end());
    }
    p.chars().take(PRIMARY_MAX).collect()
}

/// Whether a signature names its bug by a name the program's or checker's author chose: a
/// violation (an `always` label, a checker's label) or an `INVARIANT` line. Such a finding is
/// one bug in whichever case it appears. Every other signature is a status, a signal, a
/// blocked wait, or text that recurs across unrelated bugs (`exit 101` of every failing Rust
/// test, Go's `panic: runtime error: index out of range`, an `assert_eq!` without a message
/// once its line number is `N`), so the case stays part of its group.
pub fn names_its_bug(signature: &str) -> bool {
    let (head, primary) = signature.split_once(": ").unwrap_or((signature, ""));
    head.starts_with("violation ") || primary.starts_with("INVARIANT ")
}

/// The key two verdicts of one checker on one run are compared by: the verdict and the
/// finding's name as a signature gives it.
pub fn check_key(c: &Value) -> (Value, String) {
    let line = match c["label"].as_str() {
        Some(l) => violation(l, c["detail"].as_str().unwrap_or(""), true),
        None => normalise(c["detail"].as_str().unwrap_or("")),
    };
    (c["verdict"].clone(), line)
}

/// `s` with every absolute path cut to its last three components: `/home/u/src/app/crates/
/// store/src/log.rs:42` becomes `store/src/log.rs:42`. A path starts at a `/` that begins a
/// word or follows a character that cannot be part of a name (`(`, `"`, `=`, ...).
pub fn checkout_free(s: &str) -> String {
    let name = |c: char| c.is_alphanumeric() || "._-~+@".contains(c);
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('/') {
        let starts = rest[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !name(c) && c != '/');
        if !starts {
            out.push_str(&rest[..=i]);
            rest = &rest[i + 1..];
            continue;
        }
        out.push_str(&rest[..i]);
        let path = &rest[i..];
        let end = path
            .find(|c: char| c.is_whitespace() || "\"'()[]{}<>,;`".contains(c))
            .unwrap_or(path.len());
        let comps: Vec<&str> = path[..end].split('/').filter(|c| !c.is_empty()).collect();
        if comps.len() > PATH_KEEP {
            out.push_str(&comps[comps.len() - PATH_KEEP..].join("/"));
        } else {
            out.push_str(&path[..end]);
        }
        rest = &path[end..];
    }
    out.push_str(rest);
    out
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

/// The guest's own first statement of what went wrong on stderr (`guest_line_raw`), normalised.
pub fn guest_line(stderr: &str) -> Option<String> {
    guest_line_raw(stderr).map(|l| normalise(&l))
}

/// The guest's own first statement of what went wrong on stderr, as written: a Rust panic (from
/// `panicked at`, with the message line that follows it), a Go `panic:`, a C `assert`, a
/// Python exception after a traceback, or an `INVARIANT` line.
pub fn guest_line_raw(stderr: &str) -> Option<String> {
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
            return Some(s);
        }
        if l.starts_with("panic: ")
            || l.starts_with("INVARIANT ")
            || l.contains("Assertion `")
            || l.contains("assertion failed")
        {
            return Some(l.to_string());
        }
        if l.starts_with("Traceback (most recent call last)") {
            if let Some(e) = lines[i + 1..]
                .iter()
                .find(|x| !x.is_empty() && !x.starts_with(char::is_whitespace))
            {
                return Some(e.to_string());
            }
        }
    }
    None
}

/// The guest's last stderr line, normalised, when it says something: at least one word of
/// three letters (not a bare number, address or punctuation).
fn last_line(stderr: &str) -> Option<String> {
    last_line_raw(stderr).map(|l| normalise(&l))
}

/// The last line of stderr with a word in it, as written: what a failure's signature quotes
/// when the guest stated nothing `guest_line_raw` recognises.
pub fn last_line_raw(stderr: &str) -> Option<String> {
    let l = stderr.lines().rev().find(|l| !l.trim().is_empty())?.trim();
    let wordy = l
        .split(|c: char| !c.is_ascii_alphabetic())
        .any(|w| w.len() >= 3);
    wordy.then(|| l.to_string())
}

/// Collapse what varies between seeds: `0x` hex to `0x_`, digit runs to `N`, other runs of
/// six or more hex digits holding both a digit and a letter to `H`; whitespace runs to one
/// space.
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
                && c[i..i + hex_run(i)].iter().any(|x| x.is_ascii_alphabetic())
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
        // A violation is named by its label and its detail's first line, numbers collapsed.
        let v = |detail: &str| {
            json!({"outcome": "violation", "stop": "always", "message": detail,
                   "sdk": {"violation": {"label": "balance", "detail": detail}}})
        };
        assert_eq!(
            sig(v("balance -1\nstate 4"), ""),
            sig(v("balance -7\nstate 9 at 0xdead00"), "")
        );
        assert_ne!(sig(v("balance -1"), ""), sig(v("lost entry 3"), ""));
        // A decimal number is a number at any length; a hex id is one at any value.
        assert_eq!(
            sig(v("acknowledged (offset 19)"), ""),
            sig(v("acknowledged (offset 121122)"), "")
        );
        assert_eq!(
            sig(v("upload 3f9a1c2b0e done"), ""),
            sig(v("upload 77ab0e19ff done"), "")
        );
        // Without a panic line, the last informative stderr line names the failure.
        assert_eq!(
            sig(fail(1), "round 3\nno convergence after 412 rounds\n"),
            sig(fail(1), "round 9\nno convergence after 77 rounds\n")
        );
        assert_ne!(
            sig(fail(1), "no convergence after 412 rounds\n"),
            sig(fail(1), "lost write at offset 4096\n")
        );
        // A label is a name: its digits are kept.
        let l = |label: &str| {
            json!({"outcome": "violation", "stop": "always", "message": "x",
                   "sdk": {"violation": {"label": label, "detail": "x"}}})
        };
        assert_ne!(sig(l("queue-1-bound"), ""), sig(l("queue-2-bound"), ""));
        // Exit status and signal are kept; the panic's line, column and values collapse.
        let s = sig(fail(101), &panic("main", 10, "index 3 out of range"));
        assert!(s.ends_with("exit 101") && !s.contains("10:9"), "{s}");
        // Ok has none.
        assert!(of(&json!({"outcome": "ok"}), Path::new("/nonexistent")).is_null());
    }

    #[test]
    fn a_node_end_names_its_node_with_digits_collapsed() {
        let end = |node: &str| {
            let dir =
                std::env::temp_dir().join(format!("patina-sig-node-{}-{node}", std::process::id()));
            let inc = dir.join("node").join(node).join("inc-0");
            std::fs::create_dir_all(&inc).unwrap();
            std::fs::write(inc.join("stderr"), "replica diverged at 41\n").unwrap();
            let r = json!({"outcome": "failure", "stop": "node-exit", "message": "x",
                "node_end": {"node": node, "incarnation": 0, "exit": 3, "signal": null}});
            let s = of(&r, &dir);
            std::fs::remove_dir_all(&dir).unwrap();
            s.as_str().unwrap_or("").to_string()
        };
        // Replicas numbered alike: one bug.
        assert_eq!(end("n1"), end("n3"));
        // Nodes named for their roles: apart, and apart from the driver's end.
        assert_ne!(end("primary"), end("backup"));
        assert!(
            end("primary")
                != sig(
                    json!({"outcome": "failure", "stop": "node-exit",
            "message": "x", "incarnations": 1, "guest": {"exit": 3, "signal": null}}),
                    "replica diverged at 41\n"
                )
        );
    }

    #[test]
    fn a_check_is_named_as_an_always_is() {
        let always = json!({"outcome": "violation", "stop": "always", "message": "x",
            "sdk": {"violation": {"label": "acked-record-lost", "detail": "acknowledged 17, 16 stored"}}});
        let check = json!({"outcome": "violation", "stop": "check", "message": "x",
            "check": {"verdict": "fail", "label": "acked-record-lost", "detail": "acknowledged 9, 3 stored"}});
        let (a, c) = (sig(always, ""), sig(check, ""));
        assert_eq!(a.split_once(": ").unwrap().1, c.split_once(": ").unwrap().1);
        assert!(c.starts_with("violation check: acked-record-lost"), "{c}");
        // A checker's first line is the name it chose: kept whole (an `always` detail is cut),
        // its label's digits too.
        let detail = format!("open db: {} (inc-2)", "x".repeat(80));
        let check = json!({"outcome": "violation", "stop": "check", "message": "x",
            "check": {"verdict": "fail", "label": "open-ps1", "detail": detail}});
        let c = sig(check, "");
        assert!(
            c.starts_with("violation check: open-ps1: ") && c.ends_with("(inc-N)"),
            "{c}"
        );
    }

    #[test]
    fn a_checker_key_groups_and_the_detail_does_not() {
        let check = |label: &str, detail: &str| {
            sig(
                json!({"outcome": "violation", "stop": "check", "message": "x",
                       "check": {"verdict": "fail", "label": label, "detail": detail}}),
                "",
            )
        };
        // Keyed: the detail never splits a group, and the key is kept as written.
        assert_eq!(
            check("wrong-output [cat]", "line 3: got 0x0"),
            check("wrong-output [cat]", "line 9: got 1")
        );
        assert_ne!(
            check("wrong-output [cat]", "x"),
            check("wrong-output [cat2]", "x")
        );
        assert_eq!(
            check("wrong-output [exit 2: 0x0]", "x"),
            "violation check: wrong-output [exit 2: 0x0]"
        );
        // Unkeyed, as before: the detail's first line, numbers collapsed.
        assert_ne!(
            check("wrong-output", "got 0x0 in cat"),
            check("wrong-output", "got 0x0 in ls")
        );
        assert_eq!(
            check_key(&json!({"verdict": "fail", "label": "w [k]", "detail": "a 1"})),
            check_key(&json!({"verdict": "fail", "label": "w [k]", "detail": "b 2"}))
        );
    }

    #[test]
    fn only_a_named_finding_spans_cases() {
        assert!(names_its_bug("violation check: wrong-sub: got N"));
        assert!(names_its_bug("violation always: balance"));
        assert!(names_its_bug(
            "failure exit: INVARIANT open-after-crash; exit 1"
        ));
        for s in [
            "failure exit: exit 101",
            "failure exit: panic: runtime error: index out of range [N] with length N; exit 2",
            "crash signal: SIGABRT",
            "liveness time-limit: parked in sleep",
        ] {
            assert!(!names_its_bug(s), "{s}");
        }
    }

    #[test]
    fn paths_lose_their_checkout() {
        let a = "/src/a/app-ws1/crates/store/src/log.rs:42:unreachable";
        let b = "/home/u/app/crates/store/src/log.rs:42:unreachable";
        assert_eq!(checkout_free(a), checkout_free(b));
        assert_eq!(checkout_free(a), "store/src/log.rs:42:unreachable");
        assert_eq!(checkout_free("open /x/y failed"), "open /x/y failed");
        assert_eq!(
            checkout_free("at (/a/b/c/d/e.rs:1) and a/b/c/d"),
            "at (c/d/e.rs:1) and a/b/c/d"
        );
        let l = |label: &str| {
            json!({"outcome": "violation", "stop": "always", "message": "x",
                   "sdk": {"violation": {"label": label, "detail": ""}}})
        };
        assert_eq!(sig(l(a), ""), sig(l(b), ""));
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
