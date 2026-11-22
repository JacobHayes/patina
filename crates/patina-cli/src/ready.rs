//! Inside a run: a machine's `ready` probe runner (hidden `patina __ready -- CMD ARGS`), and
//! `patina wait ADDR`, a probe for a listening port.
//!
//! The supervisor starts the runner once on each machine that declares a probe, at its first
//! boot (`sup::ready`): it runs the probe, and again every 100 ms of virtual time while the
//! probe exits nonzero, then exits 0, which makes the machine ready. Each output of the probe
//! that differs from the one before goes to the machine's stderr, so the last one is there when
//! the machine is never ready. It is a guest process like any other: scheduled, in virtual time,
//! in the log.

use std::process::{Command, ExitCode, Stdio};

/// The runtime's arguments of the runner of probe `words`, as a machine's or main's command.
pub fn runner_argv(words: &[String]) -> Vec<String> {
    let mut v: Vec<String> = ["rt", crate::launch::GUEST_PATINA, "patina", "__ready", "--"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    v.extend(words.iter().cloned());
    v
}

/// `patina __ready -- CMD ARGS`.
pub fn runner(args: &[String]) -> ExitCode {
    let words = match args.split_first() {
        Some((d, w)) if d == "--" && !w.is_empty() => w,
        _ => {
            eprintln!("patina __ready: expected -- CMD ARGS");
            return ExitCode::from(2);
        }
    };
    let shown = words.join(" ");
    let mut last: Option<String> = None;
    loop {
        let said = match Command::new(&words[0])
            .args(&words[1..])
            .stdin(Stdio::null())
            .output()
        {
            Ok(o) if o.status.success() => return ExitCode::SUCCESS,
            Ok(o) => {
                let how = match o.status.code() {
                    Some(c) => format!("exit {c}"),
                    None => "killed by a signal".to_string(),
                };
                let text = String::from_utf8_lossy(&[o.stdout, o.stderr].concat())
                    .trim()
                    .replace('\n', " | ");
                if text.is_empty() {
                    how
                } else {
                    format!("{how}: {text}")
                }
            }
            Err(e) => format!("cannot run it: {e}"),
        };
        if last.as_deref() != Some(said.as_str()) {
            eprintln!("patina: ready probe `{shown}`: {said}");
            last = Some(said);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// `patina wait ADDR`: one TCP connect to `ADDR` (`:PORT` is this machine's `127.0.0.1:PORT`);
/// exit 0 when it succeeds, 1 with why when it does not.
pub fn wait(args: &[String]) -> ExitCode {
    let [addr] = args else {
        eprintln!("patina wait: expected one ADDR (HOST:PORT or :PORT)");
        return ExitCode::from(2);
    };
    let target = match addr.strip_prefix(':') {
        Some(port) => format!("127.0.0.1:{port}"),
        None => addr.clone(),
    };
    match std::net::TcpStream::connect(&target) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("patina wait: connect {target}: {e}");
            ExitCode::from(1)
        }
    }
}
