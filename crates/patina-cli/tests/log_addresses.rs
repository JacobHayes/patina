//! The boundary log records what the program did and what it was told, never an address of
//! the runtime's own: such a value would move every digest whenever the runtime's layout moves.
//! Two small runs whose calls name paths through symlinked directories (where the runtime
//! resolves the path into its own buffer and passes that on): one execs, opens and stats through
//! `/bin`, takes a signal and connects a TCP socket (a unix socket underneath); one makes
//! directories through a symlink in `/work` with file faults on, so injected-fault records name
//! such calls. No value of any record may fall inside the runtime's region, and the logged path
//! strings are the program's own (`/bin/true` as it named it), not the runtime's rewritten paths. Needs what `patina run` needs (user namespaces)
//! and the host's python3.

use proto::layout::{RT_BASE, RT_REGION_END};
use proto::nr;
use proto::rec::{Rec, REC_SIZE};
use proto::RecKind;
use std::process::Command;

/// A fresh seed for each test run: the property holds for every seed.
fn fresh_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as u64
        ^ std::process::id() as u64
}

/// One run of `sh -c SCRIPT sh ARGS..` with `opts` under `seed`; its records, after checking
/// that none holds a runtime address.
fn run(name: &str, seed: u64, opts: &[&str], script: &str, args: &[&str]) -> Vec<Rec> {
    let out = std::env::temp_dir().join(format!("patina-log-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    let st = Command::new(env!("CARGO_BIN_EXE_patina"))
        .args(["run", "--seed", &seed.to_string(), "--out"])
        .arg(&out)
        .args(opts)
        .args(["--", "/bin/sh", "-c", script, "sh"])
        .args(args)
        .output()
        .expect("patina run");
    assert!(
        st.status.success(),
        "{name} seed {seed}: patina run: {}{}",
        String::from_utf8_lossy(&st.stdout),
        String::from_utf8_lossy(&st.stderr)
    );
    let log = std::fs::read(out.join("boot-1/boundary.log")).expect("boundary log");
    let recs: Vec<Rec> = log
        .as_chunks::<REC_SIZE>()
        .0
        .iter()
        .map(|c| Rec::from_bytes(c))
        .collect();
    let rt = RT_BASE..RT_REGION_END;
    for r in &recs {
        // A Name or Str record's words are a string's bytes, not values.
        if r.kind == RecKind::Name as u8 || r.kind == RecKind::Str as u8 {
            continue;
        }
        let hit = r
            .args
            .into_iter()
            .chain([r.ret as u64])
            .find(|v| rt.contains(v));
        assert!(
            hit.is_none(),
            "{name} seed {seed}: record {} (kind {}, nr {}) holds runtime address {:#x}: {:x?}",
            r.seq,
            r.kind,
            r.nr,
            hit.unwrap_or_default(),
            r.args
        );
    }
    let _ = std::fs::remove_dir_all(&out);
    recs
}

#[test]
fn no_record_holds_a_runtime_address() {
    let seed = fresh_seed();
    let recs = run(
        "exec",
        seed,
        &[],
        "set -e; test -L /bin; for i in 1 2 3; do /bin/true; done; \
         /bin/cat /bin/true >/dev/null; /bin/sh -c 'exec /bin/true'; /bin/python3 -c \"$1\"; \
         exec /bin/ls /bin/sh",
        &[
            "import os, signal, socket; signal.signal(signal.SIGUSR1, lambda *a: None); \
           os.kill(os.getpid(), signal.SIGUSR1); \
           s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(); \
           c = socket.create_connection(s.getsockname()); a, _ = s.accept(); c.sendall(b'x'); \
           assert a.recv(1) == b'x' and a.getpeername() == c.getsockname(); \
           os.stat('/bin/sh'); os.listdir('/bin')",
        ],
    );
    let execs = recs
        .iter()
        .filter(|r| r.kind == RecKind::Trap as u8 && u64::from(r.nr) == nr::EXECVE)
        .count();
    assert!(execs > 0, "exec seed {seed}: no execve in the log");
    // The path of each execve as the program passed it: through the /bin symlink.
    let passed: Vec<Vec<u8>> = recs
        .windows(2)
        .filter(|w| {
            w[0].kind == RecKind::Trap as u8
                && u64::from(w[0].nr) == nr::EXECVE
                && w[1].kind == RecKind::Str as u8
                && w[1].class == proto::rec::STR_PATH
        })
        .map(|w| w[1].str_bytes()[..(w[1].nr as usize).min(64)].to_vec())
        .collect();
    assert!(
        passed.iter().any(|p| p == b"/bin/true"),
        "exec seed {seed}: no execve path recorded as passed: {:?}",
        passed
            .iter()
            .map(|p| String::from_utf8_lossy(p))
            .collect::<Vec<_>>()
    );

    // Half the file calls on /work fail: set up with retries, then ten mkdirs through the link.
    // A seed's draws can spare every mkdir: seeds from a fresh one on are run (each checked for
    // runtime addresses) until one injects a fault into mkdir.
    let first = fresh_seed();
    let injected = (first..first + 20).find(|&seed| {
        let recs = run(
            "faults",
            seed,
            &["--fault", "fs-error-permille=500"],
            "until mkdir -p /work/d 2>/dev/null; do :; done; \
             until ln -sfn /work/d /work/l 2>/dev/null; do :; done; test -L /work/l || exit 1; \
             for i in 1 2 3 4 5 6 7 8 9 10; do mkdir /work/l/m$i 2>/dev/null || true; done",
            &[],
        );
        recs.iter().any(|r| {
            // `mkdir` makes `mkdirat` where the architecture has no `mkdir` (arm64).
            r.kind == RecKind::Injected as u8 && [nr::MKDIR, nr::MKDIRAT].contains(&u64::from(r.nr))
        })
    });
    assert!(
        injected.is_some(),
        "faults seeds {first}..{}: no fault injected into mkdir",
        first + 20
    );
}
