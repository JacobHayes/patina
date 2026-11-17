//! The boundary log records what the program did and what it was told, never an address of
//! the runtime's own: such a value would move every digest whenever the runtime's layout moves.
//! Two small runs whose calls name paths through symlinked directories (where the runtime
//! resolves the path into its own buffer and passes that on): one execs, opens and stats through
//! `/bin`, takes a signal and connects a TCP socket (a unix socket underneath); one makes
//! directories through a symlink in `/work` with file faults on, so injected-fault records name
//! such calls. No value of any record may fall inside the runtime's region. Needs what `patina
//! run` needs (bwrap, user namespaces) and the host's python3.

use proto::layout::{RT_BASE, RT_REGION_END};
use proto::nr;
use proto::rec::{Rec, REC_SIZE};
use proto::RecKind;
use std::process::Command;

/// One run of `sh -c SCRIPT sh ARGS..` with `opts`, under a fresh seed (the property holds for
/// every seed); its seed and records, after checking that none holds a runtime address.
fn run(name: &str, opts: &[&str], script: &str, args: &[&str]) -> (u64, Vec<Rec>) {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as u64
        ^ std::process::id() as u64;
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
    let log = std::fs::read(out.join("inc-0/boundary.log")).expect("boundary log");
    let recs: Vec<Rec> = log
        .as_chunks::<REC_SIZE>()
        .0
        .iter()
        .map(|c| Rec::from_bytes(c))
        .collect();
    let rt = RT_BASE..RT_REGION_END;
    for r in &recs {
        // A Name record's words are a file name's bytes, not values.
        if r.kind == RecKind::Name as u8 {
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
    (seed, recs)
}

#[test]
fn no_record_holds_a_runtime_address() {
    let (seed, recs) = run(
        "exec",
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

    // Half the file calls on /work fail: set up with retries, then ten mkdirs through the link.
    let (seed, recs) = run(
        "faults",
        &["--fault", "fs-error-permille=500"],
        "until mkdir -p /work/d 2>/dev/null; do :; done; \
         until ln -sfn /work/d /work/l 2>/dev/null; do :; done; test -L /work/l || exit 1; \
         for i in 1 2 3 4 5 6 7 8 9 10; do mkdir /work/l/m$i 2>/dev/null || true; done",
        &[],
    );
    let injected = recs
        .iter()
        .filter(|r| r.kind == RecKind::Injected as u8 && u64::from(r.nr) == nr::MKDIR)
        .count();
    assert!(
        injected > 0,
        "faults seed {seed}: no fault injected into mkdir"
    );
}
