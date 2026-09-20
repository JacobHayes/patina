//! `conform` — the harness half of the syscall-conformance testbed, driven by
//! `run.sh`. Every subcommand takes positional arguments (so the flag-drift gate
//! sees no flag tokens for it) and reports on stdout; exit codes are the
//! contract: 0 ok, 1 gate failed / error, 2 usage, 3 leg timeout, 5
//! host-unavailable.

use std::process::exit;
use syscall_conformance::expect::{
    blessable, blessed_termination, check_trace_obligations, declared_failing, diff,
    gate_declarations, host_gate, load_divergences, load_frozen, load_manifest, load_registry,
    normalize, parse_expectation, render_expectation, selftest, validate_manifest, Header,
    HostGate, Mode, Termination, REGISTRY_SCHEMA, SCHEMA,
};
use syscall_conformance::observe::parse_stream;

const EXIT_TIMEOUT: i32 = 3;
const EXIT_HOST_UNAVAILABLE: i32 = 5;
const EXIT_NOT_DECLARED: i32 = 6;

fn usage() -> String {
    format!(
        "usage: conform <subcommand> ARGS…\n\
         \n\
         abi        REGISTRY_JSON                                 print the registry's virtual ABI level\n\
         list       PROBES_TOML                                   print every probe id\n\
         check-manifest PROBES_TOML REGISTRY_JSON REFERENCE_JSON  every row/symbol the manifest names is a registry\n\
                                                                  row of the right kind (exit 1 otherwise)\n\
         supervise  native|patina TIMEOUT_S OUT_JSONL ERR_FILE -- CMD…\n\
                                                                  run CMD in its own process group with a wall-clock\n\
                                                                  timeout (the group is killed on expiry; exit {EXIT_TIMEOUT}),\n\
                                                                  its stdout to OUT and stderr to ERR; `native` appends\n\
                                                                  the waitpid outcome as the stream's __termination\n\
                                                                  line; `patina` expects CMD to print a patina.result/v1\n\
                                                                  envelope and unpacks its guest stdout/stderr and\n\
                                                                  guest_exit into OUT/ERR the same way\n\
         bless      PROBE RAW_JSONL OUT_JSONL OS ARCH KERNEL GLIBC PROBES_TOML REGISTRY_JSON REFERENCE_JSON\n\
                                                                  normalize RAW (a supervised native stream: every check\n\
                                                                  passed, exited 0 or an announced signal death) and\n\
                                                                  write OUT with a blessing header\n\
         header     EXPECTED_JSONL                                print the blessing header as key=value lines\n\
         termination-of STREAM_JSONL [full]                       print the stream's termination as `exited N` or\n\
                                                                  `signaled N` (exit 1 if it has none); `full` adds\n\
                                                                  the core flag as the supervisor observed it\n\
         diff       native|patina PROBE VEHICLE EXPECTED_JSONL ACTUAL_JSONL DIVERGENCES_TOML [ERR_FILE]\n\
                                                                  compare ACTUAL (raw, with its __termination line)\n\
                                                                  with EXPECTED; exit 1 on any undeclared or stale\n\
                                                                  divergence, count drift, or termination mismatch\n\
         host-check PROBE PROBES_TOML REGISTRY_JSON EXPECTED_JSONL HOST_KERNEL REFERENCE_JSON\n\
                                                                  exit 0 usable, {EXIT_HOST_UNAVAILABLE} host-unavailable (the host\n\
                                                                  lacks an exercised row or implements an absent one),\n\
                                                                  1 host older than the blessing kernel\n\
         selftest                                                 prove every differ/host/frozen gate can fail (exit 1\n\
                                                                  if any planted failure is not refused)\n\
         declared-failing PROBE VEHICLE DIVERGENCES_TOML          exit 0 (and print the reason) when the probe is declared\n\
                                                                  failing under patina for that vehicle, {EXIT_NOT_DECLARED} otherwise\n\
         gate       FROZEN_TOML DIVERGENCES_TOML FAMILY           the frozen declaration rule for one family: a line\n\
                                                                  (and exit 1) per new/relabeled declaration, removed\n\
                                                                  by-design one, or pending one still present\n\
         frozen-paths FROZEN_TOML FAMILY                          print the family's frozen paths\n\
         obligations FROZEN_TOML FAMILY unit-tests|traces [OUT_DIR]\n\
                                                                  the family's design obligations: `unit-tests` lists\n\
                                                                  them tab-separated (crate, test) for gate.sh to run;\n\
                                                                  `traces` checks the replay legs' dumped traces under\n\
                                                                  OUT_DIR, one line per unmet fact (exit 1)\n\
         \n\
         Schema {SCHEMA}; REGISTRY_JSON is `cargo patina syscalls --format json` ({REGISTRY_SCHEMA})."
    )
}

fn read(path: &str) -> String {
    match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("conform: cannot read {path}: {error}");
            exit(1)
        }
    }
}

fn need(args: &[String], count: usize, what: &str) {
    if args.len() != count {
        eprintln!(
            "conform {what}: expected {count} argument(s), got {}\n{}",
            args.len(),
            usage()
        );
        exit(2);
    }
}

fn manifest_from(path: &str) -> syscall_conformance::expect::Manifest {
    match load_manifest(&read(path)) {
        Ok(manifest) => manifest,
        Err(error) => {
            eprintln!("conform: {error}");
            exit(1)
        }
    }
}

fn registry_from(path: &str) -> syscall_conformance::expect::Registry {
    match load_registry(&read(path)) {
        Ok(registry) => registry,
        Err(error) => {
            eprintln!("conform: {path}: {error}");
            exit(1)
        }
    }
}

// Reports are generated together by the runner's freshly rebuilt cargo-patina.
// Never infer identity from their filenames.
fn checked_registry(
    manifest: &syscall_conformance::expect::Manifest,
    host: &str,
    reference: &str,
) -> (
    syscall_conformance::expect::Registry,
    Vec<syscall_conformance::expect::Registry>,
) {
    let registry = registry_from(host);
    let references = vec![registry_from(reference)];
    if registry.os != std::env::consts::OS || registry.arch != std::env::consts::ARCH {
        eprintln!("conform: host registry target does not match this executable");
        exit(1);
    }
    match validate_manifest(manifest, &registry, &references) {
        Ok(nonhost) => {
            eprintln!(
                "manifest applicability: {} nonhost row instances",
                nonhost.len()
            );
            for line in nonhost {
                eprintln!("{line}");
            }
        }
        Err(error) => {
            eprintln!("conform: {error}");
            exit(1);
        }
    }
    (registry, references)
}

fn expectation_from(path: &str) -> syscall_conformance::expect::Expectation {
    match parse_expectation(&read(path)) {
        Ok(expectation) => expectation,
        Err(error) => {
            eprintln!("conform: {path}: {error}");
            exit(1)
        }
    }
}

fn divergences_from(path: &str) -> Vec<syscall_conformance::expect::Divergence> {
    match load_divergences(&read(path)) {
        Ok(divergences) => divergences,
        Err(error) => {
            eprintln!("conform: {error}");
            exit(1)
        }
    }
}

/// Append the supervisor's termination line to a stream file (its seq is the
/// next event index).
fn append_termination(path: &str, termination: &Termination) {
    use std::io::Write;
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let count = match parse_stream(&text) {
        Ok(events) => events.len() as u64,
        Err(_) => text.lines().count() as u64,
    };
    let mut out = String::new();
    if !text.is_empty() && !text.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&serde_json::to_string(&termination.event(count)).expect("event serializes"));
    out.push('\n');
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .unwrap_or_else(|error| {
            eprintln!("conform supervise: cannot append to {path}: {error}");
            exit(1)
        });
    if let Err(error) = file.write_all(out.as_bytes()) {
        eprintln!("conform supervise: cannot append to {path}: {error}");
        exit(1)
    }
}

/// `supervise`: the one place a leg's process outcome is observed. Unix only
/// (process groups and wait statuses); the runner is Linux-only anyway.
#[cfg(unix)]
fn supervise(kind: &str, timeout_secs: u64, out_path: &str, err_path: &str, cmd: &[String]) -> i32 {
    use std::io::Write;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    if kind != "native" && kind != "patina" {
        eprintln!("conform supervise: kind must be native or patina, not {kind:?}");
        return 2;
    }
    let Some((program, args)) = cmd.split_first() else {
        eprintln!("conform supervise: no command after --");
        return 2;
    };
    let out_file = std::fs::File::create(out_path).unwrap_or_else(|error| {
        eprintln!("conform supervise: cannot create {out_path}: {error}");
        exit(1)
    });
    let err_file = std::fs::File::create(err_path).unwrap_or_else(|error| {
        eprintln!("conform supervise: cannot create {err_path}: {error}");
        exit(1)
    });
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out_file))
        .stderr(Stdio::from(err_file));
    // SAFETY: `setsid` is async-signal-safe and touches no state of the parent.
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!("conform supervise: cannot run {program}: {error}");
            return 1;
        }
    };
    let pgid = child.id() as libc::pid_t;
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    timed_out = true;
                    // SAFETY: plain syscall on the child's own process group.
                    unsafe {
                        libc::kill(-pgid, libc::SIGKILL);
                    }
                    match child.wait() {
                        Ok(status) => break status,
                        Err(error) => {
                            eprintln!("conform supervise: wait failed: {error}");
                            return 1;
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => {
                eprintln!("conform supervise: wait failed: {error}");
                return 1;
            }
        }
    };
    // Nothing the leg started may outlive it (a helper the guest left behind
    // would hold the next build's binary busy).
    // SAFETY: as above; an already-empty group is ESRCH, ignored.
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
    let observed = if timed_out {
        Termination::Timeout
    } else if let Some(code) = status.code() {
        Termination::Exited(code)
    } else if let Some(signal) = status.signal() {
        Termination::Signaled {
            signal,
            core: Some(status.core_dumped()),
        }
    } else {
        Termination::Absent
    };
    if timed_out {
        if kind == "patina" {
            std::fs::write(out_path, "").ok();
        }
        append_termination(out_path, &observed);
        println!("timeout pgid={pgid}");
        return EXIT_TIMEOUT;
    }
    if kind == "native" {
        append_termination(out_path, &observed);
        println!("{}", observed.describe());
        return 0;
    }
    // The child was `cargo patina … --format json`: its stdout is the envelope,
    // the guest's streams are inside it, and `guest_exit` is what the supervisor
    // reports about the guest process.
    let text = std::fs::read_to_string(out_path).unwrap_or_default();
    let envelope: serde_json::Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(error) => {
            eprintln!(
                "conform supervise: the supervisor's stdout is not a patina.result/v1 envelope ({error}); the supervisor {}",
                observed.describe()
            );
            std::fs::write(out_path, "").ok();
            append_termination(out_path, &Termination::Absent);
            return 2;
        }
    };
    let guest_stdout = envelope["stdout"].as_str().unwrap_or("").to_string();
    let guest_stderr = envelope["stderr"].as_str().unwrap_or("").to_string();
    std::fs::write(out_path, &guest_stdout).unwrap_or_else(|error| {
        eprintln!("conform supervise: cannot write {out_path}: {error}");
        exit(1)
    });
    if let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(err_path) {
        let _ = file.write_all(guest_stderr.as_bytes());
    }
    let guest_exit = &envelope["guest_exit"];
    let guest = if let Some(signal) = guest_exit["signal"].as_i64() {
        Termination::Signaled {
            signal: signal as i32,
            core: guest_exit["core"].as_bool(),
        }
    } else if let Some(code) = guest_exit["code"].as_i64() {
        Termination::Exited(code as i32)
    } else {
        Termination::Absent
    };
    append_termination(out_path, &guest);
    println!("{}", guest.describe());
    0
}

#[cfg(not(unix))]
fn supervise(_kind: &str, _timeout_secs: u64, _out: &str, _err: &str, _cmd: &[String]) -> i32 {
    eprintln!("conform supervise: process groups and wait statuses are Unix-only");
    2
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (command, rest) = match args.split_first() {
        Some((command, rest)) => (command.as_str(), rest),
        None => {
            eprintln!("{}", usage());
            exit(2)
        }
    };
    match command {
        "--help" | "-h" | "help" => println!("{}", usage()),
        "abi" => {
            need(rest, 1, "abi");
            println!("{}", registry_from(&rest[0]).virtual_abi);
        }
        "check-manifest" => {
            need(rest, 3, "check-manifest");
            let manifest = manifest_from(&rest[0]);
            let (registry, _) = checked_registry(&manifest, &rest[1], &rest[2]);
            println!(
                "ok: {} probes, every name a registry row (virtual ABI {})",
                manifest.probe.len(),
                registry.virtual_abi
            );
        }
        "list" => {
            need(rest, 1, "list");
            for id in manifest_from(&rest[0]).probe.keys() {
                println!("{id}");
            }
        }
        "supervise" => {
            let Some(split) = rest.iter().position(|arg| arg == "--") else {
                eprintln!("conform supervise: expected `-- CMD…`\n{}", usage());
                exit(2)
            };
            let (head, cmd) = rest.split_at(split);
            need(head, 4, "supervise");
            let timeout: u64 = head[1].parse().unwrap_or_else(|_| {
                eprintln!(
                    "conform supervise: TIMEOUT_S must be an integer, not {:?}",
                    head[1]
                );
                exit(2)
            });
            exit(supervise(&head[0], timeout, &head[2], &head[3], &cmd[1..]));
        }
        "bless" => {
            need(rest, 10, "bless");
            let manifest = manifest_from(&rest[7]);
            let (registry, _) = checked_registry(&manifest, &rest[8], &rest[9]);
            if rest[3] != registry.os || rest[4] != registry.arch {
                eprintln!("conform bless: requested target does not match host registry");
                exit(1);
            }
            if !manifest.probe.contains_key(&rest[0]) {
                eprintln!("conform bless: probe {:?} is not in probes.toml", rest[0]);
                exit(1);
            }
            let raw = match parse_stream(&read(&rest[1])) {
                Ok(events) => events,
                Err(error) => {
                    eprintln!("conform bless: {}: {error}", rest[1]);
                    exit(1)
                }
            };
            if raw.len() < 2 {
                eprintln!(
                    "conform bless: {} carries no events; refusing to bless a vacuous stream",
                    rest[1]
                );
                exit(1);
            }
            if let Err(error) = blessable(&raw) {
                eprintln!("conform bless: refusing to bless {}: {error}", rest[0]);
                exit(1);
            }
            let header = Header {
                schema: SCHEMA.to_string(),
                probe: rest[0].clone(),
                os: rest[3].clone(),
                arch: rest[4].clone(),
                kernel: rest[5].clone(),
                glibc: rest[6].clone(),
                virtual_abi: registry.virtual_abi,
            };
            let rendered = render_expectation(&header, &normalize(raw));
            if let Some(parent) = std::path::Path::new(&rest[2]).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(error) = std::fs::write(&rest[2], rendered) {
                eprintln!("conform bless: cannot write {}: {error}", rest[2]);
                exit(1);
            }
            println!("blessed {} -> {}", rest[0], rest[2]);
        }
        "header" => {
            need(rest, 1, "header");
            let header = expectation_from(&rest[0]).header;
            println!("probe={}", header.probe);
            println!("os={}", header.os);
            println!("arch={}", header.arch);
            println!("kernel={}", header.kernel);
            println!("glibc={}", header.glibc);
            println!("virtual_abi={}", header.virtual_abi);
        }
        "frozen-paths" | "obligations" => {
            let list_paths = command == "frozen-paths";
            if rest.len() != if list_paths { 2 } else { 3 } && rest.len() != 4 {
                need(rest, if list_paths { 2 } else { 3 }, command);
            }
            let frozen = match load_frozen(&read(&rest[0])) {
                Ok(frozen) => frozen,
                Err(error) => {
                    eprintln!("conform {command}: {error}");
                    exit(1)
                }
            };
            let Some(family) = frozen.family.get(&rest[1]) else {
                eprintln!(
                    "conform {command}: {} freezes no family {:?}",
                    rest[0], rest[1]
                );
                exit(1)
            };
            if list_paths {
                for path in &family.paths {
                    println!("{path}");
                }
                return;
            }
            match (rest[2].as_str(), rest.get(3)) {
                ("unit-tests", None) => {
                    for o in family.obligation.iter().filter(|o| o.kind == "unit-test") {
                        println!(
                            "{}\t{}",
                            o.krate.as_deref().unwrap_or(""),
                            o.test.as_deref().unwrap_or("")
                        );
                    }
                }
                ("traces", Some(path)) => {
                    let unmet =
                        check_trace_obligations(&family.obligation, std::path::Path::new(path));
                    for line in &unmet {
                        println!("{line}");
                    }
                    if !unmet.is_empty() {
                        exit(1);
                    }
                }
                _ => {
                    eprintln!("conform obligations: bad arguments\n{}", usage());
                    exit(2)
                }
            }
        }
        "termination-of" => {
            if rest.len() == 2 && rest[1] == "full" {
                let events = match parse_stream(&read(&rest[0])) {
                    Ok(events) => events,
                    Err(error) => {
                        eprintln!("conform termination-of: {}: {error}", rest[0]);
                        exit(1)
                    }
                };
                match events.last().and_then(Termination::from_event) {
                    Some(termination) => println!("{}", termination.describe()),
                    None => {
                        eprintln!("conform termination-of: {}: no termination line", rest[0]);
                        exit(1)
                    }
                }
                return;
            }
            need(rest, 1, "termination-of");
            let events = match parse_stream(&read(&rest[0])) {
                Ok(events) => events,
                Err(error) => {
                    eprintln!("conform termination-of: {}: {error}", rest[0]);
                    exit(1)
                }
            };
            let stream = syscall_conformance::expect::Expectation {
                header: Header {
                    schema: SCHEMA.to_string(),
                    probe: String::new(),
                    os: String::new(),
                    arch: String::new(),
                    kernel: String::new(),
                    glibc: String::new(),
                    virtual_abi: String::new(),
                },
                events,
            };
            match blessed_termination(&stream) {
                Ok(Termination::Exited(code)) => println!("exited {code}"),
                Ok(Termination::Signaled { signal, .. }) => println!("signaled {signal}"),
                Ok(other) => println!("{}", other.describe()),
                Err(error) => {
                    eprintln!("conform termination-of: {}: {error}", rest[0]);
                    exit(1)
                }
            }
        }
        "diff" => {
            if rest.len() != 6 && rest.len() != 7 {
                need(rest, 6, "diff");
            }
            let Some(mode) = Mode::parse(&rest[0]) else {
                eprintln!(
                    "conform diff: mode must be native or patina, not {:?}",
                    rest[0]
                );
                exit(2)
            };
            let expected = expectation_from(&rest[3]);
            if expected.header.probe != rest[1] {
                eprintln!(
                    "conform diff: {} was blessed for probe {:?}, not {:?}",
                    rest[3], expected.header.probe, rest[1]
                );
                exit(1);
            }
            let actual = match parse_stream(&read(&rest[4])) {
                Ok(events) => events,
                Err(error) => {
                    eprintln!("conform diff: {}: {error}", rest[4]);
                    exit(1)
                }
            };
            let divergences = divergences_from(&rest[5]);
            let stderr = rest
                .get(6)
                .map(|path| std::fs::read_to_string(path).unwrap_or_default());
            let outcome = diff(
                mode,
                &rest[1],
                &rest[2],
                &expected,
                actual,
                &divergences,
                stderr.as_deref(),
            );
            for line in &outcome.lines {
                println!("{line}");
            }
            if !outcome.ok {
                exit(1);
            }
        }
        "host-check" => {
            need(rest, 6, "host-check");
            let manifest = manifest_from(&rest[1]);
            let (registry, references) = checked_registry(&manifest, &rest[2], &rest[5]);
            let expected = expectation_from(&rest[3]);
            match host_gate(
                &manifest,
                &registry,
                &references,
                &rest[0],
                &expected.header,
                &rest[4],
            ) {
                HostGate::Ok => println!("ok"),
                HostGate::Unavailable(reason) => {
                    println!("host-unavailable: {reason}");
                    exit(EXIT_HOST_UNAVAILABLE);
                }
                HostGate::TooOld(reason) => {
                    println!("FAIL: {reason}");
                    exit(1);
                }
                HostGate::Error(reason) => {
                    println!("FAIL: {reason}");
                    exit(1);
                }
            }
        }
        "declared-failing" => {
            need(rest, 3, "declared-failing");
            let divergences = divergences_from(&rest[2]);
            match declared_failing(&divergences, &rest[0], &rest[1]) {
                Some(divergence) => println!("{}", divergence.describe()),
                None => exit(EXIT_NOT_DECLARED),
            }
        }
        "gate" => {
            need(rest, 3, "gate");
            let frozen = match load_frozen(&read(&rest[0])) {
                Ok(frozen) => frozen,
                Err(error) => {
                    eprintln!("conform gate: {error}");
                    exit(1)
                }
            };
            let divergences = divergences_from(&rest[1]);
            let Some(family) = frozen.family.get(&rest[2]) else {
                eprintln!("conform gate: {} freezes no family {:?}", rest[0], rest[2]);
                exit(1)
            };
            let violations = gate_declarations(family, &divergences);
            for violation in &violations {
                println!("{violation}");
            }
            if !violations.is_empty() {
                exit(1);
            }
        }
        "selftest" => {
            need(rest, 0, "selftest");
            let outcome = selftest();
            for line in &outcome.lines {
                println!("{line}");
            }
            if !outcome.ok {
                println!("conform selftest: FAILED — a planted failure was not refused");
                exit(1);
            }
            println!("conform selftest: every planted failure refused, every control passed");
        }
        other => {
            eprintln!("conform: unknown subcommand {other:?}\n{}", usage());
            exit(2)
        }
    }
}
