//! `conform` — the harness half of the syscall-conformance testbed, driven by
//! `run.sh`. Every subcommand takes positional arguments (so the flag-drift gate
//! sees no flag tokens for it) and reports on stdout; exit codes are the
//! contract: 0 ok, 1 gate failed / error, 2 usage, 5 host-unavailable.

use std::process::exit;
use syscall_conformance::expect::{
    declared_failing, diff, host_gate, load_divergences, load_manifest, normalize,
    parse_expectation, render_expectation, selftest, Header, HostGate, Mode, SCHEMA,
};
use syscall_conformance::observe::parse_stream;

const EXIT_HOST_UNAVAILABLE: i32 = 5;
const EXIT_NOT_DECLARED: i32 = 6;

fn usage() -> String {
    format!(
        "usage: conform <subcommand> ARGS…\n\
         \n\
         abi        PROBES_TOML                                   print the virtual ABI level\n\
         list       PROBES_TOML                                   print every probe id\n\
         bless      PROBE RAW_JSONL OUT_JSONL OS ARCH KERNEL GLIBC PROBES_TOML\n\
                                                                  normalize RAW and write OUT with a blessing header\n\
         header     EXPECTED_JSONL                                print the blessing header as key=value lines\n\
         diff       native|patina PROBE VEHICLE EXPECTED_JSONL ACTUAL_JSONL DIVERGENCES_TOML ok|failed\n\
                                                                  compare ACTUAL (raw) with EXPECTED; exit 1 on any\n\
                                                                  undeclared or stale divergence, count drift, or a\n\
                                                                  failed probe\n\
         host-check PROBE PROBES_TOML EXPECTED_JSONL HOST_KERNEL   exit 0 usable, {EXIT_HOST_UNAVAILABLE} host-unavailable, 1 host older\n\
                                                                  than the blessing kernel\n\
         selftest                                                 prove every differ/host gate can fail (exit 1 if any\n\
                                                                  planted failure is not refused)\n\
         declared-failing PROBE VEHICLE DIVERGENCES_TOML          exit 0 (and print the reason) when the probe is declared\n\
                                                                  failing under patina for that vehicle, {EXIT_NOT_DECLARED} otherwise\n\
         \n\
         Schema {SCHEMA}."
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

fn expectation_from(path: &str) -> syscall_conformance::expect::Expectation {
    match parse_expectation(&read(path)) {
        Ok(expectation) => expectation,
        Err(error) => {
            eprintln!("conform: {path}: {error}");
            exit(1)
        }
    }
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
            println!("{}", manifest_from(&rest[0]).abi.virtual_level);
        }
        "list" => {
            need(rest, 1, "list");
            for id in manifest_from(&rest[0]).probe.keys() {
                println!("{id}");
            }
        }
        "bless" => {
            need(rest, 8, "bless");
            let manifest = manifest_from(&rest[7]);
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
            if raw.is_empty() {
                eprintln!(
                    "conform bless: {} carries no events; refusing to bless a vacuous stream",
                    rest[1]
                );
                exit(1);
            }
            let header = Header {
                schema: SCHEMA.to_string(),
                probe: rest[0].clone(),
                os: rest[3].clone(),
                arch: rest[4].clone(),
                kernel: rest[5].clone(),
                glibc: rest[6].clone(),
                virtual_abi: manifest.abi.virtual_level,
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
        "diff" => {
            need(rest, 7, "diff");
            let Some(mode) = Mode::parse(&rest[0]) else {
                eprintln!(
                    "conform diff: mode must be native or patina, not {:?}",
                    rest[0]
                );
                exit(2)
            };
            let probe_ok = match rest[6].as_str() {
                "ok" => true,
                "failed" => false,
                other => {
                    eprintln!("conform diff: probe status must be ok or failed, not {other:?}");
                    exit(2)
                }
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
            let divergences = match load_divergences(&read(&rest[5])) {
                Ok(divergences) => divergences,
                Err(error) => {
                    eprintln!("conform diff: {error}");
                    exit(1)
                }
            };
            let outcome = diff(
                mode,
                &rest[1],
                &rest[2],
                &expected,
                actual,
                &divergences,
                probe_ok,
            );
            for line in &outcome.lines {
                println!("{line}");
            }
            if !outcome.ok {
                exit(1);
            }
        }
        "host-check" => {
            need(rest, 4, "host-check");
            let manifest = manifest_from(&rest[1]);
            let expected = expectation_from(&rest[2]);
            match host_gate(&manifest, &rest[0], &expected.header, &rest[3]) {
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
            let divergences = match load_divergences(&read(&rest[2])) {
                Ok(divergences) => divergences,
                Err(error) => {
                    eprintln!("conform declared-failing: {error}");
                    exit(1)
                }
            };
            match declared_failing(&divergences, &rest[0], &rest[1]) {
                Some(divergence) => println!("{}", divergence.describe()),
                None => exit(EXIT_NOT_DECLARED),
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
