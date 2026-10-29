//! Native guest builds, output assertions, and kernel capability probes.
pub use super::assert_success;
use super::{invoke_with_deadline, native_workspace};
use object::{Object, ObjectSymbol};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::time::Duration;
use tempfile::TempDir;

/// Decode the UTF-8 text emitted by an acceptance guest.
pub fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).expect("UTF-8 guest output")
}

/// Require failure and every named diagnostic.
pub fn assert_refused(output: Output, diagnostics: &[&str]) -> Output {
    assert!(
        !output.status.success(),
        "unexpected success: {}",
        text(&output.stdout)
    );
    let diagnostic = format!("{}{}", text(&output.stdout), text(&output.stderr));
    for expected in diagnostics {
        assert!(
            diagnostic.contains(expected),
            "missing {expected:?}: {diagnostic}"
        );
    }
    output
}

/// Require exactly one prefixed line and return its payload.
pub fn assert_unique_line_payload<'a>(output: &'a [u8], prefix: &str) -> &'a str {
    let mut matches = text(output)
        .lines()
        .filter_map(|line| line.strip_prefix(prefix));
    let suffix = matches
        .next()
        .unwrap_or_else(|| panic!("missing {prefix:?}: {}", text(output)));
    assert!(
        matches.next().is_none(),
        "duplicate {prefix:?}: {}",
        text(output)
    );
    suffix
}

/// Require the exact key set, unique keys, and key=value syntax.
pub fn assert_fields<'a>(
    output: &'a [u8],
    prefix: &str,
    keys: &[&str],
) -> BTreeMap<&'a str, &'a str> {
    let mut fields = BTreeMap::new();
    for field in assert_unique_line_payload(output, prefix).split_whitespace() {
        let (key, value) = field.split_once('=').expect("key=value field");
        assert!(
            !key.is_empty() && !value.is_empty(),
            "empty key/value: {field}"
        );
        assert!(fields.insert(key, value).is_none(), "duplicate key: {key}");
    }
    assert_eq!(
        fields.keys().copied().collect::<BTreeSet<_>>(),
        keys.iter().copied().collect()
    );
    fields
}

/// Require an entire output line to match, not merely a substring.
pub fn assert_exact_line(output: &[u8], expected: &str) {
    assert!(
        text(output).lines().any(|line| line == expected),
        "missing {expected:?}: {}",
        text(output)
    );
}

/// Require the exact width and lowercase hexadecimal alphabet.
pub fn assert_lower_hex(value: &str, len: usize) {
    assert_eq!(value.len(), len, "hex width: {value}");
    assert!(
        value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "lowercase hex: {value}"
    );
}

/// Parse the guest's bracketed, comma-separated thread IDs, not JSON.
pub fn assert_thread_ids(output: &[u8], prefix: &str) -> Vec<usize> {
    let value = assert_unique_line_payload(output, prefix);
    let ids = value
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .expect("bracketed thread IDs");
    ids.split(',')
        .map(|id| id.trim().parse().expect("integer thread ID"))
        .collect()
}

/// Require each worker ID to occur exactly the expected number of times.
pub fn assert_thread_counts(
    ids: impl IntoIterator<Item = usize>,
    workers: usize,
    per_worker: usize,
) {
    let mut counts = vec![0; workers];
    for id in ids {
        *counts.get_mut(id).expect("thread ID in range") += 1;
    }
    assert_eq!(counts, vec![per_worker; workers]);
}

/// Locate a checked-in acceptance guest source or package directory.
pub fn guest_source(name: &str) -> PathBuf {
    native_workspace()
        .join("testbeds/native-boundary")
        .join(name)
}

/// The stdout of a single-file Rust testbed built with plain `rustc` and run
/// natively, without Patina: the oracle its Patina run must match.
#[allow(dead_code)]
pub fn native_stdout(name: &str) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("native");
    let built = std::process::Command::new("rustc")
        .args(["-O", "--edition", "2024", "-o"])
        .arg(&binary)
        .arg(guest_source(name))
        .output()
        .unwrap();
    assert!(built.status.success(), "{}", text(&built.stderr));
    let output = std::process::Command::new(&binary).output().unwrap();
    assert!(output.status.success(), "{}", text(&output.stderr));
    output.stdout
}

/// Built binary and scratch directory kept alive for a test's lifetime.
pub struct Guest {
    pub dir: TempDir,
    pub binary: PathBuf,
}

impl Guest {
    /// Require a successful build with the product's default configuration.
    pub fn assert_build(name: &str) -> Self {
        Self::assert_build_with(name, &[])
    }

    /// Require a successful build, staging package artifacts outside the sources.
    pub fn assert_build_with(name: &str, flags: &[&str]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("guest");
        let source = guest_source(name);
        let target = super::guest_target_dir(name);
        let mut args = vec![
            "build",
            source.to_str().unwrap(),
            "--output",
            binary.to_str().unwrap(),
        ];
        args.extend_from_slice(flags);
        if source.is_dir() {
            super::invoke_in_with_env(
                native_workspace(),
                &args,
                &[("CARGO_TARGET_DIR", target.to_str().unwrap())],
            );
        } else {
            super::invoke(native_workspace(), &args);
        }
        Self { dir, binary }
    }

    /// Invoke a verb with a deadline, leaving exit-status assertions to the caller.
    pub fn command(&self, verb: &str, args: &[&str]) -> Output {
        let mut argv = vec![verb, self.binary.to_str().unwrap()];
        argv.extend_from_slice(args);
        invoke_with_deadline(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &argv,
            Duration::from_secs(60),
        )
        .expect("native command exceeded 60s")
    }

    /// Require a clean audit without any guest-specific allowances.
    pub fn assert_audit_clean(&self) -> Output {
        assert_success(self.command("audit", &[]))
    }

    /// Require a successful, deterministic seeded run with the supplied
    /// configuration, and return its output. Every run a test requires to
    /// succeed is checked here, so no test repeats the check: a plain seeded
    /// run and a recorded run of the same seed must print the same stdout and
    /// guest stderr (the seed alone decides the run, recording included), and
    /// a flag-free replay of the recording must print them again.
    pub fn assert_run_success(&self, seed: u64, flags: &[&str]) -> Output {
        self.assert_recorded(seed, flags).0
    }

    /// [`assert_run_success`](Self::assert_run_success), returning the
    /// recorded run's output and the path of its trace.
    pub fn assert_recorded(&self, seed: u64, flags: &[&str]) -> (Output, PathBuf) {
        static RUNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let run = RUNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let seed = seed.to_string();
        let trace = self.dir.path().join(format!("run-{run}.patina"));
        let mut seeded = vec!["--seed", &seed];
        seeded.extend_from_slice(flags);
        let plain = assert_success(self.command("run", &seeded));
        // Patina's own flags go before a `--` that starts the guest's.
        let split = flags
            .iter()
            .position(|flag| *flag == "--")
            .unwrap_or(flags.len());
        let mut record = vec!["--seed", &seed];
        record.extend_from_slice(&flags[..split]);
        record.extend(["--record", trace.to_str().unwrap()]);
        record.extend_from_slice(&flags[split..]);
        let recorded = assert_success(self.command("run", &record));
        assert_same_guest_output(&plain, &recorded, "seeded and recorded runs");
        let replay = assert_success(self.command("replay", &[trace.to_str().unwrap()]));
        assert_same_guest_output(&recorded, &replay, "recorded run and its replay");
        (recorded, trace)
    }

    /// Require a failed seeded run and every named diagnostic.
    pub fn assert_run_refused(&self, seed: u64, diagnostics: &[&str]) -> Output {
        assert_refused(
            self.command("run", &["--seed", &seed.to_string()]),
            diagnostics,
        )
    }

    /// Require at least two distinct outputs among the supplied seeds, each
    /// from one plain seeded run.
    pub fn assert_seed_variation(&self, seeds: &[u64], flags: &[&str]) {
        let outputs: BTreeSet<_> = seeds
            .iter()
            .map(|seed| {
                let seed = seed.to_string();
                let mut args = vec!["--seed", &seed];
                args.extend_from_slice(flags);
                assert_success(self.command("run", &args)).stdout
            })
            .collect();
        assert!(outputs.len() >= 2, "output did not vary across {seeds:?}");
    }

    /// Require that no undefined symbol contains any of the given names.
    pub fn assert_no_imports(&self, names: &[&str]) {
        let bytes = std::fs::read(&self.binary).unwrap();
        let file = object::File::parse(bytes.as_slice()).unwrap();
        for sym in file
            .symbols()
            .chain(file.dynamic_symbols())
            .filter(|sym| sym.is_undefined())
        {
            let name = sym.name().unwrap();
            for denied in names {
                assert!(
                    !name.contains(denied),
                    "interposer leaked as an import: {name}"
                );
            }
        }
    }
    /// Record a direct POSIX guest through an inherited host fd, not a guest FS open.
    pub fn record_standalone(&self, args: &[&str]) -> (Output, PathBuf) {
        let trace = self.dir.path().join("standalone.patina");
        let mut command = Command::new("/bin/sh");
        command
            .env_clear()
            .args(["-c", "exec 3>\"$1\"; shift; exec \"$@\"", "native-boundary"])
            .arg(&trace)
            .arg(&self.binary)
            .args(args)
            .envs([
                ("PATINA_RT_MODE", "record"),
                ("PATINA_RT_SEED", "1"),
                ("PATINA_RT_TRACE_FD", "3"),
                ("PATINA_RT_FINGERPRINT", "native-boundary"),
            ]);
        let output = super::output_with_deadline(&mut command, Duration::from_secs(20))
            .expect("recorded standalone guest exceeded 20s");
        (output, trace)
    }

    /// Replay a [`record_standalone`](Self::record_standalone) trace the same way,
    /// through an inherited host fd. A standalone recording carries no native
    /// build identity, so `cargo patina replay` refuses it.
    pub fn replay_standalone(&self, trace: &Path, args: &[&str]) -> Output {
        let mut command = Command::new("/bin/sh");
        command
            .env_clear()
            .args(["-c", "exec 3<\"$1\"; shift; exec \"$@\"", "native-boundary"])
            .arg(trace)
            .arg(&self.binary)
            .args(args)
            .envs([
                ("PATINA_RT_MODE", "replay"),
                ("PATINA_RT_SEED", "1"),
                ("PATINA_RT_TRACE_FD", "3"),
                ("PATINA_RT_FINGERPRINT", "native-boundary"),
            ]);
        super::output_with_deadline(&mut command, Duration::from_secs(20))
            .expect("replayed standalone guest exceeded 20s")
    }

    /// Internal containment refusals must abort without publishing a complete trace.
    pub fn assert_internal_fatal(&self, args: &[&str], diagnostics: &[&str]) {
        use std::os::unix::process::ExitStatusExt;
        let (output, trace) = self.record_standalone(args);
        let output = assert_refused(output, diagnostics);
        assert_eq!(output.status.signal(), Some(6), "{}", text(&output.stderr));
        assert!(
            patina_dst_trace::TraceBundle::load(&trace).is_err(),
            "internal fatal must not finalize an invalid trace"
        );
    }
}

/// Require the same stdout and the same guest stderr. Patina's own stderr
/// lines (`patina` and `PATINA_` prefixed) say which mode ran, so they are
/// left out of the comparison.
fn assert_same_guest_output(left: &Output, right: &Output, what: &str) {
    assert!(
        left.stdout == right.stdout,
        "{what}: stdout differs:\n{}\n---\n{}",
        String::from_utf8_lossy(&left.stdout),
        String::from_utf8_lossy(&right.stdout)
    );
    let guest_stderr = |output: &Output| -> Vec<u8> {
        output
            .stderr
            .split_inclusive(|byte| *byte == b'\n')
            .filter(|line| !line.starts_with(b"patina") && !line.starts_with(b"PATINA_"))
            .flatten()
            .copied()
            .collect()
    };
    assert!(
        guest_stderr(left) == guest_stderr(right),
        "{what}: guest stderr differs:\n{}\n---\n{}",
        String::from_utf8_lossy(&left.stderr),
        String::from_utf8_lossy(&right.stderr)
    );
}

/// Mutually exclusive linkage contracts for a direct C guest.
pub enum CLink {
    Unlinked,
    Shim,
    PosixShim,
    /// Force the SUD-unavailable startup branch, without changing TSC support.
    PosixShimWithoutSud,
    /// The POSIX layer over a shim built with `planted-faults`.
    PosixShimPlanted,
}

/// Compile a C guest with an explicit linkage contract.
pub fn assert_build_c_guest(name: &str, link: CLink) -> Guest {
    assert_build_c_guest_with_flags(name, link, &[])
}

/// Supply linker/compiler flags for a C guest without changing other probes.
pub fn assert_build_c_guest_with_flags(name: &str, link: CLink, flags: &[&str]) -> Guest {
    let mut cc = super::c_compiler();
    cc.args(["-std=c11", "-D_POSIX_C_SOURCE=200809L"]);
    build_native_guest(cc, name, link, flags)
}

/// Compile a C++ guest over the POSIX layer, linking the system's shared
/// libstdc++ as a C++ program ordinarily does.
pub fn assert_build_cxx_guest(name: &str) -> Guest {
    let mut cxx = Command::new(std::env::var("CXX").unwrap_or_else(|_| "c++".into()));
    cxx.arg("-std=c++17");
    build_native_guest(cxx, name, CLink::PosixShim, &[])
}

/// Compile a native-boundary C source as a shared library in `dir`, for a
/// guest to link against; returns its path.
pub fn assert_build_c_library(name: &str, dir: &Path) -> PathBuf {
    let stem = Path::new(name).file_stem().unwrap().to_str().unwrap();
    let library = dir.join(format!("lib{stem}.so"));
    assert_success(
        super::c_compiler()
            .args([
                "-std=c11", "-O2", "-fPIC", "-shared", "-Wall", "-Wextra", "-Werror",
            ])
            .arg(guest_source(name))
            .arg("-o")
            .arg(&library)
            .output()
            .unwrap(),
    );
    library
}

fn build_native_guest(mut cc: Command, name: &str, link: CLink, flags: &[&str]) -> Guest {
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("c-guest");
    cc.args(["-Wall", "-Wextra", "-Werror"])
        .arg("-I")
        .arg(native_workspace().join("crates/patina-native-shim/include"))
        .arg(guest_source(name));
    let variant = match link {
        CLink::Unlinked => "unlinked",
        CLink::Shim => "shim",
        CLink::PosixShim => "posix",
        CLink::PosixShimWithoutSud => "posix-without-sud",
        CLink::PosixShimPlanted => "posix-planted",
    };
    let stage = |cc: &mut Command| {
        static ARCHIVE: OnceLock<PathBuf> = OnceLock::new();
        match link {
            CLink::Unlinked => {}
            CLink::Shim => {
                static PREFIXED: OnceLock<PathBuf> = OnceLock::new();
                cc.arg(PREFIXED.get_or_init(super::prefixed_shim_archive));
            }
            CLink::PosixShimPlanted => {
                // The planted reentry is a raw system call in the engine,
                // which the seal refuses by design: linked unsealed.
                static PLANTED: OnceLock<PathBuf> = OnceLock::new();
                static POSIX: OnceLock<(TempDir, PathBuf)> = OnceLock::new();
                let archive = PLANTED.get_or_init(|| super::shim_archive_with(&["planted-faults"]));
                let (_, object) = POSIX.get_or_init(|| {
                    let dir = tempfile::tempdir().unwrap();
                    let object = super::compile_posix_object(dir.path());
                    (dir, object)
                });
                cc.arg(object)
                    .arg(archive)
                    .args(super::shim_linker_args(archive, dir.path()));
            }
            CLink::PosixShim | CLink::PosixShimWithoutSud => {
                // Sealed as `cargo patina build` seals: the façade and the
                // engine in place of the POSIX object and the archive.
                let archive = ARCHIVE.get_or_init(super::shim_archive);
                let seams: &[&str] = match link {
                    CLink::PosixShimWithoutSud => &["-DPATINA_TEST_NO_SUD"],
                    _ => &[],
                };
                cc.args(super::sealed_shim(variant, archive, seams))
                    .args(super::shim_linker_args(archive, dir.path()));
            }
        }
        cc.args(flags);
    };
    link_once_per_run(cc, variant, flags, &binary, stage);
    Guest { dir, binary }
}

/// Run `cc`, a compile and link of one executable, after `stage` adds the
/// link inputs, with `-o output`; or reuse the executable the same build
/// linked earlier in this nextest run.
///
/// Linking a guest against the shim archive is most of a C guest's build, and
/// many tests build the same guest. Within one run no input of a link
/// changes, so the build is identified by what it is asked for: the compiler
/// command before staging (its program, working directory, environment and
/// arguments, a file argument also by its bytes), the linkage `variant`, the
/// extra `flags` and the output's file name. Staging writes the per-test link
/// inputs (the POSIX layer and allocator routing objects, the shim archive is
/// shared) and is skipped on reuse. A build outside nextest links afresh.
fn link_once_per_run(
    mut cc: Command,
    variant: &str,
    flags: &[&str],
    output: &Path,
    stage: impl FnOnce(&mut Command),
) {
    if std::env::var_os("NEXTEST_RUN_ID").is_none() {
        stage(&mut cc);
        assert_success(cc.arg("-o").arg(output).output().unwrap());
        return;
    }
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    let mut field = |bytes: &[u8]| {
        sha2::Digest::update(&mut hasher, (bytes.len() as u64).to_le_bytes());
        sha2::Digest::update(&mut hasher, bytes);
    };
    field(cc.get_program().as_encoded_bytes());
    field(
        cc.get_current_dir()
            .map_or(&b""[..], |dir| dir.as_os_str().as_encoded_bytes()),
    );
    for (name, value) in cc.get_envs() {
        field(name.as_encoded_bytes());
        field(value.map_or(&b"\0unset"[..], |value| value.as_encoded_bytes()));
    }
    for arg in cc.get_args() {
        field(arg.as_encoded_bytes());
        if let Ok(bytes) = std::fs::read(arg) {
            field(&bytes);
        }
    }
    field(variant.as_bytes());
    for flag in flags {
        field(flag.as_bytes());
    }
    // The macOS linker signs an executable under its file name.
    field(output.file_name().unwrap().as_encoded_bytes());
    let key: String = sha2::Digest::finalize(hasher)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let linked = super::once_per_run(&format!("c-guest-{key}"), || {
        let dir = super::guest_target_dir("c-guests").join(&key);
        // Link beside the published path under the same file name, then
        // rename it over that path.
        let partial = dir.join("partial").join(output.file_name().unwrap());
        std::fs::create_dir_all(partial.parent().unwrap()).unwrap();
        stage(&mut cc);
        assert_success(cc.arg("-o").arg(&partial).output().unwrap());
        let linked = dir.join(output.file_name().unwrap());
        std::fs::rename(&partial, &linked).unwrap();
        vec![linked]
    });
    std::fs::copy(&linked[0], output).unwrap();
}

/// Run a direct C guest with only the explicitly supplied host environment.
pub fn assert_standalone_success(binary: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    assert_success(standalone_output(binary, args, env))
}

/// Diagnostics required when raw execution cannot be contained by SUD.
pub const SUD_REFUSAL_DIAGNOSTICS: &[&str] = &["lacks syscall-user-dispatch", "direct-syscall"];

/// Kernel mechanisms whose live support controls platform-specific assertions.
pub enum KernelFeature {
    Sud,
    Tsc,
}

/// Cache each live capability probe; compile failures and abnormal exits are fatal.
pub fn kernel_supports(feature: KernelFeature) -> bool {
    static SUD: OnceLock<bool> = OnceLock::new();
    static TSC: OnceLock<bool> = OnceLock::new();
    let (cached, source) = match feature {
        KernelFeature::Sud => (&SUD, "sud_support.c"),
        KernelFeature::Tsc => (&TSC, "tsc_support.c"),
    };
    let supported = *cached.get_or_init(|| {
        let probe = assert_build_c_guest(source, CLink::Unlinked);
        let result = Command::new(&probe.binary).output().unwrap();
        match result.status.code() {
            Some(0) => true,
            Some(1) => false,
            _ => panic!("capability probe crashed: {result:?}"),
        }
    });
    // x86_64 Linux has had SUD since 5.11; its absence there is a broken host.
    assert!(
        supported
            || !matches!(feature, KernelFeature::Sud)
            || !cfg!(all(target_os = "linux", target_arch = "x86_64")),
        "the host lacks syscall-user-dispatch"
    );
    supported
}

/// Run a direct guest with an explicit environment and a bounded process group.
pub fn standalone_output(binary: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    super::output_with_deadline(
        Command::new(binary)
            .env_clear()
            .args(args)
            .envs(env.iter().copied()),
        Duration::from_secs(20),
    )
    .expect("standalone guest exceeded 20s")
}

/// Build a SUD-only C boundary probe, reporting missing runtime evidence explicitly.
// Bypass libtest capture: missing evidence must remain visible even on success.
#[allow(clippy::explicit_write)]
pub fn sud_c_guest(name: &str) -> Option<Guest> {
    if !kernel_supports(KernelFeature::Sud) {
        use std::io::Write;
        writeln!(
            std::io::stderr(),
            "SKIPPED {name}: host lacks syscall-user-dispatch"
        )
        .unwrap();
        return None;
    }
    Some(assert_build_c_guest(name, CLink::PosixShim))
}

/// A seed whose crash, at `permille`, follows the run's `index`th successful
/// crash point (0-based), and the next `count - 1` such seeds after it. A
/// crash point draws from the run's own crash stream and nothing else does,
/// so where the crash lands is a function of the seed and the rate alone; the
/// guest decides which operation that index is (see [`crash_point_index`]).
pub fn crash_seeds(permille: u16, index: usize, count: usize) -> Vec<u64> {
    use patina_dst_rng_seeded::{SplitMix64, domain_seed, fault_domain};
    (0..)
        .filter(|seed| {
            let mut rng = SplitMix64::new(domain_seed(*seed, fault_domain::CRASH_POINT));
            (0..=index)
                .map(|_| rng.next_u64() % 1000 < u64::from(permille))
                .position(|hit| hit)
                == Some(index)
        })
        .take(count)
        .collect()
}

/// A rate under which a crash at crash point `index` is a likely draw.
pub fn crash_permille_for(index: usize) -> u16 {
    (1000 / (index + 1)).max(1) as u16
}

/// The index, among a crash-free recording's successful crash points, of the
/// `nth` (0-based) operation `matches` selects: where a crash that should
/// follow that operation must land.
pub fn crash_point_index(
    trace: &Path,
    nth: usize,
    matches: impl Fn(&patina_dst_abi::Operation) -> bool,
) -> usize {
    let bundle = patina_dst_trace::TraceBundle::load(trace).unwrap();
    let points: Vec<_> = bundle.timelines[0]
        .decisions
        .iter()
        .filter(|event| event.operation.is_crash_point(&event.outcome))
        .collect();
    points
        .iter()
        .enumerate()
        .filter(|(_, event)| matches(&event.operation))
        .nth(nth)
        .unwrap_or_else(|| panic!("the recording has no crash point number {nth} that matches"))
        .0
}
