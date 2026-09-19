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
        let target = super::profile_dir()
            .parent()
            .expect("profile has a target base")
            .join("native-guests")
            .join(name);
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

    /// Require a successful seeded run with the supplied configuration.
    pub fn assert_run_success(&self, seed: u64, flags: &[&str]) -> Output {
        let seed = seed.to_string();
        let mut args = vec!["--seed", &seed];
        args.extend_from_slice(flags);
        assert_success(self.command("run", &args))
    }

    /// Require a failed seeded run and every named diagnostic.
    pub fn assert_run_refused(&self, seed: u64, diagnostics: &[&str]) -> Output {
        assert_refused(
            self.command("run", &["--seed", &seed.to_string()]),
            diagnostics,
        )
    }

    /// Require byte-identical stdout across at least two runs of one seed.
    pub fn assert_seed_repeatability(&self, seed: u64, count: usize, flags: &[&str]) -> Vec<u8> {
        assert!(count >= 2, "a determinism check needs two runs");
        let first = self.assert_run_success(seed, flags).stdout;
        for _ in 1..count {
            assert_eq!(
                first,
                self.assert_run_success(seed, flags).stdout,
                "same-seed stdout"
            );
        }
        first
    }

    /// Require at least two distinct outputs among the supplied seeds.
    pub fn assert_seed_variation(&self, seeds: &[u64], flags: &[&str]) {
        let outputs: BTreeSet<_> = seeds
            .iter()
            .map(|seed| self.assert_run_success(*seed, flags).stdout)
            .collect();
        assert!(outputs.len() >= 2, "output did not vary across {seeds:?}");
    }

    /// Require repeatability plus full stdout/trace identity and fingerprint refusal.
    pub fn assert_seeded_record_replay_identity(&self, seed: u64, flags: &[&str]) -> Vec<u8> {
        let baseline = self.assert_seed_repeatability(seed, 2, flags);
        self.assert_record_replay_identity(seed, flags, &baseline);
        baseline
    }

    /// Compare two records and flag-free replay with a checked run; return the trace path.
    pub fn assert_record_replay_identity(
        &self,
        seed: u64,
        flags: &[&str],
        baseline: &[u8],
    ) -> PathBuf {
        let trace = self.dir.path().join("run.patina");
        let repeat = self.dir.path().join("repeat.patina");
        for path in [&trace, &repeat] {
            let mut args = flags.to_vec();
            args.extend([
                "--record",
                path.to_str().unwrap(),
                "--fingerprint",
                "native-boundary-v1",
            ]);
            assert_eq!(
                baseline,
                self.assert_run_success(seed, &args).stdout,
                "seeded vs record stdout"
            );
        }
        assert_eq!(
            std::fs::read(&trace).unwrap(),
            std::fs::read(&repeat).unwrap(),
            "record trace identity"
        );
        let replay = assert_success(self.command(
            "replay",
            &[
                trace.to_str().unwrap(),
                "--fingerprint",
                "native-boundary-v1",
            ],
        ));
        assert_eq!(baseline, replay.stdout, "record/replay stdout identity");
        assert_refused(
            self.command(
                "replay",
                &[trace.to_str().unwrap(), "--fingerprint", "different"],
            ),
            &["fingerprint"],
        );
        trace
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
                ("PATINA_MODE", "record"),
                ("PATINA_SEED", "1"),
                ("PATINA_TRACE_FD", "3"),
                ("PATINA_FINGERPRINT", "native-boundary"),
            ]);
        let output = super::output_with_deadline(&mut command, Duration::from_secs(20))
            .expect("recorded standalone guest exceeded 20s");
        (output, trace)
    }

    /// Internal containment refusals must abort without publishing a complete trace.
    #[cfg(target_os = "linux")]
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

/// Mutually exclusive linkage contracts for a direct C guest.
pub enum CLink {
    Unlinked,
    Shim,
    PosixShim,
}

/// Compile a C guest with an explicit linkage contract.
pub fn assert_build_c_guest(name: &str, link: CLink) -> Guest {
    static ARCHIVE: OnceLock<PathBuf> = OnceLock::new();
    static POSIX: OnceLock<(TempDir, PathBuf)> = OnceLock::new();
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("c-guest");
    let mut cc = super::c_compiler();
    cc.args([
        "-std=c11",
        "-D_POSIX_C_SOURCE=200809L",
        "-Wall",
        "-Wextra",
        "-Werror",
    ])
    .arg("-I")
    .arg(native_workspace().join("crates/patina-native-shim/include"))
    .arg(guest_source(name));
    match link {
        CLink::Unlinked => {}
        CLink::Shim => {
            cc.arg(ARCHIVE.get_or_init(super::shim_archive));
        }
        CLink::PosixShim => {
            let (_, object) = POSIX.get_or_init(|| {
                let dir = tempfile::tempdir().unwrap();
                let obj = super::compile_posix_object(dir.path());
                (dir, obj)
            });
            cc.arg(object).arg(ARCHIVE.get_or_init(super::shim_archive));
            if cfg!(target_os = "linux") {
                cc.arg("-Wl,--wrap=dlsym");
            }
        }
    }
    assert_success(cc.arg("-o").arg(&binary).output().unwrap());
    Guest { dir, binary }
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
    if matches!(feature, KernelFeature::Sud) {
        assert_required_sud(
            supported,
            std::env::var("PATINA_REQUIRE_SUD").ok().as_deref(),
        );
    }
    supported
}

/// Refuse missing SUD evidence when the caller requires that capability.
pub fn assert_required_sud(supported: bool, requirement: Option<&str>) {
    assert!(
        supported || requirement != Some("1"),
        "PATINA_REQUIRE_SUD=1 but the host lacks syscall-user-dispatch"
    );
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
