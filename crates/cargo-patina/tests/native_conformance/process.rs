//! Probe construction, process state, run deadlines, and observation decoding.

use crate::common;
use patina_dst_conformance::compare::{Observation, Origin, Termination};
use patina_dst_conformance::host::NotRun;
use patina_dst_conformance::observe::parse_stream;
use serde_json::Value;
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

/// How long one run may take before its process group is killed.
pub(super) const RUN_DEADLINE: Duration = Duration::from_secs(60);
/// The seed of every `cargo patina` run.
pub(super) const PATINA_SEED: &str = "1";
/// The seed of the shim-linked binary run directly (no `cargo patina`).
pub(super) const DIRECT_SEED: &str = "9";
pub(super) const FINGERPRINT: &str = "patina-conformance";
/// The virtual kernel's descriptor limit and initial umask: the native run
/// starts from the same process state (and with only the three standard
/// descriptors), so allocation order, `EMFILE`, the `F_DUPFD`/`dup2` bounds and
/// the first `umask(2)` answer fall the same way.
const FD_LIMIT: libc::rlim_t = 1024;
const UMASK: libc::mode_t = 0o022;

/// The probe binary built plainly (the native oracle) and shim-linked, both
/// under this test build's target base.
pub(super) struct Probes {
    pub(super) native: PathBuf,
    pub(super) patina: PathBuf,
}

pub(super) fn probes() -> &'static Probes {
    static PROBES: OnceLock<Probes> = OnceLock::new();
    PROBES.get_or_init(|| {
        let native_target = common::guest_target_dir("conformance-native");
        let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args([
                "build",
                "--quiet",
                "--locked",
                "--release",
                "--manifest-path",
            ])
            .arg(common::workspace_manifest())
            .args(["-p", "patina-dst-conformance", "--bin", "conformance-probe"])
            .arg("--target-dir")
            .arg(&native_target)
            .status()
            .expect("cargo build runs");
        assert!(
            status.success(),
            "building the native conformance probe failed"
        );
        // Run the shim-linked probe from the path Cargo produced, never from an
        // `--output` copy: every test process (nextest runs one per test)
        // rebuilds the probe, and a copy rewrites the file in place while
        // another process may be executing it (ETXTBSY). Cargo replaces its
        // output by link, which a running executable survives; the conformance
        // scenarios are Linux-only, where the target dir hard-links.
        let patina_target = common::guest_target_dir("conformance");
        let package = common::native_workspace().join("crates/patina-conformance");
        let built = common::invoke_in_with_env(
            common::native_workspace(),
            &[
                "build",
                package.to_str().unwrap(),
                "--bin",
                "conformance-probe",
                "--release",
            ],
            &[("CARGO_TARGET_DIR", patina_target.to_str().unwrap())],
        );
        let patina = PathBuf::from(common::native::assert_unique_line_payload(
            &built.stdout,
            "PATINA_NATIVE_BUILD output=",
        ));
        Probes {
            native: named_like_the_guest(
                &native_target,
                &native_target.join("release/conformance-probe"),
            ),
            patina,
        }
    })
}

/// A link to the native probe named as `cargo patina` names every guest in
/// its `argv[0]` (`patina-guest`), for the native runs to execute: the kernel
/// names the main thread (`comm`) after the file `execve` ran, and the shim
/// after `argv[0]`, so both oracles start from the same thread name. Every
/// test process makes the same link; each renames its own into place.
fn named_like_the_guest(target: &Path, probe: &Path) -> PathBuf {
    let dir = target.join("guest-name");
    std::fs::create_dir_all(&dir).expect("create the probe link's directory");
    let link = dir.join("patina-guest");
    let staged = dir.join(format!("patina-guest.{}", std::process::id()));
    let _ = std::fs::remove_file(&staged);
    std::os::unix::fs::symlink(probe, &staged).expect("link the native probe");
    std::fs::rename(&staged, &link).expect("place the native probe's link");
    link
}

pub(super) fn logs_root() -> PathBuf {
    common::profile_dir()
        .parent()
        .expect("profile has a target base")
        .join("conformance")
}

/// Run `command` with stdin at EOF under the run deadline.
pub(super) fn run(command: &mut Command) -> Result<Output, String> {
    command.stdin(Stdio::null());
    common::output_with_deadline(command, RUN_DEADLINE)
        .ok_or_else(|| format!("exceeded {RUN_DEADLINE:?}: {command:?}"))
}

fn termination(status: ExitStatus) -> Termination {
    match (status.code(), status.signal()) {
        (Some(code), _) => Termination::Exited(code),
        (None, Some(signal)) => Termination::Signaled {
            signal,
            core: Some(status.core_dumped()),
        },
        (None, None) => Termination::Unreported,
    }
}

pub(super) fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A process run that wrote the stream itself (native, or shim-linked directly).
pub(super) fn direct_observation(output: &Output, origin: Origin) -> Result<Observation, String> {
    Ok(Observation {
        origin,
        events: parse_stream(&text(&output.stdout))?,
        termination: termination(output.status),
        stderr: text(&output.stderr),
    })
}

/// A `cargo patina … --format json` run: the guest's streams and exit are in
/// the `patina.result/v1` envelope; a refusal's message joins the stderr.
pub(super) fn envelope_observation(output: &Output, origin: Origin) -> Result<Observation, String> {
    let envelope: Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "not a patina.result/v1 envelope ({error}); cargo-patina {}: {}",
            output.status,
            text(&output.stderr)
        )
    })?;
    let guest_exit = &envelope["guest_exit"];
    let termination = match (guest_exit["signal"].as_i64(), guest_exit["code"].as_i64()) {
        (Some(signal), _) => Termination::Signaled {
            signal: signal as i32,
            core: guest_exit["core"].as_bool(),
        },
        (None, Some(code)) => Termination::Exited(code as i32),
        (None, None) => Termination::Unreported,
    };
    Ok(Observation {
        origin,
        events: parse_stream(envelope["stdout"].as_str().unwrap_or(""))?,
        termination,
        stderr: format!(
            "{}{}{}",
            text(&output.stderr),
            envelope["stderr"].as_str().unwrap_or(""),
            envelope["refusal"]["message"].as_str().unwrap_or("")
        ),
    })
}

/// The first descriptor past the standard three.
const FIRST_UNSTANDARD_FD: libc::c_uint = 3;

/// Pin the native process state the virtual kernel starts from: every
/// descriptor the test process inherited past the standard three closes at
/// exec, and the descriptor limit and umask are the virtual kernel's. Scenarios
/// declaring Need::Keys get a fresh anonymous session in this forked child only.
/// `CLOSE_RANGE_CLOEXEC` needs Linux 5.11; an older host fails every native
/// run here instead of reporting it not run.
pub(super) fn pin_process_state(needs_keys: bool) -> std::io::Result<()> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: async-signal-safe calls on this (forked) process's own state.
    unsafe {
        if libc::close_range(
            FIRST_UNSTANDARD_FD,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC as libc::c_int,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        limit.rlim_cur = FD_LIMIT;
        if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        libc::umask(UMASK);
        // Raw keyctl is async-signal-safe; no allocation or credential change
        // in the harness thread. KEYCTL_JOIN_SESSION_KEYRING with NULL name.
        if needs_keys && libc::syscall(libc::SYS_keyctl, 1, 0, 0, 0, 0) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Report a run that cannot happen on this host. Written past the test
/// harness's capture (`eprintln!` is captured), so it shows on a passing run
/// too.
#[allow(clippy::explicit_write)]
pub(super) fn not_run(what: &str, reason: &NotRun) {
    writeln!(std::io::stderr(), "NOT RUN {what}: {reason}").unwrap();
}

pub(super) fn required(variable: &str) -> bool {
    std::env::var(variable).as_deref() == Ok("1")
}
