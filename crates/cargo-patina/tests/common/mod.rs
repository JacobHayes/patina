//! Shared CLI invocation, process deadlines, workspace paths, and native shim
//! compilation for e2e and native acceptance tests. Object checks use the Rust
//! staticlib (`libpatina_dst_native_shim.a`, built on demand) and the C POSIX
//! layer compiled from embedded sources with the packaged build's flags.

#![allow(dead_code)]

use std::collections::BTreeSet;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

pub mod native;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod process_group;

use object::read::archive::ArchiveFile;
use object::{Object, ObjectSymbol};

/// The profile directory (`.../target/debug` or `.../release`) that holds the
/// test binary and, alongside it, the shim staticlib.
pub fn profile_dir() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_cargo-patina"))
        .parent()
        .expect("cargo-patina bin has a parent profile directory")
        .to_path_buf()
}

/// The Cargo target directory for an in-tree guest package a test builds: under
/// this test build's own target base, never a `target/` beside the package.
pub fn guest_target_dir(name: &str) -> PathBuf {
    profile_dir()
        .parent()
        .expect("profile has a target base")
        .join("native-guests")
        .join(name)
}

/// The paths `build` produces, built once per nextest run: the first test
/// process of a run to ask builds them, under a lock, and every later one in
/// the run reads their paths back. For artifacts whose inputs do not change
/// during a run. Outside nextest every call builds.
///
/// Another run may rebuild the paths while this one still uses them, so
/// `build` must put each artifact in place atomically (Cargo's outputs, and
/// anything written beside its path and renamed over it), and the stamp is
/// removed before a rebuild and written after it: a rebuild that dies midway
/// leaves no stamp for any run to accept.
pub fn once_per_run(name: &str, build: impl FnOnce() -> Vec<PathBuf>) -> Vec<PathBuf> {
    let Some(run) = std::env::var("NEXTEST_RUN_ID").ok() else {
        return build();
    };
    let dir = guest_target_dir("once-per-run");
    std::fs::create_dir_all(&dir).unwrap();
    let lock = std::fs::File::create(dir.join(format!("{name}.lock"))).unwrap();
    lock.lock().unwrap();
    let stamp = dir.join(format!("{name}.stamp"));
    if let Ok(text) = std::fs::read_to_string(&stamp)
        && let Some((built_in, paths)) = text.split_once('\n')
        && built_in == run
    {
        let paths: Vec<PathBuf> = paths.lines().map(PathBuf::from).collect();
        if paths.iter().all(|path| path.exists()) {
            return paths;
        }
    }
    match std::fs::remove_file(&stamp) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => panic!("{error}"),
        _ => {}
    }
    let paths = build();
    let mut text = format!("{run}\n");
    for path in &paths {
        text.push_str(path.to_str().expect("a UTF-8 artifact path"));
        text.push('\n');
    }
    let partial = dir.join(format!("{name}.stamp.partial"));
    std::fs::write(&partial, text).unwrap();
    std::fs::rename(&partial, &stamp).unwrap();
    paths
}

/// Return the repository root containing the acceptance guests.
pub fn native_workspace() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
}

/// Return the repository Cargo manifest.
pub fn workspace_manifest() -> PathBuf {
    native_workspace().join("Cargo.toml")
}

/// The linker arguments a guest linked by hand needs beside the shim archive
/// `archive`, as `cargo patina build` passes them: on Linux the `dlsym` wrap
/// behind the host-alias table, the allocator routing that keeps the
/// runtime's allocations off the guest's heap, whose object is compiled into
/// `dir`, and libc again: the shim's objects follow the driver's own `-lc`,
/// and `atexit` is in `libc_nonshared.a`, which GNU ld scans once (LLVM's
/// linker, rustc's default on x86_64, remembers it).
pub fn shim_linker_args(archive: &Path, dir: &Path) -> Vec<std::ffi::OsString> {
    if !cfg!(target_os = "linux") {
        return Vec::new();
    }
    let mut args = vec!["-Wl,--wrap=dlsym".into()];
    args.extend(
        cargo_patina::shim_allocator_linker_args(archive, dir)
            .unwrap_or_else(|error| panic!("{error}")),
    );
    args.push("-lc".into());
    args
}

/// [`shim_linker_args`] as rustc `-C` values.
pub fn shim_rustc_link_args(archive: &Path, dir: &Path) -> Vec<std::ffi::OsString> {
    shim_linker_args(archive, dir)
        .into_iter()
        .map(|arg| {
            let mut value = std::ffi::OsString::from("link-arg=");
            value.push(arg);
            value
        })
        .collect()
}

/// The façade and engine `cargo patina build` seals from `archive`, with the
/// POSIX object compiled under `flags`, for a guest linked by hand: sealed
/// once per nextest run for each `variant`.
pub fn sealed_shim(variant: &str, archive: &Path, flags: &[&str]) -> Vec<PathBuf> {
    let name = format!("sealed-{variant}");
    once_per_run(&name, || {
        let dir = guest_target_dir(&name);
        let seams = dir.join("seams");
        std::fs::create_dir_all(&seams).unwrap();
        let mut posix = compile_posix_object(&seams);
        if !flags.is_empty() {
            posix = compile_staged_posix_object(&seams, flags);
        }
        cargo_patina::seal_shim(archive, &posix, &dir)
            .unwrap_or_else(|error| panic!("{error}"))
            .to_vec()
    })
}

/// Build (idempotently) and locate `libpatina_dst_native_shim.a`.
pub fn shim_archive() -> PathBuf {
    build_shim_archive(&[], true)
}

/// The shim archive built with `features`, in a target directory of its own
/// so it never replaces the plain one other guests link.
pub fn shim_archive_with(features: &[&str]) -> PathBuf {
    build_shim_archive(features, true)
}

pub fn prefixed_shim_archive() -> PathBuf {
    build_shim_archive(&[], false)
}

/// The POSIX shim built with its `test-panic` failpoints, `panic=<strategy>`
/// and `opt-level=<opt_level>`, for tests that link the boundary's panic paths.
pub struct TestPanicShim {
    pub archive: PathBuf,
    pub rlib: PathBuf,
    /// The directories of every rlib Cargo produced, for `-L dependency=`.
    pub dependency_dirs: BTreeSet<PathBuf>,
}

/// The test-panic shim of one variant, built into a persistent target once per
/// nextest run and shared by every test binary that links it. A build Cargo
/// finds fresh can still republish its outputs, so Cargo runs for a variant
/// only once a run, never under another binary's `nm` or link.
pub fn test_panic_shim(strategy: &str, opt_level: u8) -> TestPanicShim {
    let name = format!("shim-test-panic-{strategy}-o{opt_level}");
    let mut paths = once_per_run(&name, || {
        let built = build_test_panic_shim(&guest_target_dir(&name), strategy, opt_level);
        [built.archive, built.rlib]
            .into_iter()
            .chain(built.dependency_dirs)
            .collect()
    })
    .into_iter();
    TestPanicShim {
        archive: paths.next().expect("the shim archive"),
        rlib: paths.next().expect("the shim rlib"),
        dependency_dirs: paths.collect(),
    }
}

fn build_test_panic_shim(target_dir: &Path, strategy: &str, opt_level: u8) -> TestPanicShim {
    let output = assert_success(
        Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .current_dir(native_workspace())
            .args([
                "rustc",
                "--lib",
                "--locked",
                "--offline",
                "--message-format=json",
                "-p",
                "patina-dst-native-shim",
                "--features",
                "test-panic",
                "--target-dir",
            ])
            .arg(target_dir)
            .arg("--")
            .args(patina_dst_native_shim::POSIX_RUST_FLAGS)
            .args(["-C", &format!("panic={strategy}")])
            .args(["-C", &format!("opt-level={opt_level}")])
            .output()
            .expect("cargo rustc -p patina-dst-native-shim runs"),
    );
    // Cargo can redirect intermediates separately from target-dir. Consume
    // its artifact messages rather than guessing where the outputs live.
    let filenames: Vec<PathBuf> = native::text(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("Cargo artifact JSON"))
        .filter(|message| message["reason"] == "compiler-artifact")
        .flat_map(|message| {
            message["filenames"]
                .as_array()
                .expect("artifact filenames")
                .iter()
                .map(|name| PathBuf::from(name.as_str().expect("artifact path")))
                .collect::<Vec<_>>()
        })
        .collect();
    let named = |file: &str| -> PathBuf {
        let matches: Vec<_> = filenames
            .iter()
            .filter(|path| path.file_name().is_some_and(|name| name == file))
            .collect();
        assert_eq!(matches.len(), 1, "one built {file}: {filenames:?}");
        matches[0].clone()
    };
    let dependency_dirs: BTreeSet<PathBuf> = filenames
        .iter()
        .filter(|path| path.extension().is_some_and(|ext| ext == "rlib"))
        .map(|path| path.parent().unwrap().to_owned())
        .collect();
    assert!(
        !dependency_dirs.is_empty(),
        "non-vacuous dependency artifacts"
    );
    TestPanicShim {
        archive: named("libpatina_dst_native_shim.a"),
        rlib: named("libpatina_dst_native_shim.rlib"),
        dependency_dirs,
    }
}

fn build_shim_archive(features: &[&str], posix: bool) -> PathBuf {
    let mut profile = profile_dir();
    let mut target_dir = profile
        .parent()
        .expect("profile dir has a target parent")
        .to_path_buf();
    {
        let variant = format!(
            "{}-{}",
            if posix { "posix" } else { "prefixed" },
            features.join("+")
        );
        target_dir = target_dir.join(&variant);
        profile = target_dir.join(profile.file_name().expect("profile name"));
    }
    let mut build = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    build
        .arg("rustc")
        .arg("--lib")
        .arg("--locked")
        .arg("--manifest-path")
        .arg(workspace_manifest())
        .arg("-p")
        .arg("patina-dst-native-shim")
        .arg("--target-dir")
        .arg(&target_dir);
    if !features.is_empty() {
        build.arg("--features").arg(features.join(","));
    }
    if profile.file_name().and_then(|n| n.to_str()) == Some("release") {
        build.arg("--release");
    }
    if posix {
        build
            .arg("--")
            .args(patina_dst_native_shim::POSIX_RUST_FLAGS);
    }
    let status = build
        .status()
        .expect("cargo build -p patina-dst-native-shim runs");
    assert!(
        status.success(),
        "failed to build the native shim staticlib"
    );
    let archive = profile.join("libpatina_dst_native_shim.a");
    assert!(
        archive.exists(),
        "shim staticlib not found at {}",
        archive.display()
    );
    archive
}

/// Visit the shim's *own* object members (named `patina_dst_native_shim-*`),
/// excluding the bundled std/dependency members. Asserts at least one is seen
/// so a renamed member prefix cannot make a scan vacuously pass.
pub fn for_each_shim_member(archive_bytes: &[u8], mut visit: impl FnMut(&object::File<'_>)) {
    let archive = ArchiveFile::parse(archive_bytes).expect("parse shim staticlib");
    let mut saw_shim_member = false;
    for member in archive.members() {
        let member = member.expect("archive member");
        let name = String::from_utf8_lossy(member.name());
        if !name.starts_with("patina_dst_native_shim-") {
            continue;
        }
        saw_shim_member = true;
        let data = member.data(archive_bytes).expect("member data");
        let object = object::File::parse(data).expect("parse shim object member");
        visit(&object);
    }
    assert!(
        saw_shim_member,
        "no patina_dst_native_shim-* members found in the staticlib"
    );
}

/// Compile the embedded C POSIX layer (umbrella + family slices + header) into
/// `dir` with the flags `cargo patina build` uses, returning the object path.
pub fn compile_posix_object(dir: &Path) -> PathBuf {
    for (relative, source) in patina_dst_native_shim::POSIX_C_FAMILY_SOURCES {
        let path = dir.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, source).unwrap();
    }
    std::fs::write(
        dir.join("patina_native.h"),
        patina_dst_native_shim::NATIVE_HEADER,
    )
    .unwrap();
    let source = dir.join("patina_posix.c");
    std::fs::write(&source, patina_dst_native_shim::POSIX_C_SOURCE).unwrap();
    compile_staged_posix_object(dir, &[])
}

/// Compile staged sources with acceptance-only compiler definitions.
pub fn compile_staged_posix_object(dir: &Path, flags: &[&str]) -> PathBuf {
    let source = dir.join("patina_posix.c");
    let object = dir.join("patina_posix.o");
    let status = c_compiler()
        .args(patina_dst_native_shim::POSIX_C_FLAGS)
        .args(flags)
        .arg("-I")
        .arg(dir)
        .arg("-c")
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .status()
        .expect("cc compiles the POSIX shim layer");
    assert!(status.success(), "compiling the POSIX shim layer failed");
    object
}

/// The public (global, defined) symbol names of one object, with the Mach-O
/// leading underscore removed so the names read as the C identifiers.
pub fn defined_public_symbols(object: &object::File<'_>) -> BTreeSet<String> {
    object
        .symbols()
        .filter(|symbol| symbol.is_definition() && symbol.is_global())
        .filter_map(|symbol| symbol.name().ok())
        .map(|name| {
            if cfg!(target_os = "macos") {
                name.strip_prefix('_').unwrap_or(name).to_owned()
            } else {
                name.to_owned()
            }
        })
        .collect()
}

/// Select the configured C compiler, or the platform default.
pub fn c_compiler() -> Command {
    Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()))
}

/// Require a successful invocation of the integration test's cargo-patina binary.
pub fn invoke(directory: &Path, arguments: &[&str]) -> Output {
    invoke_with(env!("CARGO_BIN_EXE_cargo-patina"), directory, arguments)
}

/// Require a successful CLI invocation with explicit environment overrides.
pub fn invoke_in_with_env(directory: &Path, arguments: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cargo-patina"));
    command.current_dir(directory).args(arguments);
    for (name, value) in envs {
        command.env(name, value);
    }
    assert_success(command.output().unwrap())
}

/// Require a successful exit, displaying both captured streams on failure.
/// Keep the payload on one error line so filtered remote test logs retain it.
pub fn assert_success(output: Output) -> Output {
    assert!(
        output.status.success(),
        "error: command failed with {}; stdout={:?}; stderr={:?}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// Require a successful invocation of the selected executable.
pub fn invoke_with(executable: &str, directory: &Path, arguments: &[&str]) -> Output {
    assert_success(invoke_unchecked(executable, directory, arguments))
}

/// Capture the selected executable without requiring a successful exit.
pub fn invoke_unchecked(executable: &str, directory: &Path, arguments: &[&str]) -> Output {
    Command::new(executable)
        .current_dir(directory)
        .args(arguments)
        .output()
        .unwrap()
}

/// Capture both output streams concurrently until the child and pipe readers finish.
/// On deadline, kill the entire process group and return `None`: descendants may
/// keep output pipes open even after the supervisor exits.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn invoke_with_deadline(
    executable: &str,
    directory: &Path,
    arguments: &[&str],
    deadline: Duration,
) -> Option<Output> {
    output_with_deadline(
        Command::new(executable)
            .current_dir(directory)
            .args(arguments),
        deadline,
    )
}

/// Capture a configured command using the same process-group deadline as CLI runs.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn output_with_deadline(command: &mut Command, deadline: Duration) -> Option<Output> {
    match output_by_deadline(command, deadline) {
        Deadlined::Finished(output) => Some(output),
        Deadlined::Killed { stdout, stderr } => {
            eprintln!(
                "deadline exceeded: {command:?}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr),
            );
            None
        }
    }
}

/// How [`output_by_deadline`] ended.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub enum Deadlined {
    Finished(Output),
    /// The deadline passed: the whole process group was killed and the child
    /// reaped; this is what it wrote until then.
    Killed {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
}

/// [`output_with_deadline`], answering a killed run's partial output rather
/// than dropping it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn output_by_deadline(command: &mut Command, deadline: Duration) -> Deadlined {
    output_until(command, deadline, |_| false)
}

/// [`output_by_deadline`] with an early stop: `stop` sees the child's pid
/// every poll and, answering true, has the run killed then (the same group
/// kill and reap as the deadline). A caller that confirms a hang this way
/// tells the two kills apart itself.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn output_until(
    command: &mut Command,
    deadline: Duration,
    mut stop: impl FnMut(u32) -> bool,
) -> Deadlined {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let stdout = std::thread::spawn(move || read_pipe(stdout));
    let stderr = std::thread::spawn(move || read_pipe(stderr));
    let give_up = Instant::now() + deadline;
    while child.try_wait().unwrap().is_none() || !stdout.is_finished() || !stderr.is_finished() {
        if Instant::now() >= give_up || stop(child.id()) {
            process_group::kill(child.id()).expect("kill deadline child process group");
            child.wait().expect("reap deadline child");
            return Deadlined::Killed {
                stdout: stdout.join().unwrap(),
                stderr: stderr.join().unwrap(),
            };
        }
        // Most runs end within a few hundred milliseconds, and every poll
        // interval is latency added to each one; a poll is a non-blocking
        // wait and two flag reads.
        std::thread::sleep(Duration::from_millis(2));
    }
    Deadlined::Finished(Output {
        status: child.wait().unwrap(),
        stdout: stdout.join().unwrap(),
        stderr: stderr.join().unwrap(),
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_pipe(mut pipe: impl std::io::Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes).unwrap();
    bytes
}
