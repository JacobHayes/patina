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
mod process_group;

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

/// Build (idempotently) and locate `libpatina_dst_native_shim.a`.
pub fn shim_archive() -> PathBuf {
    let profile = profile_dir();
    let target_dir = profile
        .parent()
        .expect("profile dir has a target parent")
        .to_path_buf();
    let mut build = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    build
        .arg("build")
        .arg("--locked")
        .arg("--manifest-path")
        .arg(workspace_manifest())
        .arg("-p")
        .arg("patina-dst-native-shim")
        .arg("--target-dir")
        .arg(&target_dir);
    if profile.file_name().and_then(|n| n.to_str()) == Some("release") {
        build.arg("--release");
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
    let object = dir.join("patina_posix.o");
    let status = c_compiler()
        .args([
            "-std=c11",
            "-D_POSIX_C_SOURCE=200809L",
            "-fno-stack-protector",
            "-Wall",
            "-Wextra",
            "-Werror",
        ])
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
pub fn assert_success(output: Output) -> Output {
    assert!(
        output.status.success(),
        "command failed with {}\nstdout:\n{}\nstderr:\n{}",
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
        if Instant::now() >= give_up {
            process_group::kill(child.id()).expect("kill deadline child process group");
            child.wait().expect("reap deadline child");
            let stdout = stdout.join().unwrap();
            let stderr = stderr.join().unwrap();
            eprintln!(
                "deadline exceeded: {command:?}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr),
            );
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Some(Output {
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
