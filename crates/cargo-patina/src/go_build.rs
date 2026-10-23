//! Go guests: a Go main package built by `go build` in cgo mode and linked
//! externally with the shim.
//!
//! A Go program reaches Patina the same way a Rust one does — as a native
//! executable with the shim linked below it — but Go's own linker cannot take
//! the shim's objects. External linking hands the final link to the C
//! toolchain, which links them exactly as rustc's link does. External linking
//! also makes the Go command link `runtime/cgo` into every program, cgo user
//! or not, so goroutine threads start through `pthread_create` — the shim's
//! managed-thread interposer — rather than Go's raw `clone`, which the runtime
//! refuses. A pure-Go package therefore needs no source change, only
//! `CGO_ENABLED=1`, which this build sets.
//!
//! Patina owns the link line (`-ldflags`) and the output (`-o`); every other
//! `go build` option passes through.

use crate::native_build::{PLATFORM_LINKER_ARGS, install_built_executable};
use crate::shim_build::BuiltNativeShim;
use crate::{CliError, shim_cache};
use object::{Object, ObjectKind};
use patina_dst_target::native_binary_is_shim_linked;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The file name every Go guest is linked under before it is installed at its
/// output, so the output's name never reaches the link.
const GO_LINK_NAME: &str = "patina-guest";

/// The `go build` options Patina sets itself, so a guest may not pass them.
const RESERVED_GO_FLAGS: &[&str] = &["ldflags", "o"];

/// Refuse a `go build` option that would replace Patina's link line or
/// output. Go accepts both `-flag` and `--flag`, each with an inline `=value`
/// or a separate value.
pub(super) fn check_go_args(go_args: &[OsString]) -> Result<(), CliError> {
    for arg in go_args {
        let Some(text) = arg.to_str() else { continue };
        let name = text
            .strip_prefix("--")
            .or_else(|| text.strip_prefix('-'))
            .map(|flag| flag.split_once('=').map_or(flag, |(name, _)| name));
        if let Some(name) = name
            && RESERVED_GO_FLAGS.contains(&name)
        {
            return Err(CliError::usage(format!(
                "go build option {text:?} is Patina's: a Go guest's link line and output are set by `cargo patina build --go`"
            )));
        }
    }
    Ok(())
}

/// The `-ldflags` value that links externally with the shim: its POSIX
/// object, its archive, the allocator routing, and the platform arguments,
/// with unused sections collected as rustc's link collects them.
///
/// The Go command splits `-ldflags` into fields, and the Go linker splits
/// `-extldflags` again, each honouring single and double quotes but no
/// escapes; so each linker argument is single-quoted inside one double-quoted
/// `-extldflags` field, and an argument containing a quote is refused.
pub(super) fn go_ldflags(
    object: &Path,
    staticlib: &Path,
    allocator: &[OsString],
) -> Result<String, CliError> {
    let mut linker_args: Vec<&OsStr> = vec![object.as_os_str(), staticlib.as_os_str()];
    linker_args.extend(allocator.iter().map(OsString::as_os_str));
    linker_args.extend(PLATFORM_LINKER_ARGS.iter().map(OsStr::new));
    linker_args.push(OsStr::new("-Wl,--gc-sections"));
    let mut quoted = Vec::with_capacity(linker_args.len());
    for arg in linker_args {
        let text = arg.to_str().ok_or_else(|| {
            CliError(format!(
                "the Go link argument {arg:?} is not UTF-8, so `go build -ldflags` cannot carry it"
            ))
        })?;
        if text.contains(['\'', '"']) {
            return Err(CliError(format!(
                "the Go link argument {text:?} contains a quote, which `go build -ldflags` cannot carry"
            )));
        }
        quoted.push(format!("'{text}'"));
    }
    Ok(format!(
        "-linkmode=external \"-extldflags={}\"",
        quoted.join(" ")
    ))
}

/// Build the Go main package in `package_dir` with the shim linked and
/// install it at `output`.
pub(super) fn build_go_package(
    package_dir: &Path,
    output: &Path,
    object: &Path,
    shim: &BuiltNativeShim,
    allocator: &[OsString],
    go_args: &[OsString],
) -> Result<PathBuf, CliError> {
    if !cfg!(target_os = "linux") {
        return Err(CliError(
            "Go guests build on Linux only: the shim's Go link uses linker wraps the Darwin linker lacks".into(),
        ));
    }
    if !package_dir.is_dir() {
        return Err(CliError(format!(
            "no Go package directory at {}",
            package_dir.display()
        )));
    }
    check_go_args(go_args)?;
    let ldflags = go_ldflags(object, &shim.staticlib, allocator)?;
    let link_dir = tempfile::tempdir()
        .map_err(|error| CliError(format!("failed to create a link directory: {error}")))?;
    let linked = link_dir.path().join(GO_LINK_NAME);
    let mut command = Command::new("go");
    shim_cache::inherit(&mut command, &shim._lease)?;
    command
        .current_dir(package_dir)
        .env("CGO_ENABLED", "1")
        .arg("build")
        .arg("-o")
        .arg(&linked)
        .arg("-ldflags")
        .arg(&ldflags)
        .args(go_args)
        .arg(".");
    let status = command.status().map_err(|error| {
        CliError(format!(
            "failed to run `go build` (is a Go toolchain on PATH?): {error}"
        ))
    })?;
    if !status.success() {
        return Err(CliError(format!(
            "building the Go package {} with the Patina shim failed",
            package_dir.display()
        )));
    }
    let bytes = std::fs::read(&linked).map_err(|error| {
        CliError(format!(
            "`go build` reported success but left no program at {}: {error}",
            linked.display()
        ))
    })?;
    check_linked_guest(&bytes, package_dir)?;
    install_built_executable(&linked, output)?;
    Ok(output.to_path_buf())
}

/// Refuse a `go build` result that is not a program with the shim linked
/// below it. `go build` succeeds on a library package or under another
/// `-buildmode` (from the arguments or `GOFLAGS`) without producing one.
fn check_linked_guest(bytes: &[u8], package_dir: &Path) -> Result<(), CliError> {
    let refused = |what: &str| {
        CliError(format!(
            "`go build` of {} produced {what}, not a shim-linked program: build a main package \
             with the default -buildmode (check the arguments and GOFLAGS)",
            package_dir.display()
        ))
    };
    let file =
        object::File::parse(bytes).map_err(|_| refused("a file that is not an executable"))?;
    let program = match file.kind() {
        ObjectKind::Executable => true,
        // A position-independent program is a dynamic object with an interpreter.
        ObjectKind::Dynamic => file.section_by_name(".interp").is_some(),
        _ => false,
    };
    if !program {
        return Err(refused("an object that is not a program"));
    }
    if !native_binary_is_shim_linked(bytes).map_err(|error| CliError(error.to_string()))? {
        return Err(refused("a program without the Patina shim"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_build_result_that_is_not_a_shim_linked_program_is_refused() {
        let dir = Path::new("pkg");
        // What `-buildmode=c-archive` leaves at the output.
        assert!(check_linked_guest(b"!<arch>\n", dir).is_err());
        // A program, but one linked without the shim: this test binary.
        let unlinked = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        assert!(check_linked_guest(&unlinked, dir).is_err());
    }

    #[test]
    fn link_line_and_output_options_are_refused_in_every_spelling() {
        for reserved in [
            "-ldflags",
            "--ldflags",
            "-ldflags=-s",
            "--ldflags=-X main.v=1",
            "-o",
            "--o=out",
        ] {
            let args = [OsString::from("-trimpath"), OsString::from(reserved)];
            assert!(check_go_args(&args).is_err(), "{reserved}");
        }
        let passing = [
            "-trimpath",
            "-tags",
            "netgo",
            "-gcflags=all=-N",
            "-buildvcs=false",
        ];
        let args: Vec<OsString> = passing.iter().map(OsString::from).collect();
        check_go_args(&args).expect("ordinary go build options pass through");
    }

    /// Splits a value the way the Go command and linker do: whitespace
    /// separates fields, and a single- or double-quoted run is one field.
    fn split_quoted(text: &str) -> Vec<String> {
        let mut fields = Vec::new();
        let mut chars = text.chars().peekable();
        while let Some(&next) = chars.peek() {
            if next.is_whitespace() {
                chars.next();
                continue;
            }
            let mut field = String::new();
            if next == '\'' || next == '"' {
                chars.next();
                for c in chars.by_ref() {
                    if c == next {
                        break;
                    }
                    field.push(c);
                }
            } else {
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() {
                        break;
                    }
                    field.push(c);
                    chars.next();
                }
            }
            fields.push(field);
        }
        fields
    }

    #[test]
    fn the_extldflags_field_carries_every_linker_argument_intact() {
        let allocator = [
            OsString::from("-Wl,--wrap=a b"),
            OsString::from("/r/route.o"),
        ];
        let ldflags = go_ldflags(Path::new("/o/posix.o"), Path::new("/a/lib.a"), &allocator)
            .expect("plain paths quote");
        let fields = split_quoted(&ldflags);
        assert_eq!(fields[0], "-linkmode=external");
        let extld = fields[1]
            .strip_prefix("-extldflags=")
            .expect("one -extldflags field");
        let mut expected = vec!["/o/posix.o", "/a/lib.a", "-Wl,--wrap=a b", "/r/route.o"];
        expected.extend(PLATFORM_LINKER_ARGS);
        expected.push("-Wl,--gc-sections");
        assert_eq!(split_quoted(extld), expected);
        assert_eq!(fields.len(), 2);
        // A quote cannot be carried through the quoted field, so it is refused.
        assert!(go_ldflags(Path::new("/o/it's.o"), Path::new("/a/lib.a"), &[]).is_err());
    }
}
