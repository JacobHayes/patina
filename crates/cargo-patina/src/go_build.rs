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
//! Every Go guest carries a compute meter. Patina runs one guest thread at a
//! time and moves virtual time by what guest calls cost, so a goroutine that
//! computes without calls would hold the thread: its timers would never come
//! due and sysmon, which preempts it natively, would never run. The build
//! compiles every package outside the runtime with Go's libFuzzer
//! instrumentation (`-d=libfuzzer`, with the `libfuzzer` build tag that
//! links the runtime's hook glue), whose comparison hooks the meter object
//! (`patina_go_meter.c`) counts and hands to the shim in batches; and it sets
//! `GOEXPERIMENT=preemptibleloops`, so a loop's back edge notices the
//! preemption sysmon then asks for, as a call's prologue does.
//!
//! The runtime's own string-comparison hooks copy both strings on every
//! unequal comparison, which makes a loop over a long string quadratic. The
//! build therefore runs `cargo-patina` as its `-toolexec` wrapper, which
//! compiles the `runtime` package from a copy of the toolchain's hook source
//! whose string hooks only count ([`run_as_toolexec`]). A guest that names
//! its own `-toolexec`, or a toolchain whose hooks Patina does not recognise,
//! keeps the copying hooks: slower, metered the same.
//!
//! Patina owns the link line (`-ldflags`) and the output (`-o`); every other
//! `go build` option passes through. A guest's own `-tags` and `-gcflags`
//! keep the meter's settings: the tag is added to its list and the debug flag
//! to each `-gcflags` value, since the Go command keeps only the last match.

use crate::CliError;
use crate::native_build::{PLATFORM_LINKER_ARGS, install_built_executable};
use crate::shim_build::BuiltNativeShim;
use object::{Object, ObjectKind};
use patina_dst_target::native_binary_is_shim_linked;
use sha2::Digest;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The file name every Go guest is linked under before it is installed at its
/// output, so the output's name never reaches the link.
const GO_LINK_NAME: &str = "patina-guest";

/// The `go build` options Patina sets itself, so a guest may not pass them.
const RESERVED_GO_FLAGS: &[&str] = &["ldflags", "o"];

/// The build tag that links the Go runtime's libFuzzer hook glue.
const METER_TAG: &str = "libfuzzer";
/// The compiler flag that instruments comparisons with libFuzzer hooks.
const METER_GCFLAG: &str = "-d=libfuzzer";
/// The Go experiment that puts a preemption check on every loop back edge.
const METER_EXPERIMENT: &str = "preemptibleloops";

/// The marker the meter object embeds (`patina_go_meter.c`): a program
/// carrying it is a Go guest built by `cargo patina build --go`.
const METER_MARKER: &[u8] = b"PATINA_GO_METER_V1";

/// The processor count a metered Go guest's runtime schedules goroutines on
/// unless the run sets `GOMAXPROCS` itself. With more than one P the Go
/// runtime busy-waits on another P's thread in places (the background sweeper
/// waits for another sweeper to finish without yielding), and Patina, which
/// runs one thread at a time, has no deterministic way to preempt runtime code
/// the meter does not count. With one P no thread holding a P can be waiting
/// for the thread that runs.
const GUEST_GOMAXPROCS: &str = "1";

/// Give a metered Go guest's environment the settings its run needs: one P
/// ([`GUEST_GOMAXPROCS`]) unless the run names `GOMAXPROCS`. `metered` is
/// whether the program [`carries_meter`]. The map is the run's recorded
/// environment, so a replay restores it.
pub(super) fn apply_go_guest_defaults(
    metered: bool,
    environment: &mut std::collections::BTreeMap<String, String>,
) {
    if metered && !environment.contains_key("GOMAXPROCS") {
        environment.insert("GOMAXPROCS".into(), GUEST_GOMAXPROCS.into());
    }
}

/// Whether the program whose bytes are `image` carries the Go meter's marker.
pub(super) fn carries_meter(image: &[u8]) -> bool {
    memchr::memmem::find(image, METER_MARKER).is_some()
}

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

/// The guest's `go build` options with the meter's settings merged in: the
/// meter's `-gcflags` first (for every package), each of the guest's own
/// `-gcflags` values extended with the meter's flag, and the meter's tag added
/// to the guest's `-tags` (or given alone).
pub(super) fn metered_go_args(go_args: &[OsString]) -> Vec<OsString> {
    let mut merged = vec![OsString::from(format!("-gcflags=all={METER_GCFLAG}"))];
    let mut tagged = false;
    let mut pending: Option<&str> = None;
    for arg in go_args {
        let text = arg.to_str();
        if let (Some(flag), Some(value)) = (pending.take(), text) {
            merged.push(OsString::from(metered_value(flag, value)));
            continue;
        }
        let flag = text.and_then(|text| {
            let name = text.strip_prefix("--").or_else(|| text.strip_prefix('-'))?;
            ["tags", "gcflags"]
                .into_iter()
                .find(|flag| name == *flag || name.starts_with(&format!("{flag}=")))
                .map(|flag| (flag, name.split_once('=').map(|(_, value)| value)))
        });
        match flag {
            Some((flag, Some(value))) => {
                tagged |= flag == "tags";
                merged.push(OsString::from(format!(
                    "-{flag}={}",
                    metered_value(flag, value)
                )));
            }
            Some((flag, None)) => {
                tagged |= flag == "tags";
                merged.push(arg.clone());
                pending = Some(flag);
            }
            None => merged.push(arg.clone()),
        }
    }
    if !tagged {
        merged.insert(1, OsString::from(format!("-tags={METER_TAG}")));
    }
    merged
}

/// A guest's `-tags` or `-gcflags` value with the meter's tag or flag added.
/// Tags are read in both of the Go command's forms (comma-separated, or the
/// older space-separated list, quotes dropped) and written back
/// comma-separated.
fn metered_value(flag: &str, value: &str) -> String {
    if flag != "tags" {
        return format!("{value} {METER_GCFLAG}");
    }
    let mut tags: Vec<&str> = if value.contains([' ', '\'']) {
        value
            .split(|c: char| c.is_whitespace() || c == '\'' || c == '"')
            .collect()
    } else {
        value.split(',').collect()
    };
    tags.retain(|tag| !tag.is_empty() && *tag != METER_TAG);
    tags.push(METER_TAG);
    tags.join(",")
}

/// Split `text` into fields as the Go command splits `GOFLAGS` and
/// space-separated flag lists: on whitespace, with a field that starts with
/// a single or double quote running to the matching quote.
fn split_go_quoted(text: &str) -> Vec<String> {
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

/// The flags of the toolchain's effective `GOFLAGS` (the environment or
/// `go env -w`) that the meter merges with: `-tags`, `-gcflags` and
/// `-toolexec`. A command-line flag replaces its `GOFLAGS` setting, so these
/// go ahead of the guest's own arguments and are merged as if given there.
fn inherited_go_flags(goflags: &str) -> Vec<OsString> {
    split_go_quoted(goflags)
        .into_iter()
        .filter(|field| {
            let name = field.strip_prefix("--").or_else(|| field.strip_prefix('-'));
            name.and_then(|name| name.split_once('='))
                .is_some_and(|(name, _)| ["tags", "gcflags", "toolexec"].contains(&name))
        })
        .map(OsString::from)
        .collect()
}

/// The `GOEXPERIMENT` value the meter builds with: the toolchain's own
/// setting (from the environment or `go env -w`), plus the meter's
/// experiment.
fn metered_experiment(configured: &str) -> String {
    let configured = configured.trim();
    if configured.is_empty() {
        METER_EXPERIMENT.to_string()
    } else {
        format!("{configured},{METER_EXPERIMENT}")
    }
}

/// The first argument that makes `cargo-patina` run as a Go build's
/// `-toolexec` wrapper ([`run_as_toolexec`]) rather than parse a verb.
pub(super) const TOOLEXEC_ROLE: &str = "__patina-go-toolexec";

/// The body the Go runtime gives its string-comparison hooks
/// (`runtime/libfuzzer.go`): on unequal strings it copies both into fresh
/// NUL-terminated buffers for libFuzzer. The meter needs only the call, so
/// the copy turns each comparison of a long string into a long allocation,
/// and a loop comparing it into quadratic time and memory.
const COPYING_STRING_HOOK: &str = "\tif s1 != s2 {\n\t\tlibfuzzerCall4(&__sanitizer_weak_hook_strcmp, uintptr(fakePC), cstring(s1), cstring(s2), uintptr(1))\n\t}";
/// The body the meter builds the runtime's string hooks with instead: one
/// comparison hook call carrying the lengths, which the meter counts like any
/// other comparison.
const METERED_STRING_HOOK: &str = "\tlibfuzzerCallTraceIntCmp(&__sanitizer_cov_trace_cmp8, uintptr(len(s1)), uintptr(len(s2)), uintptr(fakePC)%retSledSize)";

/// The runtime's `libfuzzer.go` with its string hooks rebuilt to the meter's
/// body, or `None` when the toolchain's hooks are not the body Patina knows.
fn metered_runtime_hooks(source: &str) -> Option<String> {
    source
        .contains(COPYING_STRING_HOOK)
        .then(|| source.replace(COPYING_STRING_HOOK, METERED_STRING_HOOK))
}

/// Stage the metered runtime hook source for the toolchain `package_dir`
/// builds with, under the shim's cache lease at a path named by its content,
/// so a rebuild compiles the runtime from the same path. `None` (with a note)
/// when the toolchain's hooks are not the body Patina knows: the guest then
/// keeps the copying hooks, which cost time and memory but meter the same.
fn stage_runtime_hooks(
    package_dir: &Path,
    shim: &BuiltNativeShim,
) -> Result<Option<PathBuf>, CliError> {
    let goroot = go_env(package_dir, "GOROOT")?;
    let original = Path::new(&goroot).join("src/runtime/libfuzzer.go");
    let source = std::fs::read_to_string(&original).map_err(|error| {
        CliError(format!(
            "failed to read the Go runtime's libFuzzer hooks at {}: {error}",
            original.display()
        ))
    })?;
    let Some(metered) = metered_runtime_hooks(&source) else {
        eprintln!(
            "note: the Go runtime's string-comparison hooks at {} are not the ones Patina \
             rebuilds; the guest keeps them, so each comparison of unequal strings copies both",
            original.display()
        );
        return Ok(None);
    };
    let digest = crate::hex(&sha2::Sha256::digest(metered.as_bytes()));
    let dir = shim.dir.join("go-runtime-hooks").join(digest);
    let staged = dir.join("libfuzzer.go");
    if staged.exists() {
        return Ok(Some(staged));
    }
    let failed = |error: std::io::Error| {
        CliError(format!(
            "failed to stage the metered Go runtime hooks in {}: {error}",
            dir.display()
        ))
    };
    std::fs::create_dir_all(&dir).map_err(failed)?;
    let mut partial = tempfile::NamedTempFile::new_in(&dir).map_err(failed)?;
    std::io::Write::write_all(&mut partial, metered.as_bytes()).map_err(failed)?;
    partial
        .persist(&staged)
        .map_err(|error| failed(error.error))?;
    Ok(Some(staged))
}

/// Whether the guest's own `go build` options name a `-toolexec` wrapper,
/// which then runs instead of Patina's.
fn names_toolexec(go_args: &[OsString]) -> bool {
    go_args.iter().filter_map(|arg| arg.to_str()).any(|text| {
        text.strip_prefix("--")
            .or_else(|| text.strip_prefix('-'))
            .is_some_and(|name| name == "toolexec" || name.starts_with("toolexec="))
    })
}

/// The `-toolexec` value that runs this executable in its toolexec role with
/// the staged hooks. The Go command splits the value into fields honouring
/// quotes, so each field is single-quoted and one containing a quote is
/// refused.
fn toolexec_value(executable: &Path, hooks: &Path) -> Result<String, CliError> {
    let mut fields = Vec::with_capacity(3);
    for field in [
        executable.as_os_str(),
        OsStr::new(TOOLEXEC_ROLE),
        hooks.as_os_str(),
    ] {
        let text = field.to_str().filter(|text| !text.contains(['\'', '"']));
        let Some(text) = text else {
            return Err(CliError(format!(
                "the path {field:?} is not UTF-8 or contains a quote, so `go build -toolexec` cannot carry it"
            )));
        };
        fields.push(format!("'{text}'"));
    }
    Ok(format!("-toolexec={}", fields.join(" ")))
}

/// The tag the toolexec role adds to the compiler's `-V=full` identity, so the
/// Go build cache keeps runtime archives built from different hook sources
/// apart (and apart from ones built without Patina's hooks).
fn hooks_tool_id(hooks: &[u8]) -> String {
    let digest = crate::hex(&sha2::Sha256::digest(hooks));
    format!("patina-runtime-hooks-{}", &digest[..16])
}

/// The compiler's `-V=full` line with `tag` folded in. A release line
/// (`compile version go1.26.2 X:...`) is used whole, so the tag is a field
/// added at its end; a development toolchain's line must end in its
/// `buildID=` field, whose content part is used alone, so the tag is joined
/// onto that field.
fn with_hooks_identity(line: &str, tag: &str) -> String {
    let line = line.trim_end();
    match line.rsplit_once(' ') {
        Some((_, last)) if last.starts_with("buildID=") => format!("{line}+{tag}"),
        _ => format!("{line} {tag}"),
    }
}

/// A compile command's arguments with the runtime's hook source replaced by
/// `hooks`. Only the `runtime` package's compile carries that file.
fn with_runtime_hooks(arguments: Vec<OsString>, hooks: &Path) -> Vec<OsString> {
    let replaced = Path::new("runtime").join("libfuzzer.go");
    arguments
        .into_iter()
        .map(|argument| {
            if Path::new(&argument).ends_with(&replaced) {
                hooks.as_os_str().to_owned()
            } else {
                argument
            }
        })
        .collect()
}

/// Run as a Go build's `-toolexec` wrapper: `arguments` are the staged hook
/// source, then the Go tool and its arguments. The compiler builds the
/// `runtime` package from the metered hooks and reports an identity naming
/// them; every other tool invocation runs unchanged.
pub(super) fn run_as_toolexec(arguments: Vec<OsString>) -> Result<i32, CliError> {
    let mut arguments = arguments.into_iter();
    let (Some(hooks), Some(tool)) = (arguments.next(), arguments.next()) else {
        return Err(CliError(format!(
            "{TOOLEXEC_ROLE} takes the staged hook source and a Go tool command"
        )));
    };
    let hooks = PathBuf::from(hooks);
    let mut tool_args: Vec<OsString> = arguments.collect();
    let compiler = Path::new(&tool).file_stem() == Some(OsStr::new("compile"));
    if compiler && tool_args.iter().any(|argument| argument == "-V=full") {
        let output = Command::new(&tool)
            .args(&tool_args)
            .stderr(std::process::Stdio::inherit())
            .output()
            .map_err(|error| CliError(format!("failed to run {tool:?}: {error}")))?;
        if !output.status.success() {
            return Ok(output.status.code().unwrap_or(1));
        }
        let source = std::fs::read(&hooks)
            .map_err(|error| CliError(format!("failed to read {}: {error}", hooks.display())))?;
        let identity = String::from_utf8_lossy(&output.stdout);
        println!(
            "{}",
            with_hooks_identity(&identity, &hooks_tool_id(&source))
        );
        return Ok(0);
    }
    if compiler && std::env::var_os("TOOLEXEC_IMPORTPATH").as_deref() == Some(OsStr::new("runtime"))
    {
        tool_args = with_runtime_hooks(tool_args, &hooks);
    }
    let mut command = Command::new(&tool);
    command.args(&tool_args);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let error = command.exec();
        Err(CliError(format!("failed to run {tool:?}: {error}")))
    }
    #[cfg(not(unix))]
    {
        let status = command
            .status()
            .map_err(|error| CliError(format!("failed to run {tool:?}: {error}")))?;
        Ok(status.code().unwrap_or(1))
    }
}

/// The `-ldflags` value that links externally with the shim: its objects
/// (the façade, the engine, the meter), the allocator routing, and the
/// platform arguments,
/// with unused sections collected as rustc's link collects them.
///
/// The Go command splits `-ldflags` into fields, and the Go linker splits
/// `-extldflags` again, each honouring single and double quotes but no
/// escapes; so each linker argument is single-quoted inside one double-quoted
/// `-extldflags` field, and an argument containing a quote is refused.
pub(super) fn go_ldflags(objects: &[&Path], allocator: &[OsString]) -> Result<String, CliError> {
    let mut linker_args: Vec<&OsStr> = objects.iter().map(|object| object.as_os_str()).collect();
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
    meter: &Path,
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
    let ldflags = go_ldflags(&[object, &shim.engine, meter], allocator)?;
    let experiment = go_env(package_dir, "GOEXPERIMENT")?;
    let mut effective_args = inherited_go_flags(&go_env(package_dir, "GOFLAGS")?);
    effective_args.extend_from_slice(go_args);
    let toolexec = if names_toolexec(&effective_args) {
        None
    } else {
        let executable = std::env::current_exe().map_err(|error| {
            CliError(format!(
                "failed to locate the running cargo-patina: {error}"
            ))
        })?;
        stage_runtime_hooks(package_dir, shim)?
            .map(|hooks| toolexec_value(&executable, &hooks))
            .transpose()?
    };
    let link_dir = tempfile::tempdir()
        .map_err(|error| CliError(format!("failed to create a link directory: {error}")))?;
    let linked = link_dir.path().join(GO_LINK_NAME);
    let mut command = Command::new("go");
    command
        .current_dir(package_dir)
        .env("CGO_ENABLED", "1")
        .env("GOEXPERIMENT", metered_experiment(&experiment))
        .arg("build")
        .arg("-o")
        .arg(&linked)
        .arg("-ldflags")
        .arg(&ldflags)
        .args(toolexec)
        .args(metered_go_args(&effective_args))
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

/// One setting of the Go toolchain `package_dir` builds with (`go env`).
fn go_env(package_dir: &Path, name: &str) -> Result<String, CliError> {
    let output = Command::new("go")
        .current_dir(package_dir)
        .args(["env", name])
        .output()
        .map_err(|error| {
            CliError(format!(
                "failed to run `go env` (is a Go toolchain on PATH?): {error}"
            ))
        })?;
    if !output.status.success() {
        return Err(CliError(format!(
            "`go env {name}` failed in {}: {}",
            package_dir.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
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
        for reserved in ["-ldflags", "--ldflags=-X main.v=1", "-o"] {
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

    #[test]
    fn the_extldflags_field_carries_every_linker_argument_intact() {
        let allocator = [
            OsString::from("-Wl,--wrap=a b"),
            OsString::from("/r/route.o"),
        ];
        let ldflags = go_ldflags(
            &[
                Path::new("/o/facade.o"),
                Path::new("/a/engine.o"),
                Path::new("/o/meter.o"),
            ],
            &allocator,
        )
        .expect("plain paths quote");
        let fields = split_go_quoted(&ldflags);
        assert_eq!(fields[0], "-linkmode=external");
        let extld = fields[1]
            .strip_prefix("-extldflags=")
            .expect("one -extldflags field");
        let mut expected = vec![
            "/o/facade.o",
            "/a/engine.o",
            "/o/meter.o",
            "-Wl,--wrap=a b",
            "/r/route.o",
        ];
        expected.extend(PLATFORM_LINKER_ARGS);
        expected.push("-Wl,--gc-sections");
        assert_eq!(split_go_quoted(extld), expected);
        assert_eq!(fields.len(), 2);
        // A quote cannot be carried through the quoted field, so it is refused.
        assert!(go_ldflags(&[Path::new("/o/it's.o")], &[]).is_err());
    }

    #[test]
    fn the_meter_settings_survive_a_guests_own_tags_and_gcflags() {
        let strings =
            |args: &[&str]| -> Vec<OsString> { args.iter().map(OsString::from).collect() };
        // No tags or gcflags of the guest's: the meter's alone, first.
        assert_eq!(
            metered_go_args(&strings(&["-trimpath"])),
            strings(&["-gcflags=all=-d=libfuzzer", "-tags=libfuzzer", "-trimpath"])
        );
        // Each spelling of the guest's own keeps its values and gains the meter's.
        assert_eq!(
            metered_go_args(&strings(&[
                "-tags",
                "netgo",
                "--gcflags=pkg=-N",
                "-gcflags",
                "-l"
            ])),
            strings(&[
                "-gcflags=all=-d=libfuzzer",
                "-tags",
                "netgo,libfuzzer",
                "-gcflags=pkg=-N -d=libfuzzer",
                "-gcflags",
                "-l -d=libfuzzer",
            ])
        );
        // Both of the Go command's tag-list forms come back comma-separated.
        for (given, metered) in [
            ("'netgo osusergo'", "netgo,osusergo,libfuzzer"),
            ("libfuzzer", "libfuzzer"),
        ] {
            assert_eq!(metered_value("tags", given), metered, "{given}");
        }
        assert_eq!(metered_experiment(""), "preemptibleloops");
        assert_eq!(
            metered_experiment("aliastypeparams"),
            "aliastypeparams,preemptibleloops"
        );
    }

    #[test]
    fn a_metered_go_guest_runs_on_one_p_unless_the_run_names_gomaxprocs() {
        let mut go = vec![0u8; 64 * 1024 - 5];
        go.extend_from_slice(METER_MARKER);
        let plain = vec![0u8; 3 * 64 * 1024];

        let mut environment = std::collections::BTreeMap::new();
        apply_go_guest_defaults(carries_meter(&go), &mut environment);
        assert_eq!(
            environment.get("GOMAXPROCS").map(String::as_str),
            Some(GUEST_GOMAXPROCS)
        );

        let mut chosen = std::collections::BTreeMap::from([("GOMAXPROCS".into(), "4".into())]);
        apply_go_guest_defaults(carries_meter(&go), &mut chosen);
        assert_eq!(chosen.get("GOMAXPROCS").map(String::as_str), Some("4"));

        let mut untouched = std::collections::BTreeMap::new();
        apply_go_guest_defaults(carries_meter(&plain), &mut untouched);
        assert!(untouched.is_empty());
    }

    #[test]
    fn the_runtime_string_hooks_are_rebuilt_without_the_copy() {
        let hook = |name: &str| {
            format!("func {name}(s1, s2 string, fakePC int) {{\n{COPYING_STRING_HOOK}\n}}\n")
        };
        let source = format!(
            "package runtime\n{}{}",
            hook("libfuzzerHookStrCmp"),
            hook("libfuzzerHookEqualFold")
        );
        let metered = metered_runtime_hooks(&source).unwrap();
        assert!(!metered.contains("cstring("));
        assert_eq!(metered.matches(METERED_STRING_HOOK).count(), 2);
        // A toolchain whose hooks Patina does not know keeps them.
        assert_eq!(metered_runtime_hooks("package runtime\n"), None);
    }

    #[test]
    fn goflags_settings_are_merged_rather_than_replaced() {
        let inherited = inherited_go_flags(
            "-mod=mod -tags=netgo '-gcflags=all=-N -l' -count=1 -toolexec=strace",
        );
        assert_eq!(
            inherited,
            ["-tags=netgo", "-gcflags=all=-N -l", "-toolexec=strace"].map(OsString::from)
        );
        // A wrapper named only in GOFLAGS is the guest's.
        assert!(names_toolexec(&inherited));
        // The GOFLAGS tags and gcflags survive the meter's settings.
        let merged = metered_go_args(&inherited);
        assert!(merged.contains(&OsString::from("-tags=netgo,libfuzzer")));
        assert!(merged.contains(&OsString::from("-gcflags=all=-N -l -d=libfuzzer")));
    }

    #[test]
    fn the_hook_tag_keeps_a_development_toolchains_build_id_last() {
        let release = with_hooks_identity("compile version go1.26.2 X:preemptibleloops\n", "t");
        assert_eq!(release.split_whitespace().last(), Some("t"));
        let devel = with_hooks_identity(
            "compile version devel go1.27-abc X:preemptibleloops buildID=a1/b2\n",
            "t",
        );
        let last = devel.split_whitespace().last().unwrap();
        assert!(last.starts_with("buildID="), "{devel}");
        // The content part the Go command keys a development tool by names the tag.
        assert!(last.rsplit('/').next().unwrap().contains('t'), "{devel}");
        assert_ne!(
            devel,
            "compile version devel go1.27-abc X:preemptibleloops buildID=a1/b2"
        );
    }
}
