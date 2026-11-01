//! Python guests: a script or application directory, frozen into a CPython
//! built statically and linked with the shim.
//!
//! A Python program reaches Patina as a native executable, as a Rust or Go one
//! does. CPython is built from source by a fixed recipe ([`RECIPE`]): every
//! extension module statically in `libpython`, none needing a library the
//! recipe does not build, and none of the functions the virtual machine has no
//! model for. The build is cached by source and recipe, so it runs once.
//!
//! The interpreter imports nothing from a filesystem. The standard library and
//! the application (with any `--python-path` roots, such as a virtualenv's
//! site-packages) are compiled to bytecode by the built interpreter itself
//! (`python/freeze.py`) and embedded in the executable, and the launcher
//! (`python/launcher.c`) hands them to CPython as frozen modules before it
//! starts, isolated from the environment. So a run imports the same code
//! everywhere, and the audit sees the whole program: CPython's own imports are
//! the guest's, and an unmodeled one refuses the build's run like any other.
//!
//! The CPython source is the pinned release ([`CPYTHON`]), fetched once and
//! checked against its digest, or the `--python-source` tarball or tree.

use crate::CliError;
use crate::shim_build::{lock_target_dir, patina_cache_root};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The CPython release a Python guest runs by default.
pub(crate) struct Release {
    pub(crate) version: &'static str,
    pub(crate) url: &'static str,
    pub(crate) sha256: &'static str,
}

pub(crate) const CPYTHON: Release = Release {
    version: "3.14.8",
    url: "https://www.python.org/ftp/python/3.14.8/Python-3.14.8.tar.xz",
    sha256: "c2215904f02b175596dc49351585104f4bc20341e1c47378b26a2c274360ce73",
};

const FREEZE_PY: &str = include_str!("../python/freeze.py");
const LAUNCHER_C: &str = include_str!("../python/launcher.c");
const METER_C: &str = include_str!("../python/meter.c");

/// How every C file of a Python guest is compiled: position-independent, with
/// no fortified wrappers (whose `__*_chk` entries the shim does not define),
/// no stack protector (whose canary is, on aarch64 glibc, a variable of the
/// dynamic loader's) and, on aarch64 Linux, atomics inline rather than as calls
/// into libgcc's out-of-line helpers, which the guest does not link.
const C_FLAGS: &[&str] = &[
    "-fPIC",
    "-D_FORTIFY_SOURCE=0",
    "-fno-stack-protector",
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    "-mno-outline-atomics",
];

/// The instrumentation the compute meter (`python/meter.c`) counts, given to
/// every CPython compilation at `make` time: configure's own test programs
/// must link without the meter.
const METER_CFLAGS: &str = "-fsanitize-coverage=trace-cmp";

/// How CPython is configured for a Patina guest.
pub(crate) struct Recipe {
    /// `configure` options.
    pub(crate) options: &'static [&'static str],
    /// Extension modules left out, each group with why.
    pub(crate) modules: &'static [(&'static str, &'static [&'static str])],
    /// Functions `configure` is told the C library lacks, each group with
    /// why. CPython then leaves out what calls them (an `os` function, most
    /// often), or falls back to what the virtual machine models.
    pub(crate) functions: &'static [(&'static str, &'static [&'static str])],
    /// Other `configure` answers (`ac_cv_*`), each group with why.
    pub(crate) answers: &'static [(&'static str, &'static [(&'static str, &'static str)])],
    /// `pyconfig.h` definitions withdrawn after `configure` writes them,
    /// each group with why: what `configure` decides from the platform alone,
    /// with no option or answer to say otherwise.
    pub(crate) withdrawn: &'static [(&'static str, &'static [&'static str])],
}

pub(crate) const RECIPE: Recipe = Recipe {
    options: &[
        "--disable-shared",
        "--without-mimalloc",
        "--without-ensurepip",
        "--disable-test-modules",
    ],
    modules: &[
        (
            "they need a library the recipe does not build, which configure would otherwise find on the host and link dynamically",
            &[
                "_bz2",
                "_lzma",
                "zlib",
                "_ssl",
                "_hashlib",
                "_sqlite3",
                "_ctypes",
                "_curses",
                "_curses_panel",
                "readline",
                "_dbm",
                "_gdbm",
                "_tkinter",
                "_uuid",
                "_zstd",
            ],
        ),
        (
            "they reach what the virtual machine has none of: another process's memory, named semaphores and shared memory, the host's syslog, a terminal, and the group database",
            &[
                "_remote_debugging",
                "_multiprocessing",
                "_posixshmem",
                "syslog",
                "termios",
                "grp",
            ],
        ),
    ],
    functions: &[
        (
            "the virtual machine runs one process: no spawning, no waiting for children, no process groups, sessions or job control, no scheduling policy or priority, no other credentials",
            &[
                "fexecve",
                "posix_spawn",
                "posix_spawnp",
                "vfork",
                "system",
                "wait",
                "wait3",
                "wait4",
                "getpgid",
                "getpgrp",
                "setpgrp",
                "getsid",
                "tcgetpgrp",
                "tcsetpgrp",
                "initgroups",
                "getgroups",
                "getresuid",
                "getresgid",
                "getlogin",
                "getlogin_r",
                "ctermid",
                "nice",
                "getpriority",
                "setpriority",
                "sched_get_priority_max",
                "sched_setscheduler",
                "sched_setparam",
                "sched_rr_get_interval",
                "pthread_getcpuclockid",
                "prlimit",
            ],
        ),
        (
            "it has no terminals",
            &[
                "forkpty",
                "openpty",
                "login_tty",
                "posix_openpt",
                "grantpt",
                "unlockpt",
                "ptsname",
                "ptsname_r",
            ],
        ),
        (
            "it has no host databases (protocols, services, interfaces by index), and no host name to set; gethostbyname_r's absence sends CPython to gethostbyname, which the shim refuses by name",
            &[
                "gethostbyname_r",
                "getprotobyname",
                "getservbyname",
                "getservbyport",
                "if_nameindex",
                "sethostname",
            ],
        ),
        (
            "the shim has no model of them: record locks, path limits, pipe splicing, vectored I/O with flags, configuration strings, the load average, and closing every descriptor from one up",
            &[
                "lockf",
                "pathconf",
                "fpathconf",
                "splice",
                "preadv2",
                "pwritev2",
                "confstr",
                "getloadavg",
                "closefrom",
            ],
        ),
        (
            "CPython's locks then wait on a mutex and condition variable, which the shim schedules, rather than on unnamed semaphores",
            &["sem_timedwait", "sem_clockwait"],
        ),
    ],
    answers: &[
        (
            "the libraries and device files configure would find other spellings of the functions above in",
            &[
                ("ac_cv_lib_util_forkpty", "no"),
                ("ac_cv_lib_bsd_forkpty", "no"),
                ("ac_cv_lib_util_openpty", "no"),
                ("ac_cv_lib_bsd_openpty", "no"),
                ("ac_cv_search_login_tty", "no"),
                ("ac_cv_file__dev_ptmx", "no"),
                ("ac_cv_file__dev_ptc", "no"),
            ],
        ),
        (
            "host libraries the build must not reach: zlib (until the recipe builds it), gettext and the backtrace library",
            &[
                ("ac_cv_header_zlib_h", "no"),
                ("ac_cv_header_libintl_h", "no"),
                ("ac_cv_header_execinfo_h", "no"),
            ],
        ),
    ],
    withdrawn: &[(
        "the perf profiler's trampolines write and run code at run time, flushing the instruction cache through libgcc on aarch64",
        &["PY_HAVE_PERF_TRAMPOLINE"],
    )],
};

impl Recipe {
    /// The environment `configure` runs in: the module and function answers,
    /// a `pkg-config` that finds nothing, and [`C_FLAGS`].
    fn environment(&self) -> Vec<(String, String)> {
        let mut environment = vec![
            ("MODULE_BUILDTYPE".to_owned(), "static".to_owned()),
            ("PKG_CONFIG".to_owned(), "/nonexistent".to_owned()),
            ("CFLAGS".to_owned(), C_FLAGS.join(" ")),
            ("OPT".to_owned(), "-DNDEBUG -O3 -Wall".to_owned()),
        ];
        for (_, modules) in self.modules {
            for module in *modules {
                environment.push((format!("py_cv_module_{module}"), "n/a".to_owned()));
            }
        }
        for (_, functions) in self.functions {
            for function in *functions {
                environment.push((format!("ac_cv_func_{function}"), "no".to_owned()));
            }
        }
        for (_, answers) in self.answers {
            for (name, value) in *answers {
                environment.push(((*name).to_owned(), (*value).to_owned()));
            }
        }
        environment
    }

    /// Everything that decides the build's bytes besides the source.
    fn fingerprint(&self) -> String {
        let mut text = self.options.join(" ");
        for (name, value) in self.environment() {
            text.push_str(&format!("\n{name}={value}"));
        }
        for (_, names) in self.withdrawn {
            for name in *names {
                text.push_str(&format!("\n-{name}"));
            }
        }
        text
    }
}

/// Where CPython's source comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PythonSource {
    /// The pinned release, fetched into the cache.
    Pinned,
    /// `--python-source`: a source tarball, or an unpacked source tree, which
    /// is built out of tree (incrementally).
    Given(PathBuf),
}

/// A Python application to build.
pub(crate) struct PythonApp<'a> {
    /// A `.py` script, or a directory with a `__main__.py`.
    pub(crate) app: &'a Path,
    /// Further module roots, earlier shadowing later.
    pub(crate) paths: &'a [PathBuf],
    pub(crate) source: &'a PythonSource,
}

/// What the Rust link of a Python guest needs: its generated main source and
/// the link arguments, held with the directory they live in.
pub(crate) struct PreparedPython {
    pub(crate) _workspace: tempfile::TempDir,
    /// The CPython build's lock, held until the link has read its outputs.
    pub(crate) _build: fs::File,
    pub(crate) main: PathBuf,
    pub(crate) rustc_args: Vec<OsString>,
}

fn io_error(what: &str, path: &Path, error: std::io::Error) -> CliError {
    CliError(format!("{what} {}: {error}", path.display()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Run `command`, its output into `log`; a failure names the log and its end.
fn run_logged(mut command: Command, what: &str, log: &Path) -> Result<(), CliError> {
    let file = fs::File::create(log).map_err(|error| io_error("failed to create", log, error))?;
    let errors = file
        .try_clone()
        .map_err(|error| io_error("failed to open", log, error))?;
    let status = command
        .stdout(file)
        .stderr(errors)
        .status()
        .map_err(|error| CliError(format!("failed to run {what}: {error}")))?;
    if status.success() {
        return Ok(());
    }
    let text = fs::read_to_string(log).unwrap_or_default();
    let tail: Vec<&str> = text.lines().rev().take(30).collect();
    let tail: Vec<&str> = tail.into_iter().rev().collect();
    Err(CliError(format!(
        "{what} failed ({status}); the log is {}:\n{}",
        log.display(),
        tail.join("\n")
    )))
}

/// The pinned release's tarball in the cache, fetched and checked first if
/// it is not there yet. The download lands in a directory of its own and is
/// moved into place only once its digest matches.
fn pinned_tarball(cache: &Path) -> Result<PathBuf, CliError> {
    let directory = cache.join("downloads").join(CPYTHON.sha256);
    let name = CPYTHON.url.rsplit('/').next().unwrap_or("cpython.tar.xz");
    let tarball = directory.join(name);
    if tarball.is_file() {
        return Ok(tarball);
    }
    let partial = tempfile::Builder::new()
        .prefix(".download-")
        .tempdir_in(created(cache.join("downloads"))?)
        .map_err(|error| CliError(format!("failed to create a download directory: {error}")))?;
    let fetched = partial.path().join(name);
    eprintln!(
        "patina: fetching CPython {} from {}",
        CPYTHON.version, CPYTHON.url
    );
    let status = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--output",
        ])
        .arg(&fetched)
        .arg(CPYTHON.url)
        .status()
        .map_err(|error| CliError(format!("failed to run curl to fetch CPython: {error}")))?;
    if !status.success() {
        return Err(CliError(format!(
            "fetching {} failed ({status}); pass --python-source with a CPython {} source tarball or tree instead",
            CPYTHON.url, CPYTHON.version
        )));
    }
    let bytes = fs::read(&fetched).map_err(|error| io_error("failed to read", &fetched, error))?;
    let digest = sha256_hex(&bytes);
    if digest != CPYTHON.sha256 {
        return Err(CliError(format!(
            "{} has sha256 {digest}, not the pinned {}; refusing it",
            CPYTHON.url, CPYTHON.sha256
        )));
    }
    fs::create_dir_all(&directory)
        .map_err(|error| io_error("failed to create", &directory, error))?;
    fs::rename(&fetched, &tarball)
        .map_err(|error| io_error("failed to install", &tarball, error))?;
    Ok(tarball)
}

/// `directory`, created if it is not there.
fn created(directory: PathBuf) -> Result<PathBuf, CliError> {
    fs::create_dir_all(&directory)
        .map_err(|error| io_error("failed to create", &directory, error))?;
    Ok(directory)
}

/// A tarball unpacked into the cache by its digest: the one top-level
/// directory it holds.
fn unpacked(cache: &Path, tarball: &Path) -> Result<(PathBuf, String), CliError> {
    let bytes = fs::read(tarball).map_err(|error| io_error("failed to read", tarball, error))?;
    let digest = sha256_hex(&bytes);
    let root = cache.join("source").join(&digest);
    let tree = |root: &Path| -> Result<PathBuf, CliError> {
        let mut entries: Vec<PathBuf> = fs::read_dir(root)
            .map_err(|error| io_error("failed to read", root, error))?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.is_dir())
            .collect();
        match (entries.pop(), entries.is_empty()) {
            (Some(tree), true) if tree.join("configure").is_file() => Ok(tree),
            _ => Err(CliError(format!(
                "{} does not unpack to one CPython source tree",
                tarball.display()
            ))),
        }
    };
    // One unpacking per digest at a time: a racing build waits, then finds
    // the tree published.
    let _lock = lock_target_dir(&cache.join("source-locks").join(&digest))?;
    if root.is_dir() {
        return Ok((tree(&root)?, digest));
    }
    let sources = created(cache.join("source"))?;
    let partial = tempfile::Builder::new()
        .prefix(".unpack-")
        .tempdir_in(&sources)
        .map_err(|error| CliError(format!("failed to create an unpack directory: {error}")))?;
    let status = Command::new("tar")
        .arg("-xf")
        .arg(tarball)
        .arg("-C")
        .arg(partial.path())
        .status()
        .map_err(|error| CliError(format!("failed to run tar: {error}")))?;
    if !status.success() {
        return Err(CliError(format!(
            "unpacking {} failed ({status})",
            tarball.display()
        )));
    }
    tree(partial.path())?;
    fs::rename(partial.keep(), &root)
        .map_err(|error| io_error("failed to install", &root, error))?;
    Ok((tree(&root)?, digest))
}

/// A built CPython's build directory, locked.
struct Built {
    build: PathBuf,
    lock: fs::File,
}

impl Built {
    /// The interpreter the build made, run on the host to freeze modules.
    fn interpreter(&self) -> PathBuf {
        let unix = self.build.join("python");
        if unix.is_file() {
            unix
        } else {
            self.build.join("python.exe")
        }
    }

    fn stdlib_blob(&self) -> PathBuf {
        self.build.join("patina-stdlib.bin")
    }

    fn launcher(&self) -> PathBuf {
        self.build.join("patina-launcher.o")
    }

    fn meter(&self) -> PathBuf {
        self.build.join("patina-meter.o")
    }
}

/// The C compiler every compilation of the build uses (`CC`, or `cc`), found
/// on `PATH` once so the cache key names the one that runs.
fn compiler() -> Result<PathBuf, CliError> {
    let cc = PathBuf::from(std::env::var_os("CC").unwrap_or_else(|| "cc".into()));
    if cc.components().count() > 1 {
        return Ok(cc);
    }
    std::env::var_os("PATH")
        .iter()
        .flat_map(std::env::split_paths)
        .map(|directory| directory.join(&cc))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| CliError(format!("no C compiler {} on PATH", cc.display())))
}

/// The C compiler's identity, which the build's bytes depend on.
fn compiler_identity(cc: &Path) -> Result<String, CliError> {
    let output = Command::new(cc)
        .arg("--version")
        .output()
        .map_err(|error| {
            CliError(format!(
                "failed to run the C compiler {}: {error}",
                cc.display()
            ))
        })?;
    Ok(format!(
        "{}\n{}",
        cc.display(),
        String::from_utf8_lossy(&output.stdout)
    ))
}

/// A command that sees only the environment the build decides: the host's
/// `PATH`, `HOME` and `TMPDIR` (where its tools are, and where they keep
/// state) and `CC`, and none of the variables `configure` and `make` would
/// otherwise take flags, libraries or site defaults from.
fn controlled(program: impl AsRef<std::ffi::OsStr>, cc: &Path) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    for name in ["PATH", "HOME", "TMPDIR"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.env("CC", cc);
    command
}

/// CPython built by [`RECIPE`], with its frozen standard library and the
/// compiled launcher, in the cache by source and recipe. A tree source is
/// rebuilt incrementally on every build; a tarball's build is reused once it
/// finished.
fn built_cpython(cache: &Path, source: &PythonSource) -> Result<Built, CliError> {
    let (tree, source_key, reusable) = match source {
        PythonSource::Pinned => {
            let tarball = pinned_tarball(cache)?;
            let (tree, digest) = unpacked(cache, &tarball)?;
            (tree, digest, true)
        }
        PythonSource::Given(tarball) if !tarball.is_dir() => {
            let (tree, digest) = unpacked(cache, tarball)?;
            (tree, digest, true)
        }
        PythonSource::Given(tree) => {
            let tree = std::path::absolute(tree)
                .map_err(|error| io_error("failed to resolve", tree, error))?;
            if !tree.join("configure").is_file() {
                return Err(CliError(format!(
                    "--python-source {} is not a CPython source tree (no configure)",
                    tree.display()
                )));
            }
            let key = format!("tree:{}", tree.display());
            (tree, key, false)
        }
    };
    let cc = compiler()?;
    let key = sha256_hex(
        format!(
            "{source_key}\n{}\n{}\n{FREEZE_PY}\n{LAUNCHER_C}\n{METER_C}\n{METER_CFLAGS}\n{}",
            RECIPE.fingerprint(),
            compiler_identity(&cc)?,
            env!("PATINA_BUILD_TARGET"),
        )
        .as_bytes(),
    );
    let build = cache.join("build").join(&key[..32]);
    let built = Built {
        lock: lock_target_dir(&build)?,
        build: build.clone(),
    };
    let done = build.join(".patina-built");
    if reusable && done.is_file() {
        return Ok(built);
    }
    if !build.join("Makefile").is_file() {
        eprintln!(
            "patina: building CPython from {} (once per source and recipe; this takes a few minutes)",
            tree.display()
        );
        let mut configure = controlled(tree.join("configure"), &cc);
        configure
            .current_dir(&build)
            .args(RECIPE.options)
            .arg("--prefix=/python")
            .envs(RECIPE.environment());
        run_logged(
            configure,
            "CPython's configure",
            &build.join("patina-configure.log"),
        )?;
    }
    withdraw(&build.join("pyconfig.h"), RECIPE.withdrawn)?;
    let meter = build.join("patina-meter.c");
    fs::write(&meter, METER_C).map_err(|error| io_error("failed to write", &meter, error))?;
    let inert = build.join("patina-meter-inert.o");
    compile_c(
        &meter,
        &inert,
        &["-DPATINA_PYTHON_METER_INERT"],
        &build,
        &cc,
        "the inert compute meter",
    )?;
    let jobs = std::thread::available_parallelism().map_or(4, usize::from);
    let mut make = controlled("make", &cc);
    make.current_dir(&build)
        .arg(format!("-j{jobs}"))
        .arg(format!("EXTRA_CFLAGS={METER_CFLAGS}"))
        .arg(format!("LDFLAGS_NODIST={}", inert.display()));
    run_logged(make, "CPython's make", &build.join("patina-make.log"))?;

    let freeze = build.join("patina-freeze.py");
    fs::write(&freeze, FREEZE_PY).map_err(|error| io_error("failed to write", &freeze, error))?;
    let mut stdlib = Command::new(built.interpreter());
    stdlib
        .arg("-I")
        .arg(&freeze)
        .arg("--stdlib")
        .arg(built.stdlib_blob())
        .arg(tree.join("Lib"));
    // The build's generated modules (`_sysconfigdata_*`).
    for entry in fs::read_dir(build.join("build"))
        .map_err(|error| io_error("failed to read", &build, error))?
    {
        let path = entry
            .map_err(|error| io_error("failed to read", &build, error))?
            .path();
        if path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("lib."))
        {
            stdlib.arg(path);
        }
    }
    run_logged(
        stdlib,
        "freezing the standard library",
        &build.join("patina-freeze.log"),
    )?;

    let launcher = build.join("patina-launcher.c");
    fs::write(&launcher, LAUNCHER_C)
        .map_err(|error| io_error("failed to write", &launcher, error))?;
    let include = |path: &Path| {
        let mut flag = OsString::from("-I");
        flag.push(path);
        flag
    };
    compile_c(
        &launcher,
        &built.launcher(),
        &[
            include(&build),
            include(&tree.join("Include")),
            OsString::from("-Wno-unused-parameter"),
        ],
        &build,
        &cc,
        "the Python launcher",
    )?;
    compile_c(
        &meter,
        &built.meter(),
        &[] as &[&str],
        &build,
        &cc,
        "the compute meter",
    )?;
    fs::write(&done, b"").map_err(|error| io_error("failed to write", &done, error))?;
    Ok(built)
}

/// Remove the `withdrawn` definitions from `configure`'s `pyconfig.h`, once.
fn withdraw(pyconfig: &Path, withdrawn: &[(&str, &[&str])]) -> Result<(), CliError> {
    let text = fs::read_to_string(pyconfig)
        .map_err(|error| io_error("failed to read", pyconfig, error))?;
    let names: Vec<&str> = withdrawn
        .iter()
        .flat_map(|(_, names)| names.iter().copied())
        .collect();
    let kept: String = text
        .split_inclusive('\n')
        .filter(|line| {
            let mut words = line.split_whitespace();
            !(words.next() == Some("#define")
                && words.next().is_some_and(|name| names.contains(&name)))
        })
        .collect();
    // Unchanged, the header keeps its time, so `make` rebuilds nothing.
    if kept == text {
        return Ok(());
    }
    fs::write(pyconfig, kept).map_err(|error| io_error("failed to write", pyconfig, error))
}

/// Compile one C file of Patina's into `object`, its output logged beside it.
fn compile_c<S: AsRef<std::ffi::OsStr>>(
    source: &Path,
    object: &Path,
    flags: &[S],
    build: &Path,
    cc: &Path,
    what: &str,
) -> Result<(), CliError> {
    let mut compile = controlled(cc, cc);
    compile
        .args(C_FLAGS)
        .args(["-c", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .args(flags)
        .arg(source)
        .arg("-o")
        .arg(object);
    let log = build.join(format!(
        "{}.log",
        object
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    run_logged(compile, &format!("compiling {what}"), &log)
}

/// The static libraries the CPython build made: `libpython` first, then the
/// libraries its modules link (`Modules/**/*.a`), as the link needs them.
fn static_libraries(build: &Path) -> Result<Vec<PathBuf>, CliError> {
    let mut libpython = Vec::new();
    for entry in fs::read_dir(build).map_err(|error| io_error("failed to read", build, error))? {
        let path = entry
            .map_err(|error| io_error("failed to read", build, error))?
            .path();
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.starts_with("libpython") && name.ends_with(".a") {
            libpython.push(path);
        }
    }
    if libpython.len() != 1 {
        return Err(CliError(format!(
            "the CPython build in {} made {} libpython archives, not one",
            build.display(),
            libpython.len()
        )));
    }
    let mut modules = Vec::new();
    let mut pending = vec![build.join("Modules")];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| io_error("failed to read", &directory, error))?
        {
            let path = entry
                .map_err(|error| io_error("failed to read", &directory, error))?
                .path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "a") {
                modules.push(path);
            }
        }
    }
    modules.sort();
    libpython.extend(modules);
    Ok(libpython)
}

/// The Rust main a Python guest links: the frozen blobs embedded, handed to
/// the launcher with the program's arguments.
fn main_source(app: &Path, stdlib: &Path) -> String {
    format!(
        r#"//! Generated by `cargo patina build --python`.
static APP: &[u8] = include_bytes!({app:?});
static STDLIB: &[u8] = include_bytes!({stdlib:?});

unsafe extern "C" {{
    fn patina_python_main(
        argc: std::ffi::c_int,
        argv: *mut *mut std::ffi::c_char,
        app: *const u8,
        app_length: usize,
        stdlib: *const u8,
        stdlib_length: usize,
    ) -> std::ffi::c_int;
}}

fn main() {{
    use std::os::unix::ffi::OsStringExt;
    let arguments: Vec<std::ffi::CString> = std::env::args_os()
        .map(|argument| std::ffi::CString::new(argument.into_vec()).expect("an argument holds no NUL"))
        .collect();
    let mut argv: Vec<*mut std::ffi::c_char> =
        arguments.iter().map(|argument| argument.as_ptr().cast_mut()).collect();
    argv.push(std::ptr::null_mut());
    // SAFETY: argv is NUL-terminated and outlives the call; the blobs are
    // the frozen modules the launcher reads.
    let code = unsafe {{
        patina_python_main(
            arguments.len() as std::ffi::c_int,
            argv.as_mut_ptr(),
            APP.as_ptr(),
            APP.len(),
            STDLIB.as_ptr(),
            STDLIB.len(),
        )
    }};
    std::process::exit(code);
}}
"#
    )
}

/// Build (or reuse) CPython, freeze the application, and generate the Rust
/// main and link arguments the shim link takes.
pub(crate) fn prepare_python_app(app: PythonApp<'_>) -> Result<PreparedPython, CliError> {
    if !cfg!(target_os = "linux") {
        return Err(CliError(
            "Python guests build on Linux only: CPython reaches C library calls (resource limits, signal masks, select, the password database, Apple's system log, Mach memory) the shim models on Linux and not yet on Darwin".into(),
        ));
    }
    let cache = patina_cache_root()?.join("python");
    let built = built_cpython(&cache, app.source)?;
    let workspace = tempfile::tempdir()
        .map_err(|error| CliError(format!("failed to create a build workspace: {error}")))?;
    let frozen = workspace.path().join("app.bin");
    let freeze = workspace.path().join("freeze.py");
    fs::write(&freeze, FREEZE_PY).map_err(|error| io_error("failed to write", &freeze, error))?;
    let mut command = Command::new(built.interpreter());
    command
        .arg("-I")
        .arg(&freeze)
        .arg("--app")
        .arg(app.app)
        .arg(&frozen)
        .args(app.paths);
    let status = command
        .status()
        .map_err(|error| CliError(format!("failed to run the built CPython: {error}")))?;
    if !status.success() {
        return Err(CliError(format!(
            "freezing {} failed ({status})",
            app.app.display()
        )));
    }
    let main = workspace.path().join("main.rs");
    fs::write(&main, main_source(&frozen, &built.stdlib_blob()))
        .map_err(|error| io_error("failed to write", &main, error))?;
    let mut rustc_args = Vec::new();
    let mut link = |arg: &Path| {
        rustc_args.push(OsString::from("-C"));
        rustc_args.push(crate::shim_build::link_arg(arg));
    };
    link(&built.launcher());
    link(&built.meter());
    for library in static_libraries(&built.build)? {
        link(&library);
    }
    rustc_args.push(OsString::from("-C"));
    rustc_args.push(OsString::from("link-arg=-lm"));
    Ok(PreparedPython {
        _workspace: workspace,
        _build: built.lock,
        main,
        rustc_args,
    })
}

#[cfg(test)]
#[path = "python_build/tests.rs"]
mod tests;
