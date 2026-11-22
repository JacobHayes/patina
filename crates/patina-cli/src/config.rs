//! The resolved configuration of a run: defaults, then `patina.toml`, then the environment
//! defaults, then flags. One struct; the launcher consumes it and `run.json` stores it, so a
//! replay needs neither the file nor the flags. Expert settings are config keys only.

use crate::cli::{Args, Res};
use crate::durability::materialise::Model;
use crate::faults;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The CPU count a guest is told it has when `[run] cpus` is not given: a fixed number, not the
/// host's, so that a run (Go's GOMAXPROCS, thread pools sized from it) is the same on any host.
/// Four: enough worker threads for the races of a small server, few enough that idle workers
/// polling for work (Go's Ps, tokio's workers) do not dominate the schedule.
pub const DEFAULT_CPUS: u64 = 4;
/// The most `[run] cpus` can give: the guest's affinity mask is one word.
pub const MAX_CPUS: u64 = 64;

/// The MiB a run's logs may hold when `[run] log-limit` is not given. A run that has not ended by
/// then is almost always a livelock (a loop of switches or calls that never finishes), and its
/// log fills the disk quickly (hundreds of MB a second); a long, real run raises it.
pub const DEFAULT_LOG_LIMIT_MIB: u64 = 1024;

/// Directories the program's bare name is looked up in, as the guest's `PATH` is.
pub const GUEST_PATH: [&str; 4] = ["/guest", "/usr/local/bin", "/usr/bin", "/bin"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    pub src: PathBuf,
    pub dst: String,
    pub copy: bool,
}

/// Where threads are preempted beyond system calls and spin hints (`[sched] preempt`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Preempt {
    /// Also at load-time points: stock code is rewritten as it is mapped (ARCHITECTURE.md,
    /// "Load-time rewriting"), with walks past them.
    #[default]
    Points,
    /// Only at system calls, spin hints and spin probes.
    Traps,
}

impl Preempt {
    pub fn points(self) -> bool {
        self == Preempt::Points
    }
}

/// Everything a run is given. Paths are absolute.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    pub seed: u64,
    pub cmd: Vec<String>,
    /// `K=V`, in order; a later key replaces an earlier one.
    pub env: Vec<String>,
    pub mounts: Vec<Mount>,
    pub disk: Option<PathBuf>,
    /// Where the disk is in the guest (`--disk DIR:GUEST`); none is `/work`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_at: Option<String>,
    pub stdin: Option<PathBuf>,
    pub cpus: u64,
    /// Virtual seconds.
    pub time_limit: u64,
    /// Wall seconds.
    pub timeout: u64,
    /// MiB the run's logs may hold, every boot together (`[run] log-limit`).
    pub log_limit: u64,
    /// `patina explain`'s replay: observations of data calls beside the log, outside the
    /// digest (`proto::ctl::Config::observe`). Never part of a run's settings or `run.json`.
    #[serde(skip)]
    pub observe: bool,
    /// `patina debug`'s replay: the sequence number to stop the world before
    /// (`proto::ctl::Config::debug`). Never part of a run's settings or `run.json`.
    #[serde(skip)]
    pub debug_at: Option<u64>,
    /// Size of each sandbox tmpfs in bytes (`[run] disk-mb`, in MiB).
    pub tmpfs_bytes: u64,
    /// Fault classes (`--faults`, `[faults] faults`), each `CLASS[,CLASS][@MACHINE,...]`.
    pub fault_classes: Vec<String>,
    /// `KEY=VALUE[@MACHINE,...]` fault settings, in order; they replace a class's.
    pub faults: Vec<String>,
    /// SDK labels and fault classes a sweep or report may find unmet without calling the
    /// result vacuous (`[sweep] allow-unmet`).
    pub allow_unmet: Vec<String>,
    pub fs_model: String,
    pub preempt_permille: u64,
    /// CPU time a thread may compute without a boundary event while another waits, before the
    /// run ends `compute-stall` (test input `STALL_MS`).
    pub stall_ms: u64,
    /// Every executed pause hint (`pause`; on arm64 `yield`, `wfe`, `wfi`, `isb`) is a
    /// scheduling point (test input `PAUSE_POINTS`).
    pub pause_points: bool,
    /// arm64: answer `RNDR`/`RNDRRS` from the seed and advertise them on a host without them
    /// (test input `EMULATE_RNDR`: the default follows the host).
    pub emulate_rndr: bool,
    /// Spin probes for a thread that computes without a boundary event (test input
    /// `SPIN_PROBES`).
    pub spin_probes: bool,
    /// Where threads are preempted (`[sched] preempt`).
    pub preempt: Preempt,
    /// Load-time points: the longest walk past a switch point, `W` or `A..B` drawn per seed
    /// (test input `COMPUTE_WALK`; default `proto::compute::WALK_DEFAULT`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compute_walk: Option<String>,
    /// The checker run after a run that ended ok (`--check`, `[run] check`; `check.rs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<crate::check::Check>,
    /// Guest exit statuses that end the run `ok` (`--ok-exit`, `[run] ok-exit`): the program
    /// failed cleanly, as it documents. Never 0, never a signal. Sorted, unconditional first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ok_exit: Vec<OkExit>,
    /// The sweep's known findings when `--known` is not given (`[sweep] known`): not a setting
    /// of the run, so not in `run.json`.
    #[serde(skip)]
    pub known: Option<PathBuf>,
    /// With `--crash-points` and machines, the second crashes after each first one (`[sweep]
    /// crash-pairs`): a setting of the sweep, not of a run.
    #[serde(skip)]
    pub crash_pairs: Option<usize>,
    /// Wall seconds the checker may run (`[run] check-timeout`), set on the checker once it is
    /// resolved.
    #[serde(skip)]
    pub check_timeout: Option<u64>,
    /// The case of a sweep's `--cases` run (set by the sweep), kept so that a replay or a
    /// rerun from `run.json` is the same case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case: Option<RunCase>,
    /// The machines besides main (`[machine.NAME]`), in declaration order: machine 1 upward.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub machines: Vec<Machine>,
    /// Main's `ready` probe (`[machine.main] ready`; empty: none).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ready: Vec<String>,
    /// Main's own `[machine.main]` keys, as a machine's (`Machine`): its environment, added to
    /// the run's; `faults = false`; its `disk-mb` and `max-boots`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub main_env: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub main_no_faults: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main_disk_mb: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main_max_boots: Option<u64>,
}

/// One machine of a run with several machines (`proto::machine`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Machine {
    pub name: String,
    /// `run`: the command Patina starts at each of its boots.
    pub run: Vec<String>,
    /// `K=V`, added to the run's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// The host directory copied into its disk at its start, and the tree's guest path
    /// (`work = "DIR[:GUEST]"`, as `--disk`; no `GUEST`: `/work`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_at: Option<String>,
    /// `restart`: `crash` (`None`), `always` or `never`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart: Option<String>,
    /// `ok-exit`: exit statuses of its command that stop it without a finding (none: `[0]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok_exit: Option<Vec<u8>>,
    /// `max-boots`: its boots (none: the run's `max-boots`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_boots: Option<u64>,
    /// `faults = false`: none of the seed's faults: a setting given without a scope
    /// (`--faults`, `--fault`) leaves it out, a scope may not name it, and the link faults and
    /// partitions leave its links alone.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_faults: bool,
    /// `disk-mb`: the size of its disk, `/tmp` and `/dev/shm` in MiB, `N` or `A..B`
    /// drawn per seed (`Config::machine_disk_bytes`; none: the run's `[run] disk-mb`, which it
    /// may not exceed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_mb: Option<String>,
    /// `ready`: the probe run on it every 100 ms of virtual time at its first boot until it
    /// exits 0 (`sup::ready`; empty: ready once started).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ready: Vec<String>,
}

impl Machine {
    pub fn new(name: String, run: Vec<String>) -> Machine {
        Machine {
            name,
            run,
            env: vec![],
            disk: None,
            disk_at: None,
            restart: None,
            ok_exit: None,
            max_boots: None,
            no_faults: false,
            disk_mb: None,
            ready: vec![],
        }
    }

    pub fn disk_path(&self) -> &str {
        self.disk_at.as_deref().unwrap_or("/work")
    }
}

/// The most machines besides main.
pub const MAX_MACHINES: usize = proto::machine::MAX_MACHINES - 1;

/// A sweep case, as its run records it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunCase {
    /// Its id: the line's `--name`, or its line number.
    pub id: String,
    /// The line as written, settings included.
    pub line: String,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            seed: 0,
            cmd: vec![],
            env: vec![],
            mounts: vec![],
            disk: None,
            disk_at: None,
            stdin: None,
            cpus: DEFAULT_CPUS,
            time_limit: 3600,
            timeout: 600,
            log_limit: DEFAULT_LOG_LIMIT_MIB,
            observe: false,
            debug_at: None,
            tmpfs_bytes: 256 << 20,
            fault_classes: vec![],
            faults: vec![],
            allow_unmet: vec![],
            fs_model: Model::Ext4Ordered.name().into(),
            preempt_permille: 100,
            stall_ms: 10_000,
            pause_points: true,
            emulate_rndr: false,
            spin_probes: true,
            preempt: Preempt::default(),
            compute_walk: None,
            check: None,
            ok_exit: vec![],
            known: None,
            crash_pairs: None,
            check_timeout: None,
            case: None,
            machines: vec![],
            ready: vec![],
            main_env: vec![],
            main_no_faults: false,
            main_disk_mb: None,
            main_max_boots: None,
        }
    }
}

/// The program a run executes: where it is on the host, where the guest runs it from, and
/// its SHA-256 (checked by replay).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Program {
    /// The file, symlinks resolved.
    pub host: PathBuf,
    pub guest: String,
    /// Copied to `/guest/<name>` at start.
    pub copied: bool,
    /// The host directory (symlinks resolved) mounted read-only at the guest path's
    /// directory: a program given by a host path runs from where it was given.
    pub dir: Option<PathBuf>,
    pub sha256: String,
}

/// What the launcher runs: the configuration, its program and the parsed plans.
#[derive(Clone, Debug)]
pub struct Opts {
    pub cfg: Config,
    pub program: Program,
    pub plan: faults::Plan,
    pub fs_model: Model,
    /// Each machine's program (`cfg.machines` order).
    pub machine_programs: Vec<Program>,
}

fn expand(base: &Path, p: &str) -> PathBuf {
    let p = match p.strip_prefix("~/") {
        Some(rest) => std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join(rest))
            .unwrap_or_else(|| PathBuf::from(p)),
        None => PathBuf::from(p),
    };
    let p = if p.is_absolute() { p } else { base.join(p) };
    std::path::absolute(&p).unwrap_or(p)
}

fn existing(base: &Path, what: &str, p: &str) -> Res<PathBuf> {
    let full = expand(base, p);
    std::fs::canonicalize(&full).map_err(|e| format!("{what} {p}: {e}"))
}

/// Why a mount or the disk cannot be at guest path `dst`, if it cannot: it would shadow
/// what the sandbox needs.
fn shadows(dst: &str) -> Option<String> {
    let under = |r: &str| dst == r || dst.starts_with(&format!("{r}/"));
    if dst == "/" {
        return Some("/ is the sandbox's root".into());
    }
    for r in ["/usr", "/bin", "/lib", "/lib64", "/sbin"] {
        if under(r) {
            return Some(format!(
                "{r} holds the sandbox's programs and libraries (the host's /usr)"
            ));
        }
    }
    for r in ["/proc", "/sys", "/dev"] {
        if under(r) {
            return Some(format!("{r} is the kernel's, made by the sandbox"));
        }
    }
    if under("/.patina") {
        return Some("/.patina is Patina's own".into());
    }
    for r in ["/etc", "/tmp"] {
        if dst == r {
            return Some(format!(
                "{r} itself is the sandbox's (a path under it can be mounted)"
            ));
        }
    }
    for r in crate::launch::GENERATED_ETC {
        if under(r) {
            return Some(format!("{r} is generated by the sandbox"));
        }
    }
    None
}

/// A guest path as `--mount` and `--disk` take it: absolute, without `.` or `..`, not `/`,
/// no trailing slash.
fn guest_path(what: &str, dst: &str) -> Res<String> {
    let p = Path::new(dst);
    if !p.is_absolute()
        || dst == "/"
        || p.components().any(|c| {
            !matches!(
                c,
                std::path::Component::Normal(_) | std::path::Component::RootDir
            )
        })
    {
        return Err(format!(
            "{what}: {dst} must be an absolute path without . or .."
        ));
    }
    let dst = dst.trim_end_matches('/').to_string();
    if let Some(why) = shadows(&dst) {
        return Err(format!(
            "{what}: {dst} would shadow what the sandbox needs: {why}"
        ));
    }
    Ok(dst)
}

/// `--disk DIR[:GUEST]` (DIR may be empty: an empty tree at GUEST).
fn disk_arg(base: &Path, what: &str, s: &str) -> Res<(Option<PathBuf>, Option<String>)> {
    let (dir, at) = match s.rsplit_once(':') {
        Some((d, g)) if g.starts_with('/') => (d, Some(g)),
        _ => (s, None),
    };
    let dir = match dir {
        "" if at.is_some() => None,
        d => {
            let d = existing(base, what, d)?;
            if !d.is_dir() {
                return Err(format!("{what} {}: not a directory", d.display()));
            }
            Some(d)
        }
    };
    let at = match at {
        Some(g) => {
            let g = guest_path(&format!("{what} {s}"), g)?;
            if g.len() >= proto::ctl::WORK_PATH_MAX {
                return Err(format!(
                    "{what} {s}: the guest path is at most {} bytes",
                    proto::ctl::WORK_PATH_MAX - 1
                ));
            }
            (g != "/work").then_some(g)
        }
        None => None,
    };
    Ok((dir, at))
}

fn mount(base: &Path, s: &str) -> Res<Mount> {
    let (rest, copy) = match s.strip_suffix(":copy") {
        Some(r) => (r, true),
        None => (s, false),
    };
    let (src, dst) = rest
        .rsplit_once(':')
        .ok_or_else(|| format!("--mount {s}: expected SRC:DST[:copy]"))?;
    let src = existing(base, "--mount", src)?;
    let dst = guest_path(&format!("--mount {s}"), dst)?;
    if copy && !src.is_dir() {
        return Err(format!("--mount {s}: :copy takes a directory"));
    }
    Ok(Mount { src, dst, copy })
}

/// The SHA-256 of a file, as hex. A large file's hash is kept in the cache directory under its
/// file identity (device, inode, size, change time), which any rewrite changes, as for the
/// patina binary's own (`result::build`): every run of a sweep hashes its program and checker
/// again, and an interpreter can be a large file.
pub fn sha256_file(p: &Path) -> Res<String> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt;
    const CACHED_FROM: u64 = 1 << 20;
    let m = std::fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let at = crate::launch::cache_dir()
        .join("sha256")
        .join(format!("{}-{}", m.dev(), m.ino()));
    let key = format!("{} {}.{}", m.size(), m.ctime(), m.ctime_nsec());
    if m.size() >= CACHED_FROM {
        let cached = std::fs::read_to_string(&at).ok().and_then(|t| {
            let (k, h) = t.rsplit_once(' ')?;
            (k == key && h.len() == 64).then(|| h.to_string())
        });
        if let Some(h) = cached {
            return Ok(h);
        }
    }
    let b = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let h: String = Sha256::digest(&b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect();
    if m.size() >= CACHED_FROM {
        // Best effort, written whole then renamed: a reader sees the old entry or the new one.
        let tmp = at.with_extension(format!("{}", std::process::id()));
        let _ = std::fs::create_dir_all(at.parent().unwrap())
            .and_then(|_| std::fs::write(&tmp, format!("{key} {h}")))
            .and_then(|_| std::fs::rename(&tmp, &at));
    }
    Ok(h)
}

/// Resolve `CMD` as the guest will see it. A path inside a mount is the guest's; another
/// path is the host's: under `/usr` it is run in place, elsewhere the one file is copied to
/// `/guest/<name>`. A bare name is looked up on the guest's `PATH`.
pub fn program(cmd0: &str, mounts: &[Mount]) -> Res<Program> {
    let file = |host: PathBuf, guest: String, copied: bool| -> Res<Program> {
        let md = std::fs::metadata(&host).map_err(|e| format!("program {cmd0}: {e}"))?;
        if !md.is_file() {
            return Err(format!("program {cmd0}: not a regular file"));
        }
        let sha256 = sha256_file(&host)?;
        Ok(Program {
            host,
            guest,
            copied,
            dir: None,
            sha256,
        })
    };
    if cmd0.is_empty() {
        return Err("program: empty command".into());
    }
    if !cmd0.contains('/') {
        for dir in GUEST_PATH {
            let hosts: Vec<PathBuf> = if dir == "/guest" {
                mounts
                    .iter()
                    .filter(|m| m.dst == "/guest")
                    .map(|m| m.src.join(cmd0))
                    .collect()
            } else {
                vec![Path::new(dir).join(cmd0)]
            };
            for h in hosts {
                if h.is_file() {
                    return file(h, format!("{dir}/{cmd0}"), false);
                }
            }
        }
        return Err(format!(
            "program {cmd0}: not found on the guest PATH ({})",
            GUEST_PATH.join(":")
        ));
    }
    let under = |p: &str, d: &str| p == d || p.strip_prefix(d).is_some_and(|r| r.starts_with('/'));
    let in_sandbox = |d: &str| d == "/" || crate::launch::SANDBOX_ROOTS.iter().any(|r| under(d, r));
    if cmd0.starts_with('/') {
        for m in mounts {
            if let Some(rest) = cmd0.strip_prefix(&format!("{}/", m.dst)) {
                let mut p = file(m.src.join(rest), cmd0.to_string(), false)?;
                // A path through a symlink in the mount (a build directory linked elsewhere)
                // reaches a place no mount covers: the program's directory goes there.
                let dir = Path::new(cmd0).parent().unwrap_or(Path::new("/"));
                let at = guest_resolve(&dir.display().to_string(), mounts);
                if !mounts.iter().any(|m| under(&at, &m.dst)) && !in_sandbox(&at) {
                    p.dir = std::fs::canonicalize(m.src.join(rest))
                        .ok()
                        .and_then(|f| f.parent().map(Path::to_path_buf));
                }
                return Ok(p);
            }
        }
    }
    let host = logical(cmd0);
    let canon = std::fs::canonicalize(&host).map_err(|e| format!("program {cmd0}: {e}"))?;
    if canon.starts_with("/usr/") {
        let guest = if cmd0.starts_with('/') {
            cmd0.to_string()
        } else {
            canon.display().to_string()
        };
        return file(canon, guest, false);
    }
    // Run from where it was given (programs find their siblings by their own path): its
    // directory, read-only at that path. Where that path is the sandbox's own, or holds a
    // mount, or the file is a symlink out of its directory, the one file is copied to /guest.
    let dir = host.parent().unwrap_or(Path::new("/"));
    let gdir = dir.display().to_string();
    let placed = !in_sandbox(&gdir) && !mounts.iter().any(|m| under(&m.dst, &gdir));
    let cdir = std::fs::canonicalize(dir).ok();
    if let Some(cdir) = cdir.filter(|c| placed && canon.parent() == Some(c.as_path())) {
        let mut p = file(canon, host.display().to_string(), false)?;
        p.dir = Some(cdir);
        return Ok(p);
    }
    let name = host
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("program {cmd0}: no file name"))?
        .to_string();
    file(canon, format!("/guest/{name}"), true)
}

/// Where the guest's kernel reaches when it walks `p`: a symlink inside a mount (the mount's
/// host directory holds it) is followed, as the guest would follow it, to a path that may be
/// outside every mount (`target -> /cache/build`). A mount there is placed at that path,
/// so that the path as given works in the guest.
pub fn guest_resolve(p: &str, mounts: &[Mount]) -> String {
    let under = |p: &str, d: &str| p == d || p.strip_prefix(d).is_some_and(|r| r.starts_with('/'));
    let mut path = p.to_string();
    for _ in 0..40 {
        let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        let mut cur = String::new();
        let mut next = None;
        for (i, c) in comps.iter().enumerate() {
            cur = format!("{cur}/{c}");
            let Some(m) = mounts.iter().rev().find(|m| under(&cur, &m.dst)) else {
                continue;
            };
            let host = m.src.join(cur[m.dst.len()..].trim_start_matches('/'));
            if let Ok(t) = std::fs::read_link(&host) {
                let base = Path::new(&cur).parent().unwrap_or(Path::new("/"));
                let mut t = if t.is_absolute() { t } else { base.join(t) };
                for r in &comps[i + 1..] {
                    t.push(r);
                }
                next = Some(logical(&t.display().to_string()).display().to_string());
                break;
            }
        }
        match next {
            Some(n) => path = n,
            None => return path,
        }
    }
    path
}

/// `p` absolute as the user means it: relative to the shell's working directory (`$PWD` when
/// it names the current directory, so a path through a symlinked directory keeps that
/// directory's name), with `.` and `..` removed by name. Symlinks are not resolved.
pub fn logical(p: &str) -> PathBuf {
    let path = Path::new(p);
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        let cwd = std::env::current_dir().unwrap_or_default();
        let pwd = std::env::var_os("PWD")
            .map(PathBuf::from)
            .filter(|d| d.is_absolute() && same_file(d, &cwd))
            .unwrap_or(cwd);
        pwd.join(path)
    };
    let mut out = PathBuf::from("/");
    for c in joined.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::Normal(n) => out.push(n),
            _ => {}
        }
    }
    out
}

fn same_file(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(x), Ok(y)) => (x.dev(), x.ino()) == (y.dev(), y.ino()),
        _ => false,
    }
}

fn table<'a>(v: &'a toml::Value, at: &str) -> Res<&'a toml::Table> {
    v.as_table()
        .ok_or_else(|| format!("{at}: expected a table"))
}

/// One `--ok-exit` status: `N`, or `N:CLASS[,CLASS...]`, which ends a run `ok` only when one of
/// the fault classes injected in it (`report::fired`: a class of `faults.counts`, or
/// `buggify:LABEL`). Written in `run.json` as the number, or as that text.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OkExit {
    /// Empty: always. Sorted.
    pub when: Vec<String>,
    pub status: u8,
}

impl std::fmt::Display for OkExit {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.status)?;
        if !self.when.is_empty() {
            write!(f, ":{}", self.when.join(","))?;
        }
        Ok(())
    }
}

impl Serialize for OkExit {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.when.is_empty() {
            s.serialize_u8(self.status)
        } else {
            s.serialize_str(&self.to_string())
        }
    }
}

impl<'de> Deserialize<'de> for OkExit {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<OkExit, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            N(u8),
            S(String),
        }
        match Raw::deserialize(d)? {
            Raw::N(n) => Ok(OkExit {
                status: n,
                when: vec![],
            }),
            Raw::S(t) => ok_exit_list(&t, "ok-exit").and_then(|l| match l.as_slice() {
                [one] => Ok(one.clone()),
                _ => Err(format!("ok-exit: {t:?} is not one status")),
            }),
        }
        .map_err(serde::de::Error::custom)
    }
}

/// `--ok-exit any`: every exit status (a reference sweep of a program whose failures are
/// its output); a signal still ends a run `crash`.
pub fn ok_exit_any() -> Vec<OkExit> {
    (1..=255)
        .map(|status| OkExit {
            status,
            when: vec![],
        })
        .collect()
}

/// `N[,N...]`, where an `N:CLASS` item makes N conditional and the names after it (up to the
/// next number) are more classes of the same condition: `1,5:fs-error,fsync-error`.
pub fn ok_exit_list(l: &str, at: &str) -> Res<Vec<OkExit>> {
    let mut out: Vec<OkExit> = vec![];
    for item in l.split(',').map(str::trim) {
        // `N`, `N:CLASS`, or a CLASS extending the condition before it (`buggify:LABEL` too).
        let digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
        let (n, class) = match item.split_once(':') {
            Some((n, c)) if digits(n.trim()) => (Some(n.trim()), Some(c.trim())),
            _ if digits(item) => (Some(item), None),
            _ => (None, Some(item)),
        };
        if let Some(n) = n {
            out.push(OkExit {
                status: exit_status(n, at)?,
                when: vec![],
            });
        }
        if let Some(c) = class {
            match out.last_mut() {
                Some(e) if n.is_some() || !e.when.is_empty() => e.when.push(fault_class(c, at)?),
                _ => {
                    return Err(format!(
                        "{at}: {item:?}: a fault class follows N: (N:CLASS[,CLASS...])"
                    ))
                }
            }
        }
    }
    Ok(normal(out))
}

/// Sorted, unconditional statuses first (so the list reads back as written), each once; a
/// status allowed always needs no condition.
fn normal(mut l: Vec<OkExit>) -> Vec<OkExit> {
    for e in &mut l {
        e.when.sort();
        e.when.dedup();
    }
    let always: Vec<u8> = l
        .iter()
        .filter(|e| e.when.is_empty())
        .map(|e| e.status)
        .collect();
    l.retain(|e| e.when.is_empty() || !always.contains(&e.status));
    l.sort();
    l.dedup();
    l
}

/// A fault class an `--ok-exit` condition may name: one `faults.counts` has, or `buggify:LABEL`.
fn fault_class(c: &str, at: &str) -> Res<String> {
    let known = crate::launcher::attribution::CLASSES;
    if known.contains(&c) || c.strip_prefix("buggify:").is_some_and(|l| !l.is_empty()) {
        Ok(c.to_string())
    } else {
        Err(format!(
            "{at}: {c:?} is not a fault class ({}, buggify:LABEL)",
            known.join(", ")
        ))
    }
}

/// An exit status `--ok-exit` may name: 1 to 255 (0 is `ok` already).
fn exit_status(v: &str, at: &str) -> Res<u8> {
    match v.parse::<u8>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err(format!("{at}: {v:?} is not an exit status from 1 to 255")),
    }
}

fn int(v: &toml::Value, at: &str) -> Res<u64> {
    v.as_integer()
        .and_then(|i| u64::try_from(i).ok())
        .ok_or_else(|| format!("{at}: expected a non-negative integer"))
}

fn string(v: &toml::Value, at: &str) -> Res<String> {
    v.as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("{at}: expected a string"))
}

fn strings(v: &toml::Value, at: &str) -> Res<Vec<String>> {
    v.as_array()
        .ok_or_else(|| format!("{at}: expected an array of strings"))?
        .iter()
        .map(|x| string(x, at))
        .collect()
}

/// A `ready` probe: `"CMD ARGS"` (split as a shell would, without one) or `["CMD", "ARG"]`.
fn probe(v: &toml::Value, at: &str) -> Res<Vec<String>> {
    let w = match v.as_str() {
        Some(t) => crate::sweep::words(t).map_err(|e| format!("{at}: {e}"))?,
        None => strings(v, at)?,
    };
    if w.is_empty() {
        return Err(format!("{at}: an empty command"));
    }
    Ok(w)
}

/// Main's `ok-exit` (`[run] ok-exit` or `[machine.main] ok-exit`, one of the two): `"any"`, or
/// statuses `N` and `"N:CLASS,..."`, as `--ok-exit`.
fn main_ok_exit(c: &mut Config, v: &toml::Value, at: &str) -> Res<()> {
    if !c.ok_exit.is_empty() {
        return Err(format!(
            "{at}: main's ok-exit is given twice ([run] ok-exit and [machine.main] ok-exit)"
        ));
    }
    if v.as_str() == Some("any") {
        c.ok_exit = ok_exit_any();
        return Ok(());
    }
    let mut l = vec![];
    for x in v
        .as_array()
        .ok_or_else(|| format!("{at}: expected an array of exit statuses (N or \"N:CLASS,...\")"))?
    {
        let t = match (x.as_integer(), x.as_str()) {
            (Some(i), _) => i.to_string(),
            (_, Some(t)) if t.contains(':') => t.to_string(),
            _ => x.to_string(),
        };
        let one = ok_exit_list(&t, at)?;
        if one.len() != 1 {
            return Err(format!("{at}: {t:?} is not one status"));
        }
        l.extend(one);
    }
    c.ok_exit = normal(l);
    Ok(())
}

fn boolean(v: &toml::Value, at: &str) -> Res<bool> {
    v.as_bool()
        .ok_or_else(|| format!("{at}: expected true or false"))
}

/// `points` or `traps`.
fn preempt(v: &str, at: &str) -> Res<Preempt> {
    match v {
        "points" => Ok(Preempt::Points),
        "traps" => Ok(Preempt::Traps),
        _ => Err(format!("{at}: expected points or traps, not {v}")),
    }
}

fn scalar(v: &toml::Value, at: &str) -> Res<String> {
    match v {
        toml::Value::String(s) => Ok(s.clone()),
        toml::Value::Integer(i) => Ok(i.to_string()),
        toml::Value::Boolean(b) => Ok(if *b { "1" } else { "0" }.into()),
        _ => Err(format!("{at}: expected a string, integer or boolean")),
    }
}

/// One key of `patina.toml`. `apply_file` and `machines` accept a key only if it is here, and
/// `patina --help --format json` and `patina guide config` print this table.
pub struct TomlKey {
    /// `run`, `faults`, `sched`, `sweep` or `machine.NAME`.
    pub table: &'static str,
    pub key: &'static str,
    pub value: &'static str,
    pub default: &'static str,
    pub help: &'static str,
}

const fn tk(
    table: &'static str,
    key: &'static str,
    value: &'static str,
    default: &'static str,
    help: &'static str,
) -> TomlKey {
    TomlKey {
        table,
        key,
        value,
        default,
        help,
    }
}

pub const TOML_KEYS: &[TomlKey] = &[
    tk("run", "env", "{ K = \"V\" }", "none", "added to the guest environment, as `--env`"),
    tk("run", "mounts", "[\"SRC:DST[:copy]\", ...]", "none", "as `--mount`"),
    tk("run", "stdin", "\"FILE\"", "empty", "as `--stdin`"),
    tk("run", "check", "\"CMD ARGS\"", "none", "as `--check`"),
    tk("run", "ok-exit", "[N, \"N:CLASS,...\"] or \"any\"", "none", "as `--ok-exit`"),
    tk("run", "timeout", "SECONDS", "600", "as `--timeout`: wall time"),
    tk("run", "cpus", "N", "4", "the CPU count the program sees (1 to 64)"),
    tk("run", "disk-mb", "MIB", "256", "the size of each sandbox filesystem (`/work`, `/tmp`, copied mounts)"),
    tk("run", "time-limit", "SECONDS", "3600", "virtual time after which the run ends `liveness`"),
    tk("run", "log-limit", "MIB", "1024", "log size at which the run ends `liveness` (a livelock)"),
    tk("run", "check-timeout", "SECONDS", "60", "wall time a checker may take"),
    tk("faults", "faults", "[\"CLASS[@MACHINE,...]\", ...]", "none", "as `--faults`"),
    tk("faults", "KEY", "VALUE", "none", "any fault key, as `--fault KEY=VALUE` (`patina run --fault help`)"),
    tk("faults", "fs-model", "\"ext4-ordered\" or \"posix-strict\"", "ext4-ordered", "what a machine crash keeps"),
    tk("sched", "preempt", "\"points\" or \"traps\"", "points", "`traps`: switch threads only at system calls, spin hints and spin probes (a diagnostic)"),
    tk("sched", "preempt-permille", "P", "100", "the chance in 1000 that a system call switches threads"),
    tk("sweep", "known", "\"FILE\"", "none", "as `--known`"),
    tk("sweep", "allow-unmet", "[\"LABEL\", ...]", "none", "as `--allow-unmet`"),
    tk("sweep", "crash-pairs", "K", "off", "with `--crash-points` and machines: crash a second machine at each of its next K points after a first crash"),
    tk("machine.NAME", "run", "[\"CMD\", \"ARG\", ...]", "required", "the command Patina starts at each of its boots; [machine.main] run is the command after `--`"),
    tk("machine.NAME", "env", "{ K = \"V\" }", "none", "added to the run's environment"),
    tk("machine.NAME", "ready", "\"CMD ARGS\" or [\"CMD\", \"ARG\", ...]", "ready once started", "a probe run on it every 100 ms until it exits 0: main's command and the faults wait for every machine's (main's own: the faults only)"),
    tk("machine.NAME", "disk", "\"DIR[:GUEST]\"", "empty", "its disk's starting files (main's: as `--disk`)"),
    tk("machine.NAME", "restart", "\"crash\", \"always\" or \"never\"", "crash", "after which downs the seed restarts it (`always`: also after it exits within `ok-exit`; main's: `crash`)"),
    tk("machine.NAME", "ok-exit", "N or [N, ...]", "[0]", "exit statuses that only stop the machine (main's: as `[run] ok-exit`, one of the two)"),
    tk("machine.NAME", "max-boots", "N", "the run's", "the most boots the seed's crashes give it (1 to 64)"),
    tk("machine.NAME", "disk-mb", "N or \"A..B\"", "the run's", "its filesystems' size, drawn per seed from a range"),
    tk("machine.NAME", "count", "N", "1", "N machines of this table, named NAME1 to NAMEN (not main)"),
    tk("machine.NAME", "faults", "true or false", "true", "`false`: none of the seed's faults act on it or its links (main, when it runs only the test)"),
];

fn known_key(table: &str, key: &str) -> bool {
    TOML_KEYS.iter().any(|k| k.table == table && k.key == key)
        || (table == "faults" && !key.is_empty())
}

/// Apply `patina.toml` (read from `path`; relative paths in it are relative to its directory,
/// but `[machine.main] run` and `[run] check`, commands, are relative to where patina is started), or
/// take the whole configuration a run recorded when `path` is a `run.json`. Returns `[run]
/// check`, resolved by the caller once flags are known.
fn apply_file(c: &mut Config, path: &Path) -> Res<Option<String>> {
    let name = path.display().to_string();
    if path.extension().is_some_and(|e| e == "json") {
        let run = crate::result::read_json(path)?;
        crate::result::same_build(&run, path)?;
        *c = serde_json::from_value(run["config"].clone())
            .map_err(|e| format!("{name}: config: {e}"))?;
        return Ok(None);
    }
    let mut check = None;
    let text = std::fs::read_to_string(path).map_err(|e| format!("{name}: {e}"))?;
    let doc: toml::Table = text.parse().map_err(|e| format!("{name}: {e}"))?;
    let base = path
        .parent()
        .map(|p| std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf()))
        .unwrap_or_default();
    let unknown = |k: &str| format!("{name}: unknown key {k}");
    for (sec, v) in &doc {
        let t = table(v, &format!("{name}: [{sec}]"))?;
        if sec == "machine" {
            machines(c, &text, t, &base, &name)?;
            continue;
        }
        for (k, v) in t {
            let at = format!("{name}: {sec}.{k}");
            if !TOML_KEYS.iter().any(|x| x.table == sec) {
                return Err(unknown(sec));
            }
            if !known_key(sec, k) {
                return Err(unknown(&format!("{sec}.{k}")));
            }
            match (sec.as_str(), k.as_str()) {
                ("run", "cpus") => c.cpus = int(v, &at)?,
                ("run", "env") => {
                    for (ek, ev) in table(v, &at)? {
                        c.env.push(format!("{ek}={}", string(ev, &at)?));
                    }
                }
                ("run", "mounts") => {
                    for m in strings(v, &at)? {
                        c.mounts
                            .push(mount(&base, &m).map_err(|e| format!("{at}: {e}"))?);
                    }
                }
                ("run", "stdin") => c.stdin = Some(existing(&base, &at, &string(v, &at)?)?),
                ("run", "time-limit") => c.time_limit = time_limit(int(v, &at)?, &at)?,
                ("run", "timeout") => c.timeout = int(v, &at)?,
                ("run", "log-limit") => c.log_limit = int(v, &at)?,
                ("run", "disk-mb") => c.tmpfs_bytes = int(v, &at)?.saturating_mul(1 << 20),
                ("run", "check-timeout") => c.check_timeout = Some(int(v, &at)?),
                ("run", "check") => check = Some(string(v, &at)?),
                ("run", "ok-exit") => main_ok_exit(c, v, &at)?,
                ("faults", "faults") => c.fault_classes = strings(v, &at)?,
                ("faults", "fs-model") => c.fs_model = string(v, &at)?,
                ("faults", _) => c.faults.push(format!("{k}={}", scalar(v, &at)?)),
                ("sweep", "allow-unmet") => c.allow_unmet = strings(v, &at)?,
                ("sweep", "known") => c.known = Some(base.join(string(v, &at)?)),
                ("sweep", "crash-pairs") => c.crash_pairs = Some(int(v, &at)? as usize),
                ("sched", "preempt-permille") => c.preempt_permille = int(v, &at)?,
                ("sched", "preempt") => c.preempt = preempt(&string(v, &at)?, &at)?,
                _ => return Err(unknown(&format!("{sec}.{k}"))),
            }
        }
    }
    Ok(check)
}

/// `[machine.NAME]` tables, in the order the file declares them (a TOML table's keys are not).
/// `[machine.main]` is main's: its `run` is the command after `--`, its `disk` is `--disk`'s.
fn machines(c: &mut Config, text: &str, t: &toml::Table, base: &Path, file: &str) -> Res<()> {
    let order: Vec<String> = match toml::de::DeTable::parse(text) {
        Ok(d) => {
            let mut keys: Vec<(usize, String)> =
                match d.get_ref().get("machine").map(|v| v.get_ref()) {
                    Some(toml::de::DeValue::Table(n)) => n
                        .keys()
                        .map(|k| (k.span().start, k.get_ref().to_string()))
                        .collect(),
                    _ => vec![],
                };
            keys.sort();
            keys.into_iter().map(|k| k.1).collect()
        }
        Err(e) => return Err(format!("{file}: {e}")),
    };
    let mut out = vec![];
    for n in order {
        let at = format!("{file}: machine.{n}");
        let v = t.get(&n).ok_or_else(|| format!("{at}: not found"))?;
        let main = n == "main";
        let mut machine = Machine::new(n.clone(), vec![]);
        let mut count = None;
        for (k, v) in table(v, &at)? {
            if !known_key("machine.NAME", k) {
                return Err(format!("{file}: unknown key machine.{n}.{k}"));
            }
            let at = format!("{at}.{k}");
            match k.as_str() {
                // Main's exit statuses that end the run ok, as `[run] ok-exit`.
                "ok-exit" if main => main_ok_exit(c, v, &at)?,
                "count" if main => return Err(format!("{at}: main is one machine")),
                "run" => machine.run = strings(v, &at)?,
                "ready" => machine.ready = probe(v, &at)?,
                "env" => {
                    for (ek, ev) in table(v, &at)? {
                        machine.env.push(format!("{ek}={}", string(ev, &at)?));
                    }
                }
                "disk" => (machine.disk, machine.disk_at) = disk_arg(base, &at, &string(v, &at)?)?,
                "restart" => {
                    let s = string(v, &at)?;
                    if !matches!(s.as_str(), "crash" | "always" | "never") {
                        return Err(format!("{at}: crash, always or never, not {s}"));
                    }
                    machine.restart = Some(s);
                }
                "ok-exit" => {
                    let l: Vec<i64> = match v {
                        toml::Value::Array(a) => a
                            .iter()
                            .map(|x| x.as_integer().ok_or(()))
                            .collect::<Result<_, _>>()
                            .map_err(|_| format!("{at}: a list of exit statuses"))?,
                        toml::Value::Integer(i) => vec![*i],
                        _ => return Err(format!("{at}: a list of exit statuses")),
                    };
                    if let Some(x) = l.iter().find(|x| !(0..=255).contains(*x)) {
                        return Err(format!("{at}: {x} is not an exit status (0 to 255)"));
                    }
                    machine.ok_exit = Some(l.iter().map(|x| *x as u8).collect());
                }
                "disk-mb" => {
                    machine.disk_mb = Some(match v {
                        toml::Value::Integer(i) => i.to_string(),
                        _ => string(v, &at)?,
                    })
                }
                "max-boots" => {
                    let n_: u64 = int(v, &at)?;
                    if n_ == 0 || n_ > proto::machine::BOOTS_MAX as u64 {
                        return Err(format!(
                            "{at}: 1 to {} (a machine boots at most that often)",
                            proto::machine::BOOTS_MAX
                        ));
                    }
                    machine.max_boots = Some(n_);
                }
                "count" => {
                    let c: u64 = int(v, &at)?;
                    if c == 0 || c > MAX_MACHINES as u64 {
                        return Err(format!("{at}: 1 to {MAX_MACHINES}"));
                    }
                    count = Some(c);
                }
                "faults" => {
                    if !boolean(v, &at)? {
                        machine.no_faults = true;
                    }
                }
                _ => return Err(format!("{file}: unknown key machine.{n}.{k}")),
            }
        }
        if main {
            // Main's run is the command after `--` and is started again after each crash; its
            // exit ends the run, so no other restart policy applies to it.
            if let Some(r) = machine.restart.as_deref().filter(|r| *r != "crash") {
                return Err(format!(
                    "{at}.restart: {r}: main is started again after a crash, and its exit ends the run (crash only)"
                ));
            }
            if !machine.run.is_empty() {
                c.cmd = machine.run;
            }
            if machine.disk.is_some() || machine.disk_at.is_some() {
                (c.disk, c.disk_at) = (machine.disk, machine.disk_at);
            }
            if !machine.ready.is_empty() {
                c.ready = machine.ready;
            }
            c.main_env = machine.env;
            c.main_no_faults = machine.no_faults;
            c.main_disk_mb = machine.disk_mb;
            c.main_max_boots = machine.max_boots;
            continue;
        }
        // `count = N`: machines NAME1..NAMEN in its place, each with this table.
        match count {
            Some(c) => {
                for i in 1..=c {
                    let mut x = machine.clone();
                    x.name = format!("{n}{i}");
                    out.push(x);
                }
            }
            None => out.push(machine),
        }
    }
    c.machines = out;
    Ok(())
}

/// The resolved configuration of `run` and `verify`.
/// Test inputs (AGENTS.md, "Test inputs"): `PATINA_TEST_<NAME>` environment variables set what
/// only Patina's own tests change. Each lands in the configuration, so `run.json` records it and
/// a replay needs none. Unset, nothing changes.
fn test_inputs(c: &mut Config) -> Res<()> {
    fn var(name: &str) -> Option<(String, String)> {
        let k = format!("PATINA_TEST_{name}");
        std::env::var(&k).ok().map(|v| (k, v))
    }
    let num = |(k, v): (String, String)| {
        v.parse::<u64>()
            .map_err(|_| format!("{k}={v}: expected a number"))
    };
    let flag = |(k, v): (String, String)| match v.as_str() {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(format!("{k}={v}: expected 1 or 0")),
    };
    if let Some(x) = var("STALL_MS") {
        c.stall_ms = num(x)?;
    }
    if let Some(x) = var("PAUSE_POINTS") {
        c.pause_points = flag(x)?;
    }
    if let Some(x) = var("SPIN_PROBES") {
        c.spin_probes = flag(x)?;
    }
    if let Some(x) = var("EMULATE_RNDR") {
        if !cfg!(target_arch = "aarch64") {
            return Err(format!("{}: arm64 only", x.0));
        }
        c.emulate_rndr = flag(x)?;
    }
    if let Some((_, v)) = var("COMPUTE_WALK") {
        c.compute_walk = Some(v);
    }
    Ok(())
}

pub fn resolve(a: &Args) -> Res<Config> {
    let c = resolve_any(a)?;
    if c.cmd.is_empty() {
        return Err("no command for main: give one after `--` or as [machine.main] run".into());
    }
    Ok(c)
}

/// The resolved configuration, perhaps without a command (a sweep whose cases are commands).
pub fn resolve_any(a: &Args) -> Res<Config> {
    let mut c = Config::default();
    let file = match a.last("--config") {
        Some(f) => Some(PathBuf::from(f)),
        None => Some(PathBuf::from("patina.toml")).filter(|p| p.is_file()),
    };
    let mut check = None;
    if let Some(f) = &file {
        check = apply_file(&mut c, f)?;
    }
    test_inputs(&mut c)?;
    let cwd = std::env::current_dir().map_err(|e| format!("current directory: {e}"))?;
    c.seed = a.num::<u64>("--seed")?.unwrap_or(0);
    for e in a.all("--env") {
        if !e.contains('=') {
            return Err(format!("--env {e}: expected K=V"));
        }
        c.env.push(e.clone());
    }
    for n in a.all("--machine") {
        let (name, cmd) = n
            .split_once('=')
            .ok_or_else(|| format!("--machine {n}: expected NAME='CMD ARGS'"))?;
        if c.machines.iter().any(|x| x.name == name) {
            return Err(format!(
                "--machine {name}: the run already has a machine {name}"
            ));
        }
        c.machines.push(Machine::new(
            name.to_string(),
            crate::sweep::words(cmd).map_err(|e| format!("--machine {name}: {e}"))?,
        ));
    }
    for m in a.all("--mount") {
        c.mounts.push(mount(&cwd, m)?);
    }
    if let Some(w) = a.last("--disk") {
        (c.disk, c.disk_at) = disk_arg(&cwd, "--disk", w)?;
    }
    if let Some(s) = a.last("--stdin") {
        c.stdin = Some(existing(&cwd, "--stdin", s)?);
    }

    if let Some(n) = a.num("--timeout")? {
        c.timeout = n;
    }
    c.fault_classes.extend(a.all("--faults").iter().cloned());
    // `--fault KEY=VALUE` is any `[faults]` key, the crash model's too.
    for f in a.all("--fault") {
        match f.strip_prefix("fs-model=") {
            Some(m) => c.fs_model = m.to_string(),
            None => c.faults.push(f.clone()),
        }
    }
    if let Some(k) = a.last("--check") {
        check = Some(k.to_string());
    }
    if let Some(l) = a.last("--ok-exit") {
        c.ok_exit = if l == "any" {
            ok_exit_any()
        } else {
            ok_exit_list(l, "--ok-exit")?
        };
    }
    // A checker is resolved where patina starts (one a run.json recorded, again from its own
    // directory): its SHA-256 is the file's now.
    c.check = match check {
        Some(k) => Some(crate::check::Check::resolve(&k, &logical("."))?),
        None => c.check.as_ref().map(|k| k.again()).transpose()?,
    };
    match (c.check.as_mut(), c.check_timeout) {
        (Some(k), Some(t)) => k.timeout = t,
        (None, Some(_)) => return Err("[run] check-timeout needs a checker".into()),
        _ => {}
    }
    // A sweep gives each of its --cases runs its case.
    if let (Ok(id), Ok(line)) = (
        std::env::var(crate::check::CASE_ID_VAR),
        std::env::var(crate::check::CASE_LINE_VAR),
    ) {
        c.case = Some(RunCase { id, line });
    }
    if let (Some(k), Ok(text), Ok(name)) = (
        c.check.as_mut(),
        std::env::var(crate::check::CASE_VAR),
        std::env::var(crate::check::CASE_NAME_VAR),
    ) {
        k.case = Some(crate::check::Case {
            text,
            name,
            id: std::env::var(crate::check::CASE_ID_VAR).ok(),
        });
    }
    if let Some(cmd) = a.cmd.as_ref().filter(|v| !v.is_empty()) {
        c.cmd = cmd.clone();
    }
    // A program given by a relative path: absolute, by name, so that the run's record (and
    // the command that reruns it) names the program as it was given, from anywhere.
    if let Some(c0) = c
        .cmd
        .first_mut()
        .filter(|x| x.contains('/') && !x.starts_with('/'))
    {
        *c0 = logical(c0).display().to_string();
    }
    Ok(c)
}

impl Config {
    /// Check every setting and build the launcher's plan around an already resolved program.
    pub fn opts_with(&self, program: Program) -> Res<Opts> {
        // Faults asked for: any class, or any key but the scheduler's `compute-*`.
        let asked = !self.fault_classes.is_empty()
            || self.faults.iter().any(|s| !s.starts_with("compute-"));
        let mut plan = if self.machines.is_empty() {
            // Main is the run's one machine: a scope may name it alone, and is then no scope.
            let mut given = vec![];
            for s in self.fault_classes.iter().chain(&self.faults) {
                let (body, scope) = faults::split_scope(s);
                self.scope_bits(scope, s)?;
                given.push(body.to_string());
            }
            let (cs, ss) = given.split_at(self.fault_classes.len());
            if let Some(s) = ss
                .iter()
                .find(|s| faults::machine_only(s.split_once('=').map_or(s.as_str(), |x| x.0)))
            {
                return Err(format!("--fault {s}: only in a run with machines"));
            }
            let on = !self.main_no_faults;
            let ss: Vec<String> = ss
                .iter()
                .filter(|s| on || s.starts_with("compute-"))
                .cloned()
                .collect();
            let classes = match on {
                true => faults::classes(&cs.join(","), 0, 1)?,
                false => vec![],
            };
            let mut plan = faults::resolve(
                self.seed,
                &classes,
                &ss,
                0,
                on as u64,
                faults::CrashAt::Points,
            )?;
            if asked && on {
                plan.on = vec!["main".to_string()];
            }
            if let Some(b) = self.main_max_boots {
                plan.max_boots = b;
            }
            plan
        } else {
            self.machine_plan()?
        };
        // Faults asked for, and every machine has `faults = false`: `faults on:` says none.
        plan.none_on = asked && self.main_no_faults && self.machines.iter().all(|m| m.no_faults);
        if let Some(w) = &self.compute_walk {
            plan.compute_walk = faults::walk(self.seed, w)?;
        }
        // With `ready` probes, no fault acts before every machine is ready (`sup::ready`):
        // known here, before the run starts.
        if self.has_ready() {
            plan.faults.fault_after_seq = u64::MAX;
        }
        let fs_model = Model::parse(&self.fs_model).ok_or_else(|| {
            format!(
                "fs-model: unknown model {} (ext4-ordered, posix-strict)",
                self.fs_model
            )
        })?;
        let w = self.disk_path();
        let under = |a: &str, b: &str| a == b || a.starts_with(&format!("{b}/"));
        if let Some(m) = self
            .mounts
            .iter()
            .find(|m| under(&m.dst, w) || under(w, &m.dst))
        {
            return Err(format!(
                "--mount {}:{}: the disk is at {w}; a mount cannot be in it or around it",
                m.src.display(),
                m.dst
            ));
        }
        if self.cpus == 0 || self.cpus > MAX_CPUS {
            return Err(format!("[run] cpus is 1 to {MAX_CPUS}"));
        }
        let max_log = proto::layout::LOG_MAX >> 20;
        if self.log_limit == 0 || self.log_limit > max_log {
            return Err(format!("[run] log-limit is 1 to {max_log} (MiB)"));
        }
        for k in 0..self.machines.len() {
            self.machine_disk_bytes(k)?;
        }
        self.main_disk_bytes()?;
        if self.tmpfs_bytes < 1 << 20 {
            return Err("[run] disk-mb is at least 1".into());
        }
        if self.preempt_permille > 1000 {
            return Err("preempt-permille is at most 1000".into());
        }
        let machine_programs = self.check_machines()?;
        Ok(Opts {
            cfg: self.clone(),
            program,
            plan,
            fs_model,
            machine_programs,
        })
    }

    /// Whether any machine, main included, declares a `ready` probe.
    pub fn has_ready(&self) -> bool {
        !self.ready.is_empty() || self.machines.iter().any(|m| !m.ready.is_empty())
    }

    /// The run's machines, main first (machine `k` is `names()[k]`).
    fn names(&self) -> Vec<&str> {
        std::iter::once("main")
            .chain(self.machines.iter().map(|m| m.name.as_str()))
            .collect()
    }

    /// Whether machine `k` (0: main) has faults: `faults = false` takes it out of them all.
    fn has_faults(&self, k: usize) -> bool {
        match k {
            0 => !self.main_no_faults,
            _ => !self.machines[k - 1].no_faults,
        }
    }

    /// The machines a scope names (bit `k`: machine `k`), each of which must exist and have
    /// faults; no scope: every machine with faults.
    fn scope_bits(&self, scope: Option<&str>, what: &str) -> Res<u64> {
        let names = self.names();
        let Some(l) = scope else {
            return Ok((0..names.len())
                .filter(|&k| self.has_faults(k))
                .fold(0, |b, k| b | 1 << k));
        };
        let mut bits = 0;
        for n in l.split(',') {
            let Some(k) = names.iter().position(|x| *x == n) else {
                return Err(match self.machines.is_empty() {
                    true => format!("{what}: no machine {n} (the run's one machine is main)"),
                    false => format!("{what}: no machine {n}"),
                });
            };
            if !self.has_faults(k) {
                return Err(format!("{what}: machine {n} has faults = false"));
            }
            bits |= 1 << k;
        }
        Ok(bits)
    }

    /// The machines whose links the link faults act on (bit `k`: machine `k`, `NetCfg::links`):
    /// a link class (`net`, `partition`, `all`) or key (`net-*`, `partition-*`) acts on the
    /// links between machines with faults, each one's loopback included, or, scoped, between
    /// the machines it names (`all@MACHINE` is the machine's own classes of `all`).
    pub fn link_mask(&self) -> Res<u64> {
        let mut m = 0;
        for e in &self.fault_classes {
            let (names, scope) = faults::split_scope(e);
            let links = names
                .split(',')
                .any(|c| matches!(c, "net" | "partition") || (c == "all" && scope.is_none()));
            if links {
                m |= self.scope_bits(scope, &format!("--faults {e}"))?;
            }
        }
        for s in &self.faults {
            let (kv, scope) = faults::split_scope(s);
            if faults::link_key(kv.split_once('=').map_or(kv, |x| x.0)) {
                m |= self.scope_bits(scope, &format!("--fault {s}"))?;
            }
        }
        Ok(m)
    }

    /// The fault classes of a run with machines, each with the machines it names (`None`: every
    /// machine with faults). `net` and `partition` are the links': their scope is
    /// `link_mask`'s (`all@MACHINE` is the machine's own classes of `all`).
    fn scoped_classes(&self) -> Res<Vec<(&'static str, Option<String>)>> {
        let faultable = self.link_mask()?.count_ones() as usize;
        let mut out = vec![];
        for e in &self.fault_classes {
            let (names, scope) = faults::split_scope(e);
            for c in faults::classes(names, self.machines.len(), faultable)? {
                if scope.is_some() && !faults::machine_class(c) {
                    if names.split(',').any(|n| n == c) {
                        out.push((c, None));
                    }
                    continue;
                }
                out.push((c, scope.map(str::to_string)));
            }
        }
        // `crash-gap-ms` alone crashes every machine.
        let gap = self.faults.iter().any(|s| s.starts_with("crash-gap-ms="));
        if gap && !out.iter().any(|(c, _)| matches!(*c, "crash" | "kill")) {
            out.push(("crash", None));
        }
        Ok(out)
    }

    /// Whether a class or setting of scope `scope` applies to machine `k` (0: main):
    /// unscoped, every machine with faults; `@MACHINE,...`, the machines named, which must
    /// exist and have faults.
    fn applies(&self, k: usize, scope: Option<&str>, what: &str) -> Res<bool> {
        Ok(self.scope_bits(scope, what)? & 1 << k != 0)
    }

    /// The plan of a run with machines: the run's own settings (links, partitions, crash timing,
    /// compute) resolved with the run's seed, and each machine's classes and settings with its own
    /// (`machine_seed`): its disk, memory, fault points, crashes, pauses and clock. `result.json`
    /// shows a machine's as `KEY@MACHINE`.
    fn machine_plan(&self) -> Res<faults::Plan> {
        let classes = self.scoped_classes()?;
        let run_classes: Vec<&str> = classes
            .iter()
            .filter(|(c, _)| !faults::machine_class(c))
            .map(|(c, _)| *c)
            .collect();
        let mut run_settings = vec![];
        for s in &self.faults {
            let (kv, scope) = faults::split_scope(s);
            let k = kv.split_once('=').map_or(kv, |x| x.0);
            if faults::machine_scoped(k) {
                continue;
            }
            if scope.is_some() && !faults::link_key(k) {
                return Err(format!(
                    "--fault {s}: {k} is the run's (only a machine's own keys and the links' take \
                     @MACHINE: disk, memory, fault-point, crash-point, pause, clock, net- and \
                     partition- keys)"
                ));
            }
            run_settings.push(kv.to_string());
        }
        let links_on = self.link_mask()?;
        let mut plan = faults::resolve(
            self.seed,
            &run_classes,
            &run_settings,
            self.machines.len(),
            links_on,
            faults::CrashAt::Times,
        )?;
        let between = |k: &str| {
            k.starts_with("compute-")
                || k.starts_with("net-")
                || k.starts_with("partition-")
                || matches!(k, "crash-gap-ms" | "down-ms" | "max-boots")
        };
        if let Some((k, _)) = plan.resolved.iter().find(|(k, _)| !between(k)) {
            return Err(format!(
                "--fault {k} with machines: not available yet (the disk, memory, net-, partition- \
                 and machine crash settings work)"
            ));
        }
        // Each machine's classes and settings.
        let mut per = vec![];
        let names = self.names();
        for (k, name) in names.iter().copied().enumerate() {
            let mut cs: Vec<&str> = vec![];
            for (c, scope) in &classes {
                if !faults::machine_class(c) || cs.contains(c) {
                    continue;
                }
                if self.applies(
                    k,
                    scope.as_deref(),
                    &format!("--faults {c}@{}", scope.as_deref().unwrap_or("")),
                )? {
                    if k == 0 && matches!(*c, "crash" | "kill") {
                        return Err(main_crash(&format!("--faults {c}")));
                    }
                    cs.push(c);
                }
            }
            let mut ss = vec![];
            for s in &self.faults {
                let (kv, scope) = faults::split_scope(s);
                let key = kv.split_once('=').map_or(kv, |x| x.0);
                if faults::machine_scoped(key) && self.applies(k, scope, &format!("--fault {s}"))? {
                    if k == 0 && key.starts_with("crash-") {
                        return Err(main_crash(&format!("--fault {s}")));
                    }
                    ss.push(kv.to_string());
                }
            }
            per.push((name, cs, ss));
        }
        // The machines the seed's faults act on: their own classes and settings, and the links'
        // faults on the machines whose links they act on.
        let links = !run_classes.is_empty()
            || run_settings
                .iter()
                .any(|s| faults::link_key(s.split_once('=').map_or(s.as_str(), |x| x.0)));
        plan.on = per
            .iter()
            .enumerate()
            .filter(|(k, (_, cs, ss))| {
                !cs.is_empty() || !ss.is_empty() || (links && links_on & 1 << k != 0)
            })
            .map(|(_, (name, _, _))| name.to_string())
            .collect();
        if per.iter().any(|(_, cs, _)| cs.contains(&"crash"))
            && per.iter().any(|(_, cs, _)| cs.contains(&"kill"))
        {
            return Err("--faults crash and kill: the machines crash or their processes are killed, not both".into());
        }
        // At the machines' crash points when any names a crash key, else at drawn times.
        let points = per.iter().any(|(_, _, ss)| {
            ss.iter()
                .any(|s| s.starts_with("crash-permille=") || s.starts_with("crash-at="))
        });
        if points {
            if let Some((k, _)) = plan.resolved.iter().find(|(k, _)| k == "crash-gap-ms") {
                return Err(format!(
                    "--fault {k} with crash-permille or crash-at: the crashes come at the machines' \
                     crash points, not at drawn times"
                ));
            }
        }
        // At crash points, the machines that crash are those a crash key names: a crash class
        // adds no crash to the others (it says what a crash is: `kill`, a process kill).
        let mode = if points {
            faults::CrashAt::Points
        } else {
            faults::CrashAt::Times
        };
        for (k, (name, mut cs, ss)) in per.into_iter().enumerate() {
            let keyed = ss.iter().any(|s| s.starts_with("crash-"));
            if points && !keyed {
                cs.retain(|c| !matches!(*c, "crash" | "kill"));
            }
            if cs.is_empty() && ss.is_empty() {
                continue;
            }
            let seed = machine_seed(self.seed, k);
            let sub = faults::resolve(seed, &cs, &ss, 0, 0, mode)
                .map_err(|e| format!("machine {name}: {e}"))?;
            let (g, l) = (sub.pause_gap_ns, sub.pause_ns);
            plan.machine_pause[k] = [g.0, g.1, l.0, l.1];
            plan.machine_skew[k] = sub.skew_ns;
            if k == 0 {
                faults::set_machine_keys(&mut plan.faults, &sub.faults);
                plan.sdk = sub.sdk;
            } else {
                faults::set_machine_keys(&mut plan.machine_faults[k], &sub.faults);
                plan.machine_sdk[k] = sub.sdk;
                if mode == faults::CrashAt::Times && sub.crash_class != proto::faults::CRASH_NONE {
                    plan.machine_crash |= 1 << k;
                    plan.machine_crash_kind = if sub.crash_class == proto::faults::CRASH_PROCESS {
                        proto::machine::SEED_KILL
                    } else {
                        proto::machine::SEED_CRASH
                    };
                }
            }
            for (key, v) in sub.resolved {
                plan.resolved.push((format!("{key}@{name}"), v));
            }
        }
        Ok(plan)
    }

    /// Check the machines of a run (`proto::machine`) and resolve their programs.
    fn check_machines(&self) -> Res<Vec<Program>> {
        if self.machines.is_empty() {
            return Ok(vec![]);
        }
        if self.machines.len() > MAX_MACHINES {
            return Err(format!(
                "[machine.*]: at most {MAX_MACHINES} machines besides main"
            ));
        }
        let under = |a: &str, b: &str| a == b || a.starts_with(&format!("{b}/"));
        let at = crate::launch::GUEST_PATINA;
        if let Some(m) = self.mounts.iter().find(|m| under(at, &m.dst)) {
            return Err(format!(
                "mount {} with machines: patina ctl is at {at}, which it would cover",
                m.dst
            ));
        }
        let mut programs = vec![];
        for n in &self.machines {
            let at = format!("machine.{}", n.name);
            if !proto::machine::valid_name(n.name.as_bytes()) {
                return Err(format!(
                    "{at}: a machine name is 1 to {} letters, digits and -, starting with a letter",
                    proto::machine::NAME_MAX
                ));
            }
            if n.name.as_bytes() == proto::machine::MAIN {
                return Err(format!("{at}: main is the machine of the command after --"));
            }
            if let Some(why) = proto::machine::RESERVED
                .iter()
                .find(|(r, _)| n.name.as_bytes() == *r)
                .map(|(_, why)| why)
            {
                return Err(format!("{at}: the name is taken ({why})"));
            }
            if n.run.is_empty() {
                return Err(format!("{at}: run is required"));
            }
            if let Some(e) = n.env.iter().find(|e| !e.contains('=')) {
                return Err(format!("{at}: env {e}: expected K=V"));
            }
            let w = n.disk_path();
            if let Some(m) = self
                .mounts
                .iter()
                .find(|m| under(&m.dst, w) || under(w, &m.dst))
            {
                return Err(format!(
                    "{at}: its disk is at {w}; mount {} cannot be in it or around it",
                    m.dst
                ));
            }
            if w != self.disk_path() && (under(w, self.disk_path()) || under(self.disk_path(), w)) {
                return Err(format!(
                    "{at}: its disk {w} is inside main's {} or holds it",
                    self.disk_path()
                ));
            }
            programs.push(program(&n.run[0], &self.mounts).map_err(|e| format!("{at}: {e}"))?);
        }
        Ok(programs)
    }

    /// The size of machine `k`'s (0-based, main not counted) tmpfs: its `disk-mb`, a range
    /// drawn from the run's seed, else the run's.
    pub fn machine_disk_bytes(&self, k: usize) -> Res<u64> {
        let n = &self.machines[k];
        self.disk_bytes(&n.name, n.disk_mb.as_deref())
    }

    /// The size of main's disk and `/tmp`: its `disk-mb` (`[machine.main] disk-mb`), else the
    /// run's.
    pub fn main_disk_bytes(&self) -> Res<u64> {
        self.disk_bytes("main", self.main_disk_mb.as_deref())
    }

    fn disk_bytes(&self, name: &str, v: Option<&str>) -> Res<u64> {
        let Some(v) = v else {
            return Ok(self.tmpfs_bytes);
        };
        let at = format!("[machine.{name}] disk-mb");
        let num = |s: &str| -> Res<u64> {
            s.trim()
                .parse()
                .map_err(|_| format!("{at}: a number of MiB or a range A..B, not {v}"))
        };
        let (a, b) = match v.split_once("..") {
            Some((a, b)) => (num(a)?, num(b)?),
            None => (num(v)?, num(v)?),
        };
        if a == 0 || a > b {
            return Err(format!("{at}: {v}: at least 1, and A at most B"));
        }
        if b << 20 > self.tmpfs_bytes {
            return Err(format!(
                "{at}: at most [run] disk-mb ({} MiB)",
                self.tmpfs_bytes >> 20
            ));
        }
        let key = format!("disk-mb@{name}");
        Ok((a + faults::plan_draw(self.seed, &key) % (b - a + 1)) << 20)
    }

    /// The disk's guest path.
    pub fn disk_path(&self) -> &str {
        self.disk_at.as_deref().unwrap_or("/work")
    }

    /// Resolve the program from `cmd[0]` and build the plan.
    pub fn opts(&self) -> Res<Opts> {
        let program = program(&self.cmd[0], &self.mounts)?;
        self.opts_with(program)
    }
}

/// Why a crash or kill of main is refused in a run with other machines: main's boots are the
/// launcher's, one sandbox each (`launcher::boots`), and only a run without other machines has
/// them.
fn main_crash(what: &str) -> String {
    format!(
        "{what}: acts on main too, and main is not crashed or killed beside other machines (not \
         available yet): give [machine.main] faults = false, or name the machines (@a,b)"
    )
}

/// The seed machine `k`'s own settings resolve from (main's: the run's).
fn machine_seed(seed: u64, k: usize) -> u64 {
    match k {
        0 => seed,
        _ => proto::draw::mix64(seed ^ (k as u64) << 56),
    }
}

/// A time limit in seconds whose nanoseconds, past the virtual clock's boot time, fit in a u64.
fn time_limit(s: u64, what: &str) -> Res<u64> {
    s.checked_mul(1_000_000_000)
        .and_then(|ns| ns.checked_add(proto::layout::VCLOCK_BOOT_NS + 1))
        .map(|_| s)
        .ok_or_else(|| format!("{what} {s}: too large"))
}

#[cfg(test)]
mod tests {

    #[test]
    fn ok_exit_takes_conditions_and_reads_back_as_written() {
        let l = ok_exit_list(
            "5:fsync-error, fs-error,1,7:buggify:drop,buggify:b,fs-error",
            "--ok-exit",
        )
        .unwrap();
        let shown: Vec<String> = l.iter().map(|o| o.to_string()).collect();
        assert_eq!(
            shown,
            [
                "1",
                "7:buggify:b,buggify:drop,fs-error",
                "5:fs-error,fsync-error"
            ]
        );
        assert_eq!(ok_exit_list(&shown.join(","), "x").unwrap(), l);
        let j = serde_json::to_value(&l).unwrap();
        assert_eq!(
            j,
            serde_json::json!([
                1,
                "7:buggify:b,buggify:drop,fs-error",
                "5:fs-error,fsync-error"
            ])
        );
        assert_eq!(serde_json::from_value::<Vec<OkExit>>(j).unwrap(), l);
        // A status allowed always needs no condition.
        assert_eq!(ok_exit_list("3:fs-error,3", "x").unwrap().len(), 1);
        for bad in [
            "5:nope",
            "fs-error",
            "buggify:x",
            "1,fs-error",
            "0:fs-error",
            "5:",
            "256",
        ] {
            assert!(ok_exit_list(bad, "x").is_err(), "{bad}");
        }
        // The same in patina.toml, with the sweep's known file beside it.
        let dir = std::env::temp_dir().join(format!("patina-okx-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("patina.toml");
        std::fs::write(
            &f,
            "[run]\nok-exit = [\"5:fsync-error,fs-error\", 1]\n[sweep]\nknown = \"k.txt\"\n",
        )
        .unwrap();
        let mut c = Config::default();
        apply_file(&mut c, &f).unwrap();
        assert_eq!(
            (c.ok_exit, c.known),
            (vec![l[0].clone(), l[2].clone()], Some(dir.join("k.txt")))
        );
        std::fs::write(&f, "[sweep]\njobs = 2\n").unwrap();
        assert!(apply_file(&mut Config::default(), &f).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
    use super::*;

    #[test]
    fn the_crash_model_is_a_fault_flag_as_its_key_is() {
        let a: Vec<String> = [
            "--fault",
            "fs-model=posix-strict",
            "--fault",
            "fs-error-permille=5",
            "--",
            "/bin/true",
        ]
        .map(String::from)
        .to_vec();
        let c = resolve_any(&crate::cli::parse(crate::cli::Cmd::Run, &a).unwrap()).unwrap();
        assert_eq!(c.fs_model, Model::PosixStrict.name());
        assert_eq!(c.faults, vec!["fs-error-permille=5".to_string()]);
    }

    #[test]
    fn unknown_keys_are_refused_by_name() {
        let dir = std::env::temp_dir().join(format!("patina-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("patina.toml");
        std::fs::write(&f, "[run]\ncpus = 2\nbogus-key = 1\n").unwrap();
        let e = apply_file(&mut Config::default(), &f).unwrap_err();
        assert!(e.contains("run.bogus-key"), "{e}");
        std::fs::write(&f, "[nosuch]\nx = 1\n").unwrap();
        let e = apply_file(&mut Config::default(), &f).unwrap_err();
        assert!(e.contains("nosuch"), "{e}");
        std::fs::write(
            &f,
            "[machine.main]\nrun = [\"/bin/true\"]\n[run]\ncpus = 2\nenv = { A = \"1\" }\n[faults]\nfs-error-permille = 5\n[sched]\npreempt-permille = 500\n",
        )
        .unwrap();
        let mut c = Config::default();
        apply_file(&mut c, &f).unwrap();
        assert!(c.machines.is_empty());
        assert_eq!(c.cmd, vec!["/bin/true".to_string()]);
        assert_eq!((c.cpus, c.preempt_permille), (2, 500));
        assert_eq!(c.env, vec!["A=1".to_string()]);
        assert_eq!(c.faults, vec!["fs-error-permille=5".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Every key of the table reaches its own arm of the parser: none falls through to the
    /// parser's unknown-key error (a value of the wrong type is another error).
    #[test]
    fn every_listed_key_is_parsed() {
        let dir = std::env::temp_dir().join(format!("patina-keys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("patina.toml");
        for k in TOML_KEYS.iter().filter(|k| k.key != "KEY") {
            let table = k.table.replace("NAME", "a");
            std::fs::write(&f, format!("[{table}]\n{} = 0\n", k.key)).unwrap();
            if let Err(e) = apply_file(&mut Config::default(), &f) {
                assert!(!e.contains("unknown key"), "[{}] {}: {e}", k.table, k.key);
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn machine_tables_take_their_restart_keys_and_crash_names_machines() {
        let dir = std::env::temp_dir().join(format!("patina-machines-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("patina.toml");
        std::fs::write(
            &f,
            "[machine.w]\nrun = [\"/bin/true\"]\nrestart = \"always\"\nok-exit = [0, 3]\n\
             max-boots = 4\ncount = 3\n[machine.db]\nrun = [\"/bin/true\"]\n",
        )
        .unwrap();
        let mut c = Config::default();
        apply_file(&mut c, &f).unwrap();
        let names: Vec<&str> = c.machines.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["w1", "w2", "w3", "db"]);
        assert!(c.machines[..3]
            .iter()
            .all(|n| n.ok_exit == Some(vec![0, 3]) && n.max_boots == Some(4)));
        assert_eq!(
            c.machines[3],
            Machine::new("db".into(), c.machines[3].run.clone())
        );
        // `--faults kill` covers every machine with faults, main too; main is not killed beside
        // other machines, so a test whose main drives it takes it out; `@` names some.
        let mut k = c.clone();
        k.fault_classes = vec!["kill".into()];
        assert!(k.machine_plan().is_err());
        c.main_no_faults = true;
        use proto::faults::{CRASH_MACHINE, CRASH_NONE, CRASH_PROCESS};
        use proto::machine::{SEED_CRASH, SEED_KILL};
        let crash = |c: &Config, classes: &[&str], keys: &[&str]| {
            let mut c = c.clone();
            c.fault_classes = classes.iter().map(|x| x.to_string()).collect();
            c.faults = keys.iter().map(|x| x.to_string()).collect();
            c.machine_plan()
        };
        let timed = |x: &str| {
            let p = crash(&c, &[x], &[]).unwrap();
            (p.machine_crash, p.machine_crash_kind)
        };
        assert_eq!(timed("kill"), (0b11110, SEED_KILL));
        assert_eq!(timed("kill@w2,db"), (0b10100, SEED_KILL));
        assert_eq!(timed("crash@w1"), (0b10, SEED_CRASH));
        // `crash-gap-ms` alone crashes every machine.
        let g = crash(&c, &[], &["crash-gap-ms=1000..2000"]).unwrap();
        assert_eq!(
            (g.machine_crash, g.machine_crash_kind),
            (0b11110, SEED_CRASH)
        );
        // At crash points: set in the scoped machines' own settings, none at drawn times.
        let p = crash(&c, &["crash"], &["crash-at=3@w2"]).unwrap();
        assert_eq!(p.machine_crash, 0);
        let at: Vec<u64> = p.machine_faults[1..5].iter().map(|f| f.crash_at).collect();
        assert_eq!(at, [0, 3, 0, 0]);
        let p = crash(&c, &[], &["crash-permille=5"]).unwrap();
        assert!(p.machine_faults[1..5].iter().all(|f| f.crash_permille == 5));
        // A process kill at a point: the machine's own kind, its point.
        let p = crash(&c, &["kill@w1"], &["crash-at=4@w1"]).unwrap();
        assert_eq!(p.machine_crash, 0);
        let w1 = &p.machine_faults[1];
        assert_eq!((w1.crash_kind, w1.crash_at), (CRASH_PROCESS, 4));
        assert_eq!(p.machine_faults[2].crash_kind, CRASH_NONE);
        // Settings at points: each its own machines.
        let p = crash(
            &c,
            &["kill@w3"],
            &["crash-at=5@w1", "crash-permille=0@w2,db", "crash-at=2@w3"],
        )
        .unwrap();
        let k: Vec<(u64, u64, u64)> = p.machine_faults[1..5]
            .iter()
            .map(|f| (f.crash_kind, f.crash_at, f.crash_permille))
            .collect();
        assert_eq!(
            k,
            [
                (CRASH_MACHINE, 5, 0),
                (CRASH_MACHINE, 0, 0),
                (CRASH_PROCESS, 2, 0),
                (CRASH_MACHINE, 0, 0)
            ]
        );
        for (cl, keys) in [
            (
                &["crash"][..],
                &["crash-at=5@w1", "crash-permille=6@w1"][..],
            ),
            (&["crash@w1"], &["crash-at=3@w2", "crash-gap-ms=1..2"]),
            (&["crash@w1", "kill@w2"], &[]),
            (&["kill@main"], &[]),
            (&["crash@nope"], &[]),
            (&[], &["crash-at=1@main"]),
        ] {
            assert!(crash(&c, cl, keys).is_err(), "{cl:?} {keys:?}");
        }
        for bad in [
            "restart = \"sometimes\"",
            "ok-exit = 256",
            "max-boots = 0",
            "count = 16",
            "faults = \"net\"",
        ] {
            std::fs::write(&f, format!("[machine.w]\nrun = [\"/bin/true\"]\n{bad}\n")).unwrap();
            assert!(apply_file(&mut Config::default(), &f).is_err(), "{bad}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_machine_without_faults_is_left_out_main_included() {
        let dir = std::env::temp_dir().join(format!("patina-nofaults-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("patina.toml");
        std::fs::write(
            &f,
            "[machine.a]\nrun = [\"/bin/true\"]\n[machine.m]\nrun = [\"/bin/true\"]\nfaults = false\n",
        )
        .unwrap();
        let mut c = Config::default();
        apply_file(&mut c, &f).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!c.machines[0].no_faults && c.machines[1].no_faults);
        c.faults = vec!["fs-error-permille=7".into()];
        let plan = |c: &Config| c.machine_plan();
        // Unscoped: main and a have it, m does not.
        let p = plan(&c).unwrap();
        assert_eq!(p.faults.fs_error_permille, 7);
        assert_eq!(p.machine_faults[1].fs_error_permille, 7);
        assert_eq!(p.machine_faults[2].fs_error_permille, 0);
        assert_eq!(p.on, ["main", "a"]);
        // The links' faults: between the machines with faults, never m's links.
        let mut n = c.clone();
        n.fault_classes = vec!["net".into()];
        assert_eq!(n.machine_plan().unwrap().net.links, 0b011);
        n.fault_classes = vec!["net@a".into()];
        assert_eq!(n.machine_plan().unwrap().net.links, 0b010);
        n.main_no_faults = true;
        n.fault_classes = vec!["net".into()];
        assert_eq!(n.machine_plan().unwrap().net.links, 0b010);
        let mut k = c.clone();
        k.fault_classes = vec!["crash".into()];
        assert!(k.machine_plan().is_err());
        k.main_no_faults = true;
        assert_eq!(k.machine_plan().unwrap().machine_crash, 0b010);
        // A scope may not name it.
        c.faults = vec!["fs-error-permille=7@m".into()];
        assert!(plan(&c).is_err());
        c.faults = vec!["crash-permille=5@m".into()];
        assert!(plan(&c).is_err());
        c.faults = vec!["net-drop-permille=5@m".into()];
        assert!(plan(&c).is_err());
    }

    #[test]
    fn mounts_cover_no_sandbox_path() {
        let d = std::env::temp_dir();
        let s = d.display().to_string();
        for bad in [
            "/usr/lib/x",
            "/proc/x",
            "/etc",
            "/etc/passwd",
            "/tmp",
            "/.patina/x",
        ] {
            assert!(mount(&d, &format!("{s}:{bad}")).is_err(), "{bad}");
        }
        for ok in ["/etc/myapp", "/tmp/data", "/var/lib/app", "/home/u/proj"] {
            assert_eq!(mount(&d, &format!("{s}:{ok}")).unwrap().dst, ok);
        }
        assert!(mount(&d, &format!("{s}:rel")).is_err());
        assert!(mount(&d, &format!("{s}:/a/../b")).is_err());
        let m = mount(&d, &format!("{s}:/data:copy")).unwrap();
        assert!(m.copy && m.dst == "/data");
    }

    #[test]
    fn the_work_tree_goes_where_it_is_asked_and_no_mount_overlaps_it() {
        let d = std::env::temp_dir();
        let s = d.display().to_string();
        assert_eq!(
            disk_arg(&d, "--disk", &s).unwrap(),
            (Some(d.canonicalize().unwrap()), None)
        );
        let (dir, at) = disk_arg(&d, "--disk", &format!("{s}:/var/lib/app")).unwrap();
        assert!(dir.is_some() && at.as_deref() == Some("/var/lib/app"));
        assert_eq!(
            disk_arg(&d, "--disk", ":/srv").unwrap(),
            (None, Some("/srv".into()))
        );
        assert!(disk_arg(&d, "--disk", &format!("{s}:/usr/x")).is_err());
        let mut c = Config {
            cmd: vec!["/bin/true".into()],
            disk_at: Some("/srv/app".into()),
            ..Config::default()
        };
        c.mounts.push(mount(&d, &format!("{s}:/srv")).unwrap());
        assert!(c.opts().is_err());
        c.mounts[0].dst = "/work".into();
        assert!(c.opts().is_ok());
    }
}
