//! The resolved configuration of a run: defaults, then `patina.toml`, then the environment
//! defaults, then flags. One struct; the launcher consumes it and `run.json` stores it, so a
//! replay needs neither the file nor the flags. Expert settings are config keys only.

use crate::cli::{Args, Res};
use crate::durability::materialise::Model;
use crate::faults;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The CPU count a guest is told it has when `--cpus` is not given: a fixed number, not the
/// host's, so that a run (Go's GOMAXPROCS, thread pools sized from it) is the same on any host.
/// Four: enough worker threads for the races of a small server, few enough that idle workers
/// polling for work (Go's Ps, tokio's workers) do not dominate the schedule.
pub const DEFAULT_CPUS: u64 = 4;
/// The most `--cpus` can give: the guest's affinity mask is one word.
pub const MAX_CPUS: u64 = 64;

/// The MiB a run's logs may hold when `--log-limit` is not given. A run that has not ended by
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

/// Counter preemption (`--preempt branches`, `[sched] preempt`) and its slice policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Pmu {
    pub on: bool,
    pub slice_min: u64,
    pub slice_max: u64,
    pub short_permille: u64,
    pub short_max: u64,
    pub charge_ps: u64,
    pub margin: u64,
}

impl Default for Pmu {
    fn default() -> Pmu {
        Pmu {
            on: false,
            slice_min: proto::pmu::SLICE_MIN_DEFAULT,
            slice_max: proto::pmu::SLICE_MAX_DEFAULT,
            short_permille: proto::pmu::SHORT_PERMILLE_DEFAULT,
            short_max: proto::pmu::SHORT_MAX_DEFAULT,
            charge_ps: proto::pmu::CHARGE_PS_DEFAULT,
            margin: proto::pmu::MARGIN_DEFAULT,
        }
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
    pub work: Option<PathBuf>,
    /// Where the work tree is in the guest (`--work DIR:GUEST`); none is `/work`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work_at: Option<String>,
    pub stdin: Option<PathBuf>,
    pub cpus: u64,
    /// Virtual seconds.
    pub time_limit: u64,
    /// Wall seconds.
    pub timeout: u64,
    /// MiB the run's logs may hold, every incarnation together (`--log-limit`).
    pub log_limit: u64,
    /// Path and argument strings in the boundary log (`--log-paths`, `[run] log-paths`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub log_paths: bool,
    pub tmpfs_bytes: u64,
    /// Fault presets (`--faults`, `[faults] preset`).
    pub faults_preset: Vec<String>,
    /// `KEY=VALUE` fault settings, in order; they replace a preset's.
    pub faults: Vec<String>,
    /// `[faults] faults-in-recovery = false`: no faults other than crashes after a crash.
    pub faults_in_recovery: bool,
    pub crash: Option<String>,
    /// Let SDK fault points fire (`--buggify`, `[sdk] buggify`).
    pub buggify: bool,
    /// SDK labels and fault classes a sweep or report may find unmet without calling the
    /// result vacuous (`[sdk] allow-unmet`).
    pub allow_unmet: Vec<String>,
    pub fs_model: String,
    pub max_incarnations: u64,
    pub preempt_permille: u64,
    pub stall_ms: u64,
    /// Every executed pause hint (`pause`; on arm64 `yield`, `wfe`, `wfi`, `isb`) is a
    /// scheduling point (`[sched] pause-points`).
    pub pause_points: bool,
    /// arm64: answer `RNDR`/`RNDRRS` from the seed and advertise them on a host without them
    /// (`[run] emulate-rndr`; a test of that path: the default follows the host).
    pub emulate_rndr: bool,
    /// Spin probes for a thread that computes without a boundary event (`[sched]
    /// spin-probes`; only with `--preempt traps`).
    pub spin_probes: bool,
    pub pmu: Pmu,
    /// The host CPU every sandbox process is pinned to (default: one of the allowed set,
    /// chosen by process id). Does not reach the guest.
    pub host_cpu: Option<usize>,
    /// The checker run after a run that ended ok (`--check`, `[run] check`; `check.rs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<crate::check::Check>,
    /// Guest exit statuses that end the run `ok` (`--ok-exit`, `[run] ok-exit`): the program
    /// failed cleanly, as it documents. Never 0, never a signal.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ok_exit: Vec<u8>,
    /// The case of a sweep's `--cases` run (set by the sweep), kept so that a replay or a
    /// rerun from `run.json` is the same case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case: Option<RunCase>,
}

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
            work: None,
            work_at: None,
            stdin: None,
            cpus: DEFAULT_CPUS,
            time_limit: 3600,
            timeout: 600,
            log_limit: DEFAULT_LOG_LIMIT_MIB,
            log_paths: false,
            tmpfs_bytes: 256 << 20,
            faults_preset: vec![],
            faults: vec![],
            faults_in_recovery: true,
            crash: None,
            buggify: false,
            allow_unmet: vec![],
            fs_model: Model::Ext4Ordered.name().into(),
            max_incarnations: 4,
            preempt_permille: 100,
            stall_ms: 10_000,
            pause_points: true,
            emulate_rndr: false,
            spin_probes: true,
            pmu: Pmu::default(),
            host_cpu: None,
            check: None,
            ok_exit: vec![],
            case: None,
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

/// Why a mount or the work tree cannot be at guest path `dst`, if it cannot: it would shadow
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

/// A guest path as `--mount` and `--work` take it: absolute, without `.` or `..`, not `/`,
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

/// `--work DIR[:GUEST]` (DIR may be empty: an empty tree at GUEST).
fn work(base: &Path, what: &str, s: &str) -> Res<(Option<PathBuf>, Option<String>)> {
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

/// `--ok-exit any`: every exit status (a reference sweep of a program whose failures are
/// its output); a signal still ends a run `crash`.
pub fn ok_exit_any() -> Vec<u8> {
    (1..=255).collect()
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

fn boolean(v: &toml::Value, at: &str) -> Res<bool> {
    v.as_bool()
        .ok_or_else(|| format!("{at}: expected true or false"))
}

/// `traps` or `branches`: whether counter preemption is on.
fn preempt(v: &str, at: &str) -> Res<bool> {
    match v {
        "traps" => Ok(false),
        "branches" => Ok(true),
        _ => Err(format!("{at}: expected traps or branches, not {v}")),
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

fn range(v: &str, at: &str) -> Res<(u64, u64)> {
    let (a, b) = v
        .split_once("..")
        .ok_or_else(|| format!("{at}: expected MIN..MAX"))?;
    let p = |x: &str| -> Res<u64> { x.parse().map_err(|_| format!("{at}: not a number: {x}")) };
    Ok((p(a)?, p(b)?))
}

/// Apply `patina.toml` (read from `path`; relative paths in it are relative to its directory,
/// but `[run] cmd` and `[run] check`, commands, are relative to where patina is started), or
/// take the whole configuration a run recorded when `path` is a `run.json`. Returns `[run]
/// check` (or `check-serve`, true), resolved by the caller once flags are known.
fn apply_file(c: &mut Config, path: &Path) -> Res<Option<(String, bool)>> {
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
        for (k, v) in t {
            let at = format!("{name}: {sec}.{k}");
            match (sec.as_str(), k.as_str()) {
                ("run", "cmd") => c.cmd = strings(v, &at)?,
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
                ("run", "work") => (c.work, c.work_at) = work(&base, &at, &string(v, &at)?)?,
                ("run", "stdin") => c.stdin = Some(existing(&base, &at, &string(v, &at)?)?),
                ("run", "time-limit") => c.time_limit = int(v, &at)?,
                ("run", "timeout") => c.timeout = int(v, &at)?,
                ("run", "log-limit") => c.log_limit = int(v, &at)?,
                ("run", "log-paths") => c.log_paths = boolean(v, &at)?,
                ("run", "tmpfs-bytes") => c.tmpfs_bytes = int(v, &at)?,
                ("run", "check") => check = Some((string(v, &at)?, false)),
                ("run", "check-serve") => check = Some((string(v, &at)?, true)),
                ("run", "ok-exit") if v.as_str() == Some("any") => c.ok_exit = ok_exit_any(),
                ("run", "ok-exit") => {
                    c.ok_exit = v
                        .as_array()
                        .ok_or_else(|| format!("{at}: expected an array of exit statuses"))?
                        .iter()
                        .map(|x| {
                            exit_status(
                                &x.as_integer()
                                    .map(|i| i.to_string())
                                    .unwrap_or_else(|| x.to_string()),
                                &at,
                            )
                        })
                        .collect::<Res<_>>()?
                }
                ("run", "emulate-rndr") if cfg!(target_arch = "aarch64") => {
                    c.emulate_rndr = boolean(v, &at)?
                }
                ("faults", "crash") => c.crash = Some(string(v, &at)?),
                ("faults", "preset") => c.faults_preset = vec![string(v, &at)?],
                ("faults", "faults-in-recovery") => {
                    c.faults_in_recovery = v
                        .as_bool()
                        .ok_or_else(|| format!("{at}: expected true or false"))?
                }
                ("faults", "fs-model") => c.fs_model = string(v, &at)?,
                ("faults", "max-incarnations") => c.max_incarnations = int(v, &at)?,
                ("faults", _) => c.faults.push(format!("{k}={}", scalar(v, &at)?)),
                ("sdk", "buggify") => {
                    c.buggify = v
                        .as_bool()
                        .ok_or_else(|| format!("{at}: expected true or false"))?
                }
                ("sdk", "allow-unmet") => c.allow_unmet = strings(v, &at)?,
                ("sched", "preempt-permille") => c.preempt_permille = int(v, &at)?,
                ("sched", "stall-ms") => c.stall_ms = int(v, &at)?,
                ("sched", "host-cpu") => c.host_cpu = Some(int(v, &at)? as usize),
                ("sched", "preempt") => c.pmu.on = preempt(&string(v, &at)?, &at)?,
                ("sched", "pause-points") => c.pause_points = boolean(v, &at)?,
                ("sched", "spin-probes") => c.spin_probes = boolean(v, &at)?,
                // The race-hunting policy: every segment short, stops close to traps.
                ("sched", "branches") => match string(v, &at)?.as_str() {
                    "default" => {
                        let d = Pmu::default();
                        (c.pmu.short_permille, c.pmu.short_max) = (d.short_permille, d.short_max)
                    }
                    "hunt" => (c.pmu.short_permille, c.pmu.short_max) = (1000, 64),
                    o => return Err(format!("{at}: expected default or hunt, not {o}")),
                },
                ("sched", "pmu-slice") => {
                    (c.pmu.slice_min, c.pmu.slice_max) = range(&string(v, &at)?, &at)?
                }
                ("sched", "pmu-short-permille") => c.pmu.short_permille = int(v, &at)?,
                ("sched", "pmu-short-max") => c.pmu.short_max = int(v, &at)?,
                ("sched", "pmu-charge-ps") => c.pmu.charge_ps = int(v, &at)?,
                ("sched", "pmu-margin") => c.pmu.margin = int(v, &at)?,
                ("run" | "sched" | "sdk", _) => return Err(unknown(&format!("{sec}.{k}"))),
                _ => return Err(unknown(sec)),
            }
        }
    }
    Ok(check)
}

/// The resolved configuration of `run` and `verify`.
pub fn resolve(a: &Args) -> Res<Config> {
    let c = resolve_any(a)?;
    if c.cmd.is_empty() {
        return Err("no program: give -- CMD ARGS..., or [run] cmd in patina.toml".into());
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
    let cwd = std::env::current_dir().map_err(|e| format!("current directory: {e}"))?;
    c.seed = match a.num::<u64>("--seed")? {
        Some(s) => s,
        None => match std::env::var("PATINA_SEED") {
            Ok(v) => v
                .parse()
                .map_err(|_| format!("PATINA_SEED: not a number: {v}"))?,
            Err(_) => 0,
        },
    };
    for e in a.all("--env") {
        if !e.contains('=') {
            return Err(format!("--env {e}: expected K=V"));
        }
        c.env.push(e.clone());
    }
    for m in a.all("--mount") {
        c.mounts.push(mount(&cwd, m)?);
    }
    if let Some(w) = a.last("--work") {
        (c.work, c.work_at) = work(&cwd, "--work", w)?;
    }
    if let Some(s) = a.last("--stdin") {
        c.stdin = Some(existing(&cwd, "--stdin", s)?);
    }
    if let Some(n) = a.num("--cpus")? {
        c.cpus = n;
    }
    if let Some(p) = a.last("--preempt") {
        c.pmu.on = preempt(p, "--preempt")?;
    }
    if let Some(n) = a.num("--time-limit")? {
        c.time_limit = n;
    }
    if let Some(n) = a.num("--timeout")? {
        c.timeout = n;
    }
    if let Some(n) = a.num("--log-limit")? {
        c.log_limit = n;
    }
    if a.has("--log-paths") {
        c.log_paths = true;
    }
    if let Some(p) = a.last("--faults") {
        c.faults_preset = vec![p.to_string()];
    }
    c.faults.extend(a.all("--fault").iter().cloned());
    if let Some(cr) = a.last("--crash") {
        c.crash = Some(cr.to_string());
    }
    if a.has("--buggify") {
        c.buggify = true;
    }
    match (a.last("--check"), a.last("--check-serve")) {
        (Some(_), Some(_)) => {
            return Err(
                "--check and --check-serve: give one (the same checker runs either way)".into(),
            )
        }
        (Some(k), None) => check = Some((k.to_string(), false)),
        (None, Some(k)) => check = Some((k.to_string(), true)),
        (None, None) => {}
    }
    let check_timeout = a.num::<u64>("--check-timeout")?;
    if let Some(l) = a.last("--ok-exit") {
        c.ok_exit = if l == "any" {
            ok_exit_any()
        } else {
            l.split(',')
                .map(|x| exit_status(x.trim(), "--ok-exit"))
                .collect::<Res<_>>()?
        };
    }
    c.ok_exit.sort_unstable();
    c.ok_exit.dedup();
    // A checker is resolved where patina starts (one a run.json recorded, again from its own
    // directory): its SHA-256 is the file's now.
    c.check = match check {
        Some((k, serve)) => {
            let mut k = crate::check::Check::resolve(&k, &logical("."))?;
            k.serve = serve;
            Some(k)
        }
        None => c.check.as_ref().map(|k| k.again()).transpose()?,
    };
    match (c.check.as_mut(), check_timeout) {
        (Some(k), Some(t)) => k.timeout = t,
        (None, Some(_)) => return Err("--check-timeout needs --check or --check-serve".into()),
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
        let mut plan = faults::resolve(
            self.seed,
            &self.faults_preset,
            &self.faults,
            self.crash.as_deref(),
            self.faults_in_recovery,
        )?;
        plan.sdk.buggify = self.buggify as _;
        let fs_model = Model::parse(&self.fs_model).ok_or_else(|| {
            format!(
                "fs-model: unknown model {} (ext4-ordered, posix-strict)",
                self.fs_model
            )
        })?;
        let w = self.work_path();
        let under = |a: &str, b: &str| a == b || a.starts_with(&format!("{b}/"));
        if let Some(m) = self
            .mounts
            .iter()
            .find(|m| under(&m.dst, w) || under(w, &m.dst))
        {
            return Err(format!(
                "--mount {}:{}: the work tree is at {w}; a mount cannot be in it or around it",
                m.src.display(),
                m.dst
            ));
        }
        if self.max_incarnations == 0 {
            return Err("max-incarnations is at least 1".into());
        }
        if self.cpus == 0 || self.cpus > MAX_CPUS {
            return Err(format!("--cpus is 1 to {MAX_CPUS}"));
        }
        let max_log = proto::layout::LOG_MAX >> 20;
        if self.log_limit == 0 || self.log_limit > max_log {
            return Err(format!("--log-limit is 1 to {max_log} (MiB)"));
        }
        if self.preempt_permille > 1000 {
            return Err("preempt-permille is at most 1000".into());
        }
        let p = &self.pmu;
        if p.short_permille > 1000 || p.short_max == 0 || p.short_max > 0xffff_ffff {
            return Err("pmu-short-permille is at most 1000, pmu-short-max at least 1".into());
        }
        if p.slice_min == 0 || p.slice_min > p.slice_max || p.margin < 64 {
            return Err("pmu-slice needs 1 <= MIN <= MAX; pmu-margin at least 64".into());
        }
        if p.short_max > p.margin + proto::pmu::HOP_EXTRA {
            return Err(
                "pmu-short-max is at most pmu-margin + 1024 (short slices are hopped)".into(),
            );
        }
        Ok(Opts {
            cfg: self.clone(),
            program,
            plan,
            fs_model,
        })
    }

    /// The work tree's guest path.
    pub fn work_path(&self) -> &str {
        self.work_at.as_deref().unwrap_or("/work")
    }

    /// Resolve the program from `cmd[0]` and build the plan.
    pub fn opts(&self) -> Res<Opts> {
        let program = program(&self.cmd[0], &self.mounts)?;
        self.opts_with(program)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            "[run]\ncmd = [\"/bin/true\"]\ncpus = 2\nenv = { A = \"1\" }\n[faults]\nfs-error-permille = 5\n[sched]\nstall-ms = 500\n",
        )
        .unwrap();
        let mut c = Config::default();
        apply_file(&mut c, &f).unwrap();
        assert_eq!((c.cpus, c.stall_ms), (2, 500));
        assert_eq!(c.env, vec!["A=1".to_string()]);
        assert_eq!(c.faults, vec!["fs-error-permille=5".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
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
            work(&d, "--work", &s).unwrap(),
            (Some(d.canonicalize().unwrap()), None)
        );
        let (dir, at) = work(&d, "--work", &format!("{s}:/var/lib/app")).unwrap();
        assert!(dir.is_some() && at.as_deref() == Some("/var/lib/app"));
        assert_eq!(
            work(&d, "--work", ":/srv").unwrap(),
            (None, Some("/srv".into()))
        );
        assert!(work(&d, "--work", &format!("{s}:/usr/x")).is_err());
        let mut c = Config {
            cmd: vec!["/bin/true".into()],
            work_at: Some("/srv/app".into()),
            ..Config::default()
        };
        c.mounts.push(mount(&d, &format!("{s}:/srv")).unwrap());
        assert!(c.opts().is_err());
        c.mounts[0].dst = "/work".into();
        assert!(c.opts().is_ok());
    }
}
