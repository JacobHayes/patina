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
    pub stdin: Option<PathBuf>,
    pub cpus: u64,
    /// Virtual seconds.
    pub time_limit: u64,
    /// Wall seconds.
    pub timeout: u64,
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
    #[serde(default)]
    pub allow_unmet: Vec<String>,
    pub fs_model: String,
    pub max_incarnations: u64,
    pub preempt_permille: u64,
    pub stall_ms: u64,
    /// Every executed `pause` is a scheduling point (`[sched] pause-points`).
    pub pause_points: bool,
    /// Spin probes for a thread that computes without a boundary event (`[sched]
    /// spin-probes`; only with `--preempt traps`).
    pub spin_probes: bool,
    pub pmu: Pmu,
    /// The host CPU every sandbox process is pinned to (default: one of the allowed set,
    /// chosen by process id). Does not reach the guest.
    pub host_cpu: Option<usize>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            seed: 0,
            cmd: vec![],
            env: vec![],
            mounts: vec![],
            work: None,
            stdin: None,
            cpus: DEFAULT_CPUS,
            time_limit: 3600,
            timeout: 600,
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
            spin_probes: true,
            pmu: Pmu::default(),
            host_cpu: None,
        }
    }
}

/// The program a run executes: where it is on the host, where the guest runs it from, and
/// its SHA-256 (checked by replay).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Program {
    pub host: PathBuf,
    pub guest: String,
    /// Copied to `/guest/<name>` at start.
    pub copied: bool,
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

/// Guest paths no mount may cover: the sandbox's own layout.
const RESERVED: [&str; 12] = [
    "/usr", "/bin", "/lib", "/lib64", "/sbin", "/etc", "/proc", "/sys", "/dev", "/work", "/tmp",
    "/.patina",
];

fn mount(base: &Path, s: &str) -> Res<Mount> {
    let (rest, copy) = match s.strip_suffix(":copy") {
        Some(r) => (r, true),
        None => (s, false),
    };
    let (src, dst) = rest
        .rsplit_once(':')
        .ok_or_else(|| format!("--mount {s}: expected SRC:DST[:copy]"))?;
    let src = existing(base, "--mount", src)?;
    let dst_p = Path::new(dst);
    if !dst_p.is_absolute()
        || dst_p.components().any(|c| {
            !matches!(
                c,
                std::path::Component::Normal(_) | std::path::Component::RootDir
            )
        })
        || dst == "/"
    {
        return Err(format!(
            "--mount {s}: DST must be an absolute path without . or .."
        ));
    }
    let dst = dst.trim_end_matches('/').to_string();
    if let Some(r) = RESERVED
        .iter()
        .find(|r| dst == **r || dst.starts_with(&format!("{r}/")))
    {
        return Err(format!(
            "--mount {s}: {r} is part of the sandbox (use --work for /work)"
        ));
    }
    if copy && !src.is_dir() {
        return Err(format!("--mount {s}: :copy takes a directory"));
    }
    Ok(Mount { src, dst, copy })
}

/// The SHA-256 of a file, as hex.
pub fn sha256_file(p: &Path) -> Res<String> {
    use sha2::{Digest, Sha256};
    let b = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let d = Sha256::digest(&b);
    Ok(d.iter().map(|x| format!("{x:02x}")).collect())
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
    if cmd0.starts_with('/') {
        for m in mounts {
            if let Some(rest) = cmd0.strip_prefix(&format!("{}/", m.dst)) {
                return file(m.src.join(rest), cmd0.to_string(), false);
            }
        }
    }
    let host = std::path::absolute(cmd0).map_err(|e| format!("program {cmd0}: {e}"))?;
    let canon = std::fs::canonicalize(&host).map_err(|e| format!("program {cmd0}: {e}"))?;
    if canon.starts_with("/usr/") {
        let guest = if cmd0.starts_with('/') {
            cmd0.to_string()
        } else {
            canon.display().to_string()
        };
        return file(canon, guest, false);
    }
    let name = host
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("program {cmd0}: no file name"))?
        .to_string();
    file(canon, format!("/guest/{name}"), true)
}

fn table<'a>(v: &'a toml::Value, at: &str) -> Res<&'a toml::Table> {
    v.as_table()
        .ok_or_else(|| format!("{at}: expected a table"))
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

/// Apply `patina.toml` (read from `path`; relative paths in it are relative to its directory),
/// or take the whole configuration a run recorded when `path` is a `run.json`.
fn apply_file(c: &mut Config, path: &Path) -> Res<()> {
    let name = path.display().to_string();
    if path.extension().is_some_and(|e| e == "json") {
        let run = crate::result::read_json(path)?;
        if run["schema"] != crate::result::RUN_SCHEMA {
            return Err(format!(
                "{name}: not a run.json (schema {}, this patina reads {})",
                run["schema"],
                crate::result::RUN_SCHEMA
            ));
        }
        *c = serde_json::from_value(run["config"].clone())
            .map_err(|e| format!("{name}: config: {e}"))?;
        return Ok(());
    }
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
                ("run", "work") => c.work = Some(existing(&base, &at, &string(v, &at)?)?),
                ("run", "stdin") => c.stdin = Some(existing(&base, &at, &string(v, &at)?)?),
                ("run", "time-limit") => c.time_limit = int(v, &at)?,
                ("run", "timeout") => c.timeout = int(v, &at)?,
                ("run", "tmpfs-bytes") => c.tmpfs_bytes = int(v, &at)?,
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
    Ok(())
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
    if let Some(f) = &file {
        apply_file(&mut c, f)?;
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
        c.work = Some(existing(&cwd, "--work", w)?);
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
    if let Some(cmd) = a.cmd.as_ref().filter(|v| !v.is_empty()) {
        c.cmd = cmd.clone();
    }
    if let Some(w) = &c.work {
        if !w.is_dir() {
            return Err(format!("--work {}: not a directory", w.display()));
        }
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
        if self.max_incarnations == 0 {
            return Err("max-incarnations is at least 1".into());
        }
        if self.cpus == 0 || self.cpus > MAX_CPUS {
            return Err(format!("--cpus is 1 to {MAX_CPUS}"));
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
        assert!(mount(&d, &format!("{s}:/work/x")).is_err());
        assert!(mount(&d, &format!("{s}:/usr/lib/x")).is_err());
        assert!(mount(&d, &format!("{s}:rel")).is_err());
        assert!(mount(&d, &format!("{s}:/a/../b")).is_err());
        let m = mount(&d, &format!("{s}:/data:copy")).unwrap();
        assert!(m.copy && m.dst == "/data");
    }
}
