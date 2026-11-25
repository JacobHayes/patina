//! The launcher: one sandbox per boot (`sandbox`), descriptors inherited at the hidden
//! numbers, pinning and `ADDR_NO_RANDOMIZE` set before the sandbox's keeper starts. `PR_SET_TSC`
//! is set by the runtime, not here: the host's glibc executes `rdtsc` at start-up, so the
//! supervisor would die of SIGSEGV if it were set before it.

use crate::cli::Res;
use crate::config::Opts;
use crate::outcome::Verdict;
use crate::result::RunEnd;
use crate::sandbox::{self, Op};
use crate::sys::*;
use proto::ctl::{
    Config, Ctl, CTL_SIZE, TM_COPIED, TM_EXPORTED, TM_FINISH, TM_FIRST_HELLO, TM_MAIN_EXIT,
    TM_SANDBOX_PID1, TM_SANDBOX_SETUP, TM_SUP_START,
};
use proto::layout::*;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::Ordering::*;

/// The in-guest runtime, built by `build.rs`.
static RT: &[u8] = include_bytes!(env!("PATINA_RT_EMBED"));

/// The runtime file's name: `proto::rec::hash_bytes(0x7274, RT)`, worked out by `build.rs`
/// rather than on every run (a serial pass over the runtime's megabytes).
const RT_ID: &str = env!("PATINA_RT_ID");

/// `$XDG_CACHE_HOME/patina` (default `~/.cache/patina`, else in the temporary directory).
pub fn cache_dir() -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .map(|h| PathBuf::from(h).join(".cache"))
        })
        .unwrap_or_else(std::env::temp_dir)
        .join("patina")
}

/// The runtime the sandbox executes: the file `PATINA_TEST_RT` names (runtime development), else
/// the embedded copy written once to `$XDG_CACHE_HOME/patina/rt-<hash>` (default
/// `~/.cache`, else the temporary directory) and checked against the embedded bytes, again
/// whenever the file is not the one last checked. A file, not a memfd: some LSM policies refuse
/// to execute a memfd.
pub fn rt_file() -> Res<File> {
    if let Some(p) = std::env::var_os("PATINA_TEST_RT") {
        return File::open(&p)
            .map_err(|e| format!("runtime {} (PATINA_TEST_RT): {e}", Path::new(&p).display()));
    }
    let dir = cache_dir();
    let path = dir.join(format!("rt-{RT_ID}"));
    // `rt-<id>.ok` holds the identity (device, inode, size, change time) of the file last found
    // to hold exactly the embedded bytes: while the file keeps it, at the embedded size, its
    // bytes are not read again.
    let ok = path.with_extension("ok");
    if let Ok(mut f) = File::open(&path) {
        let id = f
            .metadata()
            .ok()
            .filter(|m| m.len() == RT.len() as u64)
            .map(|m| {
                use std::os::unix::fs::MetadataExt;
                let (d, i, s) = (m.dev(), m.ino(), m.size());
                format!("{d} {i} {s} {}.{}", m.ctime(), m.ctime_nsec())
            });
        if id.is_some() && fs::read_to_string(&ok).ok() == id {
            return Ok(f);
        }
        let mut have = Vec::with_capacity(RT.len());
        if f.read_to_end(&mut have).is_ok() && have == RT {
            if let Some(id) = id {
                let tmp = dir.join(format!(".rt-ok-{}", std::process::id()));
                if fs::write(&tmp, id)
                    .and_then(|_| fs::rename(&tmp, &ok))
                    .is_err()
                {
                    let _ = fs::remove_file(&tmp);
                }
            }
            return Ok(f);
        }
    }
    fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let tmp = dir.join(format!(".rt-{}", std::process::id()));
    let write = || -> std::io::Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o555)
            .open(&tmp)?;
        std::io::Write::write_all(&mut f, RT)?;
        f.sync_all()?;
        fs::rename(&tmp, &path)
    };
    write().map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("write runtime {}: {e}", path.display())
    })?;
    File::open(&path).map_err(|e| format!("runtime {}: {e}", path.display()))
}

/// The CPUs of the launcher's affinity set.
pub fn affinity() -> Vec<usize> {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) };
    (0..libc::CPU_SETSIZE as usize)
        .filter(|&c| unsafe { libc::CPU_ISSET(c, &set) })
        .collect()
}

/// The CPUs runs use: the affinity set, of a hybrid CPU's only one kind of core
/// (`host::run_cpus`; a host where that cannot be known is refused before any run).
pub fn allowed_cpus() -> Vec<usize> {
    let a = affinity();
    crate::host::run_cpus(&a, &crate::host::CoreKinds::probe()).unwrap_or(a)
}

/// The CPU a run is pinned to without --cpu: one of the allowed set, chosen by process id, so
/// that concurrent runs (parallel checks, sweeps) spread over the host instead of all sharing
/// its first CPU. Which CPU a run uses does not reach the guest (the `cpu` variant of verify).
pub fn default_cpu() -> usize {
    let a = allowed_cpus();
    a[std::process::id() as usize % a.len()]
}

/// The files and directories under /etc the sandbox makes (`etc_files` and the links below).
pub const GENERATED_ETC: [&str; 7] = [
    "/etc/passwd",
    "/etc/group",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/ld.so.cache",
    "/etc/localtime",
    "/etc/alternatives",
];

/// `/etc/hosts`: every machine is named at its address (`10.0.0.(k + 1)`, main first) and
/// `localhost` is each machine's own loopback.
fn hosts(names: &[&str]) -> Vec<u8> {
    let mut h = String::from("127.0.0.1 localhost\n::1 localhost\n");
    for (k, n) in names.iter().enumerate() {
        h += &format!("10.0.0.{} {n}\n", k + 1);
    }
    h.into_bytes()
}

fn etc_files(home: &str, names: &[&str]) -> Vec<(&'static str, Vec<u8>)> {
    let (uid, gid) = (1000, 1000);
    vec![
        (
            "/etc/passwd",
            format!("root:x:0:0:root:{home}:/bin/sh\nuser:x:{uid}:{gid}:user:{home}:/bin/sh\n")
                .into_bytes(),
        ),
        (
            "/etc/group",
            format!("root:x:0:\nuser:x:{gid}:\n").into_bytes(),
        ),
        ("/etc/hosts", hosts(names)),
        (
            "/etc/nsswitch.conf",
            b"passwd: files\ngroup: files\nhosts: files\n".to_vec(),
        ),
    ]
}

/// The sandbox's layout for a run of `o` (`root`: the boot's `/in`): the steps in the
/// order the guest's mount table lists their mounts, the generated files' contents
/// (`Op::Data`), and the trees the supervisor copies in (`HIDDEN:DST`).
pub struct Layout {
    pub ops: Vec<Op>,
    pub data: Vec<Vec<u8>>,
    pub copies: Vec<String>,
    /// A run with machines: what the keeper needs to start each machine (`sandbox::Machines`).
    pub machines: Option<sandbox::Machines>,
}

/// Cached contents of `/etc/ld.so.cache` (once per process).
fn cached_ld_so_cache() -> Option<Vec<u8>> {
    static CACHE: std::sync::OnceLock<Option<Vec<u8>>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| fs::read("/etc/ld.so.cache").ok())
        .clone()
}

/// Cached sorted `(name, target)` entries of `/etc/alternatives`: cached in-process and on disk
/// in `$XDG_CACHE_HOME/patina/alternatives.cache`, keyed by `/etc/alternatives`'s directory
/// `(dev, ino, ctime, ctime_nsec, mtime, mtime_nsec)` so any change invalidates it immediately.
fn cached_alternatives() -> Option<Vec<(String, String)>> {
    use std::os::unix::fs::MetadataExt;
    static ALT: std::sync::OnceLock<Option<Vec<(String, String)>>> = std::sync::OnceLock::new();
    ALT.get_or_init(|| {
        let md = fs::metadata("/etc/alternatives").ok()?;
        let key = format!(
            "{} {} {}.{} {}.{}",
            md.dev(),
            md.ino(),
            md.ctime(),
            md.ctime_nsec(),
            md.mtime(),
            md.mtime_nsec()
        );
        let cache_path = cache_dir().join("alternatives.cache");
        if let Ok(text) = fs::read_to_string(&cache_path) {
            let mut lines = text.lines();
            if lines.next() == Some(key.as_str()) {
                let mut entries = Vec::new();
                let mut ok = true;
                for line in lines {
                    if let Some((n, t)) = line.split_once('\t') {
                        entries.push((n.to_string(), t.to_string()));
                    } else if !line.is_empty() {
                        ok = false;
                        break;
                    }
                }
                if ok {
                    return Some(entries);
                }
            }
        }
        let rd = fs::read_dir("/etc/alternatives").ok()?;
        let mut links: Vec<(String, String)> = vec![];
        for e in rd.flatten() {
            if let (Ok(t), Some(n)) = (fs::read_link(e.path()), e.file_name().to_str()) {
                links.push((n.to_string(), t.display().to_string()));
            }
        }
        links.sort();
        // Best-effort write through rename so concurrent readers never see a partial cache.
        if links
            .iter()
            .all(|(n, t)| !n.contains('\t') && !n.contains('\n') && !t.contains('\n'))
        {
            let mut body = String::with_capacity(key.len() + 1 + links.len() * 48);
            body.push_str(&key);
            body.push('\n');
            for (n, t) in &links {
                body.push_str(n);
                body.push('\t');
                body.push_str(t);
                body.push('\n');
            }
            let tmp = cache_dir().join(format!(".alternatives-{}", std::process::id()));
            if fs::create_dir_all(cache_dir())
                .and_then(|_| fs::write(&tmp, body))
                .and_then(|_| fs::rename(&tmp, &cache_path))
                .is_err()
            {
                let _ = fs::remove_file(&tmp);
            }
        }
        Some(links)
    })
    .clone()
}

pub fn layout(o: &Opts, root: Option<&Path>) -> Res<Layout> {
    let c = &o.cfg;
    let work = c.disk_path();
    let size = c.tmpfs_bytes;
    let ro = |src: String, dst: String| Op::Bind {
        src,
        dst,
        rw: false,
        dev: false,
    };
    let link = |t: &str, l: &str| Op::Symlink {
        target: t.into(),
        dst: l.into(),
    };
    let tmpfs = |d: &str| Op::Tmpfs {
        dst: d.into(),
        size,
    };
    // Main is a machine named like the others, whether or not others are declared.
    let names: Vec<&str> = std::iter::once("main")
        .chain(c.machines.iter().map(|n| n.name.as_str()))
        .collect();
    let mut ops = vec![
        Op::Hostname {
            name: "main".into(),
        },
        ro("/usr".into(), "/usr".into()),
    ];
    for (l, t) in [
        ("/bin", "usr/bin"),
        ("/lib", "usr/lib"),
        ("/lib64", "usr/lib64"),
        ("/sbin", "usr/sbin"),
    ] {
        ops.push(link(t, l));
    }
    ops.push(Op::Dev { dst: "/dev".into() });
    // Generated /etc: the data files below, plus the host's ld.so.cache, localtime (UTC), and
    // Debian's alternatives (`/usr/bin/awk` -> `/etc/alternatives/awk` -> gawk). Placed before
    // `Op::Proc` so persistent sandbox workers build them once at startup (user mounts cannot
    // shadow these paths, checked in `config.rs`).
    let mut etc = etc_files(work, &names);
    if let Some(cache) = cached_ld_so_cache() {
        etc.push(("/etc/ld.so.cache", cache));
    }
    ops.push(link("/usr/share/zoneinfo/UTC", "/etc/localtime"));
    if let Some(entries) = cached_alternatives() {
        ops.push(Op::SymlinkDir {
            dst: "/etc/alternatives".into(),
            entries,
        });
    }
    assert!(etc.len() <= sandbox::MAX_DATA);
    for (i, (path, _)) in etc.iter().enumerate() {
        ops.push(Op::Data {
            index: i,
            dst: path.to_string(),
        });
    }
    // Hidden read-only binds for copied program and boot /in, plus `patina` itself.
    if o.program.copied {
        let name = o.program.guest.trim_start_matches("/guest/");
        ops.push(ro(
            o.program.host.display().to_string(),
            format!("/.patina/prog/{name}"),
        ));
    }
    if let Some(root) = root {
        let r =
            fs::canonicalize(root).map_err(|e| format!("/work from {}: {e}", root.display()))?;
        ops.push(ro(r.display().to_string(), "/.patina/in".into()));
    }
    // `patina` itself, for `patina ctl` from a script: unless a mount covers its place (refused
    // in a run with machines, `Config::check_machines`; without machines the mount's tree stands).
    if !c.mounts.iter().any(|m| under(GUEST_PATINA, &m.dst)) {
        let exe = std::env::current_exe().map_err(|e| format!("own executable: {e}"))?;
        ops.push(ro(exe.display().to_string(), GUEST_PATINA.into()));
    }
    // Partition user mounts & program dir: static read-only binds not nested under any writable
    // tmpfs go before `Op::Proc` (mounted once in persistent workers); `Op::Proc`, writable
    // tmpfs mounts (`/work`, `/tmp`, `/guest`, `:copy`), and any binds nested under them go
    // after `Op::Proc` so every run gets fresh inodes and fresh `/proc`.
    let mut tmpfs_roots: Vec<String> = vec![work.into(), "/tmp".into(), "/guest".into()];
    for (i, m) in c.mounts.iter().enumerate() {
        if m.copy {
            let dst = crate::config::guest_resolve(&m.dst, &c.mounts[..i]);
            if dst != "/guest" {
                tmpfs_roots.push(dst);
            }
        }
    }
    let under_tmpfs = |p: &str| tmpfs_roots.iter().any(|t| under(p, t));
    let main_size = c.main_disk_bytes()?;
    let mut post_ops: Vec<Op> = vec![
        Op::Proc {
            dst: "/proc".into(),
        },
        // /work and /tmp: sandbox tmpfs (fresh, sequential inode numbers, their own virtual
        // times), main's size (`[machine.main] disk-mb`); programs expect /tmp for temporary files.
        // Not durable.
        Op::Tmpfs {
            dst: work.into(),
            size: main_size,
        },
        Op::Tmpfs {
            dst: "/tmp".into(),
            size: main_size,
        },
        tmpfs("/guest"),
    ];
    let mut copies: Vec<String> = vec![];
    if let (Some(d), Some(g)) = (&o.program.dir, Path::new(&o.program.guest).parent()) {
        let dst = crate::config::guest_resolve(&g.display().to_string(), &c.mounts);
        let op = ro(d.display().to_string(), dst.clone());
        if under_tmpfs(&dst) {
            post_ops.push(op);
        } else {
            ops.push(op);
        }
    }
    for (i, m) in c.mounts.iter().enumerate() {
        let dst = crate::config::guest_resolve(&m.dst, &c.mounts[..i]);
        if !m.copy {
            let op = ro(m.src.display().to_string(), dst.clone());
            if under_tmpfs(&dst) {
                post_ops.push(op);
            } else {
                ops.push(op);
            }
            continue;
        }
        let hidden = format!("/.patina/copy/{i}");
        ops.push(ro(m.src.display().to_string(), hidden.clone()));
        if dst != "/guest" {
            post_ops.push(tmpfs(&dst));
        }
        copies.push(format!("{hidden}:{dst}"));
    }
    if o.program.copied {
        copies.push("/.patina/prog:/guest".into());
    }
    ops.extend(post_ops);
    let mut progs: Vec<(String, PathBuf)> = vec![];
    if o.program.copied {
        progs.push((o.program.guest.clone(), o.program.host.clone()));
    }
    let machines = if c.machines.is_empty() {
        None
    } else {
        Some(machine_layout(o, &mut ops, &mut copies, &mut progs)?)
    };
    Ok(Layout {
        ops,
        data: etc.into_iter().map(|e| e.1).collect(),
        copies,
        machines,
    })
}

/// The guest path of `patina` itself (`patina ctl`), in the last directory of every run's
/// `PATH` (`sup::BASE_ENV`).
pub const GUEST_PATINA: &str = "/opt/patina/bin/patina";

/// Another program of the run (a machine's, a phase's) where main's is: a copied one at
/// `/guest` (refused where two programs would take one name), a program's directory bound
/// read-only where its path leads, unless a bind is there already. `progs` holds the copied
/// programs placed so far, as (guest path, host path).
fn place_program(
    p: &crate::config::Program,
    what: &str,
    mounts: &[crate::config::Mount],
    ops: &mut Vec<Op>,
    copies: &mut Vec<String>,
    progs: &mut Vec<(String, PathBuf)>,
) -> Res<()> {
    let ro = |src: String, dst: String| Op::Bind {
        src,
        dst,
        rw: false,
        dev: false,
    };
    if p.copied {
        match progs.iter().find(|(g, _)| *g == p.guest) {
            Some((_, h)) if *h != p.host => {
                return Err(format!(
                    "{what}: its program {} and another program both run as {}",
                    p.host.display(),
                    p.guest
                ))
            }
            Some(_) => {}
            None => {
                let name = p.guest.trim_start_matches("/guest/");
                ops.push(ro(
                    p.host.display().to_string(),
                    format!("/.patina/prog/{name}"),
                ));
                if !copies.iter().any(|cp| cp == "/.patina/prog:/guest") {
                    copies.push("/.patina/prog:/guest".into());
                }
                progs.push((p.guest.clone(), p.host.clone()));
            }
        }
    }
    if let (Some(d), Some(g)) = (&p.dir, Path::new(&p.guest).parent()) {
        let at = crate::config::guest_resolve(&g.display().to_string(), mounts);
        if !ops
            .iter()
            .any(|op| matches!(op, Op::Bind { dst, .. } if *dst == at))
        {
            ops.push(ro(d.display().to_string(), at));
        }
    }
    Ok(())
}

/// The layout's part for machines: each machine's program and starting tree bound where main's
/// are, its disk's mount point, and what the keeper needs to
/// start each machine in its own view.
fn machine_layout(
    o: &Opts,
    ops: &mut Vec<Op>,
    copies: &mut Vec<String>,
    progs: &mut Vec<(String, PathBuf)>,
) -> Res<sandbox::Machines> {
    let c = &o.cfg;
    let ro = |src: String, dst: String| Op::Bind {
        src,
        dst,
        rw: false,
        dev: false,
    };
    let mut specs = vec![];
    for (k, (n, p)) in c.machines.iter().zip(&o.machine_programs).enumerate() {
        let k = k + 1;
        place_program(
            p,
            &format!("machine.{}", n.name),
            &c.mounts,
            ops,
            copies,
            progs,
        )?;
        let w = n.disk_path();
        if w != c.disk_path() && !specs.iter().any(|s: &sandbox::MachineSpec| s.work == w) {
            ops.push(Op::Dir { dst: w.into() });
        }
        let input = match &n.disk {
            Some(dir) => {
                let r = fs::canonicalize(dir)
                    .map_err(|e| format!("machine.{}: work {}: {e}", n.name, dir.display()))?;
                let at = format!("/.patina/machine/{k}/in");
                ops.push(ro(r.display().to_string(), at.clone()));
                Some(at)
            }
            None => None,
        };
        let mut env: Vec<String> = crate::sup::BASE_ENV.iter().map(|s| s.to_string()).collect();
        let set = |env: &mut Vec<String>, kv: &str| {
            let key = kv.split('=').next().unwrap_or("");
            env.retain(|e| e.split('=').next() != Some(key));
            env.push(kv.to_string());
        };
        set(&mut env, &format!("HOME={w}"));
        for kv in c.env.iter().chain(&n.env) {
            set(&mut env, kv);
        }
        set(&mut env, &format!("PATINA_MACHINE={}", n.name));
        let mut argv = vec![
            "rt".to_string(),
            p.guest.clone(),
            if p.copied {
                p.guest.clone()
            } else {
                n.run[0].clone()
            },
        ];
        argv.extend(n.run[1..].iter().cloned());
        specs.push(sandbox::MachineSpec {
            name: n.name.clone(),
            work: w.into(),
            input,
            argv,
            env,
            size: c.machine_disk_bytes(k - 1)?,
            ready: (!n.ready.is_empty()).then(|| crate::ready::runner_argv(&n.ready)),
        });
    }
    let mut readonly: Vec<String> = vec!["/".into(), "/dev".into(), "/guest".into()];
    for (i, m) in c.mounts.iter().enumerate() {
        let dst = crate::config::guest_resolve(&m.dst, &c.mounts[..i]);
        if m.copy && !readonly.contains(&dst) {
            readonly.push(dst);
        }
    }
    Ok(sandbox::Machines {
        machines: specs,
        size: c.tmpfs_bytes,
        hide: vec![c.disk_path().into()],
        readonly,
    })
}

/// Set by `patina verify --vary env` for its changed runs: the launcher's child changes
/// the process state the sandbox and the supervisor inherit before it is normalised (state a caller
/// such as `nice`, `ionice`, `setarch`, `prlimit`, a terminal or a leaked descriptor leaves).
pub static PERTURB: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The perturbation itself, in the launcher's child before the keeper (async-signal-safe).
unsafe fn perturb_child() {
    // A controlling terminal: a new session that opens a pseudo-terminal.
    libc::setsid();
    let m = libc::open(c"/dev/ptmx".as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
    if m >= 0 {
        let zero: libc::c_int = 0;
        libc::ioctl(m, libc::TIOCSPTLCK, &zero);
        let s = libc::ioctl(m, libc::TIOCGPTPEER, libc::O_RDWR);
        if s >= 0 {
            libc::ioctl(s, libc::TIOCSCTTY, 0);
        }
    }
    libc::personality((libc::READ_IMPLIES_EXEC | libc::ADDR_COMPAT_LAYOUT) as libc::c_ulong);
    libc::setpriority(libc::PRIO_PROCESS, 0, 5);
    libc::syscall(libc::SYS_ioprio_set, 1, 0, 3 << 13);
    // Zeroed, not a struct literal: musl's sched_param has more fields than glibc's.
    let p: libc::sched_param = std::mem::zeroed();
    libc::sched_setscheduler(0, libc::SCHED_BATCH, &p);
    libc::prctl(libc::PR_SET_TIMERSLACK, 1_000_000, 0, 0, 0);
    libc::prctl(libc::PR_SET_THP_DISABLE, 1, 0, 0, 0);
    let f = libc::open(c"/proc/self/oom_score_adj".as_ptr(), libc::O_WRONLY);
    if f >= 0 {
        libc::write(f, b"500".as_ptr() as *const libc::c_void, 3);
        libc::close(f);
    }
    // Every soft limit moved below its hard limit (or to a value of its own).
    for r in 0..16 {
        let mut l: libc::rlimit = std::mem::zeroed();
        libc::getrlimit(r, &mut l);
        let half = if l.rlim_max == libc::RLIM_INFINITY {
            1 << 40
        } else {
            l.rlim_max / 2
        };
        l.rlim_cur = half
            .max(if r == libc::RLIMIT_NOFILE { 3100 } else { 0 })
            .min(l.rlim_max);
        libc::setrlimit(r, &l);
    }
    // A descriptor without close-on-exec, as a shell redirection leaves one (above the
    // launcher's own, which are placed after this).
    let n = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
    if n >= 0 {
        libc::fcntl(n, libc::F_DUPFD, 500);
        libc::close(n);
    }
    for s in [
        libc::SIGTERM,
        libc::SIGCHLD,
        libc::SIGALRM,
        libc::SIGWINCH,
        40,
    ] {
        libc::signal(s, libc::SIG_IGN);
    }
}

/// Run a whole chain of boots into `out` (created; must not hold an earlier run):
/// `run.json` first, then the boots, then `result.json`. With `--check`, when the run
/// ended ok the checker runs on the finished directory and `result.json` is written again
/// with its verdict (`check.rs`); the run itself, its logs and digest, are done by then.
pub fn run_one(
    o: &Opts,
    out: &Path,
    cpu: usize,
    no_personality: bool,
) -> Res<(RunEnd, serde_json::Value)> {
    let (end, r, _) = run_one_profiled(o, out, cpu, no_personality, 0, Vec::new())?;
    Ok((end, r))
}

/// Like `run_one`, collecting a `RunProfile` when `PATINA_PROFILE` / `PATINA_PROFILE_OUT` is
/// enabled and attaching `"timing"` to `result.json` (never attached when profiling is off).
pub fn run_one_profiled(
    o: &Opts,
    out: &Path,
    cpu: usize,
    no_personality: bool,
    t_start_ns: u64,
    mut pre_spans: Vec<crate::profile::Span>,
) -> Res<(
    RunEnd,
    serde_json::Value,
    Option<crate::profile::RunProfile>,
)> {
    let prof = crate::profile::enabled();
    let t_dir0 = crate::profile::stamp();
    fs::create_dir_all(out).map_err(|e| format!("create {}: {e}", out.display()))?;
    if out.join("result.json").exists() || out.join("boot-1").exists() {
        return Err(format!("{} already holds a run", out.display()));
    }
    crate::result::write_json(&out.join("run.json"), &crate::result::run_json(o)?)?;
    let t_dir1 = crate::profile::stamp();
    if prof {
        pre_spans.push(crate::profile::Span::new(
            "out_dir_and_run_json",
            "launcher",
            t_dir0,
            t_dir1,
        ));
    }
    let mut end = crate::launcher::boots::run_chain(o, out, cpu, no_personality)?;
    if prof {
        if let Some(ps) = end.planner_span.take() {
            pre_spans.push(ps);
        }
    }
    let t_res0 = crate::profile::stamp();
    let write = |end: &RunEnd, timing: Option<&serde_json::Value>| -> Res<serde_json::Value> {
        let mut r = crate::result::result_json(end, &crate::result::classified(end));
        r["signature"] = crate::signature::of(&r, out);
        if let Some(t) = timing {
            r["timing"] = t.clone();
        }
        crate::result::write_json(&out.join("result.json"), &r)?;
        Ok(r)
    };
    // With a checker, an ok run is written pending until it answers.
    let ok = crate::result::classified(&end).outcome == crate::outcome::Outcome::Ok;
    if o.cfg.check.is_some() {
        end.check = Some(if ok {
            crate::check::Verdict::pending()
        } else {
            crate::check::Verdict::not_run()
        });
    }
    let has_check = o.cfg.check.is_some() && ok;
    if has_check {
        let _ = write(&end, None)?;
        if let Some(c) = &o.cfg.check {
            end.check = Some(crate::check::run(
                c,
                out,
                o.cfg.seed,
                end.verdict.exit_status,
            ));
        }
    }
    if prof {
        let t_end = crate::profile::stamp();
        let c = crate::result::classified(&end);
        let rp = crate::profile::RunProfile {
            seed: end.seed,
            outcome: c.outcome.name().to_string(),
            traps: end.traps,
            switches: end.switches,
            t_start_ns: if t_start_ns > 0 { t_start_ns } else { t_dir0 },
            t_end_ns: t_end,
            pre_spans,
            boots: std::mem::take(&mut end.profile_boots),
            post_spans: vec![crate::profile::Span::new(
                "result_write_and_check",
                "launcher",
                t_res0,
                t_end,
            )],
        };
        let timing_val = rp.to_timing_json();
        let r = write(&end, Some(&timing_val))?;
        Ok((end, r, Some(rp)))
    } else {
        let r = write(&end, None)?;
        Ok((end, r, None))
    }
}

/// Where a boot starts: its number, `/in`, the boundary sequence number and
/// virtual time it continues from, and its fault configuration.
pub struct Start<'a> {
    pub k: u64,
    pub root: Option<&'a Path>,
    pub seq0: u64,
    pub vclock0: u64,
    pub faults: proto::faults::FaultCfg,
    /// Wall time after which the run ends `timeout` (`--timeout`).
    pub deadline: std::time::Instant,
    /// Bytes the earlier boots' logs hold (they count against `[run] log-limit`).
    pub log_used: u64,
    /// System V shared memory a process crash carries to the next boot (`FD_SHM`):
    /// one memfd for the run.
    pub shm: std::os::fd::RawFd,
    /// The run's plans, with load-time points (`launcher::plans`).
    pub planner: Option<std::sync::Arc<crate::launcher::plans::Planner>>,
}

/// The descriptor `Start::shm` names, made once per run.
pub fn shm_carrier() -> Res<OwnedFd> {
    let n = CString::new("patina-shm-state").unwrap();
    let fd = cvt_i(unsafe { libc::memfd_create(n.as_ptr(), libc::MFD_CLOEXEC) })
        .map_err(|e| format!("memfd patina-shm-state: {e}"))?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// What one boot left behind.
pub struct BootEnd {
    pub verdict: Verdict,
    pub digest: u64,
    pub traps: u64,
    pub switches: u64,
    pub refused: Vec<String>,
    /// Absolute paths an exec or open found missing (`proto::vfs::Vfs::missing`).
    pub missing: Vec<(u8, String)>,
    pub seq: u64,
    pub vclock_ns: u64,
    /// Blocking I/O counters, as in `RunEnd::io`.
    pub io: [u64; 5],
    /// Instruction-channel counters.
    pub insn: crate::result::InsnCounts,
    /// Network wire counters, as in `RunEnd::net`.
    pub net: [u64; crate::result::NET_FIELDS],
    /// AF_UNIX sockets sent in SCM_RIGHTS.
    pub unix_sockets: u64,
    /// File calls a full sandbox tmpfs answered `ENOSPC`.
    pub tmpfs_full: u64,
    /// The most bytes the shadow store held.
    pub shadow_bytes: u64,
    /// The SDK's site table.
    pub sdk: crate::result::SdkReport,
    /// `fault_after_seq` and `fault_until_seq` at the end: where the faults began (every
    /// machine ready) and ended (`settle`).
    pub fault_after_seq: u64,
    pub fault_until_seq: u64,
    /// Where `settle` stopped the faults: sequence number and virtual time ns (0: no settle).
    pub settle: [u64; 2],
    /// When each machine was first ready (`MachineTab::ready_ns`).
    pub ready_ns: [u64; proto::machine::MAX_MACHINES],
    /// Pause points and spin probes (`proto::ctl::SCHED_NAMES`).
    pub sched: [u64; proto::ctl::SCHED_FIELDS],
    /// Compute points (`proto::ctl::ComputeStats::read`), and the image table.
    pub compute: [u64; 5],
    /// Load-time plans (`proto::ctl::PLAN_NAMES`).
    pub plans: [u64; proto::ctl::PLAN_FIELDS],
    pub compute_images: crate::result::ComputeImages,
    /// Calls eligible for each runtime fault class (`proto::faults::Kind`), and crash
    /// points passed.
    pub eligible: [u64; proto::faults::NKIND],
    pub crash_points: u64,
    /// Bytes its boundary log and operation log hold.
    pub log_bytes: u64,
    /// A run with machines: `result.json`'s `machines` (`result::machines_json`).
    pub machines: Option<serde_json::Value>,
    /// Coarse phase & optional `patina-rt` profiling for this boot (`PATINA_PROFILE`).
    pub timing: Option<crate::profile::BootTiming>,
}

pub use proto::vfs::SANDBOX_ROOTS;

fn under(p: &str, dir: &str) -> bool {
    p == dir || p.strip_prefix(dir).is_some_and(|r| r.starts_with('/')) || dir == "/"
}

/// Of the paths a run's guest found missing (`(what, path)`, `proto::vfs::MISSING_*`), those
/// the host has, each as `{"path", "mount"}` (a directory to mount at its own path), or for a
/// program run by name and not on the guest's `PATH`, `{"name", "path", "host", "mount"}`
/// (where the host's `PATH` has it). Paths the sandbox itself provides or a mount covers are
/// left out: there the guest's view is the sandbox's, not the host's.
pub fn not_in_sandbox(o: &Opts, missing: &[(u8, String)]) -> Vec<serde_json::Value> {
    let mut covered: Vec<String> = o.cfg.mounts.iter().map(|m| m.dst.clone()).collect();
    covered.push(o.cfg.disk_path().to_string());
    if let Some(d) = Path::new(&o.program.guest).parent() {
        if o.program.dir.is_some() {
            covered.push(d.display().to_string());
        }
    }
    let mut out = vec![];
    let mut named: Vec<String> = vec![];
    for (what, p) in missing {
        if covered.iter().any(|c| under(p, c)) {
            continue;
        }
        let parent = |p: &Path| p.parent().unwrap_or(Path::new("/")).display().to_string();
        if p != "/tmp" && !SANDBOX_ROOTS.iter().any(|r| under(p, r)) {
            let host = Path::new(p);
            if host.exists() {
                let mount = if host.is_dir() {
                    p.clone()
                } else {
                    parent(host)
                };
                out.push(serde_json::json!({"path": p, "mount": mount}));
            }
            continue;
        }
        // A program run by name: the guest's PATH lookup tried it in each PATH directory.
        let dir = parent(Path::new(p));
        if *what != proto::vfs::MISSING_EXEC || !crate::config::GUEST_PATH.contains(&dir.as_str()) {
            continue;
        }
        let Some(name) = Path::new(p).file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // `patina` is the run's own (`GUEST_PATINA`, last on the PATH): the lookup passed the
        // other directories on its way there.
        if name == "patina" || named.iter().any(|n| n == name) {
            continue;
        }
        let found = std::env::var_os("PATH").and_then(|v| {
            std::env::split_paths(&v).map(|d| d.join(name)).find(|f| {
                f.is_file()
                    && !SANDBOX_ROOTS
                        .iter()
                        .any(|r| under(&f.display().to_string(), r))
            })
        });
        if let Some(h) = found {
            named.push(name.to_string());
            out.push(serde_json::json!({"name": name, "path": p, "host": h, "mount": parent(&h)}));
        }
    }
    out
}

/// Key identifying host preflight invariants that cannot change without a reboot, binary rebuild,
/// UID/affinity change, or sysctl change. Returns `None` when test hooks require live probing.
fn preflight_cache_key() -> Option<String> {
    if std::env::var_os("PATINA_TEST_PAGE_SIZE").is_some()
        || std::env::var_os("PATINA_NO_PREFLIGHT_CACHE").is_some()
        || root_user().is_some()
    {
        return None;
    }
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let build = crate::result::build().ok()?;
    let uid = unsafe { libc::geteuid() };
    let aff: Vec<String> = affinity().into_iter().map(|c| c.to_string()).collect();
    let apparmor = fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let sve = fs::read_to_string("/proc/sys/abi/sve_default_vector_length")
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    Some(format!(
        "{}|{}|{}|{}|{}|{}",
        boot_id.trim(),
        build,
        uid,
        aff.join(","),
        apparmor,
        sve
    ))
}

static SPIN_OK_CACHED: std::sync::atomic::AtomicI8 = std::sync::atomic::AtomicI8::new(-1);

fn cached_spin_ok() -> bool {
    let v = SPIN_OK_CACHED.load(Relaxed);
    if v >= 0 {
        return v != 0;
    }
    let ok = crate::host::spin_ok();
    SPIN_OK_CACHED.store(ok as i8, Relaxed);
    ok
}

/// Can a run start here? Checked by every command before its first sandbox: the host meets
/// this architecture's requirements (`host`, which `patina doctor` explains); as root, the
/// sandbox's user namespace can be made and the host paths it binds can be read by the user it
/// maps to; as another user, the host lets this executable make one (`userns_allowed`).
pub fn preflight(o: &Opts) -> Res<()> {
    if let Some(key) = preflight_cache_key() {
        let cache_path = cache_dir().join("preflight.ok");
        if let Ok(text) = fs::read_to_string(&cache_path) {
            if let Some((k, spin)) = text.trim().rsplit_once(' ') {
                if k == key && (spin == "0" || spin == "1") {
                    SPIN_OK_CACHED.store((spin == "1") as i8, Relaxed);
                    return Ok(());
                }
            }
        }
        let facts = crate::host::Facts::probe(None);
        crate::host::refusal(&facts)?;
        userns_allowed()?;
        let spin = facts.spin.is_ok();
        SPIN_OK_CACHED.store(spin as i8, Relaxed);
        let tmp = cache_dir().join(format!(".preflight-{}", std::process::id()));
        if fs::create_dir_all(cache_dir())
            .and_then(|_| fs::write(&tmp, format!("{key} {}\n", spin as u8)))
            .and_then(|_| fs::rename(&tmp, &cache_path))
            .is_err()
        {
            let _ = fs::remove_file(&tmp);
        }
        return Ok(());
    }
    let facts = crate::host::Facts::probe(None);
    crate::host::refusal(&facts)?;
    SPIN_OK_CACHED.store(facts.spin.is_ok() as i8, Relaxed);
    if root_user().is_none() {
        userns_allowed()?;
    }
    if let Some(user) = root_user() {
        userns()?;
        if user.0 == OVERFLOW {
            let mut paths: Vec<&Path> = o.cfg.mounts.iter().map(|m| m.src.as_path()).collect();
            paths.extend(o.program.dir.as_deref());
            if o.program.copied {
                paths.push(&o.program.host);
            }
            for p in paths {
                if let Some(why) = closed_to_others(p) {
                    return Err(format!(
                        "running as root, the sandbox's user is nobody (no SUDO_UID), and {why}: \
                         make it readable by others, or run patina through sudo as a user who can"
                    ));
                }
            }
        }
    }
    Ok(())
}

const OVERFLOW: u32 = 65534;

/// Whether the host lets this executable make the sandbox's user namespace and map itself in
/// it, as the sandbox does first: tried in a child only where a sysctl restricts unprivileged
/// user namespaces (Ubuntu 24.04 and later admit them for a program with an AppArmor
/// profile). A refusal is `patina doctor`'s finding and its fix, before any run directory.
fn userns_allowed() -> Res<()> {
    let on =
        |k: &str| std::fs::read_to_string(format!("/proc/sys/{k}")).is_ok_and(|v| v.trim() == "1");
    if !on("kernel/apparmor_restrict_unprivileged_userns") {
        return Ok(());
    }
    // The child: a new user namespace, then the write the sandbox makes first in it, dumpable
    // as the sandbox is then (a patina with file capabilities starts undumpable: its /proc/self
    // files would be root's).
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0);
            let e = if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                *libc::__errno_location()
            } else {
                let fd = libc::open(c"/proc/self/setgroups".as_ptr(), libc::O_WRONLY);
                if fd < 0 || libc::write(fd, b"deny".as_ptr().cast(), 4) != 4 {
                    *libc::__errno_location()
                } else {
                    0
                }
            };
            libc::_exit(e.clamp(0, 255));
        }
    }
    if pid < 0 {
        return Ok(());
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    match libc::WIFEXITED(st).then(|| libc::WEXITSTATUS(st)) {
        Some(0) | None => Ok(()),
        Some(e) => Err(format!(
            "this host does not let {} make its sandbox: /proc/self/setgroups: {}\nfix: {}",
            crate::doctor::exe().display(),
            std::io::Error::from_raw_os_error(e),
            crate::doctor::namespace_fix()
        )),
    }
}

/// Run as root, the host user the sandbox's user 1000 is: the user sudo was run by
/// (`SUDO_UID`, `SUDO_GID`), else nobody. `None` for an ordinary user, whose own uid it is.
fn root_user() -> Option<(u32, u32)> {
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let id = |k: &str| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|&v| v != 0)
    };
    Some((
        id("SUDO_UID").unwrap_or(OVERFLOW),
        id("SUDO_GID").unwrap_or(OVERFLOW),
    ))
}

/// Why `p` cannot be read by a user who owns nothing on the way to it, if it cannot.
fn closed_to_others(p: &Path) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = |q: &Path| {
        fs::metadata(q)
            .map(|m| (m.permissions().mode(), m.is_dir()))
            .ok()
    };
    let (m, dir) = mode(p)?;
    if m & 0o004 == 0 || (dir && m & 0o001 == 0) {
        return Some(format!("{} is mode {:o}", p.display(), m & 0o777));
    }
    for a in p.ancestors().skip(1) {
        if let Some((m, _)) = mode(a) {
            if m & 0o001 == 0 {
                return Some(format!("{} is mode {:o}", a.display(), m & 0o777));
            }
        }
    }
    None
}

/// Run as root, the user namespace the sandbox's keeper joins (`sandbox::Spec::join_userns`),
/// made once per process: its uid and gid 0 are the host user `root_user` names and nothing else
/// is mapped, as in the namespace an ordinary user's keeper makes for itself. The guests' own
/// namespace, nested in it, is the same for both, so the guest sees the same thing either way
/// and nothing of who started the run. `None` for an ordinary user.
pub fn userns() -> Res<Option<i32>> {
    static NS: std::sync::OnceLock<Result<OwnedFd, String>> = std::sync::OnceLock::new();
    let Some((uid, gid)) = root_user() else {
        return Ok(None);
    };
    match NS.get_or_init(|| make_userns(uid, gid)) {
        Ok(fd) => Ok(Some(fd.as_raw_fd())),
        Err(e) => Err(format!(
            "running as root, the sandbox's user namespace cannot be made ({e}): \
             `patina doctor` says what this host needs"
        )),
    }
}

fn make_userns(uid: u32, gid: u32) -> Result<OwnedFd, String> {
    let (mut a, mut b) = ([0i32; 2], [0i32; 2]);
    cvt_i(unsafe { libc::pipe2(a.as_mut_ptr(), libc::O_CLOEXEC) }).map_err(|e| e.to_string())?;
    cvt_i(unsafe { libc::pipe2(b.as_mut_ptr(), libc::O_CLOEXEC) }).map_err(|e| e.to_string())?;
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // The child: a new user namespace, kept until the parent has its descriptor.
        let mut c = [0u8; 1];
        unsafe {
            let ok = libc::unshare(libc::CLONE_NEWUSER) == 0;
            let e = if ok {
                0
            } else {
                *libc::__errno_location() as u8
            };
            libc::write(a[1], [e].as_ptr().cast(), 1);
            libc::read(b[0], c.as_mut_ptr().cast(), 1);
            libc::_exit(0);
        }
    }
    let ours = [a[1], b[0]];
    for fd in ours {
        unsafe { libc::close(fd) };
    }
    let (rd, wr) = unsafe { (File::from_raw_fd(a[0]), File::from_raw_fd(b[1])) };
    let res = (|| {
        if pid < 0 {
            return Err(format!("fork: {}", std::io::Error::last_os_error()));
        }
        let mut e = [0u8; 1];
        (&rd)
            .read_exact(&mut e)
            .map_err(|e| format!("child: {e}"))?;
        if e[0] != 0 {
            return Err(format!(
                "unshare: {}",
                std::io::Error::from_raw_os_error(e[0] as i32)
            ));
        }
        let w = |f: &str, v: String| {
            fs::write(format!("/proc/{pid}/{f}"), v).map_err(|e| format!("{f}: {e}"))
        };
        w("uid_map", format!("0 {uid} 1\n"))?;
        w("setgroups", "deny".into())?;
        w("gid_map", format!("0 {gid} 1\n"))?;
        File::open(format!("/proc/{pid}/ns/user"))
            .map(OwnedFd::from)
            .map_err(|e| format!("ns/user: {e}"))
    })();
    if pid > 0 {
        let _ = (&wr).write_all(b"x");
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
    }
    res
}

/// Run one boot into `bdir` (created), optionally reusing a persistent `SandboxWorker` for
/// single-machine first boots (`patina batch`).
pub fn run_boot_with_worker(
    o: &Opts,
    bdir: &Path,
    cpu: usize,
    no_personality: bool,
    start: &Start,
    worker: Option<&mut Option<sandbox::SandboxWorker>>,
) -> Res<BootEnd> {
    let t_launch = mono_ns();
    let bdir = bdir.to_path_buf();
    fs::create_dir_all(&bdir).map_err(|e| format!("create {}: {e}", bdir.display()))?;

    let create = |name: &str| -> Res<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(bdir.join(name))
            .map_err(|e| format!("create {name}: {e}"))
    };
    let log = create("boundary.log")?;
    // Blocks allocated eagerly (`LOG_INIT` first, growing geometrically in `rt::log::grow` and
    // `sup::ensure_log` up to `LOG_STEP`): a full filesystem fails here or at an extension,
    // never as a store through the mapping.
    let r = unsafe { libc::fallocate(log.as_raw_fd(), 0, 0, LOG_INIT as i64) };
    if r != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EOPNOTSUPP) {
        return Err(format!("boundary.log: {}", std::io::Error::last_os_error()));
    }
    log.set_len(LOG_INIT)
        .map_err(|e| format!("boundary.log: {e}"))?;
    let opmeta = create("oplog.meta")?;
    let opdata = create("oplog.data")?;
    // The guest's stdio are sandbox objects, never host files: an empty read-only memfd
    // for stdin and a memfd each for stdout and stderr. Their metadata is a function of the
    // guest's own writes (no host filesystem, no preallocation or writeback, no host times),
    // and the guest cannot truncate, chmod, lock or grow a host file through them. The
    // launcher keeps its own references and copies the contents into the run directory when
    // the sandbox is gone. The keeper's own stdout and stderr (and anything printed before the
    // supervisor starts) go to `sandbox.log`.
    let stdin_data = match &o.cfg.stdin {
        Some(p) => fs::read(p).map_err(|e| format!("--stdin {}: {e}", p.display()))?,
        None => vec![],
    };
    let stdin_mem = stdio_memfd("patina-stdin", Some(&stdin_data))?;
    let stdout_mem = stdio_memfd("patina-stdout", None)?;
    let stderr_mem = stdio_memfd("patina-stderr", None)?;
    let sandbox_log = create("sandbox.log")?;
    let export = create("live.tree")?;

    // Control region.
    let name = CString::new("patina-ctl").unwrap();
    let memfd = cvt_i(unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) })
        .map_err(|e| format!("memfd: {e}"))?;
    let memfd = unsafe { OwnedFd::from_raw_fd(memfd) };
    cvt_i(unsafe { libc::ftruncate(memfd.as_raw_fd(), CTL_SIZE as i64) })
        .map_err(|e| format!("ftruncate ctl: {e}"))?;
    let ctl_ptr = map_shared(memfd.as_raw_fd(), CTL_SIZE).map_err(|e| format!("map ctl: {e}"))?;
    let c = &o.cfg;
    let mut cfg = Config::default_with_seed(c.seed ^ replay_perturb());
    cfg.preempt_permille = c.preempt_permille;
    cfg.vtime_limit_ns = c.time_limit * 1_000_000_000;
    cfg.stall_ms = c.stall_ms;
    cfg.tmpfs_bytes = c.tmpfs_bytes;
    cfg.cpu_count = c.cpus;
    cfg.spin_charge_ns = cfg.trap_charge_ns;
    cfg.compute_gap = o.plan.compute_gap;
    cfg.compute_budget = o.plan.compute_budget as u64;
    cfg.compute_walk = o.plan.compute_walk;
    cfg.compute_charge_ns = proto::compute::CHARGE_NS;
    cfg.log_limit = (c.log_limit << 20).saturating_sub(start.log_used);
    // Every call's path and argument strings are in the log, for checkers and `explain`.
    cfg.log_paths = 1;
    cfg.observe = c.observe as u64;
    cfg.debug = c.debug_at.unwrap_or(0);
    if c.pause_points {
        cfg.sched |= proto::ctl::SCHED_PAUSE_POINTS;
    }
    if c.emulate_rndr {
        cfg.insn |= proto::ctl::INSN_EMULATE_RNDR;
    }
    if c.preempt.points() {
        cfg.sched |= proto::ctl::SCHED_POINTS;
    }
    // Where the host cannot make spin probes work they are off (`host::spin_probes`).
    if c.spin_probes {
        cfg.sched |= if cached_spin_ok() {
            proto::ctl::SCHED_SPIN_PROBE
        } else {
            proto::ctl::SCHED_SPIN_HOST_OFF
        };
    }
    cfg.work[..c.disk_path().len()].copy_from_slice(c.disk_path().as_bytes());
    if !c.machines.is_empty() {
        cfg.machines = c.machines.len() as u64 + 1;
    }
    unsafe { Ctl::init(ctl_ptr as *mut Ctl, cfg) };
    if !c.machines.is_empty() {
        let t = unsafe { proto::machine::MachineTab::at(ctl_ptr) };
        t.set(
            std::iter::once(proto::machine::MAIN)
                .chain(c.machines.iter().map(|n| n.name.as_bytes())),
        );
        // Each machine's restart policy, boots and ok-exit statuses, and the run's kill and
        // down-time settings (`sup::machines`); main's pauses and clock skew.
        let p = &o.plan;
        t.conf[0] = proto::machine::MachineConf {
            pause_gap_min_ns: p.machine_pause[0][0],
            pause_gap_max_ns: p.machine_pause[0][1],
            pause_min_ns: p.machine_pause[0][2],
            pause_max_ns: p.machine_pause[0][3],
            skew_min_ns: p.machine_skew[0].0,
            skew_max_ns: p.machine_skew[0].1,
            ..Default::default()
        };
        for (i, n) in c.machines.iter().enumerate() {
            let k = i + 1;
            let w = n.disk_path().as_bytes();
            t.work[k][..w.len()].copy_from_slice(w);
            let mut ok_exit = [0u64; 4];
            for s in n.ok_exit.as_deref().unwrap_or(&[0]) {
                ok_exit[(*s / 64) as usize] |= 1 << (s % 64);
            }
            t.conf[k] = proto::machine::MachineConf {
                restart: match n.restart.as_deref() {
                    Some("always") => proto::machine::RESTART_ALWAYS,
                    Some("never") => proto::machine::RESTART_NEVER,
                    _ => proto::machine::RESTART_CRASH,
                },
                max_boots: n
                    .max_boots
                    .unwrap_or(p.max_boots)
                    .min(proto::machine::BOOTS_MAX as u64),
                crash: if (p.machine_crash >> k) & 1 != 0 {
                    p.machine_crash_kind
                } else {
                    0
                },
                ok_exit,
                pause_gap_min_ns: p.machine_pause[k][0],
                pause_gap_max_ns: p.machine_pause[k][1],
                pause_min_ns: p.machine_pause[k][2],
                pause_max_ns: p.machine_pause[k][3],
                skew_min_ns: p.machine_skew[k].0,
                skew_max_ns: p.machine_skew[k].1,
            };
        }
        t.fs_model = (o.fs_model == crate::durability::materialise::Model::PosixStrict) as u64;
        (t.crash_gap_min_ns, t.crash_gap_max_ns) = p.crash_gap_ns;
        (t.down_min_ns, t.down_max_ns) = p.down_ns;
        for (f, cfg) in t.faults.iter_mut().zip(p.machine_faults).skip(1) {
            unsafe { std::ptr::write_volatile(std::ptr::addr_of_mut!(f.cfg), cfg) };
        }
        for (d, cfg) in t.sdk.iter_mut().zip(p.machine_sdk).skip(1) {
            *d = proto::sdk::SdkCfg {
                boot: start.k,
                ..cfg
            };
        }
    }
    let ctl = unsafe { Ctl::at(ctl_ptr) };
    ctl.log_cap.store(LOG_INIT, Relaxed);
    if start.k > 0 {
        ctl.seq.store(start.seq0, Relaxed);
        ctl.vclock_ns.store(start.vclock0, Relaxed);
    }
    unsafe {
        std::ptr::write_volatile(
            std::ptr::addr_of!(ctl.faults.cfg) as *mut proto::faults::FaultCfg,
            start.faults,
        )
    };
    // Network fault configuration, read by the supervisor's wire.
    unsafe { proto::wire::WireTab::at(ctl_ptr).cfg = o.plan.net };
    // SDK fault points (`proto::sdk`), read by the runtime.
    unsafe {
        proto::sdk::SdkTab::at(ctl_ptr).cfg = proto::sdk::SdkCfg {
            boot: start.k,
            ..o.plan.sdk
        }
    };

    // Outcome pipe.
    let mut p = [0i32; 2];
    cvt_i(unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) })
        .map_err(|e| format!("pipe: {e}"))?;
    let (outcome_r, outcome_w) = unsafe { (File::from_raw_fd(p[0]), OwnedFd::from_raw_fd(p[1])) };
    let t_files_ready = crate::profile::stamp();

    // The supervisor runs directly in PID 1 after sandbox setup (no second exec of patina).
    let work = c.disk_path();
    let personality = !no_personality;
    let perturb = PERTURB.load(Relaxed);
    let reuse_eligible = worker.is_some()
        && start.k == 0
        && c.machines.is_empty()
        && !no_personality
        && !perturb
        && c.debug_at.is_none()
        && std::env::var_os("PATINA_NO_SANDBOX_REUSE").is_none();

    // Reuse an already-started worker's `copies` list without rebuilding `Layout` (avoids cloning
    // `/etc/ld.so.cache` and `/etc/alternatives` and re-opening `rt_file` on every hot batch job).
    let mut cached_layout: Option<Layout> = None;
    let copies_ref: &[String] = if reuse_eligible {
        if let Some(Some(w)) = worker.as_deref() {
            w.copies()
        } else {
            cached_layout = Some(layout(o, start.root)?);
            &cached_layout.as_ref().unwrap().copies
        }
    } else {
        cached_layout = Some(layout(o, start.root)?);
        &cached_layout.as_ref().unwrap().copies
    };

    let mut sup_args: Vec<String> = vec![];
    for cp in copies_ref {
        sup_args.extend(["--copy".into(), cp.clone()]);
    }
    sup_args.extend(["--exe".into(), o.program.guest.clone()]);
    for e in c.env.iter().chain(&c.main_env) {
        sup_args.extend(["--env".into(), e.clone()]);
    }
    // The `ready` probes, at the first boot only (`sup::ready`): each machine's number, then
    // its probe's words.
    if start.k == 0 {
        let probes = std::iter::once(&c.ready).chain(c.machines.iter().map(|m| &m.ready));
        for (k, w) in probes.enumerate().filter(|(_, w)| !w.is_empty()) {
            sup_args.extend(["--ready".into(), k.to_string()]);
            for x in w {
                sup_args.extend(["--ready-arg".into(), x.clone()]);
            }
        }
    }
    if !c.machines.is_empty() {
        sup_args.push("--machines".into());
    }
    sup_args.extend(["--env".into(), "PATINA_MACHINE=main".into()]);
    sup_args.extend(["--env".into(), format!("PATINA_BOOT={}", start.k + 1)]);
    sup_args.push("--".into());
    // argv[0]: a copied program is named by where it runs from.
    sup_args.push(if o.program.copied {
        o.program.guest.clone()
    } else {
        c.cmd[0].clone()
    });
    sup_args.extend(c.cmd[1..].iter().cloned());
    // As root, the user namespace is joined from a descriptor at FD_USERNS.
    let userns = userns()?;
    // The plan broker's sandbox end.
    let (plan_sandbox, plan_ours) = match &start.planner {
        Some(_) => {
            let (a, b) = crate::launcher::plans::pair()?;
            (Some(a), Some(b))
        }
        None => (None, None),
    };
    let t_spec_ready = crate::profile::stamp();

    let mut machine_stdio = vec![];
    let mut verdict_text = String::new();
    let mut outcome_r = outcome_r;

    let reuse_req = if reuse_eligible {
        let req = sandbox::JobReq {
            sup_args: sup_args.clone(),
            chdir: work.into(),
            main_disk_bytes: c.main_disk_bytes()?,
            has_plan: plan_sandbox.is_some(),
        };
        let bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
        (bytes.len() <= sandbox::WORKER_REQ_MAX).then_some(bytes)
    } else {
        None
    };

    let (t_spawn, t_verdict, t_waited, sandbox_status) =
        if let (Some(slot), Some(req_bytes)) = (worker, reuse_req) {
            let mut job_fds = vec![
                memfd.as_raw_fd(),
                log.as_raw_fd(),
                opmeta.as_raw_fd(),
                opdata.as_raw_fd(),
                outcome_w.as_raw_fd(),
                export.as_raw_fd(),
                stdin_mem.as_raw_fd(),
                stdout_mem.as_raw_fd(),
                stderr_mem.as_raw_fd(),
                start.shm,
                sandbox_log.as_raw_fd(),
            ];
            if let Some(f) = &plan_sandbox {
                job_fds.push(f.as_raw_fd());
            }

            let t_spawn = mono_ns();
            let mut dispatched = false;
            if let Some(w) = slot.as_ref() {
                if w.dispatch(&req_bytes, &job_fds).is_ok() {
                    dispatched = true;
                } else {
                    *slot = None;
                }
            }
            if !dispatched {
                let lay = match cached_layout.take() {
                    Some(l) => l,
                    None => layout(o, start.root)?,
                };
                let rt_file = rt_file()?;
                let w = sandbox::SandboxWorker::start(
                    &lay.ops,
                    &lay.data,
                    lay.copies,
                    work,
                    rt_file.as_raw_fd(),
                    userns,
                    cpu,
                )?;
                w.dispatch(&req_bytes, &job_fds)?;
                *slot = Some(w);
            }
            drop(outcome_w);
            drop(plan_sandbox);

            let plan_broker = match (plan_ours, &start.planner) {
                (Some(ours), Some(p)) => Some(crate::launcher::plans::Broker::start(
                    ours,
                    p.clone(),
                    cpu,
                    // The control region outlives the broker (`stop` below, before the unmap).
                    &unsafe { Ctl::at(ctl_ptr) }.compute.planning,
                )?),
                _ => None,
            };
            let waited = wait_fd(outcome_r.as_raw_fd(), start.deadline);
            let timed_out = waited != Waited::Ready;
            if timed_out {
                if let Some(w) = slot.as_ref() {
                    w.cancel();
                }
            } else {
                let _ = outcome_r.read_to_string(&mut verdict_text);
            }
            let t_verdict = mono_ns();
            let finish_res = slot
                .as_ref()
                .ok_or_else(|| "sandbox worker missing".to_string())
                .and_then(|w| w.finish());
            let (code, dirty) = match finish_res {
                Ok(v) => v,
                Err(_) => {
                    *slot = None;
                    (1, true)
                }
            };
            if dirty || waited == Waited::Terminated {
                *slot = None;
            }
            if waited == Waited::Terminated {
                exit_terminated();
            }
            if timed_out {
                verdict_text = Verdict::new(
                    "timeout",
                    format!(
                        "--timeout: {} s of wall time passed (boot {})",
                        o.cfg.timeout,
                        start.k + 1
                    ),
                )
                .encode();
            }
            if let Some(b) = plan_broker {
                b.stop();
            }
            let t_waited = mono_ns();
            (t_spawn, t_verdict, t_waited, format!("exit status: {code}"))
        } else {
            let lay = match cached_layout.take() {
                Some(l) => l,
                None => layout(o, start.root)?,
            };
            let rt_file = rt_file()?;
            let spec = sandbox::Spec {
                ops: lay.ops,
                join_userns: userns.is_some(),
                chdir: work.into(),
                env: vec![],
                argv: vec![],
                exe: None,
                after: sandbox::After::Sup { args: sup_args },
                machines: lay.machines,
            };
            let spec_fd = sandbox::data_fd(&serde_json::to_vec(&spec).map_err(|e| e.to_string())?)?;
            let mut etc_fds = vec![];
            for d in &lay.data {
                etc_fds.push(sandbox::data_fd(d)?);
            }

            // Descriptors to place at fixed numbers in the child.
            let mut place: Vec<(i32, i32)> = vec![
                (memfd.as_raw_fd(), FD_CTL),
                (log.as_raw_fd(), FD_LOG),
                (opmeta.as_raw_fd(), FD_OPLOG_META),
                (opdata.as_raw_fd(), FD_OPLOG_DATA),
                (rt_file.as_raw_fd(), FD_RT),
                (outcome_w.as_raw_fd(), FD_OUTCOME),
                (export.as_raw_fd(), FD_EXPORT),
                (stdin_mem.as_raw_fd(), FD_STDIN),
                (stdout_mem.as_raw_fd(), FD_STDOUT),
                (stderr_mem.as_raw_fd(), FD_STDERR),
                (start.shm, FD_SHM),
            ];
            for (i, f) in etc_fds.iter().enumerate() {
                place.push((f.as_raw_fd(), sandbox::FD_DATA0 + i as i32));
            }
            place.push((spec_fd.as_raw_fd(), sandbox::FD_SPEC));
            if let Some(fd) = userns {
                place.push((fd, sandbox::FD_USERNS));
            }
            // Each machine's stdio: memfds as main's (an empty stdin).
            for (k, n) in c.machines.iter().enumerate() {
                let fds = [
                    stdio_memfd(&format!("patina-{}-stdin", n.name), Some(&[]))?,
                    stdio_memfd(&format!("patina-{}-stdout", n.name), None)?,
                    stdio_memfd(&format!("patina-{}-stderr", n.name), None)?,
                ];
                for (j, f) in fds.iter().enumerate() {
                    place.push((
                        f.as_raw_fd(),
                        sandbox::FD_MACHINE_STDIO0 + 3 * k as i32 + j as i32,
                    ));
                }
                machine_stdio.push(fds);
            }
            if let Some(f) = &plan_sandbox {
                place.push((f.as_raw_fd(), FD_PLAN));
            }

            let mut cmd = sandbox::command(place, move || unsafe {
                if perturb {
                    perturb_child();
                }
                // The whole persona is set, not a flag added to the caller's (setarch -R/-X
                // and friends are inherited). umask, limits, signals and the rest: sup::inherit.
                let pers = if personality {
                    libc::ADDR_NO_RANDOMIZE as libc::c_ulong
                } else {
                    0
                };
                if libc::personality(pers) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let mut set: libc::cpu_set_t = std::mem::zeroed();
                libc::CPU_SET(cpu, &mut set);
                if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
            cmd.stdin(Stdio::null())
                .stdout(sandbox_log.try_clone().map_err(|e| e.to_string())?)
                .stderr(sandbox_log.try_clone().map_err(|e| e.to_string())?);
            let t_spawn = mono_ns();
            let mut child = cmd.spawn().map_err(|e| format!("sandbox: {e}"))?;
            drop(outcome_w);
            drop(etc_fds);
            drop(spec_fd);
            drop(plan_sandbox);
            let plan_broker = match (plan_ours, &start.planner) {
                (Some(ours), Some(p)) => Some(crate::launcher::plans::Broker::start(
                    ours,
                    p.clone(),
                    cpu,
                    // The control region outlives the broker (`stop` below, before the unmap).
                    &unsafe { Ctl::at(ctl_ptr) }.compute.planning,
                )?),
                _ => None,
            };
            // `patina debug`: the stop, the user's debugger, the release (`debug::Watch`).
            let watch = c.debug_at.map(|_| {
                crate::debug::Watch::start(
                    ctl_ptr as usize,
                    child.id() as i32,
                    bdir.parent().unwrap_or(Path::new(".")),
                )
            });
            let waited = wait_fd(outcome_r.as_raw_fd(), start.deadline);
            if let Some(w) = watch {
                w.finish(waited == Waited::Ready);
            }
            let timed_out = waited != Waited::Ready;
            if timed_out {
                end_sandbox(&mut child);
            } else {
                let _ = outcome_r.read_to_string(&mut verdict_text);
            }
            let t_verdict = mono_ns();
            let status = child
                .wait()
                .map_err(|e| format!("wait for the sandbox: {e}"))?;
            if waited == Waited::Terminated {
                // Stopped (a sweep interrupted): the sandbox is gone; no result is written.
                exit_terminated();
            }
            if timed_out {
                verdict_text = Verdict::new(
                    "timeout",
                    format!(
                        "--timeout: {} s of wall time passed (boot {})",
                        o.cfg.timeout,
                        start.k + 1
                    ),
                )
                .encode();
            }
            if let Some(b) = plan_broker {
                b.stop();
            }
            let t_waited = mono_ns();
            (t_spawn, t_verdict, t_waited, status.to_string())
        };
    let stdio_max = std::env::var("PATINA_TEST_STDIO_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(STDIO_MAX);
    let mut truncated = vec![];
    for (mem, name) in [(&stdout_mem, "stdout"), (&stderr_mem, "stderr")] {
        if copy_stdio(mem, &create(name)?, stdio_max).map_err(|e| format!("copy {name}: {e}"))? {
            truncated.push(name);
        }
    }
    // Each machine's stdio: `machine/NAME/boot-K/` for its boot K (main's is `boot-1/`), each
    // the part of the machine's output from where the boot started to where the next did.
    let tab: Option<&proto::machine::MachineTab> =
        (!c.machines.is_empty()).then(|| &*unsafe { proto::machine::MachineTab::at(ctl_ptr) });
    for (i, (n, fds)) in c.machines.iter().zip(&machine_stdio).enumerate() {
        let k = i + 1;
        let boots = tab.map_or(1, |t| {
            (t.boots[k] as usize).clamp(1, proto::machine::BOOTS_MAX)
        });
        for b in 0..boots {
            let dir = bdir
                .parent()
                .unwrap_or(Path::new("."))
                .join("machine")
                .join(&n.name)
                .join(crate::durability::check::boot_dir(b as u64));
            fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
            let off = |b: usize, j: usize| -> u64 {
                match tab {
                    Some(t) if b < boots => [t.boot[k][b].out_off, t.boot[k][b].err_off][j],
                    _ if b == 0 => 0,
                    _ => u64::MAX,
                }
            };
            for (j, (mem, name)) in [(&fds[1], "stdout"), (&fds[2], "stderr")]
                .into_iter()
                .enumerate()
            {
                let f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(dir.join(name))
                    .map_err(|e| format!("create machine {} {name}: {e}", n.name))?;
                if copy_stdio_part(mem, &f, off(b, j), off(b + 1, j), stdio_max)
                    .map_err(|e| format!("copy {name}: {e}"))?
                {
                    truncated.push(name);
                }
            }
        }
    }
    drop(machine_stdio);
    // Truncate preallocated oplog files back to their written lengths before any reader sees them.
    opmeta
        .set_len(ctl.oplog_len.load(Relaxed))
        .map_err(|e| format!("truncate oplog.meta: {e}"))?;
    opdata
        .set_len(ctl.opdata_len.load(Relaxed))
        .map_err(|e| format!("truncate oplog.data: {e}"))?;
    // Each machine's disks: their parts of the shared operation log (`machine/NAME/boot-K/`, K the
    // boot a disk began with).
    if !c.machines.is_empty() {
        let run = bdir.parent().unwrap_or(Path::new("."));
        crate::durability::log::split_machines(&bdir, |k, b| {
            c.machines.get(k.wrapping_sub(1)).map(|n| {
                run.join("machine")
                    .join(&n.name)
                    .join(crate::durability::check::boot_dir(b))
            })
        })?;
    }

    let mut verdict = Verdict::decode(&verdict_text).unwrap_or_else(|| {
        let err = fs::read_to_string(bdir.join("stderr")).unwrap_or_default()
            + &fs::read_to_string(bdir.join("sandbox.log")).unwrap_or_default();
        let last = err
            .lines()
            .rev()
            .find(|l| !l.is_empty())
            .unwrap_or("")
            .to_string();
        Verdict::new(
            "infra",
            format!(
                "no verdict from the supervisor (sandbox {sandbox_status}): {last}{}",
                // The keeper's or PID 1's own refusal: the host's to fix.
                if last.starts_with("patina")
                    && (last.contains("(os error 1)") || last.contains("(os error 13)"))
                {
                    " (`patina doctor` says what this host needs)"
                } else {
                    ""
                }
            ),
        )
    });
    if verdict.class == "failed" {
        if let Ok(err) = fs::read_to_string(bdir.join("stderr")) {
            if let Some(l) = err.lines().find(|l| l.starts_with("INVARIANT ")) {
                verdict.detail = l.to_string();
            }
        }
    }

    if !truncated.is_empty() && !matches!(verdict.class.as_str(), "infra" | "disk-full") {
        // More output than the run directory takes: the comparison would miss the rest.
        verdict = Verdict::new(
            "output-limit",
            format!(
                "guest {} larger than {stdio_max} bytes",
                truncated.join(" and ")
            ),
        );
    }
    let log_len = ctl.log_len.load(Relaxed);
    log.set_len(log_len)
        .map_err(|e| format!("truncate boundary.log: {e}"))?;
    if c.observe {
        crate::log::take_observations(&bdir)?;
    }
    let t_stdio_done = crate::profile::stamp();
    let mut refused: Vec<String> = ctl
        .denied_nrs()
        .map(|n| proto::table::name(n).to_string())
        .collect();
    let vfs = unsafe { proto::vfs::Vfs::at(ctl_ptr) };
    refused.extend(
        vfs.refused()
            .map(|p| String::from_utf8_lossy(p).into_owned()),
    );
    let missing = vfs
        .missing()
        .map(|(w, p)| (w, String::from_utf8_lossy(p).into_owned()))
        .collect();
    let end = BootEnd {
        verdict,
        digest: ctl.log_hash.load(Relaxed),
        traps: ctl.stats.traps.load(Relaxed),
        switches: ctl.stats.switches.load(Relaxed),
        refused,
        missing,
        seq: ctl.seq.load(Relaxed),
        vclock_ns: ctl.vclock_ns.load(Relaxed),
        io: [
            ctl.io.parks.load(Relaxed),
            ctl.io.reattempts.load(Relaxed),
            ctl.io.spurious.load(Relaxed),
            ctl.io.blocking_done.load(Relaxed),
            ctl.io.blocking_parked.load(Relaxed),
        ],
        insn: crate::result::InsnCounts::read(&ctl.insn),
        net: crate::result::net_read(unsafe { &proto::wire::WireTab::at(ctl_ptr).counters }),
        unix_sockets: ctl.stats.unix_sockets_sent.load(Relaxed),
        tmpfs_full: ctl.stats.tmpfs_full.load(Relaxed),
        shadow_bytes: unsafe { proto::oplog::Dur::at(ctl_ptr).shadows.peak },
        sdk: crate::result::SdkReport::read(unsafe { proto::sdk::SdkTab::at(ctl_ptr) }),
        fault_after_seq: ctl.faults.cfg.fault_after_seq,
        fault_until_seq: ctl.faults.cfg.fault_until_seq,
        settle: [ctl.settle.seq.load(Relaxed), ctl.settle.ns.load(Relaxed)],
        ready_ns: unsafe { proto::machine::MachineTab::at(ctl_ptr) }.ready_ns,
        sched: ctl.sched.read(),
        compute: ctl.compute.read(),
        plans: ctl.compute.plans(),
        compute_images: crate::result::ComputeImages::read(unsafe {
            proto::ctl::ComputeTab::at(ctl_ptr)
        }),
        // Every machine's eligible calls with main's (a run without machines has none).
        eligible: std::array::from_fn(|i| {
            let t = unsafe { proto::machine::MachineTab::at(ctl_ptr) };
            ctl.faults.eligible[i].load(Relaxed)
                + t.faults
                    .iter()
                    .map(|f| f.eligible[i].load(Relaxed))
                    .sum::<u64>()
        }),
        crash_points: ctl.faults.crash_points.load(Relaxed),
        log_bytes: ctl.log_used(),
        machines: (!c.machines.is_empty()).then(|| {
            crate::result::machines_json(unsafe { proto::machine::MachineTab::at(ctl_ptr) })
        }),
        timing: if crate::profile::enabled() {
            let tm = |i: usize| ctl.timing[i].load(Relaxed);
            #[cfg(feature = "profile")]
            let rt = Some(crate::profile::RtProfileSnapshot::read_from_ctl(ctl_ptr));
            #[cfg(not(feature = "profile"))]
            let rt = None;
            Some(crate::profile::BootTiming {
                boot: start.k + 1,
                t_boot_start: t_launch,
                t_files_ready,
                t_spec_ready,
                t_spawn,
                t_sandbox_pid1: tm(TM_SANDBOX_PID1),
                t_sandbox_setup: tm(TM_SANDBOX_SETUP),
                t_sup_start: tm(TM_SUP_START),
                t_copied: tm(TM_COPIED),
                t_first_hello: tm(TM_FIRST_HELLO),
                t_main_exit: tm(TM_MAIN_EXIT),
                t_finish: tm(TM_FINISH),
                t_exported: tm(TM_EXPORTED),
                t_verdict,
                t_waited,
                t_stdio_done,
                t_boot_done: mono_ns(),
                traps: ctl.stats.traps.load(Relaxed),
                switches: ctl.stats.switches.load(Relaxed),
                rt,
            })
        } else {
            None
        },
    };
    if std::env::var_os("PATINA_TEST_TIMING").is_some() {
        // cost measurement start-up breakdown: host CLOCK_MONOTONIC ns, launcher and supervisor marks.
        let tm = |i: usize| ctl.timing[i].load(Relaxed);
        eprintln!(
            "patina-timing boot={} launch={t_launch} spawn={t_spawn} sup_start={} copied={} first_hello={} main_exit={} finish={} exported={} verdict={t_verdict} waited={t_waited} done={}",
            start.k + 1,
            tm(TM_SUP_START),
            tm(TM_COPIED),
            tm(TM_FIRST_HELLO),
            tm(TM_MAIN_EXIT),
            tm(TM_FINISH),
            tm(TM_EXPORTED),
            mono_ns()
        );
    }
    unsafe { libc::munmap(ctl_ptr as *mut _, CTL_SIZE) };
    drop(memfd);
    Ok(end)
}

/// Default cap on what the launcher copies from each guest stdio memfd into the run directory.
const STDIO_MAX: u64 = 1 << 30;

/// A memfd for the guest's stdio. `stdin` (its contents): sealed and reopened read-only
/// (reads give the contents then end of file, writes `EBADF`, as for a redirect from a file).
fn stdio_memfd(name: &str, stdin: Option<&[u8]>) -> Res<OwnedFd> {
    let n = CString::new(name).unwrap();
    let flags = libc::MFD_CLOEXEC
        | if stdin.is_some() {
            libc::MFD_ALLOW_SEALING
        } else {
            0
        };
    let fd = cvt_i(unsafe { libc::memfd_create(n.as_ptr(), flags) })
        .map_err(|e| format!("memfd {name}: {e}"))?;
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // The guest's fstat shows its owner: as root, the sandbox's user, as for an ordinary user.
    if let Some((uid, gid)) = root_user() {
        cvt_i(unsafe { libc::fchown(fd.as_raw_fd(), uid, gid) })
            .map_err(|e| format!("chown {name}: {e}"))?;
    }
    let Some(data) = stdin else {
        return Ok(fd);
    };
    write_fd(fd.as_raw_fd(), data).map_err(|e| format!("write {name}: {e}"))?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    cvt_i(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) })
        .map_err(|e| format!("seal {name}: {e}"))?;
    let p = CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
    let ro = cvt_i(unsafe { libc::open(p.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) })
        .map_err(|e| format!("reopen {name}: {e}"))?;
    Ok(unsafe { OwnedFd::from_raw_fd(ro) })
}

/// Copy a stdio memfd into `to`, data extents only (a guest that `ftruncate`s its stdout to a
/// huge size leaves a sparse file, not a disk full of zeros), at most `max` bytes. Returns
/// whether it was cut short.
fn copy_stdio(mem: &OwnedFd, to: &File, max: u64) -> std::io::Result<bool> {
    copy_stdio_part(mem, to, 0, u64::MAX, max)
}

/// `copy_stdio` of the bytes `from..until` of `mem` (a machine's boot's part of its output).
fn copy_stdio_part(
    mem: &OwnedFd,
    to: &File,
    from: u64,
    until: u64,
    max: u64,
) -> std::io::Result<bool> {
    let fd = mem.as_raw_fd();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    cvt_i(unsafe { libc::fstat(fd, &mut st) })?;
    let all = (st.st_size as u64).min(until);
    let from = from.min(all);
    let size = all - from;
    if size == 0 {
        return Ok(false);
    }
    let end = from + size.min(max);
    let mut off = from;
    let mut buf = vec![0u8; ((end - from) as usize).min(1 << 20)];
    while off < end {
        let d = unsafe { libc::lseek(fd, off as i64, libc::SEEK_DATA) };
        if d < 0 {
            break; // no data after off: a hole to the end
        }
        let d = d as u64;
        if d >= end {
            break;
        }
        let h = (unsafe { libc::lseek(fd, d as i64, libc::SEEK_HOLE) } as u64).min(end);
        let mut p = d;
        while p < h {
            let n = ((h - p) as usize).min(buf.len());
            let r = unsafe { libc::pread(fd, buf.as_mut_ptr() as *mut _, n, p as i64) };
            if r <= 0 {
                return Err(std::io::Error::last_os_error());
            }
            let w = unsafe {
                libc::pwrite(
                    to.as_raw_fd(),
                    buf.as_ptr() as *const _,
                    r as usize,
                    (p - from) as i64,
                )
            };
            if w != r {
                return Err(std::io::Error::last_os_error());
            }
            p += r as u64;
        }
        off = h;
    }
    to.set_len(end - from)?;
    Ok(size > max)
}

/// Host `CLOCK_MONOTONIC` in ns (the clock the supervisor's `timing` marks use).
pub(crate) fn mono_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Wait until `f` is readable (the supervisor's verdict, or its end) or `deadline` passes.
/// False when the deadline passed.
/// End a sandbox so that its processes are gone when its keeper is reaped: kill its PID 1 (the
/// supervisor, the keeper's child), not the keeper. The kernel ends every process of a PID
/// namespace whose first process exits, and that process's exit completes only once they are all
/// gone; the keeper, its parent, reaps it and exits. Killing the keeper instead leaves the
/// supervisor to its parent-death signal, and the guests dying after `wait` returned.
fn end_sandbox(child: &mut std::process::Child) {
    let pid = child.id();
    for _ in 0..2500 {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        match fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")) {
            Ok(k) if !k.trim().is_empty() => {
                for p in k.split_whitespace().filter_map(|p| p.parse::<i32>().ok()) {
                    unsafe { libc::kill(p, libc::SIGKILL) };
                }
                return;
            }
            // The keeper has not started PID 1 yet: look again.
            Ok(_) => std::thread::sleep(std::time::Duration::from_millis(2)),
            Err(_) => break,
        }
    }
    let _ = child.kill();
}

/// Test hook for replay: `PATINA_TEST_REPLAY_PERTURB=1` changes the seed every draw is keyed
/// on (the recorded one is unchanged), so a replay must report the first differing record.
pub fn replay_perturb() -> u64 {
    if PERTURB_DRAWS.load(Relaxed) {
        1 << 63
    } else {
        0
    }
}

/// Set by `replay` when `PATINA_TEST_REPLAY_PERTURB` is set.
pub static PERTURB_DRAWS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// `patina __native [run options] -- CMD ARGS...`: CMD run natively (no runtime, no supervisor)
/// in the sandbox a run with those options gets, after the copies the supervisor would make and
/// with its environment: the twin a check compares a run against. Exits with CMD's status.
pub fn native_main(args: &[String]) -> Res<std::process::ExitCode> {
    let a = crate::cli::parse(crate::cli::Cmd::Run, args)?;
    let o = crate::config::resolve(&a)?.opts()?;
    let c = &o.cfg;
    if !c.machines.is_empty() {
        return Err("a native twin of a run with machines: not available yet".into());
    }
    let lay = layout(&o, c.disk.as_deref())?;
    let mut env: Vec<String> = crate::sup::BASE_ENV.iter().map(|s| s.to_string()).collect();
    for kv in c.env.iter().chain(&c.main_env) {
        let k = kv.split('=').next().unwrap_or("");
        env.retain(|e| e.split('=').next() != Some(k));
        env.push(kv.clone());
    }
    let mut argv = vec![if o.program.copied {
        o.program.guest.clone()
    } else {
        c.cmd[0].clone()
    }];
    argv.extend(c.cmd[1..].iter().cloned());
    let copies = lay
        .copies
        .iter()
        .filter_map(|cp| cp.split_once(':'))
        .map(|(h, d)| (h.to_string(), d.to_string()))
        .collect();
    let spec = sandbox::Spec {
        ops: lay.ops,
        join_userns: false,
        chdir: c.disk_path().into(),
        env,
        argv,
        exe: Some(o.program.guest.clone()),
        machines: None,
        after: sandbox::After::Native {
            copies,
            work: Some(c.disk_path().into()),
        },
    };
    // The supervisor's umask, whatever the caller's.
    let r = sandbox::ready(spec, &lay.data, || {
        unsafe { libc::umask(0o022) };
        Ok(())
    })?;
    let mut cmd = r.cmd;
    let st = cmd.status().map_err(|e| format!("sandbox: {e}"))?;
    Ok(std::process::ExitCode::from(st.code().unwrap_or(1) as u8))
}

#[cfg(test)]
mod tests {
    #[test]
    fn rt_id_is_hash_bytes() {
        let h = proto::rec::hash_bytes(0x7274, super::RT);
        assert_eq!(super::RT_ID, format!("{h:016x}"));
    }
}
