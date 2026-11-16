//! The launcher: one sandbox per incarnation, descriptors inherited at the
//! hidden numbers, pinning and `ADDR_NO_RANDOMIZE` set before bwrap. `PR_SET_TSC` is set by the
//! runtime, not here: the host's glibc executes `rdtsc` at start-up, so bwrap and the supervisor
//! would die of SIGSEGV if it were set before them.

use crate::cli::{Opts, Res};
use crate::outcome::{Outcome, Verdict};
use crate::sys::*;
use proto::ctl::{
    Config, Ctl, CTL_SIZE, TM_COPIED, TM_EXPORTED, TM_FINISH, TM_FIRST_HELLO, TM_MAIN_EXIT,
    TM_SUP_START,
};
use proto::layout::*;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::Ordering::*;

/// The in-guest runtime, built by `build.rs`.
static RT: &[u8] = include_bytes!(env!("PATINA_RT_EMBED"));

/// The runtime the sandbox executes: the file `PATINA_RT` names (runtime development), else
/// the embedded copy written once to `$XDG_CACHE_HOME/patina/rt-<hash>` (default
/// `~/.cache`, else the temporary directory) and checked against the embedded bytes on every
/// open. A file, not a memfd: AppArmor's bwrap profile (Ubuntu) refuses to execute a memfd.
pub fn rt_file() -> Res<File> {
    if let Some(p) = std::env::var_os("PATINA_RT") {
        return File::open(&p)
            .map_err(|e| format!("runtime {} (PATINA_RT): {e}", Path::new(&p).display()));
    }
    let dir = std::env::var_os("XDG_CACHE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .map(|h| PathBuf::from(h).join(".cache"))
        })
        .unwrap_or_else(std::env::temp_dir)
        .join("patina");
    let path = dir.join(format!("rt-{:016x}", proto::rec::hash_bytes(0x7274, RT)));
    if let Ok(mut f) = File::open(&path) {
        let mut have = Vec::with_capacity(RT.len());
        if f.read_to_end(&mut have).is_ok() && have == RT {
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
pub fn allowed_cpus() -> Vec<usize> {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) };
    (0..libc::CPU_SETSIZE as usize)
        .filter(|&c| unsafe { libc::CPU_ISSET(c, &set) })
        .collect()
}

/// The CPU a run is pinned to without --cpu: one of the allowed set, chosen by process id, so
/// that concurrent runs (parallel checks, sweeps) spread over the host instead of all sharing
/// its first CPU. Which CPU a run uses does not reach the guest (the `cpu` variant of verify).
pub fn default_cpu() -> usize {
    let a = allowed_cpus();
    a[std::process::id() as usize % a.len()]
}

/// The CPU count a guest is told it has when `--ncpu` is not given: a fixed number, not
/// the host's, so that a run (Go's GOMAXPROCS, thread pools sized from it) is the same on any
/// host. Guest threads run one at a time whatever the count; 24 is the count of the host every
/// earlier task measured on, so their results stand.
const DEFAULT_NCPU: u64 = 24;

pub fn run(o: &Opts) -> Res<ExitCode> {
    let out = o.out.clone().ok_or("--out RUN is required")?;
    let cpu = o.cpu.unwrap_or_else(default_cpu);
    let oc = run_one(o, &out, cpu, o.no_personality)?;
    println!("{} {} {}", oc.verdict.class, oc.digest, out.display());
    Ok(ExitCode::SUCCESS)
}

/// A descriptor bwrap reads a generated file from (`--ro-bind-data`): a memfd at offset 0.
fn data_fd(data: &[u8]) -> Res<OwnedFd> {
    let name = CString::new("patina-etc").unwrap();
    let fd = cvt_i(unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) })
        .map_err(|e| format!("memfd: {e}"))?;
    write_fd(fd, data).map_err(|e| format!("memfd write: {e}"))?;
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } != 0 {
        return Err("memfd seek".into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn etc_files() -> Vec<(&'static str, Vec<u8>)> {
    let (uid, gid) = (1000, 1000);
    vec![
        (
            "/etc/passwd",
            format!("root:x:0:0:root:/work:/bin/sh\nuser:x:{uid}:{gid}:user:/work:/bin/sh\n")
                .into_bytes(),
        ),
        (
            "/etc/group",
            format!("root:x:0:\nuser:x:{gid}:\n").into_bytes(),
        ),
        (
            "/etc/hosts",
            b"127.0.0.1 localhost sim\n::1 localhost\n".to_vec(),
        ),
        (
            "/etc/nsswitch.conf",
            b"passwd: files\ngroup: files\nhosts: files\n".to_vec(),
        ),
    ]
}

/// Set by `patina verify --vary env` for its changed runs: the launcher's child changes
/// the process state bwrap and the supervisor inherit before it is normalised (state a caller
/// such as `nice`, `ionice`, `setarch`, `prlimit`, a terminal or a leaked descriptor leaves).
pub static PERTURB: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The perturbation itself, in the launcher's child before bwrap (async-signal-safe).
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
    let p = libc::sched_param { sched_priority: 0 };
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

/// Run a whole chain of incarnations into `out` (created; must not hold an earlier run)
/// and write `outcome.json`.
pub fn run_one(o: &Opts, out: &Path, cpu: usize, no_personality: bool) -> Res<Outcome> {
    let oc = crate::launcher::incarnations::run_chain(o, out, cpu, no_personality)?;
    fs::write(out.join("outcome.json"), oc.to_json()).map_err(|e| format!("outcome.json: {e}"))?;
    Ok(oc)
}

/// Where an incarnation starts: its number, `/in`, the boundary sequence number and
/// virtual time it continues from, and its fault configuration.
pub struct Start<'a> {
    pub k: u64,
    pub root: Option<&'a Path>,
    pub seq0: u64,
    pub vclock0: u64,
    pub faults: proto::faults::FaultCfg,
}

/// What one incarnation left behind.
pub struct IncEnd {
    pub verdict: Verdict,
    pub digest: u64,
    pub traps: u64,
    pub switches: u64,
    pub refused: Vec<String>,
    pub seq: u64,
    pub vclock_ns: u64,
    /// Blocking I/O counters, as in `Outcome::io`.
    pub io: [u64; 5],
    /// Instruction-channel counters.
    pub insn: crate::outcome::InsnCounts,
    /// Network wire counters, as in `Outcome::net`.
    pub net: [u64; crate::outcome::NET_FIELDS],
    /// AF_UNIX sockets sent in SCM_RIGHTS.
    pub unix_sockets: u64,
    /// Counter preemption counters (`proto::ctl::PMU_NAMES`).
    pub pmu: [u64; proto::ctl::PMU_FIELDS],
}

/// The counter event when `--pmu` is given and counters can be opened; otherwise
/// `None`, and (once per process) a message saying why it is off.
pub fn pmu_event(o: &Opts) -> Option<u64> {
    if !o.pmu {
        return None;
    }
    match crate::launcher::pmu::available() {
        Ok(ev) => Some(ev),
        Err(why) => {
            static SAID: std::sync::Once = std::sync::Once::new();
            SAID.call_once(|| eprintln!("patina: --pmu: counter preemption is off: {why}"));
            None
        }
    }
}

/// The outcome's `pmu` field: empty without `--pmu`, else "on" or "off: <reason>".
pub fn pmu_status(o: &Opts) -> String {
    if !o.pmu {
        return String::new();
    }
    match crate::launcher::pmu::available() {
        Ok(_) => "on".into(),
        Err(why) => format!("off: {why}"),
    }
}

/// Run one incarnation into `inc` (created).
pub fn run_incarnation(
    o: &Opts,
    inc: &Path,
    cpu: usize,
    no_personality: bool,
    start: &Start,
) -> Res<IncEnd> {
    let t_launch = mono_ns();
    let inc = inc.to_path_buf();
    fs::create_dir_all(&inc).map_err(|e| format!("create {}: {e}", inc.display()))?;
    let guest = match &o.guest {
        Some(g) => fs::canonicalize(g).map_err(|e| format!("--guest {}: {e}", g.display()))?,
        None => return Err("--guest DIR is required (it is mounted at /guest)".into()),
    };
    let rt_file = rt_file()?;
    let patina_file = File::open("/proc/self/exe").map_err(|e| format!("own executable: {e}"))?;

    let create = |name: &str| -> Res<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(inc.join(name))
            .map_err(|e| format!("create {name}: {e}"))
    };
    let log = create("boundary.log")?;
    log.set_len(LOG_STEP)
        .map_err(|e| format!("boundary.log: {e}"))?;
    let opmeta = create("oplog.meta")?;
    let opdata = create("oplog.data")?;
    // The guest's stdio are sandbox objects, never host files: an empty read-only memfd
    // for stdin and a memfd each for stdout and stderr. Their metadata is a function of the
    // guest's own writes (no host filesystem, no preallocation or writeback, no host times),
    // and the guest cannot truncate, chmod, lock or grow a host file through them. The
    // launcher keeps its own references and copies the contents into the run directory when
    // the sandbox is gone. bwrap's own stdout and stderr (and anything printed before the
    // supervisor starts) go to `sandbox.log`.
    let stdin_mem = stdio_memfd("patina-stdin", true)?;
    let stdout_mem = stdio_memfd("patina-stdout", false)?;
    let stderr_mem = stdio_memfd("patina-stderr", false)?;
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
    let mut cfg = Config::default_with_seed(o.seed);
    cfg.preempt_permille = o.preempt_permille;
    cfg.vtime_limit_ns = o.vtime_limit_s * 1_000_000_000;
    cfg.stall_ms = o.stall_ms;
    cfg.tmpfs_bytes = o.tmpfs_bytes;
    cfg.cpu_count = o.ncpu.unwrap_or(DEFAULT_NCPU);
    let pmu_ev = pmu_event(o);
    if pmu_ev.is_some() {
        cfg.pmu = proto::ctl::PMU_ON;
        cfg.pmu_slice_min = o.pmu_slice.0;
        cfg.pmu_slice_max = o.pmu_slice.1;
        cfg.pmu_short = o.pmu_short_permille | (o.pmu_short_max << 16);
        cfg.pmu_charge_ps = o.pmu_charge_ps;
        cfg.pmu_margin = o.pmu_margin;
    }
    unsafe { Ctl::init(ctl_ptr as *mut Ctl, cfg) };
    let ctl = unsafe { Ctl::at(ctl_ptr) };
    ctl.log_cap.store(LOG_STEP, Relaxed);
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
    unsafe { proto::wire::WireTab::at(ctl_ptr).cfg = o.net };

    // Outcome pipe.
    let mut p = [0i32; 2];
    cvt_i(unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) })
        .map_err(|e| format!("pipe: {e}"))?;
    let (outcome_r, outcome_w) = unsafe { (File::from_raw_fd(p[0]), OwnedFd::from_raw_fd(p[1])) };

    // Generated /etc files, passed to bwrap as --ro-bind-data descriptors.
    let mut etc = etc_files();

    let mut args: Vec<String> = vec![
        "--unshare-all".into(),
        "--as-pid-1".into(),
        "--die-with-parent".into(),
        "--hostname".into(),
        "sim".into(),
        // Fixed ids in the user namespace (the launcher's would show), and no
        // controlling terminal or session of the caller's.
        "--uid".into(),
        "1000".into(),
        "--gid".into(),
        "1000".into(),
        "--new-session".into(),
        "--ro-bind".into(),
        "/usr".into(),
        "/usr".into(),
    ];
    for (l, t) in [
        ("/bin", "usr/bin"),
        ("/lib", "usr/lib"),
        ("/lib64", "usr/lib64"),
        ("/sbin", "usr/sbin"),
    ] {
        args.extend([String::from("--symlink"), t.into(), l.into()]);
    }
    args.extend(["--dev", "/dev", "--proc", "/proc", "--size"].map(String::from));
    args.push(o.tmpfs_bytes.to_string());
    args.extend(["--tmpfs".into(), "/work".into()]);
    // /tmp: a second sandbox tmpfs (same argument as /work: fresh, sequential inode numbers,
    // its own virtual times); programs expect it for temporary files. Not durable.
    args.extend([
        "--size".into(),
        o.tmpfs_bytes.to_string(),
        "--tmpfs".into(),
        "/tmp".into(),
    ]);
    // Generated /etc: the data files below, plus the host's ld.so.cache and localtime
    // naming UTC. The cache is a copy (a file on the sandbox's root tmpfs), not a bind.
    if let Ok(cache) = fs::read("/etc/ld.so.cache") {
        etc.push(("/etc/ld.so.cache", cache));
    }
    args.extend([
        "--symlink".into(),
        "/usr/share/zoneinfo/UTC".into(),
        "/etc/localtime".into(),
    ]);
    // language runtimes: Debian's alternatives (`/usr/bin/awk` -> `/etc/alternatives/awk` -> gawk); without
    // them `awk` is "not found". Recreated as symlinks on the root tmpfs, in name order,
    // instead of a bind of the host directory.
    if let Ok(rd) = fs::read_dir("/etc/alternatives") {
        let mut links: Vec<(String, String)> = vec![];
        for e in rd.flatten() {
            if let (Ok(t), Some(n)) = (fs::read_link(e.path()), e.file_name().to_str()) {
                links.push((n.to_string(), t.display().to_string()));
            }
        }
        links.sort();
        args.extend(["--dir".into(), "/etc/alternatives".into()]);
        for (n, t) in links {
            args.extend(["--symlink".into(), t, format!("/etc/alternatives/{n}")]);
        }
    }
    // The guest directory and the incarnation's /in are bound at a hidden place, and the
    // supervisor copies them into sandbox tmpfs (/guest, /work) before the guest starts: what
    // the guest reads there has the sandbox's own metadata (inode numbers in copy order,
    // virtual times, tmpfs blocks), not the host's.
    args.extend([
        "--ro-bind".into(),
        guest.display().to_string(),
        "/.patina/guest".into(),
    ]);
    args.extend([
        "--size".into(),
        o.tmpfs_bytes.to_string(),
        "--tmpfs".into(),
        "/guest".into(),
    ]);
    if let Some(root) = start.root {
        let r = fs::canonicalize(root).map_err(|e| format!("--root {}: {e}", root.display()))?;
        args.extend([
            "--ro-bind".into(),
            r.display().to_string(),
            "/.patina/in".into(),
        ]);
    }
    let mut etc_fds = vec![];
    for (_, data) in &etc {
        etc_fds.push(data_fd(data)?);
    }
    const ETC_FD0: i32 = 3010;
    for (i, (path, _)) in etc.iter().enumerate() {
        args.extend([
            "--ro-bind-data".into(),
            (ETC_FD0 + i as i32).to_string(),
            path.to_string(),
        ]);
    }
    args.extend(["--clearenv".into(), "--chdir".into(), "/work".into()]);
    args.push(format!("/proc/self/fd/{FD_PATINA}"));
    args.push("__sup".into());
    for e in &o.env {
        args.extend(["--env".into(), e.clone()]);
    }
    // Only restarted incarnations get it: incarnation 0 must match a run without --crash
    // byte for byte up to the crash (the environment shapes the initial stack).
    if start.k > 0 {
        args.extend(["--env".into(), format!("PATINA_INCARNATION={}", start.k)]);
    }
    args.push("--".into());
    args.extend(o.cmd.iter().cloned());

    // Descriptors to place at fixed numbers in the child.
    let mut place: Vec<(i32, i32)> = vec![
        (memfd.as_raw_fd(), FD_CTL),
        (log.as_raw_fd(), FD_LOG),
        (opmeta.as_raw_fd(), FD_OPLOG_META),
        (opdata.as_raw_fd(), FD_OPLOG_DATA),
        (rt_file.as_raw_fd(), FD_RT),
        (outcome_w.as_raw_fd(), FD_OUTCOME),
        (export.as_raw_fd(), FD_EXPORT),
        (patina_file.as_raw_fd(), FD_PATINA),
        (stdin_mem.as_raw_fd(), FD_STDIN),
        (stdout_mem.as_raw_fd(), FD_STDOUT),
        (stderr_mem.as_raw_fd(), FD_STDERR),
    ];
    for (i, f) in etc_fds.iter().enumerate() {
        place.push((f.as_raw_fd(), ETC_FD0 + i as i32));
    }
    // The counter broker's sandbox end.
    let (pmu_sandbox, pmu_ours) = match pmu_ev {
        Some(_) => {
            let (a, b) = crate::launcher::pmu::pair()?;
            (Some(a), Some(b))
        }
        None => (None, None),
    };
    if let Some(f) = &pmu_sandbox {
        place.push((f.as_raw_fd(), FD_PMU));
    }
    let pmu_on = pmu_ev.is_some();
    assert!(place.len() <= 32);
    let personality = !no_personality;
    let perturb = PERTURB.load(Relaxed);

    let mut cmd = Command::new("bwrap");
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(sandbox_log.try_clone().map_err(|e| e.to_string())?)
        .stderr(sandbox_log.try_clone().map_err(|e| e.to_string())?);
    unsafe {
        cmd.pre_exec(move || {
            if perturb {
                perturb_child();
            }
            // An ignored SIGCHLD, inherited across exec, makes bwrap 0.9 wait forever for its
            // child (its children are reaped by the kernel). The other dispositions the guests
            // see are set by sup::inherit.
            libc::signal(libc::SIGCHLD, libc::SIG_DFL);
            // Room for the fixed descriptor numbers (3000-3022): the soft limit is raised to
            // the hard one here; the supervisor sets the limit the guests run under.
            let mut lim: libc::rlimit = std::mem::zeroed();
            libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim);
            lim.rlim_cur = lim.rlim_max;
            libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
            // Move every source out of the target range first, then place.
            let mut tmp = [(0i32, 0i32); 32];
            for (i, &(src, dst)) in place.iter().enumerate() {
                let t = libc::fcntl(src, libc::F_DUPFD_CLOEXEC, 3100);
                if t < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                tmp[i] = (t, dst);
            }
            for &(t, dst) in &tmp[..place.len()] {
                if libc::dup2(t, dst) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            // No capability may follow bwrap into the sandbox (file capabilities are
            // not inherited by exec; ambient ones would be).
            if pmu_on
                && libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_CLEAR_ALL,
                    0,
                    0,
                    0,
                ) != 0
            {
                return Err(std::io::Error::last_os_error());
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
    }
    let t_spawn = mono_ns();
    let mut child = cmd.spawn().map_err(|e| format!("bwrap: {e}"))?;
    drop(outcome_w);
    drop(etc_fds);
    drop(pmu_sandbox);
    let broker = match (pmu_ours, pmu_ev) {
        (Some(ours), Some(ev)) => Some(crate::launcher::pmu::Broker::start(
            ours,
            ev,
            child.id() as i32,
        )?),
        _ => None,
    };
    let mut verdict_text = String::new();
    let mut outcome_r = outcome_r;
    let _ = outcome_r.read_to_string(&mut verdict_text);
    let t_verdict = mono_ns();
    let status = child.wait().map_err(|e| format!("wait bwrap: {e}"))?;
    if let Some(b) = broker {
        b.stop();
    }
    let t_waited = mono_ns();
    let stdio_max = std::env::var("PATINA_STDIO_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(STDIO_MAX);
    let mut truncated = vec![];
    for (mem, name) in [(&stdout_mem, "stdout"), (&stderr_mem, "stderr")] {
        if copy_stdio(mem, &create(name)?, stdio_max).map_err(|e| format!("copy {name}: {e}"))? {
            truncated.push(name);
        }
    }

    let mut verdict = Verdict::decode(&verdict_text).unwrap_or_else(|| {
        let err = fs::read_to_string(inc.join("stderr")).unwrap_or_default()
            + &fs::read_to_string(inc.join("sandbox.log")).unwrap_or_default();
        let last = err
            .lines()
            .rev()
            .find(|l| !l.is_empty())
            .unwrap_or("")
            .to_string();
        Verdict::new(
            "infra",
            format!("no verdict from the supervisor (bwrap {status}): {last}"),
        )
    });
    if verdict.class == "failed" {
        if let Ok(err) = fs::read_to_string(inc.join("stderr")) {
            if let Some(l) = err.lines().find(|l| l.starts_with("INVARIANT ")) {
                verdict.detail = l.to_string();
            }
        }
    }

    if !truncated.is_empty() && verdict.class != "infra" {
        // More output than the run directory takes: the comparison would miss the rest.
        verdict = Verdict::new(
            "infra",
            format!(
                "guest {} larger than {stdio_max} bytes (PATINA_STDIO_MAX)",
                truncated.join(" and ")
            ),
        );
    }
    let log_len = ctl.log_len.load(Relaxed);
    log.set_len(log_len)
        .map_err(|e| format!("truncate boundary.log: {e}"))?;
    let mut refused: Vec<String> = ctl
        .denied_nrs()
        .map(|n| proto::table::name(n).to_string())
        .collect();
    let vfs = unsafe { proto::vfs::Vfs::at(ctl_ptr) };
    refused.extend(
        vfs.refused()
            .map(|p| String::from_utf8_lossy(p).into_owned()),
    );
    let end = IncEnd {
        verdict,
        digest: ctl.log_hash.load(Relaxed),
        traps: ctl.stats.traps.load(Relaxed),
        switches: ctl.stats.switches.load(Relaxed),
        refused,
        seq: ctl.seq.load(Relaxed),
        vclock_ns: ctl.vclock_ns.load(Relaxed),
        io: [
            ctl.io.parks.load(Relaxed),
            ctl.io.reattempts.load(Relaxed),
            ctl.io.spurious.load(Relaxed),
            ctl.io.blocking_done.load(Relaxed),
            ctl.io.blocking_parked.load(Relaxed),
        ],
        insn: crate::outcome::InsnCounts::read(&ctl.insn),
        net: crate::outcome::net_read(unsafe { &proto::wire::WireTab::at(ctl_ptr).counters }),
        unix_sockets: ctl.stats.unix_sockets_sent.load(Relaxed),
        pmu: ctl.pmu.read(),
    };
    if std::env::var_os("PATINA_TIMING").is_some() {
        // cost measurement start-up breakdown: host CLOCK_MONOTONIC ns, launcher and supervisor marks.
        let tm = |i: usize| ctl.timing[i].load(Relaxed);
        eprintln!(
            "patina-timing inc={} launch={t_launch} spawn={t_spawn} sup_start={} copied={} first_hello={} main_exit={} finish={} exported={} verdict={t_verdict} waited={t_waited} done={}",
            start.k,
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

/// A memfd for the guest's stdio. `stdin`: empty, sealed and reopened read-only (reads give
/// end of file, writes `EBADF`, as for a redirect from an empty file).
fn stdio_memfd(name: &str, stdin: bool) -> Res<OwnedFd> {
    let n = CString::new(name).unwrap();
    let flags = libc::MFD_CLOEXEC | if stdin { libc::MFD_ALLOW_SEALING } else { 0 };
    let fd = cvt_i(unsafe { libc::memfd_create(n.as_ptr(), flags) })
        .map_err(|e| format!("memfd {name}: {e}"))?;
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    if !stdin {
        return Ok(fd);
    }
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
    let fd = mem.as_raw_fd();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    cvt_i(unsafe { libc::fstat(fd, &mut st) })?;
    let size = st.st_size as u64;
    let end = size.min(max);
    let mut off = 0u64;
    let mut buf = vec![0u8; 1 << 20];
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
                    p as i64,
                )
            };
            if w != r {
                return Err(std::io::Error::last_os_error());
            }
            p += r as u64;
        }
        off = h;
    }
    to.set_len(end)?;
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
