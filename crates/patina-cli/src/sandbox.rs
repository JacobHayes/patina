//! The sandbox, made by Patina itself (ARCHITECTURE.md "The sandbox", where the order of the
//! steps and the invariants they keep are written down).
//!
//! The launcher executes `patina __sandbox` (the keeper) with a `Spec` at `FD_SPEC`. The keeper
//! enters a new user namespace (as root, it joins the one `launch::userns` made), makes the
//! mount, PID, network, IPC, UTS and cgroup namespaces, and forks PID 1. PID 1 lays out the
//! mounts, enters the guests' user namespace (nested in the keeper's, owning nothing), drops
//! every capability and executes the command (the supervisor). The keeper stays outside the PID
//! namespace, with the capabilities of the outer user namespace, until PID 1 exits; from it,
//! `Keeper::view` makes another mount, UTS and IPC view of the sandbox and starts a process of
//! the sandbox's PID namespace in it.

use crate::cli::Res;
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::process::ExitCode;

// The keeper's own descriptors, 3010 to 3019: between the hidden ones the supervisor keeps
// (`FD_CTL` to `FD_PLAN`) and the stdio ones it moves (`FD_STDIN`), so that one range of its
// `close_inherited` closes them all.
/// Launcher to keeper: the contents of `Op::Data` number `i` at `FD_DATA0 + i`.
pub const FD_DATA0: i32 = 3010;
pub const MAX_DATA: usize = 8;
/// Launcher to keeper: the user namespace to join (as root).
pub const FD_USERNS: i32 = 3018;
/// Launcher to keeper: the `Spec`, as JSON.
pub const FD_SPEC: i32 = 3019;
/// Launcher to keeper, in a run with nodes: node `k`'s stdin, stdout and stderr memfds at
/// `FD_NODE_STDIO0 + 3 * (k - 1)` and the two after it (above every number the supervisor
/// keeps, so its `close_inherited` closes them).
pub const FD_NODE_STDIO0: i32 = 3030;
const _: () = {
    use proto::layout::{FD_NODES, FD_PLAN, FD_PMU, FD_RT_DYN, FD_STDIN};
    assert!(FD_PMU < FD_DATA0 && FD_PLAN < FD_DATA0);
    assert!(FD_DATA0 + MAX_DATA as i32 <= FD_USERNS);
    assert!(FD_USERNS < FD_SPEC && FD_SPEC < FD_STDIN);
    assert!(FD_NODES < FD_NODE_STDIO0);
    assert!(FD_NODE_STDIO0 + 3 * (proto::node::MAX_NODES as i32 - 1) <= FD_RT_DYN);
};

/// One step of the layout, applied in order (the order is the guest's mount table order).
/// Paths are absolute: `src` in the host's view, `dst` in the sandbox's.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Op {
    /// A recursive bind of a host file or directory, nosuid, nodev unless `dev`, read-only
    /// unless `rw`, applied to every mount under it.
    Bind {
        src: String,
        dst: String,
        rw: bool,
        dev: bool,
    },
    /// A tmpfs with the device nodes null, zero, full, random, urandom and tty bound from the
    /// host, a new devpts instance at `pts`, `shm` (a directory) and the usual links.
    Dev {
        dst: String,
    },
    /// The PID namespace's own proc.
    Proc {
        dst: String,
    },
    /// A tmpfs, mode 0755, `size` bytes (0: the kernel's default).
    Tmpfs {
        dst: String,
        size: u64,
    },
    Dir {
        dst: String,
    },
    Symlink {
        target: String,
        dst: String,
    },
    /// A read-only file, mode 0600, holding the contents of descriptor `FD_DATA0 + index`.
    Data {
        index: usize,
        dst: String,
    },
    Hostname {
        name: String,
    },
}

/// What PID 1 does once the sandbox is made.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum After {
    /// Execute `argv` (the supervisor).
    Exec,
    /// A native run (`patina __native`): copy each `(hidden, dst)` tree, and `/.patina/in` into
    /// `work` if given, as the supervisor would, then execute `argv` itself.
    Native {
        copies: Vec<(String, String)>,
        work: Option<String>,
    },
    /// The check of `Keeper::view` (`patina __sandbox-views`).
    Views { size: u64 },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Spec {
    pub ops: Vec<Op>,
    /// Join the user namespace at `FD_USERNS` instead of making one (as root).
    pub join_userns: bool,
    pub chdir: String,
    /// The whole environment of the command (`PWD` is added).
    pub env: Vec<String>,
    pub argv: Vec<String>,
    /// The path executed (default `argv[0]`).
    pub exe: Option<String>,
    pub after: After,
    /// A run with nodes: PID 1 keeps its end of the keeper's socket pair at `FD_NODES` for the
    /// supervisor, and the keeper starts each node's first process when asked (`Nodes`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<Nodes>,
}

/// The nodes of a run (1 upward; the driver is PID 1's command), as the keeper starts them.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Nodes {
    pub nodes: Vec<NodeSpec>,
    /// Bytes of each tmpfs of a node's view.
    pub size: u64,
    /// Paths that get an empty tmpfs of their own in every node's view besides the node's work
    /// tree, `/tmp` and `/dev/shm` (the driver's work tree, where it is elsewhere).
    pub hide: Vec<String>,
    /// Mounts the nodes share with the driver that are read-only in a node's view (the root,
    /// `/dev`, `/guest`, `:copy` mounts): one node's writes never reach another.
    pub readonly: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeSpec {
    pub name: String,
    /// The guest path of the node's work tree.
    pub work: String,
    /// Where the node's starting tree is bound (copied into its work tree), if it has one.
    pub input: Option<String>,
    /// The runtime's arguments (`rt EXE ARGV...`) and the whole environment.
    pub argv: Vec<String>,
    pub env: Vec<String>,
}

/// The keeper's command, `patina __sandbox`: in the child, `first`, then SIGCHLD at its
/// default (the keeper waits for PID 1), room for the fixed descriptor numbers, each `(source,
/// number)` of `place` at its number, no ambient capability, and `no_new_privs` (so no file
/// capability of the executable takes effect at its `execve`).
pub fn command(
    place: Vec<(i32, i32)>,
    first: impl Fn() -> std::io::Result<()> + Send + Sync + 'static,
) -> std::process::Command {
    use std::os::unix::process::CommandExt;
    assert!(place.len() <= 72);
    let mut cmd = std::process::Command::new("/proc/self/exe");
    cmd.arg0("patina")
        .args(["__sandbox", "--parent", &std::process::id().to_string()]);
    unsafe {
        cmd.pre_exec(move || {
            first()?;
            libc::signal(libc::SIGCHLD, libc::SIG_DFL);
            // The soft limit raised to the hard one; the supervisor sets the guests' limit.
            let mut lim: libc::rlimit = std::mem::zeroed();
            libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim);
            lim.rlim_cur = lim.rlim_max;
            libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
            // Every source out of the target range first, then placed.
            let mut tmp = [(0i32, 0i32); 72];
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
            if libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            ) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            // Not root: no capability in the host's namespaces into the keeper, even from a
            // launcher given some by its file (CAP_PERFMON for the branch counters). With
            // no_new_privs the exec grants none back. Root's capabilities are its own.
            if libc::geteuid() != 0 {
                let hdr = [0x2008_0522u32, 0];
                let zero = [0u32; 6];
                if libc::syscall(libc::SYS_capset, hdr.as_ptr(), zero.as_ptr()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    cmd
}

/// A descriptor holding `data` at offset 0 (a memfd), for `place`.
pub fn data_fd(data: &[u8]) -> Res<OwnedFd> {
    let fd = unsafe { libc::memfd_create(c"patina-sandbox".as_ptr(), libc::MFD_CLOEXEC) };
    sys(fd as _, "memfd")?;
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    crate::sys::write_fd(fd.as_raw_fd(), data).map_err(|e| format!("memfd write: {e}"))?;
    Ok(fd)
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap_or_default()
}

fn last_err(what: &str) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}

fn sys(r: libc::c_long, what: &str) -> Res<()> {
    if r < 0 {
        Err(last_err(what))
    } else {
        Ok(())
    }
}

fn mount(
    src: Option<&str>,
    dst: &str,
    fs: Option<&str>,
    flags: u64,
    data: Option<&str>,
) -> Res<()> {
    let (s, d, f, o) = (src.map(c), c(dst), fs.map(c), data.map(c));
    let p = |x: &Option<CString>| x.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let r = unsafe {
        libc::mount(
            p(&s),
            d.as_ptr(),
            p(&f),
            flags as libc::c_ulong,
            p(&o) as *const libc::c_void,
        )
    };
    sys(
        r as libc::c_long,
        &format!("mount {} on {dst}", fs.or(src).unwrap_or("-")),
    )
}

const NR_MOVE_MOUNT: libc::c_long = 429;
const NR_FSOPEN: libc::c_long = 430;
const NR_FSCONFIG: libc::c_long = 431;
const NR_FSMOUNT: libc::c_long = 432;
const NR_OPENAT2: libc::c_long = 437;
const NR_MOUNT_SETATTR: libc::c_long = 442;
const MOUNT_ATTR_RDONLY: u64 = 1;
const MOUNT_ATTR_NOSUID: u64 = 2;
const MOUNT_ATTR_NODEV: u64 = 4;
const AT_RECURSIVE: libc::c_long = 0x8000;

/// Add attributes to the mount at `path` and every mount under it, in one call: other
/// per-mount flags are kept.
fn set_attrs(path: &str, set: u64) -> Res<()> {
    let attr = [set, 0u64, 0, 0];
    let p = c(path);
    let r = unsafe {
        libc::syscall(
            NR_MOUNT_SETATTR,
            libc::AT_FDCWD,
            p.as_ptr(),
            AT_RECURSIVE,
            attr.as_ptr(),
            std::mem::size_of_val(&attr),
        )
    };
    sys(r, &format!("mount_setattr {path}"))
}

/// `set_attrs` for the one mount at `path`, not those under it.
fn set_attr_one(path: &str, set: u64) -> Res<()> {
    let attr = [set, 0u64, 0, 0];
    let p = c(path);
    let r = unsafe {
        libc::syscall(
            NR_MOUNT_SETATTR,
            libc::AT_FDCWD,
            p.as_ptr(),
            0,
            attr.as_ptr(),
            std::mem::size_of_val(&attr),
        )
    };
    sys(r, &format!("mount_setattr {path}"))
}

fn mkdir(path: &str, mode: u32) -> Res<()> {
    let p = c(path);
    sys(
        unsafe { libc::mkdir(p.as_ptr(), mode) } as _,
        &format!("mkdir {path}"),
    )
}

/// A directory at `path` unless one is there.
fn ensure_dir(path: &str, mode: u32) -> Res<()> {
    match std::fs::metadata(path) {
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err(format!("{path} exists and is not a directory")),
        Err(_) => mkdir(path, mode),
    }
}

/// A file at `path` unless something other than a directory is there (`ensure_file`).
fn ensure_file(path: &str, mode: u32) -> Res<()> {
    if std::fs::metadata(path).is_ok_and(|m| !m.is_dir()) {
        return Ok(());
    }
    let p = c(path);
    let fd = unsafe {
        libc::open(
            p.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC,
            mode,
        )
    };
    sys(fd as _, &format!("create {path}"))?;
    unsafe { libc::close(fd) };
    Ok(())
}

/// The parents of `path` that are missing, made with `mode` (not `path` itself).
fn parents(path: &str, mode: u32) -> Res<()> {
    let mut at = String::new();
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    for p in &parts[..parts.len().saturating_sub(1)] {
        at.push('/');
        at.push_str(p);
        if std::fs::symlink_metadata(&at).is_err() {
            mkdir(&at, mode)?;
        }
    }
    Ok(())
}

fn symlink(target: &str, dst: &str) -> Res<()> {
    match std::os::unix::fs::symlink(target, dst) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => match std::fs::read_link(dst) {
            Ok(t) if t == Path::new(target) => Ok(()),
            _ => Err(format!("symlink {dst}: exists")),
        },
        Err(e) => Err(format!("symlink {dst}: {e}")),
    }
}

fn bind(src: &str, dst: &str, rw: bool, dev: bool) -> Res<()> {
    mount(Some(src), dst, None, libc::MS_BIND | libc::MS_REC, None)?;
    let mut set = MOUNT_ATTR_NOSUID;
    if !dev {
        set |= MOUNT_ATTR_NODEV;
    }
    if !rw {
        set |= MOUNT_ATTR_RDONLY;
    }
    set_attrs(dst, set)
}

fn tmpfs(dst: &str, size: u64) -> Res<()> {
    let opts = if size > 0 {
        format!("mode=0755,size={size}")
    } else {
        "mode=0755".to_string()
    };
    mount(
        Some("tmpfs"),
        dst,
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some(&opts),
    )
}

const NEW: &str = "/newroot";
const OLD: &str = "/oldroot";

/// One op, with the old root at `/oldroot` and the new one at `/newroot`. The working
/// directory is the setup tmpfs's root.
fn apply(op: &Op, data_seq: &mut usize) -> Res<()> {
    let at = |d: &str| format!("{NEW}{d}");
    let dst = match op {
        Op::Hostname { name } => {
            let n = c(name);
            return sys(
                unsafe { libc::sethostname(n.as_ptr(), name.len()) } as _,
                "sethostname",
            );
        }
        Op::Bind { dst, .. }
        | Op::Dev { dst }
        | Op::Proc { dst }
        | Op::Tmpfs { dst, .. }
        | Op::Dir { dst }
        | Op::Symlink { dst, .. }
        | Op::Data { dst, .. } => at(dst),
    };
    parents(&dst, 0o755)?;
    match op {
        Op::Hostname { .. } => unreachable!(),
        Op::Bind { src, rw, dev, .. } => {
            let s = format!("{OLD}{src}");
            let md = std::fs::metadata(&s).map_err(|e| format!("bind source {src}: {e}"))?;
            if md.is_dir() {
                ensure_dir(&dst, 0o755)?;
            } else {
                ensure_file(&dst, 0o444)?;
            }
            bind(&s, &dst, *rw, *dev)
        }
        Op::Dev { .. } => {
            ensure_dir(&dst, 0o755)?;
            tmpfs(&dst, 0)?;
            for n in ["null", "zero", "full", "random", "urandom", "tty"] {
                let d = format!("{dst}/{n}");
                ensure_file(&d, 0o444)?;
                bind(&format!("{OLD}/dev/{n}"), &d, true, true)?;
            }
            for (i, n) in ["stdin", "stdout", "stderr"].iter().enumerate() {
                symlink(&format!("/proc/self/fd/{i}"), &format!("{dst}/{n}"))?;
            }
            symlink("/proc/self/fd", &format!("{dst}/fd"))?;
            symlink("/proc/kcore", &format!("{dst}/core"))?;
            mkdir(&format!("{dst}/shm"), 0o755)?;
            mkdir(&format!("{dst}/pts"), 0o755)?;
            mount(
                Some("devpts"),
                &format!("{dst}/pts"),
                Some("devpts"),
                libc::MS_NOSUID | libc::MS_NOEXEC,
                Some("newinstance,ptmxmode=0666,mode=620"),
            )?;
            symlink("pts/ptmx", &format!("{dst}/ptmx"))
        }
        Op::Proc { .. } => {
            ensure_dir(&dst, 0o755)?;
            // Made by PID 1, so it is the new PID namespace's; made while the old root's
            // /proc is still attached, which the kernel requires of a new proc mount.
            mount(
                Some("proc"),
                &dst,
                Some("proc"),
                libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
                None,
            )?;
            // What could change the host if it were writable: read-only over itself.
            for d in ["sys", "sysrq-trigger", "irq", "bus"] {
                let p = format!("{dst}/{d}");
                let cp = c(&p);
                if unsafe { libc::access(cp.as_ptr(), libc::W_OK) } < 0 {
                    let e = std::io::Error::last_os_error().raw_os_error();
                    if matches!(e, Some(libc::EACCES | libc::ENOENT | libc::EROFS)) {
                        continue;
                    }
                    return Err(last_err(&format!("access {p}")));
                }
                bind(&p, &p, false, false)?;
            }
            Ok(())
        }
        Op::Tmpfs { size, .. } => {
            ensure_dir(&dst, 0o755)?;
            tmpfs(&dst, *size)
        }
        Op::Dir { .. } => ensure_dir(&dst, 0o755),
        Op::Symlink { target, .. } => symlink(target, &dst),
        Op::Data { index, .. } => {
            // On the setup tmpfs (outside the new root), bound read-only, then unlinked.
            let tmp = format!("/bindfile{}", *data_seq);
            *data_seq += 1;
            let data = read_fd(FD_DATA0 + *index as i32)?;
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&tmp)
                    .map_err(|e| format!("{tmp}: {e}"))?;
                std::io::Write::write_all(&mut f, &data).map_err(|e| format!("{tmp}: {e}"))?;
            }
            ensure_file(&dst, 0o444)?;
            bind(&tmp, &dst, false, false)?;
            std::fs::remove_file(&tmp).map_err(|e| format!("{tmp}: {e}"))
        }
    }
}

/// The whole of a descriptor's contents, from offset 0.
fn read_fd(fd: RawFd) -> Res<Vec<u8>> {
    let mut out = vec![];
    let mut buf = [0u8; 65536];
    loop {
        let n = unsafe {
            libc::pread(
                fd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                out.len() as libc::off_t,
            )
        };
        if n < 0 {
            return Err(last_err(&format!("read descriptor {fd}")));
        }
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
}

fn write_file(path: &str, v: &str) -> Res<()> {
    std::fs::write(path, v).map_err(|e| format!("{path}: {e}"))
}

/// A new user namespace whose uid and gid 0 are the caller's (setgroups denied first, as an
/// unprivileged map requires).
fn new_userns() -> Res<()> {
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    if uid == 0 || unsafe { libc::geteuid() } == 0 {
        // Would map the guests' user to the host's root: root joins `launch::userns` instead.
        return Err("as root, the sandbox joins the launcher's user namespace".into());
    }
    sys(
        unsafe { libc::unshare(libc::CLONE_NEWUSER) } as _,
        "unshare user namespace",
    )?;
    write_file("/proc/self/setgroups", "deny")?;
    write_file("/proc/self/uid_map", &format!("0 {uid} 1\n"))?;
    write_file("/proc/self/gid_map", &format!("0 {gid} 1\n"))
}

/// As root: no supplementary groups, then the user namespace at `fd`, as its uid and gid 0.
fn join_userns(fd: RawFd) -> Res<()> {
    unsafe {
        sys(libc::setgroups(0, std::ptr::null()) as _, "setgroups")?;
        sys(
            libc::setns(fd, libc::CLONE_NEWUSER) as _,
            "join user namespace",
        )?;
        libc::close(fd);
        sys(libc::setresgid(0, 0, 0) as _, "setresgid")?;
        sys(libc::setresuid(0, 0, 0) as _, "setresuid")
    }
}

/// Every capability out of the bounding set (the caller holds CAP_SETPCAP in its namespace).
fn drop_bounding() -> Res<()> {
    for cap in 0..64 {
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) } < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                break; // past the last capability this kernel has
            }
            return Err(last_err("drop the bounding set"));
        }
    }
    Ok(())
}

/// No capability left in any set, and none to gain by `execve` (the caller's uid is not 0 in
/// its user namespace, and `no_new_privs`). Checked.
fn drop_caps() -> Res<()> {
    unsafe {
        if libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        ) < 0
        {
            return Err(last_err("clear ambient capabilities"));
        }
        let hdr = [0x2008_0522u32, 0];
        let zero = [0u32; 6];
        sys(
            libc::syscall(libc::SYS_capset, hdr.as_ptr(), zero.as_ptr()),
            "capset",
        )?;
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
            return Err(last_err("no_new_privs"));
        }
        let mut got = [1u32; 6];
        sys(
            libc::syscall(libc::SYS_capget, hdr.as_ptr(), got.as_mut_ptr()),
            "capget",
        )?;
        let last: i32 = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(63);
        let bounding = (0..=last).any(|c| libc::prctl(libc::PR_CAPBSET_READ, c, 0, 0, 0) != 0);
        let ambient = (0..=last)
            .any(|c| libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_IS_SET, c, 0, 0) > 0);
        if got != [0; 6] || bounding || ambient {
            return Err("capabilities remain after dropping them".into());
        }
    }
    Ok(())
}

/// Loopback up with 127.0.0.1/8, by netlink (address, then link).
fn loopback() -> Res<()> {
    let idx = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
    if idx == 0 {
        return Err(last_err("loopback: no lo"));
    }
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    sys(fd as _, "netlink socket")?;
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let req = |seq: u32, kind: u16, flags: u16, body: &[u8]| -> Res<()> {
        let len = 16 + body.len();
        let mut m = Vec::with_capacity(len);
        m.extend_from_slice(&(len as u32).to_ne_bytes());
        m.extend_from_slice(&kind.to_ne_bytes());
        m.extend_from_slice(
            &(flags | libc::NLM_F_REQUEST as u16 | libc::NLM_F_ACK as u16).to_ne_bytes(),
        );
        m.extend_from_slice(&seq.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes());
        m.extend_from_slice(body);
        let mut dst: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        dst.nl_family = libc::AF_NETLINK as u16;
        let r = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                m.as_ptr().cast(),
                m.len(),
                0,
                &dst as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&dst) as u32,
            )
        };
        sys(r as _, "netlink send")?;
        let mut buf = [0u8; 1024];
        let n = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        sys(n as _, "netlink receive")?;
        let t = u16::from_ne_bytes([buf[4], buf[5]]);
        let err = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
        if n < 20 || t != libc::NLMSG_ERROR as u16 || err != 0 {
            return Err(format!("loopback: netlink request {kind}: error {}", -err));
        }
        Ok(())
    };
    // RTM_NEWADDR: ifaddrmsg (family, prefixlen 8, IFA_F_PERMANENT, RT_SCOPE_HOST, index),
    // then IFA_LOCAL and IFA_ADDRESS, 127.0.0.1.
    let mut a = vec![libc::AF_INET as u8, 8, 0x80, libc::RT_SCOPE_HOST];
    a.extend_from_slice(&idx.to_ne_bytes());
    for t in [libc::IFA_LOCAL, libc::IFA_ADDRESS] {
        a.extend_from_slice(&8u16.to_ne_bytes());
        a.extend_from_slice(&t.to_ne_bytes());
        a.extend_from_slice(&[127, 0, 0, 1]);
    }
    req(
        1,
        libc::RTM_NEWADDR,
        (libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16,
        &a,
    )?;
    // RTM_NEWLINK: ifinfomsg (AF_UNSPEC, type 0, index, flags IFF_UP, change IFF_UP).
    let mut l = vec![libc::AF_UNSPEC as u8, 0, 0, 0];
    l.extend_from_slice(&(idx as i32).to_ne_bytes());
    l.extend_from_slice(&(libc::IFF_UP as u32).to_ne_bytes());
    l.extend_from_slice(&(libc::IFF_UP as u32).to_ne_bytes());
    req(2, libc::RTM_NEWLINK, 0, &l)
}

fn pivot_root(new: &str, old: &str) -> Res<()> {
    let (n, o) = (c(new), c(old));
    sys(
        unsafe { libc::syscall(libc::SYS_pivot_root, n.as_ptr(), o.as_ptr()) },
        &format!("pivot_root {new}"),
    )
}

fn chdir(p: &str) -> Res<()> {
    let cp = c(p);
    sys(
        unsafe { libc::chdir(cp.as_ptr()) } as _,
        &format!("chdir {p}"),
    )
}

fn umount(p: &str) -> Res<()> {
    let cp = c(p);
    sys(
        unsafe { libc::umount2(cp.as_ptr(), libc::MNT_DETACH) } as _,
        &format!("umount {p}"),
    )
}

fn send_fd(sock: RawFd, fd: RawFd) -> Res<()> {
    unsafe {
        // A cmsghdr is read and written in place: the buffer is aligned for it.
        let mut space = [0u64; 8];
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = space.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(4) as _;
        let cm = libc::CMSG_FIRSTHDR(&msg);
        (*cm).cmsg_level = libc::SOL_SOCKET;
        (*cm).cmsg_type = libc::SCM_RIGHTS;
        (*cm).cmsg_len = libc::CMSG_LEN(4) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(cm) as *mut i32, fd);
        sys(libc::sendmsg(sock, &msg, 0) as _, "send descriptor")
    }
}

/// A descriptor sent with `send_fd`, or `None` at end of file.
fn recv_fd(sock: RawFd) -> Option<OwnedFd> {
    unsafe {
        // A cmsghdr is read and written in place: the buffer is aligned for it.
        let mut space = [0u64; 8];
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = space.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&space) as _;
        if libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC) <= 0 {
            return None;
        }
        let cm = libc::CMSG_FIRSTHDR(&msg);
        if cm.is_null() || (*cm).cmsg_type != libc::SCM_RIGHTS {
            return None;
        }
        Some(OwnedFd::from_raw_fd(std::ptr::read_unaligned(
            libc::CMSG_DATA(cm) as *const i32,
        )))
    }
}

/// Set the parent-death signal and end now if the parent is already gone: `alive` says
/// whether it is (after the signal is set, so no death goes unnoticed). Cleared by every
/// credential change, so set after the last one.
fn die_with_parent(alive: impl Fn() -> bool) {
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
        if !alive() {
            libc::_exit(1);
        }
    }
}

fn exit_code(st: i32) -> u8 {
    if libc::WIFEXITED(st) {
        libc::WEXITSTATUS(st) as u8
    } else {
        128u8.wrapping_add(libc::WTERMSIG(st) as u8)
    }
}

fn wait_pid(pid: i32) -> i32 {
    let mut st = 0;
    loop {
        let r = unsafe { libc::waitpid(pid, &mut st, 0) };
        if r == pid {
            return st;
        }
        if r < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return 127 << 8;
        }
    }
}

/// Close every descriptor from 3 up but those in `keep`, in a child about to run code of its
/// own: it ends (status 1) rather than run with a descriptor it should not have.
fn close_others(keep: &[RawFd]) {
    let close = |from: u32, to: u32| {
        if unsafe { libc::syscall(libc::SYS_close_range, from, to, 0u32) } != 0 {
            eprintln!("patina sandbox: {}", last_err("close_range"));
            unsafe { libc::_exit(1) };
        }
    };
    let mut k: Vec<u32> = keep.iter().map(|&f| f as u32).filter(|&f| f >= 3).collect();
    k.sort();
    let mut from = 3u32;
    for f in k {
        if f > from {
            close(from, f - 1);
        }
        from = f + 1;
    }
    close(from, u32::MAX);
}

/// The keeper, after PID 1 started: the outer user namespace's capabilities, the sandbox's
/// namespaces (its PID namespace for its children), and the guests' user namespace.
pub struct Keeper {
    guests_userns: OwnedFd,
}

/// Another view of the sandbox for `Keeper::view`: a new mount, UTS and IPC namespace, a fresh
/// tmpfs of `size` bytes on each of `tmpfs` (the work path, `/tmp`, `/dev/shm`), and `hostname`.
pub struct View<'a> {
    pub hostname: &'a str,
    pub tmpfs: &'a [&'a str],
    pub size: u64,
    /// Mounts made read-only in this view (each one alone, not what is mounted under it).
    pub readonly: &'a [&'a str],
}

impl Keeper {
    /// Make `v` and run `f` in a process of it: in the sandbox's PID and network namespaces,
    /// the guests' user namespace, with no capability and `no_new_privs`, its parent PID 1
    /// (it is adopted once the helper that made the view exits), in a new session, with the
    /// descriptors in `keep` and nothing else (0, 1 and 2 not in `keep` are `/dev/null`).
    /// Returns when the process exists (its result is PID 1's to reap). The helper runs only
    /// this code and opens the mount points without following symbolic links.
    pub fn view(&self, v: &View, keep: &[RawFd], f: impl FnOnce() -> i32) -> Res<()> {
        // Forked without exec: only sound while the keeper has one thread (its /proc is the
        // sandbox's, where it is not, so this cannot be checked here).
        let (rd, wr) = pipe()?;
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(last_err("fork"));
        }
        if pid == 0 {
            drop(rd);
            // Not dumpable, and holding nothing of the keeper's but what the view needs: it is
            // in the sandbox's PID namespace, where guests could see it.
            unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
            let userns = self.guests_userns.as_raw_fd();
            let mut held: Vec<RawFd> = keep.to_vec();
            held.extend([wr.as_raw_fd(), userns]);
            close_others(&held);
            let r = (|| -> Res<()> {
                sys(
                    unsafe {
                        libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWUTS | libc::CLONE_NEWIPC)
                    } as _,
                    "unshare view",
                )?;
                mount(None, "/", None, libc::MS_REC | libc::MS_PRIVATE, None)?;
                for p in v.readonly {
                    set_attr_one(p, MOUNT_ATTR_RDONLY)?;
                }
                for p in v.tmpfs {
                    mount_tmpfs_at(p, v.size)?;
                }
                let n = c(v.hostname);
                sys(
                    unsafe { libc::sethostname(n.as_ptr(), v.hostname.len()) } as _,
                    "sethostname",
                )
            })();
            if let Err(e) = r {
                let _ = crate::sys::write_fd(wr.as_raw_fd(), e.as_bytes());
                unsafe { libc::_exit(1) };
            }
            let g = unsafe { libc::fork() };
            if g == 0 {
                let r = (|| -> Res<()> {
                    sys(
                        unsafe { libc::setns(userns, libc::CLONE_NEWUSER) } as _,
                        "join the guests' user namespace",
                    )?;
                    unsafe { libc::close(userns) };
                    drop_bounding()?;
                    drop_caps()?;
                    // Standard descriptors the caller does not pass are /dev/null; no terminal.
                    let null = unsafe {
                        libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC)
                    };
                    sys(null as _, "open /dev/null")?;
                    for fd in 0..3 {
                        if !keep.contains(&fd) {
                            sys(unsafe { libc::dup2(null, fd) } as _, "dup2")?;
                        }
                    }
                    unsafe { libc::close(null) };
                    sys(unsafe { libc::setsid() } as _, "setsid")
                })();
                if let Err(e) = r {
                    let _ = crate::sys::write_fd(wr.as_raw_fd(), e.as_bytes());
                    unsafe { libc::_exit(1) };
                }
                drop(wr);
                let code = f();
                unsafe { libc::_exit(code) };
            }
            unsafe { libc::_exit(if g < 0 { 1 } else { 0 }) };
        }
        drop(wr);
        let mut err = vec![];
        let _ = std::io::Read::read_to_end(&mut std::fs::File::from(rd), &mut err);
        let st = wait_pid(pid);
        if !err.is_empty() || st != 0 {
            return Err(format!(
                "view {}: {}",
                v.hostname,
                String::from_utf8_lossy(&err)
            ));
        }
        Ok(())
    }
}

fn pipe() -> Res<(OwnedFd, OwnedFd)> {
    let mut p = [0i32; 2];
    sys(
        unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) } as _,
        "pipe",
    )?;
    Ok(unsafe { (OwnedFd::from_raw_fd(p[0]), OwnedFd::from_raw_fd(p[1])) })
}

/// A new tmpfs on the directory at `path`, reached without following a symbolic link (a guest
/// can change what is under the work path or `/dev`): opened with `openat2`, the mount made with
/// `fsopen` and moved onto that descriptor.
fn mount_tmpfs_at(path: &str, size: u64) -> Res<()> {
    const RESOLVE_NO_MAGICLINKS: u64 = 2;
    const RESOLVE_NO_SYMLINKS: u64 = 4;
    const FSCONFIG_SET_STRING: u32 = 1;
    const FSCONFIG_CMD_CREATE: u32 = 6;
    const MOVE_MOUNT_F_EMPTY_PATH: u32 = 4;
    const MOVE_MOUNT_T_EMPTY_PATH: u32 = 0x40;
    let how = [
        (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        0,
        RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    ];
    let p = c(path);
    let at = |r: libc::c_long, what: &str| -> Res<OwnedFd> {
        sys(r, &format!("{what} {path}"))?;
        Ok(unsafe { OwnedFd::from_raw_fd(r as i32) })
    };
    unsafe {
        let dir = at(
            libc::syscall(
                NR_OPENAT2,
                libc::AT_FDCWD,
                p.as_ptr(),
                how.as_ptr(),
                24usize,
            ),
            "open",
        )?;
        let fs = at(libc::syscall(NR_FSOPEN, c"tmpfs".as_ptr(), 1u32), "fsopen")?;
        for (k, v) in [("mode", "0755".to_string()), ("size", size.to_string())] {
            let (k, v) = (c(k), c(&v));
            sys(
                libc::syscall(
                    NR_FSCONFIG,
                    fs.as_raw_fd(),
                    FSCONFIG_SET_STRING,
                    k.as_ptr(),
                    v.as_ptr(),
                    0,
                ),
                "fsconfig",
            )?;
        }
        sys(
            libc::syscall(
                NR_FSCONFIG,
                fs.as_raw_fd(),
                FSCONFIG_CMD_CREATE,
                0usize,
                0usize,
                0,
            ),
            "fsconfig create",
        )?;
        let mnt = at(
            libc::syscall(
                NR_FSMOUNT,
                fs.as_raw_fd(),
                1u32,
                (MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV) as u32,
            ),
            "fsmount",
        )?;
        sys(
            libc::syscall(
                NR_MOVE_MOUNT,
                mnt.as_raw_fd(),
                c"".as_ptr(),
                dir.as_raw_fd(),
                c"".as_ptr(),
                MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
            ),
            &format!("move_mount {path}"),
        )
    }
}

/// `patina __sandbox --parent PID`: the keeper.
pub fn keeper_main(args: &[String]) -> Res<ExitCode> {
    let parent: i32 = match args {
        [f, p] if f == "--parent" => p.parse().map_err(|_| "__sandbox: --parent PID")?,
        _ => return Err("__sandbox: usage: __sandbox --parent PID".into()),
    };
    let spec: Spec =
        serde_json::from_slice(&read_fd(FD_SPEC)?).map_err(|e| format!("__sandbox: spec: {e}"))?;
    unsafe { libc::close(FD_SPEC) };
    if spec.join_userns {
        join_userns(FD_USERNS)?;
    } else {
        new_userns()?;
    }
    die_with_parent(|| unsafe { libc::getppid() } == parent);
    let mut flags = libc::CLONE_NEWNS
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWNET
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUTS;
    if Path::new("/proc/self/ns/cgroup").exists() {
        flags |= libc::CLONE_NEWCGROUP;
    }
    sys(unsafe { libc::unshare(flags) } as _, "unshare namespaces")?;
    // At the root, so that the pivots move this process's root and working directory too: the
    // keeper keeps no reference to the host's tree.
    chdir("/")?;
    let mut sp = [0i32; 2];
    sys(
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                sp.as_mut_ptr(),
            )
        } as _,
        "socketpair",
    )?;
    let (ours, theirs) = unsafe { (OwnedFd::from_raw_fd(sp[0]), OwnedFd::from_raw_fd(sp[1])) };
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(last_err("fork"));
    }
    if pid == 0 {
        drop(ours);
        pid1(&spec, theirs);
    }
    drop(theirs);
    let Some(guests_userns) = recv_fd(ours.as_raw_fd()) else {
        return Ok(ExitCode::from(exit_code(wait_pid(pid))));
    };
    let keeper = Keeper { guests_userns };
    if let After::Views { size } = spec.after {
        views_keeper(&keeper, ours.as_raw_fd(), size);
    }
    if let Some(n) = &spec.nodes {
        nodes_keeper(&keeper, ours.as_raw_fd(), n);
    }
    Ok(ExitCode::from(exit_code(wait_pid(pid))))
}

/// Every time of `p` and of everything under it (links themselves) set to the virtual file
/// epoch, as the copied tree reads under the runtime.
fn stamp(p: &Path) -> std::io::Result<()> {
    let m = std::fs::symlink_metadata(p)?;
    if m.is_dir() {
        for e in std::fs::read_dir(p)? {
            stamp(&e?.path())?;
        }
    }
    let t = libc::timespec {
        tv_sec: proto::layout::FILE_EPOCH_S as _,
        tv_nsec: 0,
    };
    let path = c(&p.display().to_string());
    let r = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path.as_ptr(),
            [t, t].as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// PID 1: the layout, the guests' user namespace, then the command.
fn pid1(spec: &Spec, chan: OwnedFd) -> ! {
    let fail = |e: String| -> ! {
        eprintln!("patina sandbox: {e}");
        unsafe { libc::_exit(1) }
    };
    if let Err(e) = setup(spec, &chan) {
        fail(e);
    }
    match &spec.after {
        // With nodes, the supervisor asks the keeper to start them through PID 1's end.
        After::Exec if spec.nodes.is_some() => {
            if unsafe { libc::dup2(chan.as_raw_fd(), proto::layout::FD_NODES) }
                != proto::layout::FD_NODES
            {
                fail(last_err("dup2 the nodes channel"));
            }
        }
        After::Exec => {}
        After::Native { copies, work } => {
            for (h, d) in copies {
                if let Err(e) = crate::sup::inherit::copy_tree(Path::new(h), Path::new(d)) {
                    fail(format!("copying into {d}: {e}"));
                }
            }
            if let Some(w) = work {
                if Path::new("/.patina/in").is_dir() {
                    if let Err(e) =
                        crate::sup::crash::copy_in(Path::new("/.patina/in"), Path::new(w))
                    {
                        fail(e);
                    }
                    // Under the runtime the copied tree's times read as the virtual file epoch.
                    if let Err(e) = stamp(Path::new(w)) {
                        fail(format!("times of {w}: {e}"));
                    }
                }
            }
            // The command is PID 1's child, as a guest is the supervisor's: PID 1 reaps every
            // process and exits with the command's status when it ends.
            let child = unsafe { libc::fork() };
            if child < 0 {
                fail(last_err("fork"));
            }
            if child == 0 {
                // The command gets 0, 1 and 2 only, as a guest of a run.
                close_others(&[]);
            }
            if child > 0 {
                drop(chan);
                loop {
                    let mut st = 0;
                    let r = unsafe { libc::waitpid(-1, &mut st, 0) };
                    if r == child || r < 0 {
                        unsafe { libc::_exit(if r < 0 { 1 } else { exit_code(st) as i32 }) };
                    }
                }
            }
        }
        After::Views { .. } => views_pid1(chan.as_raw_fd()),
    }
    let argv: Vec<CString> = spec.argv.iter().map(|a| c(a)).collect();
    let mut env: Vec<CString> = spec.env.iter().map(|a| c(a)).collect();
    env.push(c(&format!("PWD={}", spec.chdir)));
    let mut av: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    av.push(std::ptr::null());
    let mut ev: Vec<*const libc::c_char> = env.iter().map(|a| a.as_ptr()).collect();
    ev.push(std::ptr::null());
    let exe = c(spec.exe.as_deref().unwrap_or(&spec.argv[0]));
    unsafe { libc::execve(exe.as_ptr(), av.as_ptr(), ev.as_ptr()) };
    fail(last_err(&format!("execute {}", spec.argv[0])))
}

/// PID 1's part, in order (ARCHITECTURE.md "The sandbox").
fn setup(spec: &Spec, chan: &OwnedFd) -> Res<()> {
    let old_umask = unsafe { libc::umask(0) };
    loopback()?;
    // Bind sources as the host resolves them, before the host's root moves.
    let mut ops = spec.ops.clone();
    for op in &mut ops {
        if let Op::Bind { src, .. } = op {
            *src = std::fs::canonicalize(&*src)
                .map_err(|e| format!("{src}: {e}"))?
                .display()
                .to_string();
        }
    }
    // Nothing made here propagates to the host (events from the host still arrive, as before).
    mount(None, "/", None, libc::MS_REC | libc::MS_SLAVE, None)?;
    // The setup tmpfs; the new root is a directory on it, the old root moves under it.
    mount(
        Some("tmpfs"),
        "/tmp",
        Some("tmpfs"),
        libc::MS_NODEV | libc::MS_NOSUID,
        None,
    )?;
    chdir("/tmp")?;
    mkdir("newroot", 0o755)?;
    mount(
        Some("newroot"),
        "newroot",
        None,
        libc::MS_BIND | libc::MS_REC,
        None,
    )?;
    mkdir("oldroot", 0o755)?;
    pivot_root("/tmp", "oldroot")?;
    chdir("/")?;
    let mut seq = 0;
    for op in &ops {
        apply(op, &mut seq)?;
    }
    // Detach the host's tree: private first, so the unmount reaches no other namespace.
    mount(
        Some("oldroot"),
        "oldroot",
        None,
        libc::MS_REC | libc::MS_PRIVATE,
        None,
    )?;
    umount("oldroot")?;
    let setup_root = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    sys(setup_root as _, "open /")?;
    chdir(NEW)?;
    pivot_root(".", ".")?;
    sys(unsafe { libc::fchdir(setup_root) } as _, "fchdir")?;
    unsafe { libc::close(setup_root) };
    umount(".")?;
    chdir("/")?;
    // Private from here: a mount the host makes later under a bound path does not arrive.
    mount(None, "/", None, libc::MS_REC | libc::MS_PRIVATE, None)?;
    // The generated files are in place; their descriptors go no further.
    for fd in FD_DATA0..FD_DATA0 + MAX_DATA as i32 {
        unsafe { libc::close(fd) };
    }
    // The guests' user namespace: nested in the keeper's, it owns no namespace, so nothing in
    // it can mount, unshare a namespace it could use, or change the network or hostname.
    sys(
        unsafe { libc::unshare(libc::CLONE_NEWUSER) } as _,
        "unshare the guests' user namespace",
    )?;
    drop_bounding()?;
    // Its own map: written while dumpable, or /proc/self is the host root's (as root, the
    // keeper's change of uid left it undumpable). The supervisor's exec sets it again anyway.
    sys(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } as _,
        "dumpable",
    )?;
    write_file("/proc/self/uid_map", "1000 0 1\n")?;
    write_file("/proc/self/gid_map", "1000 0 1\n")?;
    let ns = unsafe {
        libc::open(
            c"/proc/self/ns/user".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    sys(ns as _, "open the guests' user namespace")?;
    send_fd(chan.as_raw_fd(), ns)?;
    unsafe { libc::close(ns) };
    drop_caps()?;
    unsafe { libc::umask(old_umask) };
    chdir(&spec.chdir)?;
    sys(unsafe { libc::setsid() } as _, "setsid")?;
    let ch = chan.as_raw_fd();
    die_with_parent(|| {
        let mut p = libc::pollfd {
            fd: ch,
            events: 0,
            revents: 0,
        };
        unsafe { libc::poll(&mut p, 1, 0) == 0 }
    });
    Ok(())
}

/// The views check, PID 1's part: write `/work/f`, tell the keeper, then reap every process
/// the keeper's views start (adopted by PID 1) and print this view's line last.
fn views_pid1(chan: RawFd) -> ! {
    let _ = std::fs::write("/work/f", "base");
    unsafe {
        libc::write(chan, b"r".as_ptr().cast(), 1);
        let mut b = [0u8; 1];
        libc::read(chan, b.as_mut_ptr().cast(), 1);
    }
    let mut reaped = vec![];
    loop {
        let mut st = 0;
        let r = unsafe { libc::waitpid(-1, &mut st, 0) };
        if r < 0 {
            break;
        }
        reaped.push(format!("[{r},{}]", exit_code(st)));
    }
    println!(
        "{{\"view\":\"base\",{},\"reaped\":[{}]}}",
        view_facts(),
        reaped.join(",")
    );
    unsafe { libc::_exit(0) }
}

/// What a process of a view sees, as JSON fields.
fn view_facts() -> String {
    let ns = |n: &str| {
        std::fs::read_link(format!("/proc/self/ns/{n}"))
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    };
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |k: &str| {
        status
            .lines()
            .find(|l| l.starts_with(k))
            .map(|l| l[k.len()..].trim().to_string())
            .unwrap_or_default()
    };
    let mut host = [0u8; 65];
    unsafe { libc::gethostname(host.as_mut_ptr().cast(), 64) };
    let host = String::from_utf8_lossy(&host[..host.iter().position(|&b| b == 0).unwrap_or(0)])
        .to_string();
    let tmp: Vec<String> = std::fs::read_dir("/tmp")
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    serde_json::json!({
        "pid": unsafe { libc::getpid() },
        "ppid": unsafe { libc::getppid() },
        "uid": unsafe { libc::getuid() },
        "hostname": host,
        "work": std::fs::read_to_string("/work/f").unwrap_or_default(),
        "tmp": tmp,
        "cap_eff": field("CapEff:"),
        "cap_prm": field("CapPrm:"),
        "cap_inh": field("CapInh:"),
        "cap_amb": field("CapAmb:"),
        "cap_bnd": field("CapBnd:"),
        "nnp": field("NoNewPrivs:"),
        "mnt": ns("mnt"), "uts": ns("uts"), "ipc": ns("ipc"),
        "pid_ns": ns("pid"), "net": ns("net"), "user": ns("user"),
    })
    .to_string()
    .trim_start_matches('{')
    .trim_end_matches('}')
    .to_string()
}

/// The views check, the keeper's part: two views, each with a process that writes its own
/// `/work/f` and `/tmp/mark` and prints what it sees.
fn views_keeper(k: &Keeper, chan: RawFd, size: u64) {
    let mut b = [0u8; 1];
    unsafe { libc::read(chan, b.as_mut_ptr().cast(), 1) };
    // Every view's process stays until both are made: one that exited could leave its
    // namespaces' numbers to the next.
    let (Ok((ready_r, ready_w)), Ok((hold_r, hold_w))) = (pipe(), pipe()) else {
        eprintln!("patina sandbox: pipe");
        return;
    };
    let keep = [1, 2, ready_w.as_raw_fd(), hold_r.as_raw_fd()];
    for name in ["n1", "n2"] {
        let v = View {
            hostname: name,
            tmpfs: &["/work", "/tmp", "/dev/shm"],
            size,
            readonly: &[],
        };
        let r = k.view(&v, &keep, || {
            let _ = std::fs::write("/work/f", name);
            let _ = std::fs::write("/tmp/mark", name);
            println!("{{\"view\":\"{name}\",{}}}", view_facts());
            let mut b = [0u8; 1];
            unsafe {
                libc::write(keep[2], b"r".as_ptr().cast(), 1);
                while libc::read(keep[3], b.as_mut_ptr().cast(), 1) > 0 {}
            }
            0
        });
        match r {
            Ok(()) => unsafe {
                libc::read(ready_r.as_raw_fd(), b.as_mut_ptr().cast(), 1);
            },
            Err(e) => eprintln!("patina sandbox: {e}"),
        }
    }
    drop(hold_w);
    unsafe { libc::write(chan, b"d".as_ptr().cast(), 1) };
}

/// A keeper ready to start for `spec`: the command and the descriptors it places (kept open
/// until it has started). As root, it joins `launch::userns`.
pub struct Ready {
    pub cmd: std::process::Command,
    _fds: Vec<OwnedFd>,
}

pub fn ready(
    mut spec: Spec,
    data: &[Vec<u8>],
    first: impl Fn() -> std::io::Result<()> + Send + Sync + 'static,
) -> Res<Ready> {
    let userns = crate::launch::userns()?;
    spec.join_userns = userns.is_some();
    let mut fds = vec![data_fd(
        &serde_json::to_vec(&spec).map_err(|e| e.to_string())?,
    )?];
    let mut place = vec![(fds[0].as_raw_fd(), FD_SPEC)];
    assert!(data.len() <= MAX_DATA);
    for (i, d) in data.iter().enumerate() {
        fds.push(data_fd(d)?);
        place.push((fds[i + 1].as_raw_fd(), FD_DATA0 + i as i32));
    }
    if let Some(fd) = userns {
        place.push((fd, FD_USERNS));
    }
    Ok(Ready {
        cmd: command(place, first),
        _fds: fds,
    })
}

/// The smallest sandbox: `/usr` and its links, `/dev`, `/proc`, a 1 MiB tmpfs at `/tmp` and
/// `/work`, hostname `sim`; `argv` run natively.
pub fn minimal(after: After, argv: Vec<String>) -> Spec {
    let mut ops = vec![
        Op::Hostname { name: "sim".into() },
        Op::Bind {
            src: "/usr".into(),
            dst: "/usr".into(),
            rw: false,
            dev: false,
        },
    ];
    for (l, t) in [
        ("/bin", "usr/bin"),
        ("/lib", "usr/lib"),
        ("/lib64", "usr/lib64"),
    ] {
        ops.push(Op::Symlink {
            target: t.into(),
            dst: l.into(),
        });
    }
    ops.push(Op::Dev { dst: "/dev".into() });
    ops.push(Op::Proc {
        dst: "/proc".into(),
    });
    for d in ["/work", "/tmp"] {
        ops.push(Op::Tmpfs {
            dst: d.into(),
            size: 1 << 20,
        });
    }
    Spec {
        ops,
        join_userns: false,
        chdir: "/work".into(),
        env: vec!["PATH=/usr/bin:/bin".into()],
        argv,
        exe: None,
        after,
        nodes: None,
    }
}

/// `patina __sandbox-views`: the check of `Keeper::view`. A sandbox whose keeper makes two more
/// views (`n1`, `n2`); every process prints one JSON line of what it sees (hostname, its
/// `/work/f`, `/tmp`, capabilities, namespaces), PID 1's (`base`) last with the processes it reaped.
pub fn views_main() -> Res<ExitCode> {
    let r = ready(
        minimal(After::Views { size: 1 << 20 }, vec!["-".into()]),
        &[],
        || Ok(()),
    )?;
    let mut cmd = r.cmd;
    let st = cmd.status().map_err(|e| format!("sandbox: {e}"))?;
    Ok(ExitCode::from(st.code().unwrap_or(1) as u8))
}

/// The AppArmor profile that lets the executable at `exe` make user namespaces where Ubuntu
/// restricts them (`patina doctor --print-apparmor-profile`): unconfined otherwise, like the
/// profiles Ubuntu ships for programs that make their own sandboxes.
pub fn apparmor_profile(exe: &Path) -> Res<String> {
    let Some(p) = exe.to_str().map(str::to_string) else {
        return Err(format!(
            "{}: not UTF-8; install patina at another path",
            exe.display()
        ));
    };
    if p.chars()
        .any(|ch| ch.is_control() || "*?[]{}^\"\\@".contains(ch))
    {
        return Err(format!(
            "{p}: a path with AppArmor pattern characters cannot name one file; install patina elsewhere"
        ));
    }
    Ok(format!(
        "# Lets the patina executable below create the user namespace its sandbox needs where\n\
         # kernel.apparmor_restrict_unprivileged_userns=1 (`patina doctor --print-apparmor-profile`).\n\
         abi <abi/4.0>,\n\
         include <tunables/global>\n\
         \n\
         profile patina \"{p}\" flags=(unconfined) {{\n\
         \x20 userns,\n\
         \n\
         \x20 include if exists <local/patina>\n\
         }}\n"
    ))
}

/// The keeper of a run with nodes: start node `k`'s first process each time the supervisor
/// asks (one byte, `k`), answer `ok` or why not, until PID 1's end closes.
fn nodes_keeper(k: &Keeper, chan: RawFd, n: &Nodes) {
    use proto::layout::*;
    loop {
        let mut b = [0u8; 1];
        let r = unsafe { libc::recv(chan, b.as_mut_ptr().cast(), 1, 0) };
        if r <= 0 {
            return;
        }
        let i = b[0] as usize;
        let res = match n.nodes.get(i.wrapping_sub(1)) {
            None => Err(format!("no node {i}")),
            Some(ns) => {
                // The keeper's stderr (`sandbox.log`) until the node's own replaces it.
                let mut keep = vec![2, FD_CTL, FD_LOG, FD_OPLOG_META, FD_OPLOG_DATA, FD_RT];
                for fd in [FD_PMU, FD_PLAN] {
                    if unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0 {
                        keep.push(fd);
                    }
                }
                let stdio = FD_NODE_STDIO0 + 3 * (i as i32 - 1);
                keep.extend(stdio..stdio + 3);
                let mut tmpfs: Vec<&str> = vec![&ns.work, "/tmp", "/dev/shm"];
                tmpfs.extend(n.hide.iter().map(String::as_str).filter(|h| *h != ns.work));
                let readonly: Vec<&str> = n.readonly.iter().map(String::as_str).collect();
                let v = View {
                    hostname: &ns.name,
                    tmpfs: &tmpfs,
                    size: n.size,
                    readonly: &readonly,
                };
                k.view(&v, &keep, || node_main(ns, stdio, n.size))
            }
        };
        let reply = match res {
            Ok(()) => "ok".to_string(),
            Err(e) => e,
        };
        unsafe { libc::send(chan, reply.as_ptr().cast(), reply.len(), libc::MSG_NOSIGNAL) };
    }
}

/// A node's first process, in its view: its starting tree, its stdio, the process state every
/// guest inherits (as the supervisor's own child has it, `sup::inherit`), then the runtime.
fn node_main(ns: &NodeSpec, stdio: RawFd, size: u64) -> i32 {
    let fail = |e: String| -> i32 {
        eprintln!("patina sandbox: node {}: {e}", ns.name);
        126
    };
    if let Some(input) = &ns.input {
        if let Err(e) = crate::sup::crash::copy_in(Path::new(input), Path::new(&ns.work)) {
            return fail(e);
        }
    }
    if let Err(e) = chdir(&ns.work) {
        return fail(e);
    }
    for k in 0..3 {
        if unsafe { libc::dup2(stdio + k, k) } != k {
            return fail(last_err("dup2 stdio"));
        }
        unsafe { libc::close(stdio + k) };
    }
    // Joining the guests' namespace and dropping capabilities left the process undumpable, so
    // its own /proc files are root's; the supervisor's own state was set after an exec.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } != 0 {
        return fail(last_err("PR_SET_DUMPABLE"));
    }
    if let Err(e) = crate::sup::inherit::normalise(size) {
        return fail(e);
    }
    let argv: Vec<CString> = ns.argv.iter().map(|a| c(a)).collect();
    let env: Vec<CString> = ns.env.iter().map(|a| c(a)).collect();
    let mut av: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    av.push(std::ptr::null());
    let mut ev: Vec<*const libc::c_char> = env.iter().map(|a| a.as_ptr()).collect();
    ev.push(std::ptr::null());
    unsafe {
        if !crate::sup::inherit::child() {
            return fail("process state".into());
        }
        if libc::prctl(libc::PR_SET_TSC, libc::PR_TSC_SIGSEGV, 0, 0, 0) != 0 {
            return fail(last_err("PR_SET_TSC"));
        }
        libc::syscall(
            libc::SYS_execveat,
            proto::layout::FD_RT,
            c"".as_ptr(),
            av.as_ptr(),
            ev.as_ptr(),
            libc::AT_EMPTY_PATH,
        );
    }
    fail(last_err("execute the runtime"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_names_one_file() {
        let p = apparmor_profile(Path::new("/opt/patina 1/bin/patina")).unwrap();
        assert!(
            p.contains("profile patina \"/opt/patina 1/bin/patina\""),
            "{p}"
        );
        for bad in [
            "/a/*/patina",
            "/a/{b,c}/patina",
            "/a/b?/patina",
            "/a/\"/patina",
        ] {
            assert!(apparmor_profile(Path::new(bad)).is_err(), "{bad}");
        }
    }
}
