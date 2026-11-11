//! The launcher of the guest's child processes.
//!
//! A guest that spawns an admitted program gets a second guest process:
//! the root asks the supervisor, over the launch channel
//! ([`patina_dst_runtime::ENV_LAUNCH_FD`]), to start the admitted artifact (the
//! file the admission holds open, by its descriptor),
//! and hands it the child's end of their channel, its stdin, stdout and
//! stderr, the write end of its stop pipe, its page (the memory file it
//! shares with the hub) and, when the run records or replays, its trace
//! (the page again, its decisions' log, or the timeline it replays). A
//! launcher thread serves those requests. Each child starts as
//! the root did: the root's control plane less what only the root writes
//! (facts, trace, coverage, stop records, reports, crash and restart
//! channels, the base filesystem and staged stdin) and the filesystem fault
//! knobs (the root's driver stack serves a child's filesystem), its own
//! seed, place in the process tree, working directory, channel, stop pipe,
//! page and trace, its guest environment through the initial
//! stack slots, and the same address layout pin. A child dies with the
//! launcher thread (`PR_SET_PDEATHSIG`) and inherits no other descriptor.
//! The launcher reaps each child as it dies; the root asks it how a child
//! whose host process ended without a word died, and it answers with the
//! wait status. A child the launcher cannot hold a pidfd for is killed at
//! once, its launch failed. When the root ends (the supervisor drops its
//! end of the launch channel as soon as it reaps the root, before it reads
//! the rest of the run's output), the launcher kills (by pidfd) and reaps
//! every child still running.

use super::*;
use serde::Deserialize;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::thread::JoinHandle;

/// The launch channel: the root's end and the launcher's, both
/// close-on-exec.
pub(super) fn launch_channel() -> Result<(OwnedFd, OwnedFd), CliError> {
    let mut pair = [-1; 2];
    // SAFETY: a writable pair of descriptors.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(CliError(format!(
            "failed to create the process launch channel: {}",
            io::Error::last_os_error()
        )));
    }
    // SAFETY: both descriptors are fresh and owned here.
    Ok(unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) })
}

/// Control-plane entries a child does not inherit from the root: the
/// channels only the root writes or reads, what a child gets its own of,
/// and what the layout pin and the envp slots set afresh.
fn child_inherits(name: &str) -> bool {
    use patina_dst_runtime as rt;
    const OWN: &[&str] = &[
        rt::ENV_FACTS_FD,
        rt::ENV_TRACE_FD,
        rt::ENV_COVERAGE_FD,
        rt::ENV_CRASH_REPORT_FD,
        rt::ENV_HANDOFF_FD,
        rt::ENV_HANDOFF_KEY,
        rt::ENV_RESTART_SNAPSHOT_FD,
        rt::ENV_RESTART_REALTIME_NANOS,
        rt::ENV_RESTART_FAULTS,
        rt::ENV_FS_IMAGE_FD,
        rt::ENV_GUEST_STDIN_FD,
        rt::ENV_STOP_FD,
        rt::ENV_REPORTS_FD,
        rt::ENV_GUEST_ENV,
        rt::ENV_GUEST_ARGV,
        rt::ENV_GUEST_CWD,
        rt::ENV_SEED,
        rt::ENV_LAUNCH_FD,
        rt::ENV_ADDRESS_LAYOUT,
        rt::ENV_INITIAL_STACK,
        // The root's driver stack draws every filesystem fault. Latency is
        // the calling process's own (its runtime charges it, from its own
        // seeded stream), so a child keeps that knob.
        rt::ENV_FS_ERROR_PERMILLE,
        rt::ENV_FS_SHORT_PERMILLE,
        rt::ENV_FS_ERROR_AT,
    ];
    !OWN.contains(&name) && !name.starts_with(ENVP_SLOT_PREFIX) && !name.starts_with("_PATINA_PAD_")
}

/// How every child of a run starts.
pub(super) struct Template {
    /// The admitted artifacts, by id: descriptors of the files the
    /// supervisor holds open and confirmed the audited bytes of.
    artifacts: BTreeMap<usize, OwnedFd>,
    /// The root's control plane a child inherits.
    control: Vec<(OsString, OsString)>,
    allow_randomized: bool,
}

impl Template {
    /// A child's start, from the root's `command`.
    pub(super) fn of_root(
        command: &Command,
        artifacts: BTreeMap<usize, OwnedFd>,
        allow_randomized: bool,
    ) -> Self {
        let control = command
            .get_envs()
            .filter_map(|(name, value)| Some((name.to_owned(), value?.to_owned())))
            .filter(|(name, _)| name.to_str().is_some_and(child_inherits))
            .collect();
        Self {
            artifacts,
            control,
            allow_randomized,
        }
    }
}

/// What the root asks of the launcher.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Request {
    /// Start a child (its descriptors ride beside the request).
    Launch(Launch),
    /// The host wait status of child `pid`, whose host process is gone,
    /// answered as eight little-endian bytes (-1 when unknown).
    Reaped(i32),
}

/// A launch the root asks for.
#[derive(Deserialize)]
struct Launch {
    artifact: u32,
    argv: Vec<String>,
    env: BTreeMap<String, String>,
    pid: i32,
    parent: i32,
    pgid: i32,
    sid: i32,
    seed: u64,
    cwd: String,
}

/// A child the launcher started: a pidfd that names it until it is reaped
/// (so a kill never reaches a recycled pid), and the thread that reaps it
/// as soon as it dies.
struct Running {
    pidfd: OwnedFd,
    /// Answers the child's raw wait status once it is reaped.
    reaper: JoinHandle<Option<i32>>,
}

/// Serve the root's launch requests on `channel` until the root's end
/// closes, then kill and reap every child still running. Each child is
/// reaped when it dies (the hub kills a frozen child by having it raise
/// `SIGKILL` on itself).
pub(super) fn start(channel: OwnedFd, template: Template) -> JoinHandle<()> {
    std::thread::spawn(move || {
        use std::os::unix::process::ExitStatusExt;
        let mut children: BTreeMap<i32, Running> = BTreeMap::new();
        // Children reaped while the root ran: their wait statuses, without
        // the pidfd and thread each held (a machine may start any number).
        let mut reaped: BTreeMap<i32, Option<i32>> = BTreeMap::new();
        while let Some((payload, fds)) = receive(channel.as_raw_fd()) {
            let done: Vec<i32> = children
                .iter()
                .filter(|(_, child)| child.reaper.is_finished())
                .map(|(pid, _)| *pid)
                .collect();
            for pid in done {
                if let Some(child) = children.remove(&pid) {
                    reaped.insert(pid, child.reaper.join().ok().flatten());
                }
            }
            let request = serde_json::from_slice(&payload)
                .map_err(|error| CliError(format!("malformed process launch request: {error}")));
            match request {
                Ok(Request::Launch(request)) => {
                    let pid = request.pid;
                    match launch(&template, request, fds) {
                        Ok(mut child) => {
                            // SAFETY: a plain system call; the child is not
                            // reaped before its reaper starts below.
                            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) };
                            if raw < 0 {
                                // Its end could not be guaranteed: the launch
                                // fails (the root sees the child die before it
                                // is ready).
                                eprintln!(
                                    "patina: failed to hold process {pid}: {}",
                                    io::Error::last_os_error()
                                );
                                let _ = child.kill();
                                let _ = child.wait();
                                continue;
                            }
                            // SAFETY: a fresh descriptor owned here.
                            let pidfd = unsafe { OwnedFd::from_raw_fd(raw as RawFd) };
                            let reaper = std::thread::spawn(move || {
                                child.wait().ok().map(ExitStatusExt::into_raw)
                            });
                            children.insert(pid, Running { pidfd, reaper });
                        }
                        // The root waits for the child's ready on its channel,
                        // whose far end the failed launch dropped: it stops
                        // the run there.
                        Err(error) => eprintln!("patina: {error}"),
                    }
                }
                Ok(Request::Reaped(pid)) => {
                    let status = match children.remove(&pid) {
                        Some(child) => child.reaper.join().ok().flatten(),
                        None => reaped.remove(&pid).flatten(),
                    };
                    let answer = i64::from(status.unwrap_or(-1)).to_le_bytes();
                    // SAFETY: a live buffer of its length.
                    unsafe {
                        libc::send(
                            channel.as_raw_fd(),
                            answer.as_ptr().cast(),
                            answer.len(),
                            libc::MSG_NOSIGNAL,
                        )
                    };
                }
                Err(error) => eprintln!("patina: {error}"),
            }
        }
        for child in children.into_values() {
            // SAFETY: a plain system call on a pidfd owned here.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    child.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            let _ = child.reaper.join();
        }
    })
}

/// Start one child, as `payload` asks, with `fds`: its channel end, stdin,
/// stdout and stderr, its stop pipe, its page, and maybe its trace.
fn launch(
    template: &Template,
    request: Launch,
    fds: Vec<OwnedFd>,
) -> Result<std::process::Child, CliError> {
    // The child's channel, stdio, stop pipe, page, and on a recording or a
    // replay the child's own trace.
    let mut fds = fds.into_iter();
    let (
        Some(channel),
        Some(stdin),
        Some(stdout),
        Some(stderr),
        Some(stops),
        Some(page),
        trace,
        None,
    ) = (
        fds.next(),
        fds.next(),
        fds.next(),
        fds.next(),
        fds.next(),
        fds.next(),
        fds.next(),
        fds.next(),
    )
    else {
        return Err(CliError(
            "a process launch request must carry six or seven descriptors".into(),
        ));
    };
    let artifact = template
        .artifacts
        .get(&(request.artifact as usize))
        .ok_or_else(|| CliError(format!("no admitted artifact {}", request.artifact)))?;
    // The held file itself, by its descriptor: the bytes the admission
    // audited, whatever has since happened to the path it was found at. The
    // forked child still has the descriptor when it execs (it closes on exec).
    let artifact = PathBuf::from(format!("/proc/self/fd/{}", artifact.as_raw_fd()));
    let argv0 = request
        .argv
        .first()
        .map_or(NATIVE_GUEST_ARGV0, String::as_str);
    let mut command = Command::new(&artifact);
    command
        .arg0(argv0)
        .args(request.argv.iter().skip(1))
        .env_clear();
    command.env(ENV_INITIAL_STACK, "1");
    for slot in 0..request.env.len() + NATIVE_INITIAL_STACK_TRAILER_SLOTS {
        command.env(format!("{ENVP_SLOT_PREFIX}{slot}"), "");
    }
    for (name, value) in &template.control {
        command.env(name, value);
    }
    let environment = json(&request.env)?;
    let arguments = json(&request.argv.get(1..).unwrap_or_default())?;
    if !request.env.is_empty() {
        command.env(ENV_GUEST_ENV, &environment);
    }
    let raw_channel = channel.as_raw_fd();
    let raw_stops = stops.as_raw_fd();
    let raw_page = page.as_raw_fd();
    let raw_trace = trace.as_ref().map(AsRawFd::as_raw_fd);
    if let Some(trace) = raw_trace {
        command.env(patina_dst_runtime::ENV_TRACE_FD, trace.to_string());
    }
    command.env(patina_dst_runtime::ENV_STOP_FD, raw_stops.to_string());
    command.env(
        patina_dst_runtime::ENV_PROCESS_PAGE_FD,
        raw_page.to_string(),
    );
    command
        .env(ENV_SEED, request.seed.to_string())
        .env(
            patina_dst_runtime::ENV_PROCESS,
            format!(
                "{}:{}:{}:{}",
                request.pid, request.parent, request.pgid, request.sid
            ),
        )
        .env(patina_dst_runtime::ENV_CHANNEL_FD, raw_channel.to_string())
        .env(ENV_GUEST_CWD, &request.cwd)
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    // SAFETY: the hook runs in the forked child before exec and makes only
    // async-signal-safe system calls, allocating nothing.
    unsafe {
        command.pre_exec(move || {
            inherit_only([
                Some(raw_channel),
                Some(raw_stops),
                Some(raw_page),
                raw_trace,
            ])
        });
    }
    layout::pin(
        &mut command,
        argv0,
        ENVP_SLOT_PREFIX,
        environment.len() + arguments.len(),
        template.allow_randomized,
    )?;
    let child = command.spawn().map_err(|error| {
        CliError(format!(
            "failed to start process {} ({}): {error}",
            request.pid,
            artifact.display()
        ))
    })?;
    drop(channel);
    drop(stops);
    drop(page);
    drop(trace);
    Ok(child)
}

/// The JSON a child's control plane carries `value` as.
fn json(value: &impl serde::Serialize) -> Result<String, CliError> {
    serde_json::to_string(value)
        .map_err(|error| CliError(format!("failed to encode a process launch: {error}")))
}

/// In the forked child: die with the launcher thread, and let only stdio
/// and `kept` (the channel, the stop pipe, the page, a trace) cross the
/// exec.
fn inherit_only(kept: [Option<RawFd>; 4]) -> io::Result<()> {
    let check = |rc: libc::c_long| {
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    };
    // SAFETY: plain system calls on this process's own state.
    unsafe {
        check(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) as libc::c_long)?;
        check(libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        ))?;
        for fd in kept.into_iter().flatten() {
            check(libc::fcntl(fd, libc::F_SETFD, 0) as libc::c_long)?;
        }
    }
    Ok(())
}

/// The next launch request on `fd` and its descriptors; `None` once the
/// root's end is closed.
fn receive(fd: RawFd) -> Option<(Vec<u8>, Vec<OwnedFd>)> {
    let mut payload = vec![0u8; 1 << 20];
    // Room for a few more descriptors than a request carries, so a request
    // with too many still arrives whole and is refused.
    let mut control = [0u64; 16];
    loop {
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        // SAFETY: an all-zero msghdr is valid; the buffers below outlive the call.
        let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
        header.msg_iov = &mut iov;
        header.msg_iovlen = 1;
        header.msg_control = control.as_mut_ptr().cast();
        header.msg_controllen = size_of_val(&control) as _;
        // SAFETY: the header names live buffers.
        let received = unsafe { libc::recvmsg(fd, &mut header, libc::MSG_CMSG_CLOEXEC) };
        if received < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return None;
        }
        if received == 0 {
            return None;
        }
        let mut fds = Vec::new();
        // SAFETY: walking the control messages the kernel wrote.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&header);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                    let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
                    let count = ((*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize)
                        / size_of::<RawFd>();
                    for index in 0..count {
                        fds.push(OwnedFd::from_raw_fd(data.add(index).read_unaligned()));
                    }
                }
                cmsg = libc::CMSG_NXTHDR(&header, cmsg);
            }
        }
        payload.truncate(received as usize);
        return Some((payload, fds));
    }
}
