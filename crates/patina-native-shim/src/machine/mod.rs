//! The machine: the guest's processes, run in lockstep.
//!
//! Every guest process is a host process running the whole runtime (its own
//! Context, scheduler, descriptor table and models), and only one of them
//! runs at a time: the machine holds one process baton. The root process
//! (the one the run starts) is the machine's hub. It holds the process table
//! and decides which process runs next: its scheduler holds one foreign task
//! per child ([`Operation::TaskForeign`]), and a pick of one is a process
//! switch, recorded like any other scheduling decision. A child's scheduler
//! holds a single foreign task, [`ELSEWHERE`], for the rest of the machine; a
//! pick of it hands the baton back to the hub.
//!
//! The supervisor starts every child ([`launch`]): the hub asks it over the
//! launch channel ([`patina_dst_runtime::ENV_LAUNCH_FD`]) to start an
//! admitted artifact, with the per-child channel's far end. Hub and child
//! then speak strict ping-pong over that `SOCK_SEQPACKET` channel
//! ([`wire`]): the hub resumes a child with the machine's time and a view of
//! the other processes; the child yields with its time and its own state,
//! asks the hub for what only the hub holds (ids), or exits.
//!
//! [`Operation::TaskForeign`]: patina_dst_abi::Operation::TaskForeign
#![cfg_attr(not(patina_posix_exports), allow(dead_code))]

use crate::thread;
use crate::{SpinMutex, TaskId};
use patina_dst_abi::ForeignState;
use std::collections::BTreeMap;
use std::ffi::c_int;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};

pub(crate) mod fs;
pub(crate) mod spawn;
mod wire;

use wire::Message;

/// Foreign tasks live above every task id a scheduler numbers: a child
/// process's task in the hub is `FOREIGN_BASE + pid`, and a child's view of
/// the rest of the machine is `FOREIGN_BASE` itself. No thread id ever maps
/// to one.
const FOREIGN_BASE: u64 = 1 << 48;

/// A child's one foreign task: every other process of the machine.
pub(crate) const ELSEWHERE: TaskId = TaskId(FOREIGN_BASE);

/// The hub's foreign task for child `pid`.
fn foreign_task(pid: i32) -> TaskId {
    TaskId(FOREIGN_BASE + pid as u64)
}

/// Whether `task` stands for another process rather than a thread.
pub(crate) fn is_foreign(task: TaskId) -> bool {
    task.0 >= FOREIGN_BASE
}

const ROLE_SINGLE: u8 = 0;
const ROLE_ROOT: u8 = 1;
const ROLE_CHILD: u8 = 2;

/// This process's place in the machine: the root, alone until its first
/// spawn, or a child.
static ROLE: AtomicU8 = AtomicU8::new(ROLE_SINGLE);
/// A child's channel to the hub; -1 in the root.
static CHANNEL: AtomicI32 = AtomicI32::new(-1);

/// Whether this process is a child of the machine's root.
pub(crate) fn is_child() -> bool {
    ROLE.load(Ordering::Relaxed) == ROLE_CHILD
}

/// Whether the machine holds (or held) a process besides this one.
pub(crate) fn is_multiprocess() -> bool {
    ROLE.load(Ordering::Relaxed) != ROLE_SINGLE
}

/// The next process or thread id of the machine, which the hub hands out:
/// one namespace, in creation order, as the kernel's pid allocator.
static NEXT_ID: AtomicI32 = AtomicI32::new(crate::registry::ROOT_PID as i32 + 1);

/// A new id for a thread or process of the machine. A child asks the hub.
pub(crate) fn allocate_id() -> c_int {
    if is_child() {
        match exchange(&Message::AllocId) {
            Message::Id(id) => id,
            other => protocol_fatal("an id", &other),
        }
    } else {
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    }
}

/// A child process the hub knows: live until it exits, then a zombie
/// holding its wait status until its parent reaps it.
struct Child {
    parent: i32,
    channel: c_int,
    status: Option<i32>,
}

/// The hub's process table.
static CHILDREN: SpinMutex<BTreeMap<i32, Child>> = SpinMutex::new(BTreeMap::new());

/// Read this process's place in the machine from the control plane, before
/// the runtime is built: a child knows its pid, its parent and its channel.
pub(crate) fn configure() -> Result<(), patina_dst_runtime::RuntimeError> {
    use patina_dst_runtime::{ENV_CHANNEL_FD, ENV_PROCESS, RuntimeError};
    let Some(process) = crate::control_env(ENV_PROCESS) else {
        return Ok(());
    };
    let invalid = || RuntimeError::Config(format!("{ENV_PROCESS} must be PID:PPID:PGID:SID"));
    let fields: Vec<i32> = process
        .split(':')
        .map(|field| field.parse().map_err(|_| invalid()))
        .collect::<Result<_, _>>()?;
    let [pid, parent, pgid, sid] = fields[..] else {
        return Err(invalid());
    };
    let channel = crate::parse_control_u64(ENV_CHANNEL_FD)?.ok_or_else(|| {
        RuntimeError::Config(format!("a child process requires {ENV_CHANNEL_FD}"))
    })?;
    crate::identity::enter_process(pid, parent, pgid, sid);
    CHANNEL.store(channel as c_int, Ordering::Relaxed);
    ROLE.store(ROLE_CHILD, Ordering::Relaxed);
    Ok(())
}

/// A child, once its runtime is installed and before any guest code runs:
/// its main thread becomes its first managed task, it tells the hub it is
/// ready, and it waits for the baton.
pub(crate) fn child_start() {
    if !is_child() {
        return;
    }
    if let Err(message) = thread::activate() {
        protocol_fatal_text(&message);
    }
    context(|context| context.task_foreign(ELSEWHERE, ForeignState::Parked));
    send(channel(), &Message::Ready);
    ELSEWHERE_RUNS.store(true, Ordering::Relaxed);
    let first = receive(channel());
    ELSEWHERE_RUNS.store(false, Ordering::Relaxed);
    let (now, view) = match first {
        Some(Message::Resume { now, view }) => (now, view),
        Some(other) => protocol_fatal("the first resume", &other),
        None => orphaned(),
    };
    context(|context| {
        context.advance_to(now)?;
        context.task_foreign(ELSEWHERE, view)
    });
}

fn channel() -> c_int {
    CHANNEL.load(Ordering::Relaxed)
}

/// Run a Context step the machine takes, or end the run naming it.
fn context<T>(
    step: impl FnOnce(&mut crate::Context) -> Result<T, patina_dst_runtime::RuntimeError>,
) -> T {
    crate::with_context_msg(step).unwrap_or_else(|message| protocol_fatal_text(&message))
}

/// The baton moves to another process: the scheduler picked `picked`, a
/// foreign task. Runs the switch and answers the local task the baton
/// comes back to, which the caller hands it on to. In the hub this thread
/// serves the machine until a local task is picked; in a child it waits on
/// the hub.
pub(crate) fn run_elsewhere(picked: TaskId) -> TaskId {
    ELSEWHERE_RUNS.store(true, Ordering::Relaxed);
    let local = if is_child() {
        yield_to_hub(picked)
    } else {
        serve_children(picked)
    };
    ELSEWHERE_RUNS.store(false, Ordering::Relaxed);
    local
}

/// Set while another process holds the baton: this process runs no guest
/// code (frozen on its channel, or serving as the hub), so the compute
/// observer has no candidate here.
static ELSEWHERE_RUNS: AtomicBool = AtomicBool::new(false);

/// Whether another process of the machine holds the baton.
pub(crate) fn elsewhere_runs() -> bool {
    ELSEWHERE_RUNS.load(Ordering::Relaxed)
}

/// The hub's side of a switch: resume the picked child and serve it until
/// it yields or exits, then pick again, until the pick is local.
fn serve_children(mut picked: TaskId) -> TaskId {
    loop {
        let pid = (picked.0 - FOREIGN_BASE) as i32;
        let channel = CHILDREN
            .lock()
            .get(&pid)
            .filter(|child| child.status.is_none())
            .map(|child| child.channel)
            .unwrap_or_else(|| protocol_fatal_text(&format!("no live process {pid} to resume")));
        let (now, view) =
            context(|context| Ok((context.machine_now()?, context.process_view(Some(picked)))));
        send(channel, &Message::Resume { now, view });
        match serve(pid, channel) {
            Message::Yield { now, state } => {
                context(|context| {
                    context.advance_to(now)?;
                    context.task_foreign(picked, state)
                });
            }
            Message::Exit { now, status } => {
                context(|context| {
                    context.advance_to(now)?;
                    context.task_foreign(picked, ForeignState::Gone)
                });
                exited(pid, status);
            }
            other => protocol_fatal("a child's yield or exit", &other),
        }
        picked = thread::pick_next();
        if !is_foreign(picked) {
            return picked;
        }
    }
}

/// Serve child `pid` on `channel` (ids, filesystem calls) until it says
/// something only its caller acts on (ready, yield, exit), and answer that.
fn serve(pid: i32, channel: c_int) -> Message {
    loop {
        match receive(channel) {
            Some(Message::AllocId) => {
                send(
                    channel,
                    &Message::Id(NEXT_ID.fetch_add(1, Ordering::Relaxed)),
                );
            }
            Some(Message::Fs { len }) => {
                let request = receive_payload(channel, len).unwrap_or_else(|| died(pid));
                let request = serde_json::from_slice(&request).unwrap_or_else(|error| {
                    protocol_fatal_text(&format!("decoding a filesystem call: {error}"))
                });
                // The root's driver stack answers; the root records nothing.
                let answer = crate::with_context_raw(|context| {
                    Ok(fs::serve(context.machine_filesystem(), request))
                })
                .unwrap_or_else(|errno| {
                    protocol_fatal_text(&format!("the root's runtime is gone ({errno})"))
                });
                let answer = serde_json::to_vec(&answer).unwrap_or_else(|error| {
                    protocol_fatal_text(&format!("encoding a filesystem answer: {error}"))
                });
                send_frame(
                    channel,
                    Message::FsReply {
                        len: answer.len() as u64,
                    },
                    &answer,
                );
            }
            Some(message) => return message,
            None => died(pid),
        }
    }
}

/// Child `pid` exited with wait status `status`: it is a zombie until its
/// parent reaps it, and every task waiting for a child of that parent
/// looks again.
fn exited(pid: i32, status: i32) {
    let mut children = CHILDREN.lock();
    let Some(child) = children.get_mut(&pid) else {
        return;
    };
    child.status = Some(status);
    let channel = child.channel;
    drop(children);
    close(channel);
    spawn::wake_waiters();
}

/// A child whose host process is gone without telling the hub how it ended.
fn died(pid: i32) -> ! {
    protocol_fatal_text(&format!(
        "process {pid} ended without reporting its exit to the machine"
    ))
}

/// A child's side of a switch: hand the baton to the hub with this
/// process's time and state, wait to be resumed, then pick a local task
/// first (the hub chose this process to run).
fn yield_to_hub(mut picked: TaskId) -> TaskId {
    loop {
        debug_assert_eq!(picked, ELSEWHERE);
        let (now, state) = context(|context| {
            Ok((
                context.machine_now()?,
                context.process_view(Some(ELSEWHERE)),
            ))
        });
        send(channel(), &Message::Yield { now, state });
        let (now, view) = match receive(channel()) {
            Some(Message::Resume { now, view }) => (now, view),
            Some(other) => protocol_fatal("a resume", &other),
            None => orphaned(),
        };
        let local = context(|context| {
            context.advance_to(now)?;
            let local = context.process_view(Some(ELSEWHERE)) == ForeignState::Runnable;
            if !local {
                context.task_foreign(ELSEWHERE, view)?;
            } else {
                context.task_foreign(ELSEWHERE, ForeignState::Parked)?;
            }
            Ok(local)
        });
        picked = thread::pick_next();
        if local {
            context(|context| context.task_foreign(ELSEWHERE, view));
        }
        if picked != ELSEWHERE {
            return picked;
        }
    }
}

/// A child's exit: the hub learns its status and its time, and the host
/// process ends without writing anything of its own (the root writes the
/// run's facts and trace).
pub(crate) fn child_exit(status: i32) {
    // After `main` returned: a read of the clock, no scheduling operation.
    let now = crate::with_context_raw(|context| context.machine_now()).unwrap_or(0);
    send(channel(), &Message::Exit { now, status });
}

/// The hub is gone (the root ended): a child has no machine to run in.
fn orphaned() -> ! {
    // SAFETY: libc's `_exit`, through the host alias.
    unsafe { (crate::hostapi::get().host_immediate_exit)(137) }
}

fn protocol_fatal(expected: &str, got: &Message) -> ! {
    protocol_fatal_text(&format!("the machine expected {expected}, not {got:?}"))
}

fn protocol_fatal_text(message: &str) -> ! {
    thread::fatal(&format!("machine: {message}"))
}

/// Send `message` and wait for the hub's answer (a child's request).
fn exchange(message: &Message) -> Message {
    send(channel(), message);
    receive(channel()).unwrap_or_else(|| orphaned())
}

fn send(fd: c_int, message: &Message) {
    send_bytes(fd, &message.encode());
}

/// Send `header`, then `payload` in packets of at most
/// [`wire::CHUNK_BYTES`].
fn send_frame(fd: c_int, header: Message, payload: &[u8]) {
    send(fd, &header);
    for chunk in payload.chunks(wire::CHUNK_BYTES) {
        send_bytes(fd, chunk);
    }
}

/// One packet.
fn send_bytes(fd: c_int, bytes: &[u8]) {
    loop {
        // SAFETY: a live buffer of `bytes.len()` bytes.
        let sent = unsafe {
            crate::sud_host_syscall(
                libc::SYS_sendto,
                fd as _,
                bytes.as_ptr() as _,
                bytes.len() as _,
                libc::MSG_NOSIGNAL as _,
                0,
                0,
            )
        };
        if sent == bytes.len() as i64 {
            return;
        }
        if sent < 0 && crate::abi::host_errno() == libc::EINTR {
            continue;
        }
        if is_child() {
            orphaned();
        }
        protocol_fatal_text(&format!("sending on channel {fd} failed"));
    }
}

/// A frame's `len` payload bytes, or `None` if the peer is gone first.
fn receive_payload(fd: c_int, len: u64) -> Option<Vec<u8>> {
    let mut payload = Vec::with_capacity(len as usize);
    let mut chunk = vec![0u8; wire::CHUNK_BYTES];
    while (payload.len() as u64) < len {
        let received = receive_bytes(fd, &mut chunk)?;
        payload.extend_from_slice(&chunk[..received]);
    }
    Some(payload)
}

/// One packet into `buffer`: its length, or `None` at end of stream.
fn receive_bytes(fd: c_int, buffer: &mut [u8]) -> Option<usize> {
    loop {
        // SAFETY: a writable buffer of its length.
        let received = unsafe {
            crate::sud_host_syscall(
                libc::SYS_recvfrom,
                fd as _,
                buffer.as_mut_ptr() as _,
                buffer.len() as _,
                0,
                0,
                0,
            )
        };
        if received < 0 && crate::abi::host_errno() == libc::EINTR {
            continue;
        }
        if received <= 0 {
            return None;
        }
        return Some(received as usize);
    }
}

/// The next message on `fd`, or `None` at end of stream (the peer is gone).
fn receive(fd: c_int) -> Option<Message> {
    let mut buffer = [0u8; wire::MESSAGE_BYTES];
    let received = receive_bytes(fd, &mut buffer)?;
    Some(
        Message::decode(&buffer[..received])
            .unwrap_or_else(|| protocol_fatal_text("an undecodable message")),
    )
}

fn close(fd: c_int) {
    // SAFETY: closes a descriptor the machine owns.
    unsafe { crate::sud_host_syscall(libc::SYS_close, fd as _, 0, 0, 0, 0, 0) };
}
