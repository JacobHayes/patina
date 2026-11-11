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
use patina_dst_abi::Fd;
use patina_dst_abi::ForeignState;
use patina_dst_runtime::MachineCarry;
use patina_dst_trace::ProcessEnd;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::c_int;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};

pub(crate) mod fs;
mod log;
pub(crate) mod pipes;
pub(crate) mod spawn;
mod wire;

pub(crate) use log::{DecisionLog, note_step};

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

/// The foreign task that stands for child `pid` in the hub: what a root
/// channel's interest of that child wakes.
pub(crate) fn process_task(pid: c_int) -> TaskId {
    foreign_task(pid)
}

/// A wait queue of this process named another process's foreign task (a
/// child's interest in a root pipe): the machine wakes that process.
pub(crate) fn remote_wake(task: TaskId) {
    pipes::woke(Some(task));
}

/// A task of this process woke: what a child's request the hub serves now
/// says it did to the rest of the machine.
pub(crate) fn note_wake() {
    pipes::woke(None);
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

/// Id `id` is taken (a thread of a root that is still the whole machine,
/// numbered after its task): the machine's next ids come after it.
pub(crate) fn reserve_id(id: c_int) {
    NEXT_ID.fetch_max(id.saturating_add(1), Ordering::Relaxed);
}

/// A child process the hub knows: live until it exits, then a zombie
/// holding its wait status until its parent reaps it.
struct Child {
    parent: i32,
    channel: c_int,
    /// The read end of the pipe the child's signal front writes a stop
    /// record to (its `PATINA_STOP_FD`), which never enters Rust.
    stops: c_int,
    /// Its page: its time, its compute stop, its decisions; unmapped once
    /// it ended.
    page: Option<log::HubPage>,
    /// Whether it reported ready: before, its death is never its guest's.
    ready: bool,
    status: Option<i32>,
    /// The admitted artifact it runs (0, the guest's own executable).
    artifact: u64,
}

/// The hub's process table.
static CHILDREN: SpinMutex<BTreeMap<i32, Child>> = SpinMutex::new(BTreeMap::new());

/// The root's filesystem handles each child holds open: closed when the
/// child ends, however it ends.
static HANDLES: SpinMutex<BTreeMap<i32, BTreeSet<Fd>>> = SpinMutex::new(BTreeMap::new());

/// `SIGKILL`'s wait status.
const KILLED: i32 = libc::SIGKILL;

/// Whether another process of the machine lives now: a child's root always
/// does; the root's children while one has not ended.
pub(crate) fn others_live() -> bool {
    match ROLE.load(Ordering::Relaxed) {
        ROLE_SINGLE => false,
        ROLE_CHILD => true,
        _ => CHILDREN.lock().values().any(|child| child.status.is_none()),
    }
}

/// Stop the run by name if another process of the machine lives: `what` is
/// state each process models on its own that is really the machine's
/// (locks, FIFOs, shared file mappings, System V IPC), which another
/// process could not see.
///
/// While this process is alone, the first such state it makes is noted
/// ([`shared_state_used`]): a later spawn would hand a child a machine whose
/// state that process holds on its own, and is refused.
pub(crate) fn refuse_shared(what: &'static str) {
    if !others_live() {
        if !SHARED_USED_SET.load(Ordering::Relaxed) {
            let mut used = SHARED_USED.lock();
            if used.is_none() {
                *used = Some(what);
                SHARED_USED_SET.store(true, Ordering::Relaxed);
            }
        }
        return;
    }
    refuse_beside_others(what);
}

/// Stop the run by name if another process of the machine lives: `what`
/// changes something every process of the machine sees (its process
/// group, its session) that only this one's table would hold.
pub(crate) fn refuse_beside_others(what: &str) {
    if others_live() {
        crate::trap_unmodeled(&format!(
            "{what} while the guest's machine holds several processes is not modeled"
        ));
    }
}

/// The first per-process state of the machine's (see [`refuse_shared`])
/// this process made while alone.
static SHARED_USED: SpinMutex<Option<&'static str>> = SpinMutex::new(None);
/// Whether [`SHARED_USED`] is set: the hot paths that note shared state
/// read this, not the lock.
static SHARED_USED_SET: AtomicBool = AtomicBool::new(false);

/// What per-process state of the machine's this process made while alone,
/// if any: a spawn now would leave a child outside it.
pub(crate) fn shared_state_used() -> Option<&'static str> {
    if !SHARED_USED_SET.load(Ordering::Relaxed) {
        return None;
    }
    *SHARED_USED.lock()
}

/// Stop the run by name if this process has had a child: what a child
/// spent (`RUSAGE_CHILDREN`, `times`) is not carried back to its parent.
pub(crate) fn refuse_child_usage(what: &str) {
    if is_multiprocess() && !is_child() {
        crate::trap_unmodeled(&format!(
            "{what} after a child process ran (its CPU time is not carried to the parent) \
is not modeled"
        ));
    }
}

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
    let page = crate::parse_control_u64(patina_dst_runtime::ENV_PROCESS_PAGE_FD)?
        .and_then(|fd| log::open(fd as c_int))
        .ok_or_else(|| {
            RuntimeError::Config(format!(
                "a child process requires {}",
                patina_dst_runtime::ENV_PROCESS_PAGE_FD
            ))
        })?;
    crate::identity::enter_process(pid, parent, pgid, sid);
    CHANNEL.store(channel as c_int, Ordering::Relaxed);
    START.store(page, Ordering::Relaxed);
    ROLE.store(ROLE_CHILD, Ordering::Relaxed);
    Ok(())
}

/// A child's start: the machine's time when it was spawned.
static START: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The machine's time a child's clock starts at; `None` in the root.
pub(crate) fn start_nanos() -> Option<u64> {
    is_child().then(|| START.load(Ordering::Relaxed))
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
    // Its descriptors, as its spawn arranged them.
    spawn::install_plan();
    // A recording child: the root keeps its recording, under the metadata
    // its runtime records with.
    if let Some(metadata) = context(|context| Ok(context.machine_recording_metadata())) {
        send_frame(
            channel(),
            Message::TraceBegin {
                len: metadata.len() as u64,
            },
            &metadata,
        );
    }
    send(channel(), &Message::Ready);
    ELSEWHERE_RUNS.store(true, Ordering::Relaxed);
    let (now, view, carry) = await_resume();
    ELSEWHERE_RUNS.store(false, Ordering::Relaxed);
    context(|context| {
        context.advance_to(now)?;
        context.import_machine_carry(carry);
        context.task_foreign(ELSEWHERE, view)
    });
    raise_pending();
}

/// What this process hands the next one with the baton: the time, what
/// every task but `except` amounts to (its timers as of now included), and
/// the machine's carried state, which this process gives up.
fn hand_over(except: TaskId) -> (u64, ForeignState, MachineCarry) {
    let alarm = thread::earliest_timer();
    context(|context| {
        Ok((
            context.machine_now()?,
            context.process_view(Some(except), alarm),
            context.export_machine_carry()?,
        ))
    })
}

/// Take the baton back from another process, at its time `now`, with the
/// machine's `carry`, and set `task`, the foreign task that stands for it,
/// to `state`.
fn take_over(now: u64, carry: MachineCarry, task: TaskId, state: ForeignState) {
    context(|context| {
        context.advance_to(now)?;
        context.import_machine_carry(carry);
        context.task_foreign(task, state)
    });
}

fn channel() -> c_int {
    CHANNEL.load(Ordering::Relaxed)
}

/// A frozen child's wait for the baton: the hub resumes it, or kills it.
/// The signals other processes sent it meanwhile come first; it generates
/// them once it took the baton ([`raise_pending`]).
fn await_resume() -> (u64, ForeignState, MachineCarry) {
    loop {
        match receive(channel()) {
            Some(Message::Resume { now, view, carry }) => return (now, view, carry),
            Some(Message::Raise { len }) => {
                let info = receive_payload(channel(), len).unwrap_or_else(|| orphaned());
                RAISED.lock().push(info_words(&info));
            }
            Some(Message::Kill) => killed(),
            Some(Message::Describe) => {
                // The machine is deadlocked: the hub names this process's
                // blocked tasks.
                let tasks = crate::with_context_raw(|context| Ok(context.machine_parked_tasks()))
                    .unwrap_or_default();
                let answer = serde_json::to_vec(&[(crate::patina_pid(), blocked(&tasks))])
                    .unwrap_or_default();
                send_frame(
                    channel(),
                    Message::DescribeReply {
                        len: answer.len() as u64,
                    },
                    &answer,
                );
            }
            Some(other) => protocol_fatal("a resume", &other),
            None => orphaned(),
        }
    }
}

/// The signals a frozen child was sent, until it resumes.
static RAISED: SpinMutex<Vec<[u64; 16]>> = SpinMutex::new(Vec::new());

/// A resumed child generates the signals it was sent while frozen, in the
/// order they were sent, each a recorded decision of its own: its model
/// then acts on them (a handler, a mask, an interrupted wait, a default
/// action).
fn raise_pending() {
    let raised = std::mem::take(&mut *RAISED.lock());
    for info in raised {
        thread::machine_signal(info);
    }
}

/// This frozen child was sent `SIGKILL`: the host process dies of it, and
/// its channel's end closes, which tells the hub.
fn killed() -> ! {
    // SAFETY: plain system calls on this host process.
    unsafe {
        let host = crate::sud_host_syscall(libc::SYS_getpid, 0, 0, 0, 0, 0, 0);
        crate::sud_host_syscall(libc::SYS_kill, host as _, libc::SIGKILL as _, 0, 0, 0, 0);
        (crate::hostapi::get().host_immediate_exit)(128 + libc::SIGKILL)
    }
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
        let (now, view, carry) = hand_over(picked);
        // The signals sent it while it was frozen go first: it generates
        // them as it resumes.
        let raised = PENDING.lock().remove(&pid).unwrap_or_default();
        let sent = raised.iter().all(|info| {
            let bytes = info_bytes(info);
            send_bytes_once(
                channel,
                &Message::Raise {
                    len: bytes.len() as u64,
                }
                .encode(),
            ) && send_bytes_once(channel, &bytes)
        });
        if !sent || !send_bytes_once(channel, &Message::Resume { now, view, carry }.encode()) {
            // It died frozen: the machine keeps what it would have handed it.
            context(|context| {
                context.import_machine_carry(carry);
                Ok(())
            });
            host_death(pid);
            picked = thread::pick_next();
            if !is_foreign(picked) {
                return picked;
            }
            continue;
        }
        match serve(pid, channel) {
            Some(Message::Yield { now, state, carry }) => {
                collect(pid);
                take_over(now, carry, picked, state);
            }
            Some(Message::Exit { now, status, carry }) => {
                context(|context| {
                    context.advance_to(now)?;
                    context.import_machine_carry(carry);
                    Ok(())
                });
                ended(pid, status, ProcessEnd::Exit, Notify::Parent);
            }
            Some(other) => protocol_fatal("a child's yield or exit", &other),
            None => {
                // The child's host process is gone mid-quantum: the machine
                // goes on with what it handed it, at the time it reached.
                context(|context| {
                    context.import_machine_carry(carry);
                    Ok(())
                });
                host_death(pid);
            }
        }
        picked = thread::pick_next();
        if !is_foreign(picked) {
            return picked;
        }
    }
}

/// Serve child `pid` on `channel` (ids, filesystem calls) until it says
/// something only its caller acts on (ready, yield, exit), and answer that;
/// `None` when its host process is gone first.
fn serve(pid: i32, channel: c_int) -> Option<Message> {
    loop {
        match receive(channel) {
            Some(Message::AllocId) => {
                let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
                CHILD_THREADS.lock().insert(id);
                reply(channel, Message::Id(id), &[])?;
            }
            Some(Message::Fs { len }) => {
                let request = receive_payload(channel, len)?;
                let request = serde_json::from_slice(&request).unwrap_or_else(|error| {
                    protocol_fatal_text(&format!("decoding a filesystem call: {error}"))
                });
                // The root's driver stack answers; the root records nothing.
                let call = fs::Call::of(&request);
                let answer = crate::with_context_raw(|context| {
                    Ok(fs::serve(context.machine_filesystem(), request))
                })
                .unwrap_or_else(|errno| {
                    protocol_fatal_text(&format!("the root's runtime is gone ({errno})"))
                });
                call.note(&answer, HANDLES.lock().entry(pid).or_default());
                let answer = serde_json::to_vec(&answer).unwrap_or_else(|error| {
                    protocol_fatal_text(&format!("encoding a filesystem answer: {error}"))
                });
                reply(
                    channel,
                    Message::FsReply {
                        len: answer.len() as u64,
                    },
                    &answer,
                )?;
            }
            Some(Message::Signal { pid: target, len }) => {
                let info = info_words(&receive_payload(channel, len)?);
                let answer = if target > 0 {
                    signal_process(pid, target, info).unwrap_or(-i64::from(libc::ESRCH))
                } else {
                    signal_others(pid, info)
                };
                reply(channel, Message::Id(answer as i32), &[])?;
            }
            Some(Message::TraceBegin { len }) => {
                let metadata = receive_payload(channel, len)?;
                BEGUN.lock().insert(pid, metadata);
            }
            Some(Message::Facts { len }) => {
                let facts = receive_payload(channel, len)?;
                if let Ok(Some(fd)) = crate::runtime::control_facts_fd() {
                    let _ = crate::host_write_all(fd, &process_facts(pid, &facts));
                }
            }
            Some(Message::Stop { len }) => {
                let record = receive_payload(channel, len)?;
                child_stopped(pid, &record);
            }
            Some(Message::Pipe { len }) => {
                let request = receive_payload(channel, len)?;
                let answer = pipes::serve(pid, &request);
                reply(
                    channel,
                    Message::PipeReply {
                        len: answer.len() as u64,
                    },
                    &answer,
                )?;
            }
            Some(Message::Describe) => {
                // The child found the machine deadlocked: every other
                // process's blocked tasks.
                let answer = serde_json::to_vec(&describe_others(pid)).unwrap_or_default();
                reply(
                    channel,
                    Message::DescribeReply {
                        len: answer.len() as u64,
                    },
                    &answer,
                )?;
            }
            Some(Message::Plan) => {
                let plan = spawn::PLANS.lock().remove(&pid).unwrap_or_default();
                reply(
                    channel,
                    Message::PlanReply {
                        len: plan.len() as u64,
                    },
                    &plan,
                )?;
            }
            Some(message) => return Some(message),
            None => return None,
        }
    }
}

/// `tasks` (a process's parked tasks, each with why it parked) as a
/// deadlock names them: its own threads, not the foreign tasks that stand
/// for other processes.
fn blocked(tasks: &[(TaskId, String)]) -> String {
    let named: Vec<String> = tasks
        .iter()
        .filter(|(task, _)| !is_foreign(*task))
        .map(|(task, reason)| format!("{} ({reason})", task.0))
        .collect();
    format!("parked tasks: {}", named.join(", "))
}

/// The machine is deadlocked: process `asker` (a child) asks for every
/// other process's blocked tasks. The hub's own, then each live child's
/// but the asker's, in pid order; a child gone meanwhile names none.
fn describe_others(asker: i32) -> Vec<(i32, String)> {
    let tasks =
        crate::with_context_raw(|context| Ok(context.machine_parked_tasks())).unwrap_or_default();
    let mut described = vec![(crate::patina_pid(), blocked(&tasks))];
    let live: Vec<(i32, c_int)> = CHILDREN
        .lock()
        .iter()
        .filter(|(pid, child)| **pid != asker && child.status.is_none())
        .map(|(pid, child)| (*pid, child.channel))
        .collect();
    for (_, channel) in live {
        described.extend(ask_describe(channel));
    }
    described
}

/// A frozen child's blocked tasks, which it answers on `channel`; none if
/// it is gone.
fn ask_describe(channel: c_int) -> Vec<(i32, String)> {
    if !send_bytes_once(channel, &Message::Describe.encode()) {
        return Vec::new();
    }
    match receive(channel) {
        Some(Message::DescribeReply { len }) => receive_payload(channel, len)
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// This process's scheduler found every task blocked, `tasks` its parked
/// tasks (foreign ones included). When the machine holds other processes
/// the deadlock is the machine's: a foreign task is parked only when every
/// task of the processes it stands for is, with no timer due. The stop's
/// detail names each live process and its blocked tasks, in pid order,
/// with the processes it holds; `None` for a process alone.
pub(crate) fn deadlock(tasks: &[(TaskId, String)]) -> Option<(String, Vec<i32>)> {
    if !is_multiprocess() {
        return None;
    }
    let mut described = vec![(crate::patina_pid(), blocked(tasks))];
    if is_child() {
        send(channel(), &Message::Describe);
        match receive(channel()) {
            Some(Message::DescribeReply { len }) => described.extend(
                receive_payload(channel(), len)
                    .and_then(|bytes| serde_json::from_slice::<Vec<(i32, String)>>(&bytes).ok())
                    .unwrap_or_default(),
            ),
            Some(other) => protocol_fatal("the machine's blocked tasks", &other),
            None => orphaned(),
        }
    } else {
        let live: Vec<c_int> = CHILDREN
            .lock()
            .values()
            .filter(|child| child.status.is_none())
            .map(|child| child.channel)
            .collect();
        for channel in live {
            described.extend(ask_describe(channel));
        }
    }
    described.sort_by_key(|(pid, _)| *pid);
    let detail = described
        .iter()
        .map(|(pid, tasks)| format!("process {pid}: {tasks}"))
        .collect::<Vec<_>>()
        .join("; ");
    Some((detail, described.into_iter().map(|(pid, _)| pid).collect()))
}

/// Child `pid`'s facts document, marked as that process's (`"process"`), so
/// the run's reader keeps each process's own beside the root's.
fn process_facts(pid: i32, document: &[u8]) -> Vec<u8> {
    match document.strip_prefix(b"{") {
        Some(rest) => {
            let mut marked = format!("{{\"process\":{pid},").into_bytes();
            marked.extend_from_slice(rest);
            marked
        }
        None => protocol_fatal_text("a process's facts are not a JSON object"),
    }
}

/// The root's recording of child `pid`.
struct RootRecording {
    pid: i32,
    /// A decision line the root's recorder refused, if one was.
    refused: Option<patina_dst_runtime::RuntimeError>,
}

impl log::ProcessRecording for (&mut crate::Context, &mut RootRecording) {
    fn decisions(&mut self, decisions: &[u8]) {
        if let Err(error) = self.0.machine_process_decisions(self.1.pid, decisions) {
            self.1.refused.get_or_insert(error);
        }
    }
    fn overflowed(&mut self) {
        self.0.machine_process_overflowed(self.1.pid);
    }
    fn compute_stop(&mut self, stop: patina_dst_trace::ComputeStop) {
        self.0.machine_process_compute_stop(self.1.pid, stop);
    }
}

/// Read what child `pid` recorded since the hub last looked into the root's
/// recording of it. A page no child writes stops the run on the child's
/// account.
fn collect(pid: i32) {
    if let Err(violation) = try_collect(pid)
        && !STOPPING.load(Ordering::Relaxed)
    {
        page_violation(pid, violation);
    }
}

/// [`collect`], answering a page no child writes.
fn try_collect(pid: i32) -> Result<(), log::PageViolation> {
    // Out of the table while the root's runtime takes it: no table lock is
    // held under the runtime's.
    let Some(mut page) = CHILDREN
        .lock()
        .get_mut(&pid)
        .and_then(|child| child.page.take())
    else {
        return Ok(());
    };
    let mut recording = RootRecording { pid, refused: None };
    let collected =
        crate::with_context_raw(|context| Ok(page.collect(&mut (context, &mut recording))))
            .unwrap_or_else(|errno| {
                protocol_fatal_text(&format!("the root's runtime is gone ({errno})"))
            });
    if let Some(child) = CHILDREN.lock().get_mut(&pid) {
        child.page = Some(page);
    }
    if let Some(error) = recording.refused {
        protocol_fatal_text(&error.to_string());
    }
    collected
}

/// Set once the run stops on a child's account: what the children still
/// running leave as the machine ends adds nothing to the stop.
static STOPPING: AtomicBool = AtomicBool::new(false);

/// Child `pid`'s page holds what no child of this shim writes (its guest
/// code wrote over it): the run stops, naming the child.
fn page_violation(pid: i32, violation: log::PageViolation) -> ! {
    let detail = format!(
        "process {pid}'s page holds what its runtime never writes ({}); the machine \
cannot trust what it says",
        violation.0
    );
    machine_stop(
        pid,
        crate::RunStop::new(
            patina_dst_abi::RunClass::Internal,
            "process_page",
            &[detail.as_bytes()],
        ),
    )
}

/// Child `pid`'s host process is gone without telling the hub how it ended
/// (found mid-quantum, frozen, before it was ready or mid-frame): the one
/// path every such death takes.
///
/// A stop it sent that the hub had not read yet, or a stop record its
/// signal front left on its stop pipe, stops the run with it. Otherwise
/// only a death the shim leaves to the host is the guest's own: a
/// synchronous fault its code raised, which the front leaves to the
/// default action, once it was ready. The child died of that signal (the
/// machine at the time the child reached) and its parent reaps it. Any
/// other signal came from outside the run (an operator, the out-of-memory
/// killer, a resource limit) and stops it as the host's; any other end is
/// the shim's failure. Returns only after a death its parent sees.
fn host_death(pid: i32) {
    if let Some(record) = queued_stop(pid).or_else(|| front_stop(pid)) {
        child_stopped(pid, &record);
    }
    let Some(ready) = CHILDREN.lock().get(&pid).map(|child| child.ready) else {
        protocol_fatal_text(&format!("no process {pid} to end"))
    };
    match spawn::host_status(pid) {
        Some(status)
            if libc::WIFSIGNALED(status)
                && ready
                && GUEST_FAULTS.contains(&libc::WTERMSIG(status)) =>
        {
            let floor = context(|context| context.machine_now());
            let now = CHILDREN
                .lock()
                .get_mut(&pid)
                .and_then(|child| child.page.as_mut())
                .map(|page| page.now(floor));
            match now {
                Some(Ok(now)) => context(|context| context.advance_to(now)),
                Some(Err(violation)) => page_violation(pid, violation),
                None => {}
            }
            replay_whole(pid);
            ended(
                pid,
                signal_status(libc::WTERMSIG(status)),
                ProcessEnd::Exit,
                Notify::Parent,
            )
        }
        Some(status) if libc::WIFSIGNALED(status) && !ready => {
            // A death before the child ran any guest code of its own is its
            // startup's: Patina's, or the host's under it.
            let detail = format!(
                "process {pid} of the guest's machine died of signal {} while it started, \
before it was ready to run guest code",
                libc::WTERMSIG(status)
            );
            machine_stop(pid, crate::RunStop::internal(&[detail.as_bytes()]))
        }
        Some(status) if libc::WIFSIGNALED(status) => {
            let detail = format!(
                "process {pid} of the guest's machine was ended by signal {} from outside the \
run; not a guest failure",
                libc::WTERMSIG(status)
            );
            machine_stop(
                pid,
                crate::RunStop::new(
                    patina_dst_abi::RunClass::Internal,
                    "host_kill",
                    &[detail.as_bytes()],
                ),
            )
        }
        _ => died(pid),
    }
}

/// The signals a guest's own code raises synchronously (a fault), whose
/// default action the shim's signal front leaves to the host. Not `SIGSYS`:
/// under system call user dispatch the shim handles every one the guest
/// raises, so a death by it is the host's (a seccomp kill, say).
const GUEST_FAULTS: [i32; 5] = [
    libc::SIGSEGV,
    libc::SIGBUS,
    libc::SIGILL,
    libc::SIGFPE,
    libc::SIGTRAP,
];

/// A stop record child `pid` sent before it died that the hub has not read
/// yet (it died frozen); the facts it sent with it go to the run.
fn queued_stop(pid: i32) -> Option<Vec<u8>> {
    let channel = CHILDREN.lock().get(&pid).map(|child| child.channel)?;
    loop {
        match receive(channel)? {
            Message::Stop { len } => return receive_payload(channel, len),
            Message::Facts { len } => {
                let facts = receive_payload(channel, len)?;
                if let Ok(Some(fd)) = crate::runtime::control_facts_fd() {
                    let _ = crate::host_write_all(fd, &process_facts(pid, &facts));
                }
            }
            _ => {}
        }
    }
}

/// The stop record child `pid`'s signal front wrote to its stop pipe, if
/// it wrote one, its detail naming the child.
fn front_stop(pid: i32) -> Option<Vec<u8>> {
    let stops = CHILDREN.lock().get(&pid).map(|child| child.stops)?;
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    // The child is gone, and with it the pipe's only writer.
    loop {
        // SAFETY: a writable buffer of its length.
        let read = unsafe {
            crate::sud_host_syscall(
                libc::SYS_read,
                stops as _,
                buffer.as_mut_ptr() as _,
                buffer.len() as _,
                0,
                0,
                0,
            )
        };
        if read < 0 && crate::abi::host_errno() == libc::EINTR {
            continue;
        }
        if read <= 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read as usize]);
    }
    bytes
        .split(|byte| *byte == b'\n')
        .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
        .find_map(|mut record| {
            let detail = record.pointer_mut("/stop/detail")?;
            *detail = format!("process {pid}: {}", detail.as_str().unwrap_or_default()).into();
            let mut line = serde_json::to_vec(&record).ok()?;
            line.push(b'\n');
            Some(line)
        })
}

/// The wait status of a death by `sig`: a signal whose default action dumps
/// core reports it dumped (`WCOREDUMP`), as Linux does where a dump is
/// taken, whatever the host's core limit says.
pub(crate) fn signal_status(sig: i32) -> i32 {
    const CORE: [i32; 10] = [
        libc::SIGQUIT,
        libc::SIGILL,
        libc::SIGTRAP,
        libc::SIGABRT,
        libc::SIGBUS,
        libc::SIGFPE,
        libc::SIGSEGV,
        libc::SIGXCPU,
        libc::SIGXFSZ,
        libc::SIGSYS,
    ];
    if CORE.contains(&sig) { sig | 0x80 } else { sig }
}

/// How the rest of the root hears of a child's end.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Notify {
    /// While the root runs: `SIGCHLD` is queued, and every task waiting for
    /// a child looks again.
    Parent,
    /// At the root's end (teardown): no guest code runs any more, so
    /// nothing is queued and no task is woken (the waiters are forgotten).
    Nobody,
}

/// A recording child's metadata, from its start until its spawn adds it
/// to the root's recording.
pub(super) static BEGUN: SpinMutex<BTreeMap<i32, Vec<u8>>> = SpinMutex::new(BTreeMap::new());

/// Child `pid` ended with wait status `status`: its foreign task is gone
/// (recorded), the root's filesystem handles it held are closed, it is a
/// zombie until its parent reaps it, and, as `notify` says, its parent
/// hears of it (`SIGCHLD`, waiters woken).
fn ended(pid: i32, status: i32, end: ProcessEnd, notify: Notify) {
    collect(pid);
    let (channel, stops) = {
        let mut children = CHILDREN.lock();
        let Some(child) = children
            .get_mut(&pid)
            .filter(|child| child.status.is_none())
        else {
            return;
        };
        child.status = Some(status);
        // Read for the last time above: a zombie keeps no page mapped.
        child.page = None;
        (child.channel, child.stops)
    };
    // What it was sent and never took dies with it.
    PENDING.lock().remove(&pid);
    close(channel);
    close(stops);
    let handles = HANDLES.lock().remove(&pid).unwrap_or_default();
    // Also after the root's `main` returned (teardown): a recorded state
    // change, no scheduling decision.
    let _ = crate::with_context_raw(|context| {
        context.task_foreign(foreign_task(pid), ForeignState::Gone)?;
        context.machine_process_ended(pid, status, end);
        let filesystem = context.machine_filesystem();
        for handle in handles {
            let _ = filesystem.close(handle);
        }
        Ok(())
    });
    // It shares no description with the root any more.
    spawn::unshare(pid, None);
    match notify {
        Notify::Parent => {
            // What it held of the root's descriptions is released: the
            // last writer gone, a reader sees end of file.
            pipes::release_all(pid);
            thread::child_changed(pid, status);
            spawn::wake_waiters();
        }
        Notify::Nobody => spawn::forget_waiters(),
    }
}

/// What the hub answers a child's signal it does not model across
/// processes: the child stops the run by name.
const UNMODELED_SIGNAL: i64 = i32::MIN as i64;

/// The signals the hub holds for each live child until its next resume,
/// each as its sender made it.
static PENDING: SpinMutex<BTreeMap<i32, Vec<[u64; 16]>>> = SpinMutex::new(BTreeMap::new());

/// The thread ids the hub handed to children's threads.
static CHILD_THREADS: SpinMutex<BTreeSet<i32>> = SpinMutex::new(BTreeSet::new());

/// `kill(pid, sig)` (or a queued signal, `queued`) with `info`, as the
/// caller made it, where `pid` names another process of the machine, its
/// group or every process: the call's answer, or `None` when it names only
/// this process (or init, or nothing), which the caller's own model
/// answers. A signal to the machine's group goes to every other process
/// here and answers `None`: the caller's model takes its own share.
///
/// Every process of the machine shares one credential, so a signal from
/// one to another is permitted; a stop signal (job control) and `SIGSYS`
/// across processes stop the run by name.
pub(crate) fn signal_elsewhere(
    pid: i32,
    sig: i32,
    mut info: [u64; 16],
    queued: bool,
) -> Option<i64> {
    // The signal is the call's, whatever the information says
    // (`do_rt_sigqueueinfo` sets it too).
    info[0] = (info[0] & !0xffff_ffff) | u64::from(sig as u32);
    if pid > 0 {
        if pid == crate::patina_pid()
            || pid == crate::registry::INIT_PID as i32
            || crate::identity::lookup(pid).is_some()
        {
            return None;
        }
        let answer = if is_child() {
            ask_hub(pid, info)
        } else {
            signal_process(crate::patina_pid(), pid, info)?
        };
        return Some(refused(answer, sig, pid));
    }
    if queued || !others_live() || !(0..=SIGNAL_MAX).contains(&sig) {
        return None;
    }
    let every = pid == -1;
    if !every && pid != 0 && pid.checked_neg() != Some(crate::identity::pgid()) {
        // Another group: none holds a process of the machine.
        return None;
    }
    let answer = if is_child() {
        ask_hub(pid, info)
    } else {
        signal_others(crate::patina_pid(), info)
    };
    let answer = refused(answer, sig, pid);
    // Every process but the caller (and init), or the group, the caller in
    // it.
    every.then_some(answer)
}

/// A child's signal to other processes of the machine: the hub sends it
/// and answers.
fn ask_hub(pid: i32, info: [u64; 16]) -> i64 {
    let bytes = info_bytes(&info);
    send_frame(
        channel(),
        Message::Signal {
            pid,
            len: bytes.len() as u64,
        },
        &bytes,
    );
    match receive(channel()) {
        Some(Message::Id(answer)) => {
            // The hub's view of the rest of the machine changed (a process
            // the signal woke, or killed and whose parent wakes): the next
            // pick of it asks.
            context(|context| context.task_foreign(ELSEWHERE, ForeignState::Runnable));
            i64::from(answer)
        }
        Some(other) => protocol_fatal("a signal's result", &other),
        None => orphaned(),
    }
}

/// The caller's answer, unless the signal crosses processes where the
/// machine does not model it, which stops the run by name.
fn refused(answer: i64, sig: i32, pid: i32) -> i64 {
    if answer == UNMODELED_SIGNAL {
        crate::trap_unmodeled(&format!(
            "signal {sig} from process {} to {} of the guest's machine is not modeled (a stop \
signal, SIGSYS, or a thread of another process)",
            crate::patina_pid(),
            match pid {
                -1 => "every process".to_owned(),
                pid if pid <= 0 => "the process group".to_owned(),
                pid => format!("process {pid}"),
            }
        ))
    }
    answer
}

/// Whether the machine carries `sig` from one process to another: not a
/// stop signal (job control: no process of the machine stops), not
/// `SIGSYS` (reserved for containment).
fn crosses(sig: i32) -> bool {
    !matches!(sig, libc::SIGSTOP | libc::SIGSYS)
}

/// The hub sends `info` from process `from` to process `pid` (`kill`'s
/// positive pid): `None` when no process of the machine has that pid. As
/// the kernel does, the target is found first, then the signal judged
/// (`EINVAL`). The root takes it in its own model; a live child gets it
/// when it next resumes (its foreign task becomes runnable, a recorded
/// decision of the root's), but for `SIGKILL`, which kills it now; signal
/// 0 probes; a zombie takes nothing.
fn signal_process(from: i32, pid: i32, info: [u64; 16]) -> Option<i64> {
    let sig = info[0] as u32 as i32;
    let root = pid == crate::patina_pid() && from != pid;
    if !root && CHILD_THREADS.lock().contains(&pid) {
        // A thread of a child, which may have ended: the hub cannot tell.
        return Some(UNMODELED_SIGNAL);
    }
    let live = root
        || CHILDREN
            .lock()
            .get(&pid)
            .map(|child| child.status.is_none())?;
    if !(0..=SIGNAL_MAX).contains(&sig) {
        return Some(-i64::from(libc::EINVAL));
    }
    if sig != 0 && !crosses(sig) {
        return Some(UNMODELED_SIGNAL);
    }
    match sig {
        0 => {}
        _ if !live => {}
        _ if root => thread::machine_signal(info),
        libc::SIGKILL => kill(pid, Notify::Parent),
        _ => queue(pid, info),
    }
    Some(0)
}

/// The highest signal number.
const SIGNAL_MAX: i32 = 64;

/// The hub sends `info` from process `from` to every other process of the
/// machine (its one group, or every process: the same set), in pid order:
/// the root first, then each live child.
fn signal_others(from: i32, info: [u64; 16]) -> i64 {
    let sig = info[0] as u32 as i32;
    if sig != 0 && !crosses(sig) {
        return UNMODELED_SIGNAL;
    }
    if sig == 0 {
        return 0;
    }
    let root = crate::patina_pid();
    if from != root {
        thread::machine_signal(info);
    }
    let live: Vec<i32> = CHILDREN
        .lock()
        .iter()
        .filter(|(pid, child)| **pid != from && child.status.is_none())
        .map(|(pid, _)| *pid)
        .collect();
    for pid in live {
        if sig == libc::SIGKILL {
            kill(pid, Notify::Parent);
        } else {
            queue(pid, info);
        }
    }
    0
}

/// Hold `info` for live child `pid` until it next resumes, and make its
/// foreign task runnable: the signal may wake it.
fn queue(pid: i32, info: [u64; 16]) {
    PENDING.lock().entry(pid).or_default().push(info);
    crate::with_context_raw(|context| {
        context.task_foreign(foreign_task(pid), ForeignState::Runnable)
    })
    .unwrap_or_else(|errno| protocol_fatal_text(&format!("the root's runtime is gone ({errno})")));
}

/// A signal's information as it travels on the channel.
fn info_bytes(info: &[u64; 16]) -> [u8; 128] {
    let mut bytes = [0u8; 128];
    for (chunk, word) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(info) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

/// A signal's information from the channel.
fn info_words(bytes: &[u8]) -> [u64; 16] {
    if bytes.len() != 128 {
        protocol_fatal_text("a signal's information is not 128 bytes");
    }
    let mut info = [0u64; 16];
    for (word, chunk) in info.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*chunk);
    }
    info
}

/// Kill live child `pid`, frozen on its channel: it dies of `SIGKILL`, and
/// its end of the channel closes once the host process is gone. The wait
/// for that is the host's, so no guest code of this process runs meanwhile
/// (the compute observer has no candidate).
fn kill(pid: i32, notify: Notify) {
    let Some(channel) = CHILDREN
        .lock()
        .get(&pid)
        .filter(|child| child.status.is_none())
        .map(|child| child.channel)
    else {
        return;
    };
    let sent = send_bytes_once(channel, &Message::Kill.encode());
    // What it sent before it took the kill, a stop included, is read; a
    // stop it sent ends the run with it (while the root runs).
    let stop = off_guest(|| {
        let mut stop = None;
        while let Some(message) = receive(channel) {
            if let Message::Stop { len } = message {
                stop = receive_payload(channel, len);
            }
        }
        stop
    });
    if notify == Notify::Parent {
        if let Some(record) = stop {
            child_stopped(pid, &record);
        }
        if !sent {
            // It was gone before the kill reached it.
            host_death(pid);
            return;
        }
    }
    replay_whole(pid);
    let end = match notify {
        Notify::Parent => ProcessEnd::Killed,
        Notify::Nobody => ProcessEnd::Teardown,
    };
    ended(pid, KILLED, end, notify);
}

/// A replayed child `pid` that ends where it cannot check its own replay
/// (killed, torn down, dead of a fault) must have consumed its whole
/// recorded timeline: one with decisions left over has diverged, as a
/// child that exits finds for itself.
fn replay_whole(pid: i32) {
    let consumed = CHILDREN
        .lock()
        .get(&pid)
        .and_then(|child| child.page.as_ref())
        .map(log::HubPage::consumed);
    let recorded = crate::with_context_raw(|context| Ok(context.machine_process_recorded(pid)))
        .ok()
        .flatten();
    if let (Some(consumed), Some(recorded)) = (consumed, recorded)
        && consumed != recorded
        && !STOPPING.load(Ordering::Relaxed)
    {
        let detail = format!(
            "process {pid} ended having replayed {consumed} of its {recorded} recorded \
decisions"
        );
        let _ = crate::with_context_raw(|context| {
            context.machine_note_replay_divergence();
            Ok(())
        });
        machine_stop(
            pid,
            crate::RunStop::new(
                patina_dst_abi::RunClass::Nondeterministic,
                "replay_divergence",
                &[detail.as_bytes()],
            ),
        )
    }
}

/// Run `wait`, a host wait on another process, as if another process held
/// the baton: no guest code of this process runs meanwhile, so the compute
/// observer has no candidate here.
pub(crate) fn off_guest<T>(wait: impl FnOnce() -> T) -> T {
    let before = ELSEWHERE_RUNS.swap(true, Ordering::Relaxed);
    let answer = wait();
    ELSEWHERE_RUNS.store(before, Ordering::Relaxed);
    answer
}

/// The root's end: every child still running is killed (its foreign task's
/// end recorded), so no process of the machine outlives it.
pub(crate) fn teardown() {
    if is_child() {
        return;
    }
    let live: Vec<i32> = CHILDREN
        .lock()
        .iter()
        .filter(|(_, child)| child.status.is_none())
        .map(|(pid, _)| *pid)
        .collect();
    for pid in live {
        kill(pid, Notify::Nobody);
    }
}

/// Child `pid` stopped the run with stop record `record` (its class, its
/// reason, its detail naming it): every other child is killed, and the root
/// ends the run with that record as its own, as a stop in the root would.
///
/// The root's own evidence goes with it, as a stop the runtime takes leaves
/// it: its facts, written after every child's, and its recording so far.
fn child_stopped(pid: i32, record: &[u8]) -> ! {
    let record = located(pid, record);
    end_machine(pid);
    crate::process::host_abort_with_record(&record)
}

/// Child `pid`'s stop record, saying which admitted artifact the child runs
/// when it is not the guest's own executable and the record holds a sampled
/// PC (`yield_point_delta`): the supervisor names the site from that
/// program, not the root's.
fn located(pid: i32, record: &[u8]) -> Vec<u8> {
    let artifact = CHILDREN.lock().get(&pid).map_or(0, |child| child.artifact);
    let annotated = (artifact != 0)
        .then(|| serde_json::from_slice::<serde_json::Value>(record.trim_ascii_end()).ok())
        .flatten()
        .and_then(|mut parsed| {
            let stop = parsed.get_mut("stop")?.as_object_mut()?;
            if !stop.contains_key("yield_point_delta") {
                return None;
            }
            stop.insert("artifact".into(), artifact.into());
            let mut line = serde_json::to_vec(&parsed).ok()?;
            line.push(b'\n');
            Some(line)
        });
    annotated.unwrap_or_else(|| record.to_vec())
}

/// The run stops on what became of child `pid`, as `stop` says, with the
/// root's evidence (see [`child_stopped`]).
fn machine_stop(pid: i32, stop: crate::RunStop<'_>) -> ! {
    end_machine(pid);
    crate::host_abort(stop.with_processes(&[pid]))
}

/// What every stop on a child's account does before the root ends the run:
/// the child's last decisions are read and it is done, every other child is
/// killed, and the root's facts and recording so far go out.
fn end_machine(pid: i32) {
    STOPPING.store(true, Ordering::Relaxed);
    let _ = try_collect(pid);
    if let Some(child) = CHILDREN.lock().get_mut(&pid)
        && child.status.is_none()
    {
        child.status = Some(KILLED);
        close(child.channel);
        close(child.stops);
    }
    teardown();
    let _ = crate::with_context_raw(|context| {
        context.machine_stopped();
        Ok(())
    });
    crate::patina_flush_captured_stdio();
}

/// A child whose host process is gone without telling the hub how it ended,
/// and with no signal to say: the shim's failure.
fn died(pid: i32) -> ! {
    let detail = format!("process {pid} ended without reporting its exit to the machine");
    machine_stop(pid, crate::RunStop::internal(&[detail.as_bytes()]))
}

/// A child's side of a switch: hand the baton to the hub with this
/// process's time and state, wait to be resumed, then pick a local task
/// first (the hub chose this process to run).
fn yield_to_hub(mut picked: TaskId) -> TaskId {
    loop {
        debug_assert_eq!(picked, ELSEWHERE);
        let (now, state, carry) = hand_over(ELSEWHERE);
        send(channel(), &Message::Yield { now, state, carry });
        let (now, view, carry) = await_resume();
        context(|context| {
            context.advance_to(now)?;
            context.import_machine_carry(carry);
            Ok(())
        });
        // A signal sent it wakes the task it interrupts before the remote
        // waiters look again, so the wait ends as the signal says.
        raise_pending();
        // Whatever the rest of the machine did meanwhile, each task parked
        // on a pipe the root holds looks again.
        thread::wake_remote_waiters();
        let local = context(|context| {
            // Whether a task of this process is runnable: no timer counts.
            let local = context.process_view(Some(ELSEWHERE), None) == ForeignState::Runnable;
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

/// Set once a child told the hub it ended: what it does after is its host
/// process's end, which the hub no longer hears.
static EXITED: AtomicBool = AtomicBool::new(false);

/// The signal whose default action ends this child, if one does.
static DYING_OF: AtomicI32 = AtomicI32::new(0);

/// A child about to end by `sig`'s default action: its parent sees a death
/// by that signal, not an exit.
pub(crate) fn note_signal_death(sig: u8) {
    DYING_OF.store(i32::from(sig), Ordering::Relaxed);
}

/// The wait status a child's end reports: its exit `code`, or the signal
/// it dies of.
pub(crate) fn exit_status(code: i32) -> i32 {
    match DYING_OF.load(Ordering::Relaxed) {
        0 => (code & 0xff) << 8,
        sig => signal_status(sig),
    }
}

/// A child ships `bytes` to the hub as a `header` frame, where a stop may be
/// (no allocation): `false` when it cannot, because it reported its end
/// already, or this thread was stopped mid-send and holds the channel
/// itself. Another thread's frame is waited out: it is mid-send, and the
/// hub reads while the child holds the baton.
fn ship(header: Message, bytes: &[u8]) -> bool {
    if !is_child() || EXITED.load(Ordering::Relaxed) {
        return false;
    }
    let Some(_sending) = Sending::unless_mine() else {
        return false;
    };
    let _ = send_raw(channel(), &header.encode());
    for chunk in bytes.chunks(wire::CHUNK_BYTES) {
        let _ = send_raw(channel(), chunk);
    }
    true
}

/// A child's stop record goes to the hub, which ends the run with it; when
/// the channel is not this thread's to send on, to its stop pipe, which
/// the hub reads once the child is gone.
pub(crate) fn ship_stop(record: &[u8]) {
    let shipped = ship(
        Message::Stop {
            len: record.len() as u64,
        },
        record,
    );
    if !shipped
        && !EXITED.load(Ordering::Relaxed)
        && let Some(fd) = crate::process::stop_record_fd()
    {
        let _ = crate::host_write_all(fd, record);
    }
}

/// A child's channel is one thread's to send a frame on at a time: a
/// frame's packets never interleave with another's (a guest thread's
/// request, the observer's stop). Holds the host thread handle of the
/// thread sending, or 0.
static SENDING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// The right to send one frame on this child's channel.
struct Sending;

impl Sending {
    /// Wait for the channel (a guest thread's request).
    fn take() -> Self {
        Self::unless_mine()
            .unwrap_or_else(|| protocol_fatal_text("a thread sends a frame inside its own frame"))
    }

    /// Wait for the channel, unless the thread holding it never finishes
    /// its frame: this thread (a stop that interrupted it mid-send), or the
    /// thread the compute observer froze to sample it. Whether it can is
    /// decided by which thread holds it, never by how long it is held.
    fn unless_mine() -> Option<Self> {
        let me = crate::watchdog::host_thread_self();
        loop {
            match SENDING.compare_exchange(0, me, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => return Some(Sending),
                Err(holder) if holder == me || crate::watchdog::sampled(holder) => return None,
                Err(_) => std::hint::spin_loop(),
            }
        }
    }
}

impl Drop for Sending {
    fn drop(&mut self) {
        SENDING.store(0, Ordering::Release);
    }
}

/// A child's facts document goes to the hub, which writes it for the run.
pub(crate) struct ChannelFactsSink;

impl patina_dst_runtime::FactsSink for ChannelFactsSink {
    fn write_facts(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        // Facts a stop cannot ship (it interrupted this thread mid-send)
        // are lost: the stop itself is not.
        let _ = ship(
            Message::Facts {
                len: bytes.len() as u64,
            },
            bytes,
        );
        Ok(())
    }
}

/// A child's exit: the hub learns its status and its time, and the host
/// process ends without writing anything of its own (the root writes the
/// run's facts and trace).
pub(crate) fn child_exit(status: i32) {
    // After `main` returned: a read of the clock, no scheduling operation.
    let (now, carry) = crate::with_context_raw(|context| {
        Ok((context.machine_now()?, context.export_machine_carry()?))
    })
    .unwrap_or_else(|errno| {
        let detail = format!("a child process's end could not read its time ({errno})");
        crate::host_abort(crate::RunStop::internal(&[detail.as_bytes()]))
    });
    send(channel(), &Message::Exit { now, status, carry });
    EXITED.store(true, Ordering::Relaxed);
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
    let _sending = is_child().then(Sending::take);
    send_bytes(fd, &message.encode());
}

/// Send `header`, then `payload` in packets of at most
/// [`wire::CHUNK_BYTES`].
fn send_frame(fd: c_int, header: Message, payload: &[u8]) {
    let _sending = is_child().then(Sending::take);
    send_bytes(fd, &header.encode());
    for chunk in payload.chunks(wire::CHUNK_BYTES) {
        send_bytes(fd, chunk);
    }
}

/// One packet: `Err(errno)` when it is not sent whole.
fn send_raw(fd: c_int, bytes: &[u8]) -> Result<(), c_int> {
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
        if sent < 0 {
            match crate::abi::host_errno() {
                libc::EINTR => continue,
                errno => return Err(errno),
            }
        }
        return if sent == bytes.len() as i64 {
            Ok(())
        } else {
            Err(libc::EMSGSIZE)
        };
    }
}

/// One packet: `false` if the peer is gone (its end closed); any other
/// failure is the shim's own, and fatal.
fn send_bytes_once(fd: c_int, bytes: &[u8]) -> bool {
    match send_raw(fd, bytes) {
        Ok(()) => true,
        Err(libc::EPIPE | libc::ECONNRESET) => false,
        Err(errno) => protocol_fatal_text(&format!("sending on channel {fd} failed ({errno})")),
    }
}

/// One packet.
fn send_bytes(fd: c_int, bytes: &[u8]) {
    if send_bytes_once(fd, bytes) {
        return;
    }
    if is_child() {
        orphaned();
    }
    protocol_fatal_text(&format!("sending on channel {fd} failed"));
}

/// The hub's answer to child `pid`'s request: `None` when the child is gone
/// first (killed from outside while it waited), whose death the caller
/// takes on the one path.
fn reply(channel: c_int, header: Message, payload: &[u8]) -> Option<()> {
    if !send_bytes_once(channel, &header.encode()) {
        return None;
    }
    for chunk in payload.chunks(wire::CHUNK_BYTES) {
        if !send_bytes_once(channel, chunk) {
            return None;
        }
    }
    Some(())
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

/// Close a descriptor the control plane handed this process that it does
/// not keep.
pub(crate) fn close_fd(fd: c_int) {
    close(fd);
}

fn close(fd: c_int) {
    // SAFETY: closes a descriptor the machine owns.
    unsafe { crate::sud_host_syscall(libc::SYS_close, fd as _, 0, 0, 0, 0, 0) };
}
