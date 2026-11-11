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
pub(crate) mod spawn;
mod wire;

pub(crate) use log::DecisionLog;

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
    /// A recording child's decision log.
    log: Option<log::HubLog>,
    status: Option<i32>,
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
    is_child() || CHILDREN.lock().values().any(|child| child.status.is_none())
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
        let mut used = SHARED_USED.lock();
        if used.is_none() {
            *used = Some(what);
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

/// What per-process state of the machine's this process made while alone,
/// if any: a spawn now would leave a child outside it.
pub(crate) fn shared_state_used() -> Option<&'static str> {
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
fn await_resume() -> (u64, ForeignState, MachineCarry) {
    match receive(channel()) {
        Some(Message::Resume { now, view, carry }) => (now, view, carry),
        Some(Message::Kill) => killed(),
        Some(other) => protocol_fatal("a resume", &other),
        None => orphaned(),
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
        send(channel, &Message::Resume { now, view, carry });
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
                // goes on from where it resumed the child, with what it
                // handed it.
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
                send_frame(
                    channel,
                    Message::FsReply {
                        len: answer.len() as u64,
                    },
                    &answer,
                );
            }
            Some(Message::Signal { pid: target, sig }) => {
                let answer = if target == pid || target == crate::patina_pid() {
                    // Itself, which it signals on its own, or the root.
                    UNMODELED_SIGNAL
                } else {
                    signal_child(target, sig).unwrap_or(-i64::from(libc::ESRCH))
                };
                send(channel, &Message::Id(answer as i32));
            }
            Some(Message::TraceBegin { len }) => {
                let metadata = receive_payload(channel, len).unwrap_or_else(|| died(pid));
                BEGUN.lock().insert(pid, metadata);
            }
            Some(Message::Facts { len }) => {
                let facts = receive_payload(channel, len).unwrap_or_else(|| died(pid));
                if let Ok(Some(fd)) = crate::runtime::control_facts_fd() {
                    let _ = crate::host_write_all(fd, &process_facts(pid, &facts));
                }
            }
            Some(Message::Stop { len }) => {
                let record = receive_payload(channel, len).unwrap_or_else(|| died(pid));
                child_stopped(pid, &record);
            }
            Some(message) => return Some(message),
            None => return None,
        }
    }
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

/// Read what child `pid` recorded since the hub last looked into the root's
/// recording of it.
fn collect(pid: i32) {
    let Some(decisions) = CHILDREN
        .lock()
        .get_mut(&pid)
        .and_then(|child| child.log.as_mut())
        .map(log::HubLog::take)
    else {
        return;
    };
    if decisions.is_empty() {
        return;
    }
    crate::with_context_raw(|context| Ok(context.machine_process_decisions(pid, &decisions)))
        .unwrap_or_else(|errno| {
            protocol_fatal_text(&format!("the root's runtime is gone ({errno})"))
        })
        .unwrap_or_else(|error| protocol_fatal_text(&error.to_string()));
}

/// Child `pid`'s host process is gone without telling the hub how it ended.
/// A stop record its signal front left stops the run with it; a death by a
/// signal with no record is the guest's own (the shim cannot stop without
/// leaving one), and the child died of that signal; anything else is the
/// shim's failure.
fn host_death(pid: i32) {
    if let Some(record) = front_stop(pid) {
        child_stopped(pid, &record);
    }
    match spawn::host_status(pid) {
        Some(status) if libc::WIFSIGNALED(status) => ended(
            pid,
            signal_status(libc::WTERMSIG(status)),
            ProcessEnd::Exit,
            Notify::Parent,
        ),
        _ => died(pid),
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
    let (channel, stops, log) = {
        let mut children = CHILDREN.lock();
        let Some(child) = children
            .get_mut(&pid)
            .filter(|child| child.status.is_none())
        else {
            return;
        };
        child.status = Some(status);
        (child.channel, child.stops, child.log.take())
    };
    drop(log);
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
    match notify {
        Notify::Parent => {
            thread::child_changed(pid, status);
            spawn::wake_waiters();
        }
        Notify::Nobody => spawn::forget_waiters(),
    }
}

/// What the hub answers a child's signal to a process it does not model
/// signals to: the child stops the run by name.
pub(crate) const UNMODELED_SIGNAL: i64 = i32::MIN as i64;

/// `kill(pid, sig)` of child `pid` from the process holding the baton:
/// `None` when no child has that pid. Signal 0 probes it; `SIGKILL` kills a
/// live one (a zombie is already dead); another signal stops the run by
/// name.
pub(crate) fn signal_child(pid: i32, sig: i32) -> Option<i64> {
    let live = CHILDREN
        .lock()
        .get(&pid)
        .map(|child| child.status.is_none())?;
    match sig {
        0 => {}
        libc::SIGKILL if live => kill(pid, Notify::Parent),
        libc::SIGKILL => {}
        _ => return Some(UNMODELED_SIGNAL),
    }
    Some(0)
}

/// `kill(pid, sig)` of another process of the machine from a child: the
/// hub answers. A signal it does not model stops the run by name.
pub(crate) fn signal_from_child(pid: i32, sig: i32) -> i64 {
    match exchange(&Message::Signal { pid, sig }) {
        Message::Id(answer) if i64::from(answer) == UNMODELED_SIGNAL => {
            crate::trap_unmodeled(&format!(
                "signal {sig} from process {} to process {pid} of the guest's machine is not \
modeled (only SIGKILL and the probe, signal 0, cross processes)",
                crate::patina_pid()
            ))
        }
        Message::Id(answer) => {
            // The hub's view of the rest of the machine changed (a killed
            // process's waiting parent wakes): the next pick of it asks.
            context(|context| context.task_foreign(ELSEWHERE, ForeignState::Runnable));
            i64::from(answer)
        }
        other => protocol_fatal("a signal's result", &other),
    }
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
    send(channel, &Message::Kill);
    off_guest(|| while receive(channel).is_some() {});
    let end = match notify {
        Notify::Parent => ProcessEnd::Killed,
        Notify::Nobody => ProcessEnd::Teardown,
    };
    ended(pid, KILLED, end, notify);
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
    collect(pid);
    if let Some(child) = CHILDREN.lock().get_mut(&pid) {
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
    crate::process::host_abort_with_record(record)
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
        let (now, state, carry) = hand_over(ELSEWHERE);
        send(channel(), &Message::Yield { now, state, carry });
        let (now, view, carry) = await_resume();
        let local = context(|context| {
            context.advance_to(now)?;
            context.import_machine_carry(carry);
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
/// (no allocation, no lock); a no-op once it reported its end, or in the
/// root.
fn ship(header: Message, bytes: &[u8]) {
    if !is_child() || EXITED.load(Ordering::Relaxed) {
        return;
    }
    let _ = send_bytes_once(channel(), &header.encode());
    for chunk in bytes.chunks(wire::CHUNK_BYTES) {
        let _ = send_bytes_once(channel(), chunk);
    }
}

/// A child's stop record goes to the hub, which ends the run with it.
pub(crate) fn ship_stop(record: &[u8]) {
    ship(
        Message::Stop {
            len: record.len() as u64,
        },
        record,
    );
}

/// A child's facts document goes to the hub, which writes it for the run.
pub(crate) struct ChannelFactsSink;

impl patina_dst_runtime::FactsSink for ChannelFactsSink {
    fn write_facts(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        ship(
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
    .unwrap_or_default();
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

/// One packet, or `false` if the peer is gone.
fn send_bytes_once(fd: c_int, bytes: &[u8]) -> bool {
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
        if sent < 0 && crate::abi::host_errno() == libc::EINTR {
            continue;
        }
        return sent == bytes.len() as i64;
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
