//! `posix_spawn` of an admitted program, and `wait4`/`waitid` over the
//! hub's process table.
//!
//! A spawn makes the child a process of the machine: the hub numbers it
//! from the machine's one id namespace, asks the supervisor to start the
//! admitted artifact with the child's end of a fresh channel and this
//! process's host stdio, waits for the child to report ready, and adds it
//! to the table and to its scheduler as a runnable foreign task. The child
//! runs when the scheduler picks it.
//!
//! The child's descriptors are the caller's that stay open across exec,
//! after the spawn's file actions (`dup2`, `close`, `closefrom`, `chdir`,
//! `fchdir`), each as the same description: the run's standard streams and
//! the memory devices are the child's own, a file is the root's open file
//! (a duplicate of the root's handle, its offset shared), and a pipe end is
//! the root's description, which the child reaches through the hub
//! ([`super::pipes`]). The child asks for them before it is ready
//! ([`install_plan`]).
//!
//! A recording root keeps each child's recording (the child appends each
//! decision to a log the hub maps, [`super::log`]); a replaying one hands
//! each child its recorded timeline as a trace of its own, in a memory file.
//!
//! What this slice does not model stops the run by name (`unsupported`,
//! `not_modeled`): a spawn from a child, a file action that opens a file or
//! one glibc's own code added, a descriptor of another kind (a socket, a
//! FIFO, a directory, an epoll instance, ...) open across exec, spawn
//! attributes other than the signal mask and default dispositions a fresh
//! process has anyway, a signal mask that is not empty, a run the
//! supervisor gave no launch channel (crash-restart and the
//! scheduling-policy knobs), arguments or environment that are not UTF-8,
//! and a launch request (the arguments and environment, encoded) over
//! [`LAUNCH_LIMIT`].

use super::*;
use crate::fdtable::{DescId, FdKind};
use core::ffi::{CStr, c_char};
use patina_dst_runtime::{ENV_LAUNCH_FD, ExecutionMode};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::sync::atomic::AtomicU64;

/// `WNOHANG`, `WNOWAIT` and `WEXITED`.
const WNOHANG: u32 = 0x0000_0001;
const WEXITED: u32 = 0x0000_0004;
const WNOWAIT: u32 = 0x0100_0000;

/// `POSIX_SPAWN_SETSIGDEF`, `POSIX_SPAWN_SETSIGMASK` and
/// `POSIX_SPAWN_USEVFORK`: a fresh process has default dispositions and an
/// empty mask, and how glibc makes it does not show.
const SPAWN_MODELED_FLAGS: i16 = 0x04 | 0x08 | 0x40;
/// `POSIX_SPAWN_SETSIGMASK`.
const SPAWN_SETSIGMASK: i16 = 0x08;

/// The largest launch request a spawn sends: the supervisor reads it as one
/// packet, and the child's environment travels in one exec string, which
/// Linux caps at 128 KiB (`MAX_ARG_STRLEN`).
const LAUNCH_LIMIT: usize = 120 << 10;

/// Tasks of this process parked in a wait for a child.
static WAITERS: SpinMutex<Vec<TaskId>> = SpinMutex::new(Vec::new());

/// Each new child's descriptor plan, until it asks for it.
pub(super) static PLANS: SpinMutex<BTreeMap<i32, Vec<u8>>> = SpinMutex::new(BTreeMap::new());

/// What a spawn entry was handed, as the caller handed it.
pub(crate) struct Spawn {
    pub(crate) symbol: &'static CStr,
    pub(crate) pid: *mut libc::pid_t,
    pub(crate) path: *const c_char,
    pub(crate) file_actions: *const libc::posix_spawn_file_actions_t,
    pub(crate) attr: *const libc::posix_spawnattr_t,
    pub(crate) argv: *const *mut c_char,
    pub(crate) envp: *const *mut c_char,
}

/// One file action a spawn carries out in its child, as the caller added
/// it.
#[derive(Clone, Debug)]
pub(crate) enum Action {
    Dup2 { fd: c_int, to: c_int },
    Close(c_int),
    Open,
    Chdir(CString),
    Fchdir(c_int),
    Closefrom(c_int),
}

/// The actions of each live actions object, by the id its `init` wrote
/// into it ([`ACTIONS_ID`]): glibc's own action array stays empty.
static ACTIONS: SpinMutex<BTreeMap<u64, Vec<Action>>> = SpinMutex::new(BTreeMap::new());
static NEXT_ACTIONS: AtomicU64 = AtomicU64::new(1);
/// Where in glibc's actions object (its `__pad`, which glibc never reads)
/// the shim keeps the object's id.
const ACTIONS_ID: usize = 16;

/// `posix_spawn_file_actions_init` on a zeroed object: it gets an id and an
/// empty action list.
///
/// # Safety
/// `acts` is null or a writable actions object.
pub(crate) unsafe fn actions_init(acts: *mut libc::posix_spawn_file_actions_t) {
    if acts.is_null() {
        return;
    }
    let id = NEXT_ACTIONS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: inside the object (glibc's is 80 bytes; the id fills 8 of its
    // 64 padding bytes).
    unsafe {
        acts.cast::<u8>()
            .add(ACTIONS_ID)
            .cast::<u64>()
            .write_unaligned(id)
    };
    ACTIONS.lock().insert(id, Vec::new());
}

/// The id `init` wrote into `acts`, 0 for none.
///
/// # Safety
/// `acts` is a live actions object.
unsafe fn actions_id(acts: *const libc::posix_spawn_file_actions_t) -> u64 {
    // SAFETY: inside the object, per the contract.
    unsafe {
        acts.cast::<u8>()
            .add(ACTIONS_ID)
            .cast::<u64>()
            .read_unaligned()
    }
}

/// Add `action` to `acts`: 0, or `EINVAL` for an object no `init` of the
/// shim's made.
///
/// # Safety
/// `acts` is null or a live actions object.
pub(crate) unsafe fn actions_add(
    acts: *mut libc::posix_spawn_file_actions_t,
    action: Action,
) -> c_int {
    if acts.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: per the contract.
    let id = unsafe { actions_id(acts) };
    match ACTIONS.lock().get_mut(&id) {
        Some(actions) => actions.push(action),
        None => return libc::EINVAL,
    }
    0
}

/// `posix_spawn_file_actions_destroy`: the object's actions are gone.
///
/// # Safety
/// `acts` is null or a live actions object.
pub(crate) unsafe fn actions_destroy(acts: *mut libc::posix_spawn_file_actions_t) {
    if !acts.is_null() {
        // SAFETY: per the contract.
        let id = unsafe { actions_id(acts) };
        ACTIONS.lock().remove(&id);
    }
}

/// The program `posix_spawnp` runs for `file`: `file` itself when it names
/// a path (holds a `/`), else the first admitted program among the
/// caller's `PATH` directories (glibc's default, `/bin:/usr/bin`, when it
/// has none). `None` when no candidate is admitted, and the caller refuses
/// `file` by name: the search never looks at the host.
#[cfg(patina_posix_exports)]
pub(crate) fn search(file: &CStr) -> Option<CString> {
    use crate::admission::{Admission, admitted_program};
    let bytes = file.to_bytes();
    if bytes.is_empty() || bytes.contains(&b'/') {
        return None;
    }
    // SAFETY: a static name; the read follows getenv's contract.
    let path = unsafe { crate::posix_env::env_lookup(c"PATH".as_ptr()) };
    let path = if path.is_null() {
        b"/bin:/usr/bin".to_vec()
    } else {
        // SAFETY: the environment's value, a C string.
        unsafe { CStr::from_ptr(path) }.to_bytes().to_vec()
    };
    path.split(|byte| *byte == b':').find_map(|directory| {
        let mut candidate = directory.to_vec();
        if !candidate.is_empty() && !candidate.ends_with(b"/") {
            candidate.push(b'/');
        }
        candidate.extend_from_slice(bytes);
        let candidate = CString::new(candidate).ok()?;
        (!matches!(admitted_program(&candidate), Admission::Unadmitted)).then_some(candidate)
    })
}

/// `posix_spawn`/`posix_spawnp` of `spawn.path`: `None` when the program is
/// not admitted (the caller refuses it as it refuses every spawn), else the
/// entry's answer.
///
/// # Safety
/// Every pointer follows libc's `posix_spawn` argument contract.
pub(crate) unsafe fn spawn(spawn: &Spawn) -> Option<c_int> {
    use crate::admission::{Admission, admitted_program};
    if spawn.path.is_null() {
        return None;
    }
    // SAFETY: a NUL-terminated string, per the entry's contract.
    let path = unsafe { CStr::from_ptr(spawn.path) };
    let Admission::Admitted(artifact) = admitted_program(path) else {
        return None;
    };
    if is_child() {
        refuse(spawn, "from a child process (nested spawn)");
    }
    let Ok(Some(launcher)) = crate::parse_control_u64(ENV_LAUNCH_FD) else {
        refuse(spawn, "in a run the supervisor gives no launch channel");
    };
    // SAFETY: the caller's actions object, per the entry's contract.
    let actions = unsafe { file_actions(spawn) };
    if thread::children_reap_themselves() {
        refuse(spawn, "while SIGCHLD is ignored or carries SA_NOCLDWAIT");
    }
    if let Some(what) = shared_state_used() {
        refuse(
            spawn,
            &format!("after the guest used {what}, which a child would not share"),
        );
    }
    if !spawn.attr.is_null() {
        // SAFETY: the caller's attributes object, per the entry's contract.
        let (flags, mask_empty) = unsafe { attributes(spawn.attr) };
        if flags & !SPAWN_MODELED_FLAGS != 0 {
            refuse(spawn, "with spawn attributes");
        }
        if flags & SPAWN_SETSIGMASK != 0 && !mask_empty {
            refuse(spawn, "with a signal mask");
        }
    }
    // SAFETY: NULL-terminated arrays of strings, per the entry's contract.
    let argv = unsafe { strings(spawn.argv) }
        .unwrap_or_else(|| refuse(spawn, "with arguments that are not UTF-8"));
    // SAFETY: as above.
    let entries = unsafe { strings(spawn.envp) }
        .unwrap_or_else(|| refuse(spawn, "with an environment that is not UTF-8"));
    let mut env = BTreeMap::new();
    for entry in entries {
        if let Some((name, value)) = entry.split_once('=') {
            env.entry(name.to_owned())
                .or_insert_with(|| value.to_owned());
        }
    }
    if let Err(message) = thread::activate() {
        protocol_fatal_text(&message);
    }
    // The child starts in the caller's working directory, as its actions
    // leave it, with the caller's descriptors as its actions leave them.
    let cwd = crate::paths::cwd_path().unwrap_or_else(|errno| {
        protocol_fatal_text(&format!("the working directory is unreadable ({errno})"))
    });
    let (cwd, table) = match arrange(spawn, &actions, cwd) {
        Ok(arranged) => arranged,
        // The child would fail before it ran anything: the spawn's answer.
        Err(errno) => return Some(errno),
    };
    // A file the child holds is the root's open file: a handle of its own
    // on it, which the hub closes when the child ends if the child did not.
    let mut files = BTreeMap::new();
    for shared in table.values() {
        if let Shared::File { handle, .. } = *shared
            && !files.contains_key(&handle)
        {
            match crate::with_context(|context| context.fs_dup(Fd(handle))) {
                Ok(duplicate) => {
                    files.insert(handle, duplicate);
                }
                Err(errno) => {
                    for duplicate in files.into_values() {
                        let _ = crate::with_context(|context| context.fs_close(duplicate));
                    }
                    return Some(errno);
                }
            }
        }
    }
    let pid = allocate_id();
    let (pgid, sid) = crate::identity::add_child(pid);
    let parent = crate::patina_pid();
    let seed = context(|context| Ok(child_seed(context.root_seed(), pid)));
    let plan = plan(pid, &table, &files);
    if !files.is_empty() {
        HANDLES
            .lock()
            .entry(pid)
            .or_default()
            .extend(files.values());
    }
    PLANS.lock().insert(pid, plan);
    let [hub, child] = socketpair();
    // The launch request: the admitted artifact by its index in the
    // supervisor's list, and the child's arguments, environment, place in
    // the process tree, seed and working directory. Its descriptors are the child's channel
    // end, then stdin, stdout and stderr.
    let request = serde_json::json!({"launch": {
        "artifact": artifact,
        "argv": argv,
        "env": env,
        "pid": pid,
        "parent": parent,
        "pgid": pgid,
        "sid": sid,
        "seed": seed,
        "cwd": cwd,
    }});
    let payload = serde_json::to_vec(&request)
        .unwrap_or_else(|error| protocol_fatal_text(&format!("encoding a launch: {error}")));
    if payload.len() > LAUNCH_LIMIT {
        refuse(
            spawn,
            &format!(
                "with arguments and environment over {} KiB",
                LAUNCH_LIMIT >> 10
            ),
        );
    }
    // A replayed child replays its own recorded timeline, handed to it as a
    // trace of its own; a replay that spawns a child its recording lacks
    // has diverged.
    let trace =
        (context(|context| Ok(context.execution_mode())) == ExecutionMode::Replay).then(|| {
            match context(|context| Ok(context.machine_process_trace(pid))) {
                Some(Ok(bytes)) => memfd_with(&bytes),
                Some(Err(error)) => protocol_fatal_text(&error.to_string()),
                None => {
                    let detail = format!(
                        "the replay spawned process {pid}, which the recording does not hold"
                    );
                    crate::host_abort(crate::RunStop::new(
                        patina_dst_abi::RunClass::Error,
                        "trace_mismatch",
                        &[detail.as_bytes()],
                    ))
                }
            }
        });
    // The child's page, its clock starting at the machine's time; a
    // recording child appends its decisions to it, and records through it
    // (its trace).
    let now = context(|context| context.machine_now());
    let (page, page_fd) = super::log::HubPage::create(now);
    let recording = context(|context| Ok(context.execution_mode())) == ExecutionMode::Record;
    let trace = if recording { Some(page_fd) } else { trace };
    // The pipe the child's signal front writes a stop record to.
    let [stops, stop_writer] = pipe();
    match trace {
        Some(trace) => {
            send_with_fds(
                launcher as c_int,
                &payload,
                &[child, 0, 1, 2, stop_writer, page_fd, trace],
            );
            if trace != page_fd {
                close(trace);
            }
        }
        None => send_with_fds(
            launcher as c_int,
            &payload,
            &[child, 0, 1, 2, stop_writer, page_fd],
        ),
    }
    close(page_fd);
    close(child);
    close(stop_writer);
    // In the table from here on, so a death before it is ready takes the
    // one path every death does.
    CHILDREN.lock().insert(
        pid,
        Child {
            parent,
            channel: hub,
            stops,
            page: Some(page),
            ready: false,
            status: None,
        },
    );
    ROLE.store(ROLE_ROOT, Ordering::Relaxed);
    // The child may use the filesystem before it is ready (its working
    // directory): the hub serves it meanwhile.
    match off_guest(|| serve(pid, hub)) {
        Some(Message::Ready) => {}
        Some(other) => protocol_fatal("a new process's ready", &other),
        None => {
            host_death(pid);
            protocol_fatal_text(&format!("process {pid} died before it was ready"))
        }
    }
    // A recording root keeps the child's recording from here on.
    if let Some(metadata) = super::BEGUN.lock().remove(&pid) {
        // SAFETY: a NUL-terminated string (checked non-null above).
        let program = unsafe { CStr::from_ptr(spawn.path) }
            .to_string_lossy()
            .into_owned();
        context(|context| {
            context.machine_begin_process(pid, parent, program, argv.clone(), &metadata)
        });
    }
    if let Some(child) = CHILDREN.lock().get_mut(&pid) {
        child.ready = true;
    }
    context(|context| context.task_foreign(foreign_task(pid), ForeignState::Runnable));
    if !spawn.pid.is_null() {
        // SAFETY: a writable pid, per the entry's contract.
        unsafe { spawn.pid.write(pid) };
    }
    Some(0)
}

/// A child's seed: the run's, mixed with the child's pid (splitmix64), so
/// each process draws its own stream and the same run draws the same ones.
fn child_seed(root: u64, pid: i32) -> u64 {
    let mut z = root ^ (pid as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The spawn stops the run: `what` is the part of it this slice does not
/// model.
fn refuse(spawn: &Spawn, what: &str) -> ! {
    // SAFETY: a NUL-terminated string (checked non-null by the caller).
    let path = unsafe { CStr::from_ptr(spawn.path) }.to_string_lossy();
    let detail = format!(
        "the guest called {} `{path}` {what}, which Patina does not model yet",
        spawn.symbol.to_string_lossy()
    );
    let line = format!("patina: process spawn reached under patina: {detail}; failing closed\n");
    let _ = crate::host_write_all(2, line.as_bytes());
    crate::patina_flush_captured_stdio();
    crate::host_abort(crate::RunStop::unmodeled(&[detail.as_bytes()]))
}

/// What a child is handed at one of its descriptors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shared {
    /// The run's standard streams and the memory devices: the child's own
    /// description of the same kind and handle.
    Own(FdKind, u64, u32),
    /// The root's open file `handle`, through a handle of the child's own.
    File { handle: u64, status: u32 },
    /// The root's pipe end, description `desc`, the reading end when `read`.
    Pipe {
        desc: DescId,
        read: bool,
        status: u32,
    },
}

/// The spawn's file actions, or a refusal of what this slice does not
/// carry out.
///
/// # Safety
/// `spawn.file_actions` is null or a live actions object.
unsafe fn file_actions(spawn: &Spawn) -> Vec<Action> {
    if spawn.file_actions.is_null() {
        return Vec::new();
    }
    // SAFETY: per the contract.
    let (id, used) = unsafe {
        (
            actions_id(spawn.file_actions),
            actions_used(spawn.file_actions),
        )
    };
    let actions = ACTIONS.lock().get(&id).cloned().unwrap_or_default();
    // An action the shim did not record (one glibc's own code added) is
    // one it cannot carry out.
    if actions.len() != used as usize {
        refuse(spawn, "with a file action Patina does not record");
    }
    if actions.iter().any(|action| matches!(action, Action::Open)) {
        refuse(spawn, "with a file action that opens a file");
    }
    actions
}

/// Carry out the spawn's `actions` on the caller's descriptor table, as the
/// child would before it execs, from working directory `cwd`: the child's
/// working directory and what each of its descriptors is. `Err(errno)`
/// when an action fails (the spawn answers it, and no child runs); a
/// descriptor of a kind no child shares refuses the spawn.
fn arrange(
    spawn: &Spawn,
    actions: &[Action],
    mut cwd: String,
) -> Result<(String, BTreeMap<c_int, Shared>), c_int> {
    // Every open number, its description and its close-on-exec bit.
    let mut table: BTreeMap<c_int, (crate::fdtable::Resolved, bool)> = {
        let table = crate::state::fd_table().lock();
        table
            .numbers()
            .into_iter()
            .filter_map(|number| Some((number, (table.resolve(number)?, false))))
            .map(|(number, (resolved, _))| (number, (resolved, resolved.cloexec)))
            .collect()
    };
    for action in actions {
        match action {
            Action::Dup2 { fd, to } => {
                // The copy stays open across exec; glibc's `dup2` of a
                // number onto itself clears its close-on-exec bit.
                let (resolved, _) = *table.get(fd).ok_or(libc::EBADF)?;
                table.insert(*to, (resolved, false));
            }
            Action::Close(fd) => {
                table.remove(fd);
            }
            Action::Closefrom(from) => table.retain(|number, _| number < from),
            Action::Chdir(path) => {
                let path = path.to_str().map_err(|_| libc::ENOENT)?;
                let path = if path.starts_with('/') {
                    path.to_owned()
                } else {
                    format!("{}/{path}", cwd.trim_end_matches('/'))
                };
                cwd = crate::paths::searchable_directory(crate::paths::AT_FDCWD, &path)?.path;
            }
            Action::Fchdir(fd) => {
                let (resolved, _) = *table.get(fd).ok_or(libc::EBADF)?;
                if resolved.kind != FdKind::Dir {
                    return Err(libc::ENOTDIR);
                }
                cwd = crate::paths::node_path(Fd(resolved.handle))?;
            }
            Action::Open => unreachable!("refused with the actions"),
        }
    }
    let mut shared = BTreeMap::new();
    for (number, (resolved, cloexec)) in table {
        if cloexec {
            continue;
        }
        let what = match resolved.kind {
            FdKind::Stdin | FdKind::Stdout | FdKind::Stderr | FdKind::MemDevice => {
                Shared::Own(resolved.kind, resolved.handle, resolved.status)
            }
            FdKind::File => Shared::File {
                handle: resolved.handle,
                status: resolved.status,
            },
            FdKind::Pipe if thread::fifo_end_ino(resolved.handle).is_none() => Shared::Pipe {
                desc: resolved.desc,
                read: resolved.status & crate::O_WRITE == 0,
                status: resolved.status,
            },
            FdKind::Pipe => refuse(
                spawn,
                &format!("with descriptor {number}, a FIFO, open across exec"),
            ),
            other => refuse(
                spawn,
                &format!("with descriptor {number} ({other:?}) open across exec"),
            ),
        };
        shared.insert(number, what);
    }
    Ok((cwd, shared))
}

/// Child `pid`'s descriptor plan, as [`install_plan`] reads it: one entry
/// per description the child holds, and each number's description. Each
/// pipe the child holds is a reference of its own on the root's
/// description, taken here; each file is the duplicate `files` names.
fn plan(pid: i32, table: &BTreeMap<c_int, Shared>, files: &BTreeMap<u64, Fd>) -> Vec<u8> {
    let mut distinct: Vec<Shared> = Vec::new();
    let mut numbers = Vec::new();
    for (number, shared) in table {
        let index = distinct
            .iter()
            .position(|known| known == shared)
            .unwrap_or_else(|| {
                distinct.push(*shared);
                distinct.len() - 1
            });
        numbers.push(serde_json::json!([number, index]));
    }
    let descriptions: Vec<serde_json::Value> = distinct
        .iter()
        .map(|shared| match *shared {
            Shared::Own(kind, handle, status) => {
                serde_json::json!({"kind": kind.wire(), "handle": handle, "status": status})
            }
            Shared::File { handle, status } => serde_json::json!({
                "kind": FdKind::File.wire(),
                "handle": files[&handle].0,
                "status": status,
            }),
            Shared::Pipe { desc, read, status } => {
                super::pipes::retain(pid, desc);
                serde_json::json!({
                    "kind": FdKind::Pipe.wire(),
                    "remote": desc,
                    "read": read,
                    "status": status,
                })
            }
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({"descriptions": descriptions, "numbers": numbers}))
        .unwrap_or_else(|error| protocol_fatal_text(&format!("encoding a plan: {error}")))
}

/// A child, before it is ready: its descriptor table becomes what its
/// spawn arranged.
pub(super) fn install_plan() {
    send(channel(), &Message::Plan);
    let len = match receive(channel()) {
        Some(Message::PlanReply { len }) => len,
        Some(other) => protocol_fatal("a descriptor plan", &other),
        None => orphaned(),
    };
    let bytes = receive_payload(channel(), len).unwrap_or_else(|| orphaned());
    let plan: serde_json::Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| protocol_fatal_text(&format!("decoding a plan: {error}")));
    let field =
        |value: &serde_json::Value, name: &str| value.get(name).and_then(serde_json::Value::as_u64);
    let kinds = [
        FdKind::Stdin,
        FdKind::Stdout,
        FdKind::Stderr,
        FdKind::File,
        FdKind::MemDevice,
        FdKind::Pipe,
    ];
    let descriptions: Vec<(FdKind, u64, u32)> = plan["descriptions"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|description| {
            let kind = field(description, "kind")
                .and_then(|wire| kinds.into_iter().find(|kind| kind.wire() as u64 == wire))
                .unwrap_or_else(|| protocol_fatal_text("a plan's descriptor of no kind"));
            let status = field(description, "status").unwrap_or_default() as u32;
            let handle = match (kind, field(description, "remote")) {
                (FdKind::Pipe, Some(remote)) => {
                    let read = description["read"].as_bool().unwrap_or_default();
                    thread::remote_end(remote, read) as u64
                }
                _ => field(description, "handle").unwrap_or_default(),
            };
            (kind, handle, status)
        })
        .collect();
    let numbers: Vec<(c_int, usize)> = plan["numbers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| Some((entry[0].as_i64()? as c_int, entry[1].as_u64()? as usize)))
        .collect();
    let released = crate::state::fd_table()
        .lock()
        .replace(&descriptions, &numbers)
        .unwrap_or_else(|errno| protocol_fatal_text(&format!("installing a plan ({errno})")));
    for release in released {
        let _ = crate::state::release_description(release);
    }
}

/// glibc's `posix_spawn_file_actions_t.__used`: how many actions it holds.
///
/// # Safety
/// `actions` is a live actions object.
unsafe fn actions_used(actions: *const libc::posix_spawn_file_actions_t) -> c_int {
    // SAFETY: `__used` is the second `int` of glibc's actions object.
    unsafe { actions.cast::<c_int>().add(1).read_unaligned() }
}

/// glibc's `posix_spawnattr_t`: its flags (`__flags`, the leading `short`)
/// and whether its signal mask (`__ss`, after the flags, the group and the
/// default set) is empty.
///
/// # Safety
/// `attr` is a live attributes object.
unsafe fn attributes(attr: *const libc::posix_spawnattr_t) -> (i16, bool) {
    const MASK_OFFSET: usize = 8 + size_of::<libc::sigset_t>();
    // SAFETY: both fields lie inside glibc's attributes object.
    unsafe {
        let flags = attr.cast::<i16>().read_unaligned();
        let mask = attr
            .cast::<u8>()
            .add(MASK_OFFSET)
            .cast::<libc::sigset_t>()
            .read_unaligned();
        let empty = (1..=64).all(|sig| libc::sigismember(&mask, sig) != 1);
        (flags, empty)
    }
}

/// The strings of a NULL-terminated array (none for NULL), or `None` if one
/// is not UTF-8.
///
/// # Safety
/// `array` is NULL or a NULL-terminated array of C strings.
unsafe fn strings(array: *const *mut c_char) -> Option<Vec<String>> {
    let mut strings = Vec::new();
    if array.is_null() {
        return Some(strings);
    }
    for index in 0.. {
        // SAFETY: within the NULL-terminated array.
        let item = unsafe { *array.add(index) };
        if item.is_null() {
            break;
        }
        // SAFETY: a C string, per the contract.
        let text = unsafe { CStr::from_ptr(item) }.to_str().ok()?;
        strings.push(text.to_owned());
    }
    Some(strings)
}

/// A close-on-exec memory file holding `bytes`, read from its start.
fn memfd_with(bytes: &[u8]) -> c_int {
    // SAFETY: a static name; the flags are plain.
    let fd = unsafe {
        crate::sud_host_syscall(
            libc::SYS_memfd_create,
            c"patina-process-trace".as_ptr() as _,
            libc::MFD_CLOEXEC as _,
            0,
            0,
            0,
            0,
        )
    } as c_int;
    if fd < 0 {
        protocol_fatal_text("creating a process's trace file failed");
    }
    let mut written = 0;
    while written < bytes.len() {
        // SAFETY: a live buffer of the remaining length.
        let n = unsafe {
            crate::sud_host_syscall(
                libc::SYS_write,
                fd as _,
                bytes[written..].as_ptr() as _,
                (bytes.len() - written) as _,
                0,
                0,
                0,
            )
        };
        if n <= 0 {
            protocol_fatal_text("writing a process's trace failed");
        }
        written += n as usize;
    }
    // SAFETY: a seek on the descriptor just made.
    unsafe { crate::sud_host_syscall(libc::SYS_lseek, fd as _, 0, libc::SEEK_SET as _, 0, 0, 0) };
    fd
}

/// A close-on-exec pipe: its read end, its write end.
fn pipe() -> [c_int; 2] {
    let mut pair = [-1 as c_int; 2];
    // SAFETY: a writable pair of descriptors.
    let rc = unsafe {
        crate::sud_host_syscall(
            libc::SYS_pipe2,
            pair.as_mut_ptr() as _,
            libc::O_CLOEXEC as _,
            0,
            0,
            0,
            0,
        )
    };
    if rc != 0 {
        protocol_fatal_text("creating a process's stop pipe failed");
    }
    pair
}

/// The host wait status of child `pid`, whose host process is gone: the
/// supervisor's launcher reaped it and answers over the launch channel.
/// `None` if it cannot say.
pub(super) fn host_status(pid: i32) -> Option<i32> {
    let launcher = crate::parse_control_u64(ENV_LAUNCH_FD).ok()?? as c_int;
    let request = serde_json::to_vec(&serde_json::json!({ "reaped": pid })).ok()?;
    if !send_bytes_once(launcher, &request) {
        return None;
    }
    let mut answer = [0u8; 8];
    let received = off_guest(|| receive_bytes(launcher, &mut answer))?;
    let status = i64::from_le_bytes(answer);
    (received == answer.len() && status >= 0).then_some(status as i32)
}

/// A `SOCK_SEQPACKET` pair, close-on-exec: the hub's end, the child's end.
fn socketpair() -> [c_int; 2] {
    let mut pair = [-1 as c_int; 2];
    // SAFETY: a writable pair of descriptors.
    let rc = unsafe {
        crate::sud_host_syscall(
            libc::SYS_socketpair,
            libc::AF_UNIX as _,
            (libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC) as _,
            0,
            pair.as_mut_ptr() as _,
            0,
            0,
        )
    };
    if rc != 0 {
        protocol_fatal_text("creating a process channel failed");
    }
    pair
}

/// Send `payload` on `fd` with `fds` as `SCM_RIGHTS`.
fn send_with_fds(fd: c_int, payload: &[u8], fds: &[c_int]) {
    let fd_bytes = size_of_val(fds);
    // SAFETY: `CMSG_SPACE` is arithmetic.
    let space = unsafe { libc::CMSG_SPACE(fd_bytes as u32) } as usize;
    let mut control = vec![0u64; space.div_ceil(8)];
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut _,
        iov_len: payload.len(),
    };
    // SAFETY: an all-zero msghdr is valid; the fields set below point at
    // buffers live for the call.
    let mut header: libc::msghdr = unsafe { core::mem::zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = space as _;
    // SAFETY: the control buffer holds one header and `fds`.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&header);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(fd_bytes as u32) as _;
        core::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(cmsg).cast(), fds.len());
    }
    loop {
        // SAFETY: the header and its buffers are live for the call.
        let sent = unsafe {
            crate::sud_host_syscall(
                libc::SYS_sendmsg,
                fd as _,
                (&raw const header) as _,
                libc::MSG_NOSIGNAL as _,
                0,
                0,
                0,
            )
        };
        if sent == payload.len() as i64 {
            return;
        }
        if sent < 0 && crate::abi::host_errno() == libc::EINTR {
            continue;
        }
        protocol_fatal_text("asking the supervisor to launch a process failed");
    }
}

/// What a wait finds among the caller's children.
enum Found {
    /// A zombie: its pid and wait status.
    Zombie(i32, i32),
    /// Children that match, none of them a zombie yet.
    Running,
    /// No child matches (`ECHILD`).
    None,
}

/// Look for a child of the caller that `pid` matches (`wait4`'s `pid`: one
/// child, -1 any, 0 or minus the caller's group any in that group).
fn find(pid: i32) -> Found {
    let me = crate::patina_pid();
    let group = crate::identity::pgid();
    let any = pid == -1 || pid == 0 || pid == -group;
    let children = CHILDREN.lock();
    let mut running = false;
    for (child_pid, child) in children.iter() {
        if child.parent != me || !(any || *child_pid == pid) {
            continue;
        }
        match child.status {
            Some(status) => return Found::Zombie(*child_pid, status),
            None => running = true,
        }
    }
    if running { Found::Running } else { Found::None }
}

/// Reap zombie `pid`: it leaves the table, and the machine forgets it.
fn reap(pid: i32) {
    CHILDREN.lock().remove(&pid);
    crate::identity::remove_child(pid);
}

/// Park the caller until a child changes state; `Err(errno)` when a signal
/// ends the wait.
fn park() -> Result<(), c_int> {
    let mut me = None;
    let parked = thread::wait_for_child(|task| {
        me = Some(task);
        WAITERS.lock().push(task);
    });
    // The waker took the task off the list; a signal left it there.
    if let Some(me) = me {
        WAITERS.lock().retain(|task| *task != me);
    }
    parked
}

/// The root ends: no task waits for a child any more, and none is woken.
pub(super) fn forget_waiters() {
    WAITERS.lock().clear();
}

/// A child exited: every task waiting for one looks again.
pub(super) fn wake_waiters() {
    let waiters = core::mem::take(&mut *WAITERS.lock());
    thread::wake_waiting(&waiters);
}

/// `wait4` (`pid`, the status out-pointer `status`, `options`, whether it
/// was handed a resource-usage out-pointer) over the table, its options
/// already checked.
pub(crate) fn wait4(pid: i32, status: usize, options: u32, rusage: bool) -> i64 {
    loop {
        match find(pid) {
            Found::Zombie(..) if rusage => refuse_rusage("wait4"),
            Found::Zombie(child, wait_status) => {
                if status != 0 && crate::uaccess::write(status, &wait_status).is_err() {
                    return -i64::from(libc::EFAULT);
                }
                reap(child);
                return i64::from(child);
            }
            Found::None => return -i64::from(libc::ECHILD),
            Found::Running if options & WNOHANG != 0 => return 0,
            Found::Running => {
                // A signal that ends the wait (SIGCHLD's handler, say) still
                // leaves the child that changed state to find, as the kernel's
                // wait looks for one before it looks for a signal.
                if let Err(errno) = park()
                    && !matches!(find(pid), Found::Zombie(..))
                {
                    return -i64::from(errno);
                }
            }
        }
    }
}

/// `waitid` (`P_ALL` as `id` -1, `P_PID` as the pid; the `siginfo_t`
/// out-pointer `info`; `options`) over the table, its options checked.
pub(crate) fn waitid(id: i32, info: usize, options: u32, rusage: bool) -> i64 {
    if options & WEXITED == 0 {
        // Stopped and continued children are never: nothing to wait for.
        return match find(id) {
            Found::None => -i64::from(libc::ECHILD),
            _ if options & WNOHANG != 0 => write_info(info, None),
            _ => {
                thread::fatal_unmodeled(
                    "waitid for stopped or continued children only, which never come",
                );
            }
        };
    }
    loop {
        match find(id) {
            Found::Zombie(..) if rusage => refuse_rusage("waitid"),
            Found::Zombie(child, wait_status) => {
                let answer = write_info(info, Some((child, wait_status)));
                if answer == 0 && options & WNOWAIT == 0 {
                    reap(child);
                }
                return answer;
            }
            Found::None => return -i64::from(libc::ECHILD),
            Found::Running if options & WNOHANG != 0 => return write_info(info, None),
            Found::Running => {
                // A signal that ends the wait (SIGCHLD's handler, say) still
                // leaves the child that changed state to find, as the kernel's
                // wait looks for one before it looks for a signal.
                if let Err(errno) = park()
                    && !matches!(find(id), Found::Zombie(..))
                {
                    return -i64::from(errno);
                }
            }
        }
    }
}

/// A wait that would reap a child into a resource-usage out-pointer: what
/// a child spent is not carried to its parent.
fn refuse_rusage(call: &str) -> ! {
    crate::trap_unmodeled(&format!(
        "{call} with a resource-usage out-pointer for a child process (its usage is not \
carried to the parent) is not modeled"
    ))
}

/// Fill the caller's `siginfo_t` for `found` (a child's pid and wait
/// status), or zero its fields when nothing changed state.
fn write_info(info: usize, found: Option<(i32, i32)>) -> i64 {
    if info == 0 {
        return 0;
    }
    // si_signo, si_errno, si_code, padding, si_pid, si_uid, si_status.
    let mut words = [0i32; 7];
    if let Some((pid, status)) = found {
        let (code, value) = if libc::WIFEXITED(status) {
            (libc::CLD_EXITED, libc::WEXITSTATUS(status))
        } else if libc::WCOREDUMP(status) {
            (libc::CLD_DUMPED, libc::WTERMSIG(status))
        } else {
            (libc::CLD_KILLED, libc::WTERMSIG(status))
        };
        words = [
            libc::SIGCHLD,
            0,
            code,
            0,
            pid,
            crate::identity::credential().uid as i32,
            value,
        ];
    }
    match crate::uaccess::write_slice(info, &words) {
        Ok(()) => 0,
        Err(_) => -i64::from(libc::EFAULT),
    }
}
