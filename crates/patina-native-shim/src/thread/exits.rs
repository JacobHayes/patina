//! A finished thread's host exit, which no task may run beside.
//!
//! A managed thread's task completes as its start routine ends (on Linux
//! from glibc's thread-local destructor pass), and the baton passes on
//! there. The C library then goes on running on that host thread: its
//! `pthread_key` destructors, the allocator's thread shutdown, the stack's
//! release, the exit. That code shares the C library's locks and heap with
//! the tasks, so a task running beside it would see the host's timing. A
//! completing thread therefore publishes a beacon the host kernel fires once
//! the thread has left user space for good, and the task that takes the
//! baton next waits for it ([`await_exits`]) before it runs anything else.
//!
//! * Linux: the thread's host robust list is the beacon, a word naming the
//!   host thread that the kernel's exit walk marks `FUTEX_OWNER_DIED`
//!   (`super::registrations`).
//! * Darwin: a dead-name notification on the thread's kernel port, requested
//!   while the new thread is still suspended ([`arm`]). The kernel destroys
//!   that port as it reclaims the terminated thread (`ipc_thread_terminate`),
//!   which follows the thread's last call (`__bsdthread_terminate`), after
//!   everything libpthread runs on it.

use super::*;

/// A published beacon: on Linux the robust-list beacon's address, on Darwin
/// the dead-name notification's ports.
#[cfg(target_os = "linux")]
type Beacon = usize;
#[cfg(target_os = "macos")]
type Beacon = darwin::DeadName;

/// The beacons of threads whose tasks completed, for the next task to wait
/// for.
#[derive(Default)]
pub(super) struct Exits {
    /// Darwin: each live managed thread's armed beacon, by task.
    #[cfg(target_os = "macos")]
    armed: BTreeMap<TaskId, Beacon>,
    exiting: Vec<Beacon>,
    /// Whether the baton holder waits for a finished thread's host exit: off
    /// the guest, as long as the host takes.
    awaiting: bool,
}

impl Exits {
    /// Whether the baton holder waits for a finished thread's host exit
    /// (the compute watchdog's ineligible window, as a creation is).
    pub(super) fn awaiting(&self) -> bool {
        self.awaiting
    }
}

/// Hand a completing thread's beacon to the task that takes the baton next.
#[cfg(target_os = "linux")]
pub(super) fn publish(beacon: Beacon) {
    lock_state().exits.exiting.push(beacon);
}

/// Wait until every thread whose task completed has left user space: called
/// by a task as it takes the baton, before it runs anything else.
pub(super) fn await_exits() {
    let exiting = {
        let mut state = lock_state();
        let exiting = std::mem::take(&mut state.exits.exiting);
        state.exits.awaiting = !exiting.is_empty();
        exiting
    };
    if exiting.is_empty() {
        return;
    }
    for beacon in exiting {
        #[cfg(target_os = "linux")]
        super::registrations::await_exit(beacon);
        #[cfg(target_os = "macos")]
        beacon.await_exit();
    }
    lock_state().exits.awaiting = false;
}

#[cfg(target_os = "macos")]
pub(super) use darwin::{arm, armed, exiting};

#[cfg(target_os = "macos")]
pub(in crate::thread) mod darwin {
    use super::*;

    type KernReturn = c_int;
    type MachPort = u32;

    const KERN_SUCCESS: KernReturn = 0;
    const MACH_PORT_RIGHT_SEND: u32 = 0;
    const MACH_PORT_RIGHT_RECEIVE: u32 = 1;
    const MACH_PORT_RIGHT_DEAD_NAME: u32 = 4;
    /// `MACH_NOTIFY_FIRST + 8` (`<mach/notify.h>`).
    const MACH_NOTIFY_DEAD_NAME: c_int = 0o110;
    const MACH_MSG_TYPE_MAKE_SEND_ONCE: u32 = 21;
    const MACH_RCV_MSG: c_int = 2;
    const MACH_RCV_INTERRUPTED: KernReturn = 0x1000_4005;

    /// The Mach calls the beacon makes, resolved through the host-alias
    /// resolver, never named as imports.
    struct Mach {
        task: MachPort,
        allocate: Allocate,
        mod_refs: ModRefs,
        request_notification: RequestNotification,
        msg: Msg,
    }

    type Allocate = unsafe extern "C" fn(MachPort, u32, *mut MachPort) -> KernReturn;
    type ModRefs = unsafe extern "C" fn(MachPort, MachPort, u32, c_int) -> KernReturn;
    type RequestNotification = unsafe extern "C" fn(
        MachPort,
        MachPort,
        c_int,
        u32,
        MachPort,
        u32,
        *mut MachPort,
    ) -> KernReturn;
    type Msg =
        unsafe extern "C" fn(*mut c_void, c_int, u32, u32, MachPort, u32, MachPort) -> KernReturn;

    fn mach() -> &'static Mach {
        static MACH: std::sync::OnceLock<Mach> = std::sync::OnceLock::new();
        MACH.get_or_init(|| {
            let resolve = crate::hostapi::resolve;
            // SAFETY: each pointer is the libsystem_kernel function of that
            // name, transmuted to its C signature (`<mach/mach_port.h>`,
            // `<mach/message.h>`).
            unsafe {
                Mach {
                    task: crate::hostapi::get().task_self,
                    allocate: std::mem::transmute::<*mut c_void, Allocate>(resolve(
                        c"mach_port_allocate",
                    )),
                    mod_refs: std::mem::transmute::<*mut c_void, ModRefs>(resolve(
                        c"mach_port_mod_refs",
                    )),
                    request_notification: std::mem::transmute::<*mut c_void, RequestNotification>(
                        resolve(c"mach_port_request_notification"),
                    ),
                    msg: std::mem::transmute::<*mut c_void, Msg>(resolve(c"mach_msg")),
                }
            }
        })
    }

    /// A thread's dead-name notification: its kernel port's name, on which
    /// this task holds a send right of its own, and the receive right the
    /// notification arrives on.
    pub(in crate::thread) struct DeadName {
        thread: MachPort,
        notify: MachPort,
    }

    /// Arm a beacon on a new host thread's kernel port `thread`, while the
    /// thread is still suspended (alive). The extra send right keeps the
    /// name this task's until the notification is taken, whatever
    /// libpthread does with its own. Takes no lock: the creator holds the
    /// runtime's, and records it as the task's ([`armed`]). Only managed
    /// threads have one (`spawn_managed_host_thread`).
    pub(in crate::thread) fn arm(thread: MachPort) -> DeadName {
        let mach = mach();
        let mut notify: MachPort = 0;
        let mut previous: MachPort = 0;
        // SAFETY: the resolved Mach calls on this task's own port space.
        let armed = unsafe {
            (mach.mod_refs)(mach.task, thread, MACH_PORT_RIGHT_SEND, 1) == KERN_SUCCESS
                && (mach.allocate)(mach.task, MACH_PORT_RIGHT_RECEIVE, &mut notify) == KERN_SUCCESS
                && (mach.request_notification)(
                    mach.task,
                    thread,
                    MACH_NOTIFY_DEAD_NAME,
                    1,
                    notify,
                    MACH_MSG_TYPE_MAKE_SEND_ONCE,
                    &mut previous,
                ) == KERN_SUCCESS
        };
        if !armed {
            fatal("arming a thread's exit notification failed (mach_port_request_notification)");
        }
        DeadName { thread, notify }
    }

    /// Record `beacon` as `task`'s, under the runtime lock its creator holds.
    pub(in crate::thread) fn armed(exits: &mut Exits, task: TaskId, beacon: DeadName) {
        exits.armed.insert(task, beacon);
    }

    /// `task` completed on the calling thread: hand its beacon to the task
    /// that takes the baton next.
    pub(in crate::thread) fn exiting(task: TaskId) {
        let mut state = lock_state();
        if let Some(beacon) = state.exits.armed.remove(&task) {
            state.exits.exiting.push(beacon);
        }
    }

    impl DeadName {
        /// Wait for the notification, then release both names.
        pub(super) fn await_exit(self) {
            let mach = mach();
            // `mach_dead_name_notification_t` and its trailer, with room.
            let mut message = [0u64; 32];
            loop {
                // SAFETY: a receive into this buffer on our receive right.
                let received = unsafe {
                    (mach.msg)(
                        message.as_mut_ptr().cast(),
                        MACH_RCV_MSG,
                        0,
                        std::mem::size_of_val(&message) as u32,
                        self.notify,
                        0,
                        0,
                    )
                };
                match received {
                    KERN_SUCCESS => break,
                    MACH_RCV_INTERRUPTED => continue,
                    _ => fatal("waiting for a thread's exit notification failed (mach_msg)"),
                }
            }
            // SAFETY: the resolved Mach calls on names this task holds: the
            // notification's receive right, and the dead name's two
            // references that are ours (our send right's, and the one the
            // notification added); any other holder's stay.
            unsafe {
                (mach.mod_refs)(mach.task, self.notify, MACH_PORT_RIGHT_RECEIVE, -1);
                (mach.mod_refs)(mach.task, self.thread, MACH_PORT_RIGHT_DEAD_NAME, -2);
            }
        }
    }
}
