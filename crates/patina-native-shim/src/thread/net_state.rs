//! Shared simulated-network and descriptor-class state.

use super::*;

// ------------------------------------------------------------------
// The descriptor classes the thread runtime owns beside the sockets
// (`net`): pipes and FIFOs, eventfds, and the readiness reactors.

pub(crate) struct NetState {
    /// Every socket and the socket families' namespaces (`net`).
    pub(crate) sockets: net::Sockets,
    // In-process pipe channels. Endpoints are keyed by class handle
    // (`next_handle`, shared with the sockets, so a handle is a socket
    // XOR a pipe end); the descriptor table maps guest numbers onto them and
    // says which kind a number names. `pipe_channels` are the directed byte
    // buffers each endpoint reads from / writes to; see the "in-process
    // pipe" section.
    pub(crate) pipe_ends: BTreeMap<c_int, PipeEnd>,
    pub(crate) pipe_channels: BTreeMap<u64, PipeChannel>,
    /// The channel currently backing each open FIFO, keyed by the
    /// deterministic filesystem INODE of the FIFO entry — the identity two
    /// openers of the same named pipe must agree on. A name would be the
    /// wrong key: renaming the FIFO must not split its openers, and a fresh
    /// FIFO created at a vacated name must not inherit them. The binding
    /// exists only while some descriptor is open on the FIFO.
    pub(crate) fifo_channels: BTreeMap<u64, u64>,
    pub(crate) next_channel: u64,
    /// The pipefs and sockfs nodes behind anonymous pipes and sockets
    /// ([`PipeInode`]), keyed by their inode number.
    pub(crate) pipe_inodes: BTreeMap<u64, PipeInode>,
    pub(crate) next_pipe_ino: u64,
    // Virtual kqueue readiness reactors, keyed by registry id. The
    // descriptor table holds the description (a `dup`/`F_DUPFD` of a kqueue
    // fd — tokio's IO driver clones its selector this way — is a second
    // number on the same description), so the registry outlives any one
    // number and drops only when the last closes. macOS-only: kqueue/kevent
    // have no Linux counterpart.
    #[cfg(target_os = "macos")]
    pub(super) kqueues: BTreeMap<u64, KqueueSlot>,
    #[cfg(target_os = "macos")]
    pub(super) next_kq: u64,
    // Virtual epoll readiness reactors — the Linux mirror of the kqueue
    // table above, keyed by registry id the same way (mio clones its
    // selector through `F_DUPFD_CLOEXEC` on Linux exactly as on macOS: a
    // second number on one description in the descriptor table).
    #[cfg(target_os = "linux")]
    pub(super) epolls: BTreeMap<u64, EpollSlot>,
    #[cfg(target_os = "linux")]
    pub(crate) next_epoll: u64,
    // Deterministic in-process eventfd counters (Linux; mio's `Waker`
    // vehicle, the EVFILT_USER analogue), keyed by class handle.
    #[cfg(target_os = "linux")]
    pub(crate) eventfds: BTreeMap<c_int, EventFd>,
    /// The class-handle allocator shared by `sockets`, `pipe_ends` and
    /// `eventfds`: an internal identity the descriptor table maps guest
    /// numbers onto, never a number the guest sees (see `next_handle`).
    pub(crate) next_handle: c_int,
}

impl NetState {
    pub(crate) fn new() -> Self {
        Self {
            sockets: net::Sockets::default(),
            pipe_ends: BTreeMap::new(),
            pipe_channels: BTreeMap::new(),
            fifo_channels: BTreeMap::new(),
            next_channel: 0,
            pipe_inodes: BTreeMap::new(),
            next_pipe_ino: 1,
            #[cfg(target_os = "macos")]
            kqueues: BTreeMap::new(),
            #[cfg(target_os = "macos")]
            next_kq: 0,
            #[cfg(target_os = "linux")]
            epolls: BTreeMap::new(),
            #[cfg(target_os = "linux")]
            next_epoll: 0,
            #[cfg(target_os = "linux")]
            eventfds: BTreeMap::new(),
            next_handle: 0,
        }
    }
}

/// A dotted-quad `IP:PORT` as a host-order address and port.
fn parse_addr(addr: &str) -> Option<(u32, u16)> {
    let (host, port) = addr.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let ip: std::net::Ipv4Addr = host.parse().ok()?;
    Some((u32::from(ip), port))
}

pub(crate) fn wake_all(waiters: Vec<TaskId>) {
    let mut scheduler = RealScheduler;
    for task in waiters {
        #[cfg(target_os = "linux")]
        lock_state().remove_signal_wait(task);
        if let Err(message) = scheduler.wake(task) {
            fatal(&message);
        }
    }
}

/// Resolve a host name through the run's deterministic DNS host table.
///
/// Writes the resolved address as a host-byte-order `u32` and returns 0; on
/// failure returns -1 with errno set. Resolution is a recorded boundary
/// operation, so an injected failure or latency reproduces on replay.
///
/// # Safety
/// C ABI entry point: `name` must be a NUL-terminated string and `ip` must
/// point at a writable `uint32_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_dns_resolve(name: *const c_char, ip: *mut u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if let Err(errno) = sched_point() {
        return super::fail(errno);
    }
    if name.is_null() || ip.is_null() {
        return super::fail(EINVAL);
    }
    let Ok(name) = (unsafe { std::ffi::CStr::from_ptr(name) }).to_str() else {
        return super::fail(EINVAL);
    };
    let resolved = match with_context_raw(|context| context.dns_resolve(name)) {
        Ok(address) => address,
        Err(errno) => return super::fail(errno),
    };
    // The runtime's resolutions are dotted quads by construction (the host
    // table validates every entry at configuration time), so a malformed one
    // here means the runtime and this shim disagree — fail loudly rather
    // than hand the guest a wrong address.
    let Some((address, _)) = parse_addr(&format!("{resolved}:0")) else {
        fatal("DNS resolution returned a malformed address");
    };
    unsafe { ip.write(address) };
    super::set_errno(0);
    0
}
