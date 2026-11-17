//! Descriptors and file data.
use super::*;

const G: Group = Group::Fd;

const DATA: &str = "Regular-file I/O on tmpfs or host-stable files does not wait and returns full counts except at end of file or ENOSPC (a function of the guest's own writes). Reads of /dev/urandom descriptors are entropy draws; synthesised /proc files are memfds read normally.";
const WDATA: &str = "Regular-file writes on tmpfs do not wait and return full counts except at ENOSPC (a function of the guest's own writes). A write of at least one byte to a sandbox tmpfs file stamps its mtime and ctime in the virtual time table; on /work it is reported to the durability hook.";
const V2: &str = "As readv/writev with an offset (pipes and sockets: offset -1 only, then as read/write). On regular files RWF_NOWAIT from the guest is stripped (it would expose page-cache state); on a pipe, socket or eventfd it is honoured (one attempt, EAGAIN).";
const READ: &str = "Regular files, directories and devices: as pread (cannot wait, contents are sandbox history or host-stable; /dev/urandom descriptors are entropy draws). Pipes, FIFOs, sockets, eventfd and timerfd (decided by fstat at the call): one non-blocking attempt (preadv2 with RWF_NOWAIT, never touching the description's flags); if it would wait, the thread parks until the I/O generation moves (SO_RCVTIMEO is a virtual deadline, then EAGAIN). A descriptor already O_NONBLOCK gets EAGAIN. Readiness of these objects changes only as a synchronous effect of sandbox calls.";
const WRITE: &str = "Regular files: cannot wait and return full counts except at ENOSPC; the virtual time table and the durability hook are updated. Pipes, FIFOs, sockets, eventfd (decided by fstat at the call): non-blocking attempts (pwritev2 with RWF_NOWAIT; eventfd, which refuses RWF_NOWAIT, after a zero-timeout poll for POLLOUT); a partial count on a blocking descriptor is continued after a park, so the call returns the full count as blocking semantics require (a signal after a partial write returns the partial count). Writes of at most 4096 bytes to a pipe stay atomic because the kernel completes or refuses them whole. Pipe capacity and socket buffer sizes are fixed at creation.";
const POLL: &str = "Readiness of pipes, sockets, eventfds, timerfds and files is a synchronous function of sandbox calls: the same call with a zero timeout is the attempt; if nothing is ready and the timeout allows waiting, the thread parks until the I/O generation moves or the virtual deadline passes (then 0). A zero timeout from the guest never parks but is charged like any trap (poll churn). A sigmask argument is not given to the kernel (the guest's mask is virtual). Hidden descriptors in the set read as invalid.";
const EPWAIT: &str = "The epoll object is the kernel's, passed through; only the wait is an attempt: epoll_pwait with a zero timeout, parked until the I/O generation moves or the virtual deadline passes (then 0). The ready list order is the order the events were raised. A sigmask is not given to the kernel (virtual).";
const TFD: &str = "Virtual timer: the descriptor is an eventfd made by the runtime (non-semaphore, same 8-byte counter semantics); the supervisor holds a duplicate and writes the expiry count at virtual expiry times from its event queue; settime and gettime are answered from supervisor state. Only CLOCK_REALTIME, CLOCK_MONOTONIC and CLOCK_BOOTTIME; the alarm clocks answer EPERM as without CAP_WAKE_ALARM.";
const DESC: &str = "Lowest-free allocation and descriptor state are per-process kernel tables changed only by that process's calls; hidden descriptors (3000 and up) read as EBADF. Entropy and /proc marks follow duplicates.";
const NEWFD: &str = "Creates a descriptor at the lowest free number (per-process table); the object's inode number comes from a host-global counter and is only ever shown as a virtual number (stat, /proc/self/fd). Blocking use is blocking I/O's.";
const PIPE: &str = "Creates two descriptors at the lowest free numbers (per-process table); the capacity is set to 65,536 bytes with F_SETPIPE_SZ at creation so that the host's pipe limits are not an input (if the host refuses that size, per-user pipe accounting shared with every process of the host user, the run ends as infra); the inode number is only ever shown virtualised.";
const SYNC: &str = "Durability is the tracker's decision; on tmpfs the kernel call would do nothing. Answers EBADF for a bad descriptor, else 0.";
const FATTR: &str = "Attribute or size change through a descriptor on a sandbox or host file. The virtual time table is stamped (ctime; mtime too for size changes); on /work reported to the durability hook.";
const SPLICE: &str = "Between pipes, or a pipe and a regular file: an attempt with SPLICE_F_NONBLOCK (it affects only the pipe side), parked until the I/O generation moves if it would wait (EAGAIN if the guest asked for SPLICE_F_NONBLOCK). A socket or other descriptor on either side answers EINVAL, so programs fall back to read and write. Data spliced into a file stamps it like a write.";
const ADVICE: &str = "Page-cache advice has no visible effect on tmpfs or host-stable files; the answer depends only on the arguments and descriptor.";

pub const ROWS: &[Row] = &[
    Row::new(G, nr::READ, Attempt, A, READ).fd(0).outs(&[out(1, Len::Ret { max: 2 })]),
    Row::new(G, nr::WRITE, Attempt, A, WRITE).fd(0).ins(&[out(1, Len::Ret { max: 2 })]),
    Row::new(G, nr::PREAD64, Pass, A, DATA).fd(0).outs(&[out(1, Len::Ret { max: 2 })]),
    Row::new(G, nr::PWRITE64, Pass, A, WDATA).fd(0).ins(&[out(1, Len::Ret { max: 2 })]),
    Row::new(G, nr::READV, Attempt, A, READ).fd(0).outs(&[out(1, Len::IovRet { cnt: 2 })]),
    Row::new(G, nr::WRITEV, Attempt, A, WRITE).fd(0).ins(&[out(1, Len::IovRet { cnt: 2 })]),
    Row::new(G, nr::PREADV, Pass, A, DATA).fd(0).outs(&[out(1, Len::IovRet { cnt: 2 })]),
    Row::new(G, nr::PWRITEV, Pass, A, WDATA).fd(0).ins(&[out(1, Len::IovRet { cnt: 2 })]),
    Row::new(G, nr::PREADV2, Attempt, A, V2).fd(0).outs(&[out(1, Len::IovRet { cnt: 2 })]),
    Row::new(G, nr::PWRITEV2, Attempt, A, V2).fd(0).ins(&[out(1, Len::IovRet { cnt: 2 })]),
    Row::new(G, nr::COPY_FILE_RANGE, Pass, A, "Between regular files it cannot wait and copies a function of sandbox history. With a pipe or socket on either side it answers EINVAL (as for files the kernel cannot copy between), so programs fall back to read and write, which are attempts. The target is stamped like a write.").fd(0).fd(2).refs(&[out(1, Len::Fixed(8)), out(3, Len::Fixed(8))]),
    Row::new(G, nr::SENDFILE, Pass, A, "Between regular files it cannot wait. With a pipe or socket on either side it answers EINVAL (the kernel's own non-blocking mode for it comes only from the output description's O_NONBLOCK, which is never toggled), so programs fall back to read and write. The target is stamped like a write.").fd(0).fd(1).refs(&[out(2, Len::Fixed(8))]),
    Row::new(G, nr::SPLICE, Attempt, A, SPLICE).fd(0).fd(2).refs(&[out(1, Len::Fixed(8)), out(3, Len::Fixed(8))]),
    Row::new(G, nr::TEE, Attempt, A, SPLICE).fd(0).fd(1),
    Row::new(G, nr::LSEEK, Pass, A, "File offsets are per-description kernel state changed only by sandbox calls; SEEK_DATA/SEEK_HOLE follow tmpfs allocation, a function of the guest's writes.").fd(0),
    Row::new(G, nr::FTRUNCATE, Pass, A, FATTR).fd(0),
    Row::new(G, nr::FALLOCATE, Pass, A, FATTR).fd(0),
    Row::new(G, nr::FCHMOD, Pass, A, FATTR).fd(0),
    Row::new(G, nr::FCHOWN, Pass, A, FATTR).fd(0),
    Row::new(G, nr::FSETXATTR, Pass, A, FATTR).fd(0).ins(&[out(1, Len::CStr), out(2, Len::Arg(3))]),
    Row::new(G, nr::FREMOVEXATTR, Pass, A, FATTR).fd(0).ins(&[out(1, Len::CStr)]),
    Row::new(G, nr::FGETXATTR, Pass, A, "Extended attributes on tmpfs are sandbox history; on host files host-stable.").fd(0).ins(&[out(1, Len::CStr)]).outs(&[out(2, Len::Ret { max: 3 })]),
    Row::new(G, nr::FLISTXATTR, Pass, A, "Extended attribute names in insertion order on tmpfs; host-stable on host files.").fd(0).outs(&[out(1, Len::Ret { max: 2 })]),
    Row::new(G, nr::FSYNC, Virt, C, SYNC).fd(0),
    Row::new(G, nr::FDATASYNC, Virt, C, SYNC).fd(0),
    Row::new(G, nr::SYNCFS, Virt, C, SYNC).fd(0),
    Row::new(G, nr::SYNC_FILE_RANGE, Virt, C, SYNC).fd(0),
    Row::new(G, nr::SYNC, Virt, C, "Durability is the tracker's decision; always 0."),
    Row::new(G, nr::FADVISE64, Pass, A, ADVICE).fd(0),
    Row::new(G, nr::READAHEAD, Pass, A, ADVICE).fd(0),
    Row::new(G, nr::CLOSE, Pass, A, DESC).fd(0),
    Row::new(G, nr::CLOSE_RANGE, Pass, A, "Per-process descriptor table; the range is clamped below the hidden descriptors, which are never closed or marked close-on-exec by the guest."),
    Row::new(G, nr::DUP, Pass, A, DESC).fd(0),
    Row::new(G, nr::DUP2, Pass, A, DESC).fd(0).fd(1),
    Row::new(G, nr::DUP3, Pass, A, DESC).fd(0).fd(1),
    Row::new(G, nr::FCNTL, Pass, A, "Descriptor and status flags, F_DUPFD (never at a hidden number), pipe size, seals and record locks are per-process or per-file sandbox state. F_SETLKW and F_OFD_SETLKW are F_SETLK/F_OFD_SETLK attempts, parked until the I/O generation moves (a lock release moves it); the kernel's EDEADLK detection for POSIX locks is not reproduced. O_DIRECT is dropped and recorded. Any other command (owner, signal, lease, notify, new ones) answers EINVAL and is recorded as fcntl:CMD (deny by default).").fd(0).refs(&[out(2, Len::Fcntl)]),
    Row::new(G, nr::FLOCK, Attempt, A, "Lock state is per-file sandbox state; a blocking request is a LOCK_NB attempt, parked until the I/O generation moves (unlock and close move it).").fd(0),
    Row::new(G, nr::PIPE, Pass, A, PIPE).outs(&[out(0, Len::Fixed(8))]),
    Row::new(G, nr::PIPE2, Pass, A, PIPE).outs(&[out(0, Len::Fixed(8))]),
    Row::new(G, nr::EVENTFD, Pass, A, NEWFD),
    Row::new(G, nr::EVENTFD2, Pass, A, NEWFD),
    Row::new(G, nr::MEMFD_CREATE, Pass, A, "Creates an anonymous tmpfs file at the lowest free descriptor; the name is visible only to this process (as /memfd:name in /proc/self/fd links) and the inode number (a per-CPU host batch) is only ever shown virtualised.").ins(&[out(0, Len::CStr)]),
    Row::new(G, nr::IOCTL, Virt, C, "There is no terminal: terminal requests answer ENOTTY. FIONBIO, FIOCLEX, FIONCLEX, FIONREAD, FICLONE, FICLONERANGE, FIDEDUPERANGE, FS_IOC_GETFLAGS, FS_IOC_FSGETXATTR and FIGETBSZ pass (answers are functions of the file). Any other request answers ENOTTY and is recorded as ioctl:0xREQ (deny by default).")
        .fd(0)
        .refs(&[out(2, Len::Ioctl)]),
    Row::new(G, nr::POLL, Attempt, A, POLL).outs(&[out(0, Len::ArgTimes { arg: 1, size: 8 })]),
    Row::new(G, nr::PPOLL, Attempt, A, POLL).outs(&[out(0, Len::ArgTimes { arg: 1, size: 8 })]).refs(&[out(2, Len::Fixed(16)), out(3, Len::Arg(4))]),
    Row::new(G, nr::SELECT, Attempt, A, POLL).refs(&[out(1, Len::FdSet { nfds: 0 }), out(2, Len::FdSet { nfds: 0 }), out(3, Len::FdSet { nfds: 0 }), out(4, Len::Fixed(16))]),
    Row::new(G, nr::PSELECT6, Attempt, A, POLL).refs(&[out(1, Len::FdSet { nfds: 0 }), out(2, Len::FdSet { nfds: 0 }), out(3, Len::FdSet { nfds: 0 }), out(4, Len::Fixed(16)), out(5, Len::SigPair)]),
    Row::new(G, nr::EPOLL_CREATE, Pass, A, NEWFD),
    Row::new(G, nr::EPOLL_CREATE1, Pass, A, NEWFD),
    Row::new(G, nr::EPOLL_CTL, Pass, A, "The interest list is per-epoll kernel state changed only by sandbox calls; EPOLLET, EPOLLONESHOT and EPOLLEXCLUSIVE pass. A change moves the I/O generation (a waiter on this epoll may now be ready).").fd(0).fd(2).ins(&[out(3, Len::Fixed(crate::abi::EPOLL_EVENT_SIZE))]),
    Row::new(G, nr::EPOLL_WAIT, Attempt, A, EPWAIT).fd(0).outs(&[out(1, Len::RetTimes { max: 2, size: crate::abi::EPOLL_EVENT_SIZE })]),
    Row::new(G, nr::EPOLL_PWAIT, Attempt, A, EPWAIT).fd(0).outs(&[out(1, Len::RetTimes { max: 2, size: crate::abi::EPOLL_EVENT_SIZE })]).refs(&[out(4, Len::Arg(5))]),
    Row::new(G, nr::EPOLL_PWAIT2, Attempt, A, EPWAIT).fd(0).outs(&[out(1, Len::RetTimes { max: 2, size: crate::abi::EPOLL_EVENT_SIZE })]).refs(&[out(3, Len::Fixed(16)), out(4, Len::Arg(5))]),
    Row::new(G, nr::TIMERFD_CREATE, Virt, C, TFD),
    Row::new(G, nr::TIMERFD_SETTIME, Virt, C, TFD).fd(0).outs(&[out(3, Len::Fixed(32))]).refs(&[out(2, Len::Fixed(32))]),
    Row::new(G, nr::TIMERFD_GETTIME, Virt, C, TFD).fd(0).outs(&[out(1, Len::Fixed(32))]),
    Row::new(G, nr::VMSPLICE, Attempt, A, "Moves user memory into or out of a pipe: an attempt with SPLICE_F_NONBLOCK (it acts on the pipe only), parked until the I/O generation moves.").fd(0).refs(&[out(1, Len::IovRet { cnt: 2 })]),
];
