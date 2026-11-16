//! Sockets. `AF_UNIX` (stream, datagram, seqpacket) is a pass-through kernel object with
//! attempt semantics: every call that could wait is made in a form that cannot
//! (`MSG_DONTWAIT`, `RWF_NOWAIT`, a zero-timeout `poll` before `accept4`) and parks in the
//! supervisor if it would. Other families end the run (`AF_INET`/`AF_INET6` are the network wire).
use super::misc::n;
use super::*;

const G: Group = Group::Net;

const UNIX: &str = "AF_UNIX objects are created in the sandbox and changed only by sandbox calls; readiness and byte movement are synchronous effects of those calls. Path names resolve in the sandbox's filesystems; abstract names live in the sandbox's network namespace.";
const CREATE: &str = "AF_UNIX only: a descriptor at the lowest free number; SO_SNDBUF and SO_RCVBUF are set to fixed sizes at creation so that host defaults are not an input; the inode number (host-global) is only ever shown virtualised. Other families end the run (AF_INET/AF_INET6: the network wire).";
const SEND: &str = "AF_UNIX: an attempt with MSG_DONTWAIT; would-block parks until the I/O generation moves, and a partial count on a blocking stream socket is continued so the call returns the full count (SO_SNDTIMEO is a virtual deadline). MSG_DONTWAIT or O_NONBLOCK from the guest: one attempt. SCM_RIGHTS and SCM_CREDENTIALS pass; a hidden descriptor in SCM_RIGHTS answers EBADF.";
const RECV: &str = "AF_UNIX: an attempt with MSG_DONTWAIT; would-block parks until the I/O generation moves; SO_RCVTIMEO is a virtual deadline, then EAGAIN; MSG_WAITALL is continued until the full count, end of stream or a signal. MSG_DONTWAIT or O_NONBLOCK from the guest: one attempt.";
const META: &str = "Names, options and peer credentials of AF_UNIX sockets are sandbox state (namespace PIDs and ids); an autobind name is chosen by the runtime from a run counter instead of the kernel's random one. Socket options of AF_UNIX sockets are an allowlist on SOL_SOCKET (buffer sizes, timeouts, low-water marks, linger, keepalive, reuse, priority, peek offset, passcred; and to read: type, error, domain, protocol, acceptconn, peercred); any other level or name answers ENOPROTOOPT and is recorded as sockopt:LEVEL:NAME (deny by default; wire sockets have their own table).";

pub const ROWS: &[Row] = &[
    Row::new(G, n(41, "socket"), Attempt, A, CREATE),
    Row::new(G, n(53, "socketpair"), Attempt, A, CREATE).outs(&[out(3, Len::Fixed(8))]),
    Row::new(G, n(49, "bind"), Attempt, A, "AF_UNIX: a path creates a socket file on a sandbox filesystem (a function of sandbox history); an abstract name is confined to the sandbox's network namespace. An autobind request (address of family only) gets a name from a run counter, not the kernel's random choice.").fd(0).ins(&[out(1, Len::Arg(2))]),
    Row::new(G, n(50, "listen"), Attempt, A, UNIX).fd(0),
    Row::new(G, n(43, "accept"), Attempt, A, "AF_UNIX: a zero-timeout poll for a pending connection, then accept4 (which then cannot wait), without changing the listening description; parks until the I/O generation moves. The new socket's buffer sizes are fixed as at creation.").fd(0),
    Row::new(G, n(288, "accept4"), Attempt, A, "AF_UNIX: a zero-timeout poll for a pending connection, then accept4 (which then cannot wait), without changing the listening description; parks until the I/O generation moves. The new socket's buffer sizes are fixed as at creation.").fd(0),
    Row::new(G, n(42, "connect"), Attempt, A, "AF_UNIX: a connect that cannot wait (the description is made non-blocking for the duration of the call only; no other guest thread runs meanwhile, so nobody can observe it); a full backlog (EAGAIN) parks until the I/O generation moves; the answer is a function of the sandbox's files and listeners.")
        .fd(0)
        .ins(&[out(1, Len::Arg(2))]),
    Row::new(G, n(51, "getsockname"), Attempt, A, META).fd(0),
    Row::new(G, n(52, "getpeername"), Attempt, A, META).fd(0),
    Row::new(G, n(54, "setsockopt"), Attempt, A, META).fd(0).ins(&[out(3, Len::Arg(4))]),
    Row::new(G, n(55, "getsockopt"), Attempt, A, META).fd(0),
    Row::new(G, n(48, "shutdown"), Attempt, A, UNIX).fd(0),
    Row::new(G, n(44, "sendto"), Attempt, A, SEND).fd(0).ins(&[out(1, Len::Ret)]),
    Row::new(G, n(46, "sendmsg"), Attempt, A, SEND).fd(0).ins(&[out(1, Len::MsgIovRet)]),
    Row::new(G, n(307, "sendmmsg"), Attempt, A, SEND).fd(0),
    Row::new(G, n(45, "recvfrom"), Attempt, A, RECV).fd(0).outs(&[out(1, Len::Ret)]),
    Row::new(G, n(47, "recvmsg"), Attempt, A, RECV).fd(0).outs(&[out(1, Len::MsgIovRet)]),
    Row::new(G, n(299, "recvmmsg"), Attempt, A, "AF_UNIX: as recvmsg for each message (MSG_DONTWAIT attempts, park while nothing is available); a blocking call returns once at least one message arrived, as with MSG_WAITFORONE. The timeout argument is a virtual deadline.").fd(0),
];
