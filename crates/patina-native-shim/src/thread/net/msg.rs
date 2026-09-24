//! Message calls: `sendmsg`/`recvmsg` and, on Linux, their batch forms
//! `sendmmsg`/`recvmmsg` (net/socket.c `___sys_sendmsg`, `___sys_recvmsg`,
//! `__sys_sendmmsg`, `do_recvmmsg`; net/core/scm.c).
//!
//! The header, the iovecs and the control messages are copied in the
//! kernel's order and with its refusals (`EMSGSIZE` past `UIO_MAXIOV` iovecs,
//! `EINVAL` for a negative segment, `EFAULT` for what cannot be read); the
//! bytes gathered from every iovec are ONE message, and a receive scatters
//! what arrives over the segments in order. Control messages are the
//! `SOL_SOCKET` ones `__scm_send` takes — `SCM_RIGHTS` (descriptors whose
//! open file descriptions travel with the message) and `SCM_CREDENTIALS`
//! (checked against the one unprivileged process, `scm_check_creds`) — on
//! the families that carry them; on the way out they are laid into the
//! caller's control buffer as `put_cmsg` and `scm_detach_fds` lay them,
//! `MSG_CTRUNC` for what does not fit.

use super::*;

/// `struct msghdr`'s layout.
#[cfg(target_os = "linux")]
mod layout {
    pub(super) const MSGHDR: usize = 56;
    pub(super) const NAME: usize = 0;
    pub(super) const NAMELEN: usize = 8;
    pub(super) const IOV: usize = 16;
    pub(super) const IOVLEN: usize = 24;
    pub(super) const CONTROL: usize = 32;
    pub(super) const CONTROLLEN: usize = 40;
    pub(super) const FLAGS: usize = 48;
    /// `struct mmsghdr`: the header, then `msg_len`.
    pub(super) const MMSGHDR: usize = 64;
    /// `struct cmsghdr`: a `size_t` length, the level and the type.
    pub(super) const CMSGHDR: usize = 16;
    pub(super) const CMSG_ALIGN: usize = 8;
}

#[cfg(target_os = "macos")]
mod layout {
    pub(super) const MSGHDR: usize = 48;
    pub(super) const NAME: usize = 0;
    pub(super) const NAMELEN: usize = 8;
    pub(super) const IOV: usize = 16;
    pub(super) const IOVLEN: usize = 24;
    pub(super) const CONTROL: usize = 32;
    pub(super) const CONTROLLEN: usize = 40;
    pub(super) const FLAGS: usize = 44;
    pub(super) const CMSGHDR: usize = 12;
    pub(super) const CMSG_ALIGN: usize = 4;
}

use layout::*;

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn usize_at(bytes: &[u8], at: usize) -> usize {
    usize::from_ne_bytes(bytes[at..at + 8].try_into().unwrap())
}

/// The iovec length field and the control length field, by width.
#[cfg(target_os = "linux")]
fn iovlen(header: &[u8]) -> usize {
    usize_at(header, IOVLEN)
}
#[cfg(target_os = "macos")]
fn iovlen(header: &[u8]) -> usize {
    u32_at(header, IOVLEN) as i32 as isize as usize
}
#[cfg(target_os = "linux")]
fn controllen(header: &[u8]) -> usize {
    usize_at(header, CONTROLLEN)
}
#[cfg(target_os = "macos")]
fn controllen(header: &[u8]) -> usize {
    u32_at(header, CONTROLLEN) as usize
}

fn cmsg_align(len: usize) -> usize {
    len.div_ceil(CMSG_ALIGN) * CMSG_ALIGN
}

/// `CMSG_LEN`/`CMSG_SPACE`.
fn cmsg_len(data: usize) -> usize {
    CMSG_ALIGN_HDR + data
}
fn cmsg_space(data: usize) -> usize {
    CMSG_ALIGN_HDR + cmsg_align(data)
}
const CMSG_ALIGN_HDR: usize = CMSGHDR.div_ceil(CMSG_ALIGN) * CMSG_ALIGN;

/// A header's fields.
struct Header {
    name: usize,
    namelen: i32,
    iov: usize,
    iovlen: usize,
    control: usize,
    controllen: usize,
}

fn header(addr: usize) -> Result<Header, c_int> {
    let bytes = uaccess::read_bytes(addr, MSGHDR)?;
    Ok(Header {
        name: usize_at(&bytes, NAME),
        namelen: u32_at(&bytes, NAMELEN) as i32,
        iov: usize_at(&bytes, IOV),
        iovlen: iovlen(&bytes),
        control: usize_at(&bytes, CONTROL),
        controllen: controllen(&bytes),
    })
}

/// `import_iovec`: every segment, `EMSGSIZE` past `UIO_MAXIOV`, `EINVAL` for
/// a length negative as an `ssize_t`.
fn iovecs(iov: usize, count: usize) -> Result<Vec<(usize, usize)>, c_int> {
    if count > UIO_MAXIOV {
        return Err(EMSGSIZE);
    }
    let raw = uaccess::read_bytes(iov, count * 16)?;
    let segments: Vec<(usize, usize)> = raw
        .chunks_exact(16)
        .map(|segment| (usize_at(segment, 0), usize_at(segment, 8)))
        .collect();
    if segments
        .iter()
        .any(|(_, len)| isize::try_from(*len).is_err())
    {
        return Err(EINVAL);
    }
    Ok(segments)
}

/// `__scm_send` over the control buffer: the descriptors (retained) and the
/// stated credentials, for a family that carries them.
/// A control message at a protocol level (`SOL_IP`, `SOL_IPV6`, `SOL_UDP`):
/// its level, type and data, for the protocol to read once the destination
/// is known.
pub(crate) type ProtocolCmsg = (c_int, c_int, Vec<u8>);

/// What a send's control buffer carries: descriptors in flight (retained),
/// stated credentials, and the protocol-level messages.
type Control = (Vec<DescId>, Option<Creds>, Vec<ProtocolCmsg>);

fn control(handle: c_int, bytes: &[u8]) -> Result<Control, c_int> {
    let carrier = {
        let state = lock_state();
        let socket = state.net.sockets.table.get(&handle).ok_or(crate::EBADF)?;
        match &socket.proto {
            Proto::Unix(_) => Carrier::Unix,
            #[cfg(target_os = "linux")]
            Proto::Netlink(_) => Carrier::Netlink,
            Proto::Inet(_) => Carrier::Inet {
                datagram: socket.ty == SOCK_DGRAM,
            },
        }
    };
    let unix = matches!(carrier, Carrier::Unix);
    // Credentials are Linux's `SCM_CREDENTIALS` (AF_UNIX and netlink).
    #[cfg(target_os = "linux")]
    let carries_creds = !matches!(carrier, Carrier::Inet { .. });
    let mut rights = Vec::new();
    let mut protocol = Vec::new();
    #[cfg(target_os = "linux")]
    let mut creds = None;
    #[cfg(target_os = "macos")]
    let creds = None;
    let parsed = (|| {
        let mut at = 0;
        while bytes.len() >= at + CMSGHDR {
            #[cfg(target_os = "linux")]
            let len = usize_at(bytes, at);
            #[cfg(target_os = "macos")]
            let len = u32_at(bytes, at) as usize;
            let level = u32_at(bytes, at + CMSGHDR - 8) as i32;
            let kind = u32_at(bytes, at + CMSGHDR - 4) as i32;
            // `CMSG_OK`.
            if len < CMSGHDR || len > bytes.len() - at {
                return Err(EINVAL);
            }
            let data = &bytes[at + CMSG_ALIGN_HDR.min(len)..at + len];
            if let Carrier::Inet { datagram } = carrier {
                if level == SOL_SOCKET {
                    inet_socket_control(datagram, kind)?;
                } else if datagram {
                    // The datagram protocols read their own levels once the
                    // destination's family is known (`udp_sendmsg`,
                    // `udpv6_sendmsg`); a stream skips them.
                    protocol.push((level, kind, data.to_vec()));
                }
            } else if level == SOL_SOCKET {
                match kind {
                    SCM_RIGHTS if unix => {
                        let count = data.len() / 4;
                        if rights.len() + count > SCM_MAX_FD {
                            return Err(EINVAL);
                        }
                        for fd in data.chunks_exact(4) {
                            let fd = i32::from_ne_bytes(fd.try_into().unwrap());
                            let desc = crate::fd_table()
                                .lock()
                                .resolve(fd)
                                .ok_or(crate::EBADF)?
                                .desc;
                            crate::fd_table().lock().retain(desc)?;
                            rights.push(desc);
                        }
                    }
                    #[cfg(target_os = "linux")]
                    SCM_CREDENTIALS if carries_creds => {
                        if len != cmsg_len(12) {
                            return Err(EINVAL);
                        }
                        let pid = u32_at(data, 0) as i32;
                        let uid = u32_at(data, 4);
                        let gid = u32_at(data, 8);
                        if uid == u32::MAX || gid == u32::MAX {
                            return Err(EINVAL);
                        }
                        // `scm_check_creds`: the caller's own pid and ids;
                        // anything else needs capabilities it lacks.
                        if pid != Creds::PROCESS.pid
                            || uid != Creds::PROCESS.uid
                            || gid != Creds::PROCESS.gid
                        {
                            return Err(crate::EPERM);
                        }
                        creds = Some(Creds { pid, uid, gid });
                    }
                    _ => return Err(EINVAL),
                }
            }
            // AF_UNIX and netlink skip every other level.
            at += cmsg_align(len);
        }
        Ok(())
    })();
    match parsed {
        Ok(()) => Ok((rights, creds, protocol)),
        Err(errno) => {
            release_rights(&rights);
            Err(errno)
        }
    }
}

/// `net.core.optmem_max`'s default: the largest control buffer a send takes.
const OPTMEM_MAX: usize = 131_072;

/// Who reads a control buffer: `__scm_send` for AF_UNIX (rights and
/// credentials) and netlink (credentials); the inet protocols their own way.
#[derive(Clone, Copy)]
enum Carrier {
    Unix,
    #[cfg(target_os = "linux")]
    Netlink,
    Inet {
        datagram: bool,
    },
}

/// `SOL_SOCKET` control messages an inet socket takes (`__sock_cmsg_send`).
#[cfg(target_os = "linux")]
mod inet_cmsg {
    pub(super) const SO_MARK: i32 = 36;
    pub(super) const SO_TIMESTAMPING_OLD: i32 = 37;
    pub(super) const SCM_TXTIME: i32 = 61;
    pub(super) const SCM_TS_OPT_ID: i32 = 81;
}

/// One socket-level control message on an inet socket (`__sock_cmsg_send`;
/// a stream's `sock_cmsg_send` answers any error `EINVAL`). The marks need
/// `CAP_NET_ADMIN`; timestamping and transmit times are not modeled and fail
/// closed by name.
fn inet_socket_control(datagram: bool, kind: i32) -> Result<(), c_int> {
    #[cfg(target_os = "linux")]
    {
        use inet_cmsg::*;
        match kind {
            SO_MARK if datagram => Err(crate::EPERM),
            SO_TIMESTAMPING_OLD | SCM_TXTIME | SCM_TS_OPT_ID => fatal(&format!(
                "socket-level ancillary data type {kind} (timestamping, transmit time) on an \
                 inet socket is not modeled; failing closed"
            )),
            _ => Err(EINVAL),
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (datagram, kind);
        Err(EINVAL)
    }
}

/// One `___sys_sendmsg` on a socket already looked up: the header at `msg`
/// sent through `handle`.
fn send_one(handle: c_int, nonblocking: bool, msg: usize, flags: c_int) -> Result<usize, c_int> {
    let header = header(msg)?;
    let namelen = if header.name == 0 { 0 } else { header.namelen };
    if namelen < 0 {
        return Err(EINVAL);
    }
    let to = if header.name != 0 && namelen > 0 {
        Some(super::addr::copy_in(
            header.name,
            i64::from(namelen).min(SOCKADDR_STORAGE_LEN as i64),
        )?)
    } else {
        None
    };
    let segments = iovecs(header.iov, header.iovlen)?;
    // `sock_kmalloc`: a control buffer past `net.core.optmem_max` (its
    // default) is refused before it is copied.
    if header.controllen > OPTMEM_MAX {
        return Err(ENOBUFS);
    }
    let control_bytes = if header.controllen > 0 {
        uaccess::read_bytes(header.control, header.controllen)?
    } else {
        Vec::new()
    };
    let (rights, creds, protocol) = control(handle, &control_bytes)?;
    let message = Outgoing {
        protocol,
        data: Payload::gathered(segments),
        to,
        rights,
        creds,
        flags: with_nonblock(flags, nonblocking),
    };
    send_message(handle, message)
}

/// `sendmsg(2)`.
#[unsafe(no_mangle)]
pub extern "C" fn patina_sock_sendmsg(fd: c_int, msg: usize, flags: c_int) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    errno_result((|| {
        sched_point()?;
        let (handle, nonblocking) = lookup(fd)?;
        send_one(handle, nonblocking, msg, flags).map(|sent| sent as i64)
    })())
}

/// Lay one control message into the guest's buffer at `*at` (`put_cmsg`):
/// truncated, with `MSG_CTRUNC`, when it does not fit.
fn put_cmsg(
    buffer: usize,
    room: usize,
    used: &mut usize,
    flags: &mut c_int,
    level: c_int,
    kind: c_int,
    data: &[u8],
) -> Result<(), c_int> {
    let left = room - *used;
    if buffer == 0 || left < CMSGHDR {
        *flags |= MSG_CTRUNC;
        return Ok(());
    }
    let mut len = cmsg_len(data.len());
    if left < len {
        *flags |= MSG_CTRUNC;
        len = left;
    }
    let mut bytes = cmsg_header(len, level, kind);
    bytes.extend_from_slice(&data[..len - CMSG_ALIGN_HDR]);
    uaccess::write_bytes(buffer + *used, &bytes)?;
    *used += cmsg_space(data.len()).min(left);
    Ok(())
}

/// A `struct cmsghdr` of `len` at `level`, padded to its alignment.
fn cmsg_header(len: usize, level: c_int, kind: c_int) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CMSG_ALIGN_HDR);
    #[cfg(target_os = "linux")]
    bytes.extend(len.to_ne_bytes());
    #[cfg(target_os = "macos")]
    bytes.extend((len as u32).to_ne_bytes());
    bytes.extend(level.to_ne_bytes());
    bytes.extend(kind.to_ne_bytes());
    bytes.resize(CMSG_ALIGN_HDR, 0);
    bytes
}

/// `scm_detach_fds`: install as many of the received descriptors as the
/// buffer has room for (close-on-exec under `MSG_CMSG_CLOEXEC`), drop the
/// rest, `MSG_CTRUNC` when any did not fit.
fn detach_fds(
    buffer: usize,
    room: usize,
    used: &mut usize,
    flags: &mut c_int,
    rights: &[DescId],
    cloexec: bool,
) -> Result<(), c_int> {
    let left = room - *used;
    let fits = if left <= CMSGHDR {
        0
    } else {
        (left - CMSGHDR) / 4
    };
    let count = fits.min(rights.len());
    let mut fds = Vec::with_capacity(count);
    for desc in &rights[..count] {
        match crate::fd_table().lock().install_existing(*desc, cloexec) {
            Ok(fd) => fds.push(fd),
            Err(_) => break,
        }
    }
    if !fds.is_empty() {
        let len = cmsg_len(fds.len() * 4);
        let mut bytes = cmsg_header(len, SOL_SOCKET, SCM_RIGHTS);
        for fd in &fds {
            bytes.extend(fd.to_ne_bytes());
        }
        uaccess::write_bytes(buffer + *used, &bytes)?;
        *used += cmsg_space(fds.len() * 4).min(left);
    }
    if fds.len() < rights.len() {
        *flags |= MSG_CTRUNC;
    }
    // The installed numbers hold their own references now; every in-flight
    // one goes.
    release_rights(rights);
    Ok(())
}

/// One `___sys_recvmsg` on a socket already looked up: the message received
/// into the header at `msg`; the call's answer.
fn recv_one(handle: c_int, nonblocking: bool, msg: usize, flags: c_int) -> Result<usize, c_int> {
    let header = header(msg)?;
    let segments = iovecs(header.iov, header.iovlen)?;
    let capacity = segments
        .iter()
        .fold(0usize, |total, (_, len)| total.saturating_add(*len))
        .min(MAX_RW_COUNT);
    let want = Want {
        capacity,
        flags: with_nonblock(flags, nonblocking),
    };
    let incoming = recv_message(handle, want)?;
    let mut at = 0;
    for &(base, len) in &segments {
        if at == incoming.data.len() {
            break;
        }
        let take = len.min(incoming.data.len() - at);
        uaccess::write_bytes(base, &incoming.data[at..at + take])?;
        at += take;
    }
    if header.name != 0 {
        let from = incoming.from.as_deref().unwrap_or(&[]);
        super::addr::copy_out(from, header.name, msg + NAMELEN)?;
    }
    // `____sys_recvmsg` starts the returned flags from the caller's
    // `MSG_CMSG_*` bits; the protocol adds its own.
    let mut msg_flags = cmsg_flags(flags) | incoming.flags;
    let mut used = 0;
    let room = if header.control == 0 {
        0
    } else {
        header.controllen
    };
    if header.control == 0 {
        if incoming.creds.is_some() || !incoming.rights.is_empty() || !incoming.control.is_empty() {
            msg_flags |= MSG_CTRUNC;
        }
        release_rights(&incoming.rights);
    } else {
        for (level, kind, data) in &incoming.control {
            put_cmsg(
                header.control,
                room,
                &mut used,
                &mut msg_flags,
                *level,
                *kind,
                data,
            )?;
        }
        #[cfg(target_os = "linux")]
        if let Some(creds) = incoming.creds {
            put_cmsg(
                header.control,
                room,
                &mut used,
                &mut msg_flags,
                SOL_SOCKET,
                SCM_CREDENTIALS,
                &creds.bytes(),
            )?;
        }
        if !incoming.rights.is_empty() {
            detach_fds(
                header.control,
                room,
                &mut used,
                &mut msg_flags,
                &incoming.rights,
                cmsg_flags(flags) != 0,
            )?;
        }
    }
    uaccess::write(msg + FLAGS, &msg_flags)?;
    #[cfg(target_os = "linux")]
    uaccess::write(msg + CONTROLLEN, &used)?;
    #[cfg(target_os = "macos")]
    uaccess::write(msg + CONTROLLEN, &(used as u32))?;
    Ok(incoming.len)
}

/// The caller's `MSG_CMSG_*` bits (`MSG_CMSG_MASK`): close-on-exec for the
/// descriptors a receive installs. Darwin has none.
#[cfg(target_os = "linux")]
fn cmsg_flags(flags: c_int) -> c_int {
    flags & MSG_CMSG_CLOEXEC
}
#[cfg(target_os = "macos")]
fn cmsg_flags(_flags: c_int) -> c_int {
    0
}

/// `recvmsg(2)`.
#[unsafe(no_mangle)]
pub extern "C" fn patina_sock_recvmsg(fd: c_int, msg: usize, flags: c_int) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    errno_result((|| {
        sched_point()?;
        let (handle, nonblocking) = lookup(fd)?;
        recv_one(handle, nonblocking, msg, flags).map(|len| len as i64)
    })())
}

/// `sendmmsg(2)`: up to `UIO_MAXIOV` messages, each's sent length written
/// back; the count sent, or the first message's error when none was.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn patina_sock_sendmmsg(fd: c_int, vec: usize, vlen: u32, flags: c_int) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    errno_result((|| {
        sched_point()?;
        let vlen = (vlen as usize).min(UIO_MAXIOV);
        let (handle, nonblocking) = lookup(fd)?;
        let mut sent = 0;
        let mut error = None;
        while sent < vlen {
            let entry = vec + sent * MMSGHDR;
            match send_one(handle, nonblocking, entry, flags) {
                Ok(len) => {
                    if let Err(errno) = uaccess::write(entry + MSGHDR, &(len as u32)) {
                        error = Some(errno);
                        break;
                    }
                    sent += 1;
                }
                Err(errno) => {
                    error = Some(errno);
                    break;
                }
            }
        }
        match error {
            Some(errno) if sent == 0 => Err(errno),
            _ => Ok(sent as i64),
        }
    })())
}

/// `MSG_WAITFORONE`: after the first message a batch receive stops waiting.
#[cfg(target_os = "linux")]
const MSG_WAITFORONE_FLAG: c_int = MSG_WAITFORONE;

/// `recvmmsg(2)` (`do_recvmmsg`): the messages received, each's length
/// written back. An invalid timeout is refused before anything; the
/// timeout is checked after each message; an error after the first is left
/// pending on the socket (unless it is `EAGAIN`).
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn patina_sock_recvmmsg(
    fd: c_int,
    vec: usize,
    vlen: u32,
    flags: c_int,
    timeout: usize,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    errno_result((|| {
        let end = if timeout == 0 {
            None
        } else {
            let [sec, nsec]: [i64; 2] = uaccess::read(timeout)?;
            if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
                return Err(EINVAL);
            }
            Some(now()?.saturating_add((sec as u64).saturating_mul(1_000_000_000) + nsec as u64))
        };
        sched_point()?;
        let vlen = (vlen as usize).min(UIO_MAXIOV);
        let (handle, nonblocking) = lookup(fd)?;
        if let Some(error) = lock_state()
            .net
            .sockets
            .table
            .get_mut(&handle)
            .and_then(Socket::take_error)
        {
            return Err(error);
        }
        let waitforone = flags & MSG_WAITFORONE_FLAG != 0;
        let mut flags = flags & !MSG_WAITFORONE_FLAG;
        let mut received = 0;
        let mut error = None;
        while received < vlen {
            let entry = vec + received * MMSGHDR;
            match recv_one(handle, nonblocking, entry, flags) {
                Ok(len) => {
                    uaccess::write(entry + MSGHDR, &(len as u32))?;
                    received += 1;
                }
                Err(errno) => {
                    error = Some(errno);
                    break;
                }
            }
            if waitforone {
                flags |= MSG_DONTWAIT;
            }
            if let Some(end) = end {
                let left = end.saturating_sub(now()?);
                uaccess::write(
                    timeout,
                    &[(left / 1_000_000_000) as i64, (left % 1_000_000_000) as i64],
                )?;
                if left == 0 {
                    break;
                }
            }
        }
        match error {
            Some(errno) if received == 0 => Err(errno),
            Some(errno) => {
                if errno != EWOULDBLOCK {
                    if let Some(socket) = lock_state().net.sockets.table.get_mut(&handle) {
                        socket.error = errno;
                    }
                }
                Ok(received as i64)
            }
            None => Ok(received as i64),
        }
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The socket level an inet socket takes: its marks need a capability a
    /// datagram's sender lacks; a stream answers every error `EINVAL`.
    #[test]
    fn inet_socket_control_answers_as_sock_cmsg_send() {
        assert_eq!(inet_socket_control(true, SCM_RIGHTS), Err(EINVAL));
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                inet_socket_control(true, inet_cmsg::SO_MARK),
                Err(crate::EPERM)
            );
            assert_eq!(inet_socket_control(false, inet_cmsg::SO_MARK), Err(EINVAL));
        }
    }
}
