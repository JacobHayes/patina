//! Socket creation and address rows.

use super::*;

impl Probe {
    // ---- sockets -----------------------------------------------------------

    pub fn socket(&self, domain: i32, kind: i32, protocol: i32) -> i32 {
        let result = self.call(
            Syscall::N_socket,
            [domain as i64, kind as i64, protocol as i64, 0, 0, 0],
        );
        self.event(Syscall::N_socket, result)
            .arg("domain", domain)
            .arg("type", kind)
            .arg("protocol", protocol)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    pub fn listen(&self, fd: i32, backlog: i32) -> i64 {
        let result = self.call(Syscall::N_listen, [fd as i64, backlog as i64, 0, 0, 0, 0]);
        let builder = self.event(Syscall::N_listen, result);
        self.fd_arg(builder, "fd", fd)
            .arg("backlog", backlog)
            .emit();
        result
    }

    pub fn shutdown(&self, fd: i32, how: i32) -> i64 {
        let result = self.call(Syscall::N_shutdown, [fd as i64, how as i64, 0, 0, 0, 0]);
        let builder = self.event(Syscall::N_shutdown, result);
        self.fd_arg(builder, "fd", fd).arg("how", how).emit();
        result
    }

    // ---- addresses ---------------------------------------------------------
    /// An AF_UNIX path under the run directory, required to fit `sun_path`
    /// (a deep `TMPDIR` leaves no room: the scenario cannot run there).
    pub fn unix_path(&self, name: &str) -> String {
        let path = format!("{}/{name}", self.dir());
        self.require(
            &format!("the AF_UNIX path {path:?} fits sun_path ({SUN_PATH_MAX} bytes with its NUL)"),
            path.len() < SUN_PATH_MAX,
        );
        path
    }

    /// `bind` to any address.
    pub fn bind_to(&self, fd: i32, addr: &SockAddr) -> i64 {
        let (raw, len) = addr.encode();
        let result = self.call(
            Syscall::N_bind,
            [fd as i64, &raw as *const _ as i64, len as i64, 0, 0, 0],
        );
        let builder = self.fd_arg(self.event(Syscall::N_bind, result), "fd", fd);
        addr.record(builder, false, "addr")
            .arg("addrlen", len)
            .emit();
        result
    }

    /// `connect` to any address.
    pub fn connect_to(&self, fd: i32, addr: &SockAddr) -> i64 {
        let (raw, len) = addr.encode();
        let result = self.call(
            Syscall::N_connect,
            [fd as i64, &raw as *const _ as i64, len as i64, 0, 0, 0],
        );
        let builder = self.fd_arg(self.event(Syscall::N_connect, result), "fd", fd);
        addr.record(builder, false, "addr")
            .arg("addrlen", len)
            .emit();
        result
    }

    /// `getsockname` (or `getpeername`) of any family with a name buffer of
    /// `cap` bytes; the reported length is recorded (it exceeds `cap` when
    /// the name was truncated).
    pub fn name_of(&self, fd: i32, peer: bool, cap: u32) -> (i64, Option<SockAddr>, u32) {
        let row = if peer {
            Syscall::N_getpeername
        } else {
            Syscall::N_getsockname
        };
        // SAFETY: an all-zero sockaddr_storage is a valid value.
        let mut raw: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len = cap;
        let result = self.call(
            row,
            [
                fd as i64,
                &mut raw as *mut _ as i64,
                &mut len as *mut u32 as i64,
                0,
                0,
                0,
            ],
        );
        let addr = (result >= 0).then(|| SockAddr::decode(&raw, len.min(cap)));
        let builder = self
            .fd_arg(self.event(row, result), "fd", fd)
            .arg("cap", cap);
        let builder = match &addr {
            Some(addr) => addr.record(builder, true, "addr").field("addrlen", len),
            None => builder,
        };
        builder.emit();
        (result, addr, len)
    }

    /// `accept` (`legacy`: the `accept` row and symbol) or `accept4`, with a
    /// peer-name buffer when `want_addr`.
    pub fn accept_from(
        &self,
        fd: i32,
        flags: i32,
        legacy: bool,
        want_addr: bool,
    ) -> (i32, Option<SockAddr>) {
        // SAFETY: an all-zero sockaddr_storage is a valid value.
        let mut raw: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        let (addr_ptr, len_ptr) = if want_addr {
            (&mut raw as *mut _ as i64, &mut len as *mut u32 as i64)
        } else {
            (0, 0)
        };
        let row = if legacy {
            Syscall::N_accept
        } else {
            Syscall::N_accept4
        };
        let result = self.call(row, [fd as i64, addr_ptr, len_ptr, flags as i64, 0, 0]);
        let peer = (result >= 0 && want_addr).then(|| SockAddr::decode(&raw, len));
        let builder = self.fd_arg(self.event(row, result), "fd", fd);
        let builder = if legacy {
            builder
        } else {
            builder.arg("flags", flags)
        };
        let builder = builder
            .arg("want_addr", want_addr)
            .norm("ret", Norm::Relative("fd"));
        let builder = match &peer {
            Some(peer) => peer.record(builder, true, "peer").field("addrlen", len),
            None => builder,
        };
        builder.emit();
        (result as i32, peer)
    }

    /// `sendto` with any destination (`None` passes NULL).
    pub fn send_to(&self, fd: i32, data: &[u8], flags: i32, to: Option<&SockAddr>) -> i64 {
        let encoded = to.map(SockAddr::encode);
        let (ptr, len) = encoded.as_ref().map_or((0, 0), |(raw, len)| {
            (raw as *const _ as i64, i64::from(*len))
        });
        let result = self.call(
            Syscall::N_sendto,
            [
                fd as i64,
                data.as_ptr() as i64,
                data.len() as i64,
                flags as i64,
                ptr,
                len,
            ],
        );
        let builder = self
            .fd_arg(self.event(Syscall::N_sendto, result), "fd", fd)
            .arg("len", data.len())
            .arg("flags", flags);
        match to {
            Some(to) => to.record(builder, false, "addr").emit(),
            None => builder.arg("addr", Value::Null).emit(),
        }
        result
    }

    /// `recvfrom` of any family, with a source-name buffer when `want_addr`.
    pub fn recv_from(
        &self,
        fd: i32,
        len: usize,
        flags: i32,
        want_addr: bool,
    ) -> (i64, Vec<u8>, Option<SockAddr>) {
        let mut buf = vec![0u8; len];
        // SAFETY: an all-zero sockaddr_storage is a valid value.
        let mut raw: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut alen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        let (aptr, lptr) = if want_addr {
            (&mut raw as *mut _ as i64, &mut alen as *mut u32 as i64)
        } else {
            (0, 0)
        };
        let result = self.call(
            Syscall::N_recvfrom,
            [
                fd as i64,
                buf.as_mut_ptr() as i64,
                len as i64,
                flags as i64,
                aptr,
                lptr,
            ],
        );
        // MSG_TRUNC on a datagram answers the full length, past the buffer.
        buf.truncate(if result >= 0 {
            (result as usize).min(len)
        } else {
            0
        });
        let from = (result >= 0 && want_addr).then(|| SockAddr::decode(&raw, alen));
        let builder = self
            .fd_arg(self.event(Syscall::N_recvfrom, result), "fd", fd)
            .arg("len", len)
            .arg("flags", flags)
            .arg("want_addr", want_addr);
        let builder = if result >= 0 {
            builder.field("data", printable(&buf))
        } else {
            builder
        };
        let builder = match &from {
            Some(from) => from.record(builder, true, "src").field("addrlen", alen),
            None => builder,
        };
        builder.emit();
        (result, buf, from)
    }

    /// `send(3)`: glibc's `send` under the libc vehicle, the `sendto` row
    /// with no address (glibc's own spelling) otherwise.
    pub fn send(&self, fd: i32, data: &[u8], flags: i32) -> i64 {
        let args = [
            fd as i64,
            data.as_ptr() as i64,
            data.len() as i64,
            flags as i64,
            0,
            0,
        ];
        let result = match self.vehicle {
            // SAFETY: the buffer holds `data.len()` bytes.
            Vehicle::Libc => {
                fold_errno(
                    unsafe { libc::send(fd, data.as_ptr().cast(), data.len(), flags) } as i64,
                )
            }
            _ => self.call(Syscall::N_sendto, args),
        };
        self.fd_arg(self.rec.event("send", result), "fd", fd)
            .arg("len", data.len())
            .arg("flags", flags)
            .emit();
        result
    }

    /// `recv(3)`: glibc's `recv` under the libc vehicle, the `recvfrom` row
    /// with no address otherwise.
    pub fn recv(&self, fd: i32, len: usize, flags: i32) -> (i64, Vec<u8>) {
        let mut buf = vec![0u8; len];
        let args = [
            fd as i64,
            buf.as_mut_ptr() as i64,
            len as i64,
            flags as i64,
            0,
            0,
        ];
        let result = match self.vehicle {
            // SAFETY: the buffer holds `len` bytes.
            Vehicle::Libc => {
                fold_errno(unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), len, flags) } as i64)
            }
            _ => self.call(Syscall::N_recvfrom, args),
        };
        buf.truncate(if result >= 0 {
            (result as usize).min(len)
        } else {
            0
        });
        let builder = self
            .fd_arg(self.rec.event("recv", result), "fd", fd)
            .arg("len", len)
            .arg("flags", flags);
        let builder = if result >= 0 {
            builder.field("data", printable(&buf))
        } else {
            builder
        };
        builder.emit();
        (result, buf)
    }
}
