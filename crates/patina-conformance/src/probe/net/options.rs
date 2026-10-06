//! Socket option rows.

use super::*;

impl Probe {
    // ---- options -----------------------------------------------------------

    /// `setsockopt` with `value`'s bytes and `optlen` (normally its length;
    /// a shorter one is an error row). `label` names the value as recorded.
    pub fn setsockopt_bytes(
        &self,
        fd: i32,
        level: i32,
        name: i32,
        value: &[u8],
        optlen: usize,
        label: &str,
    ) -> i64 {
        let result = self.call(
            Syscall::N_setsockopt,
            [
                fd as i64,
                level as i64,
                name as i64,
                value.as_ptr() as i64,
                optlen as i64,
                0,
            ],
        );
        self.fd_arg(self.event(Syscall::N_setsockopt, result), "fd", fd)
            .arg("level", level)
            .arg("name", name)
            .arg("value", label)
            .arg("optlen", optlen)
            .emit();
        result
    }

    /// `getsockopt` into a buffer of `cap` bytes (`optlen` in); answers the
    /// bytes the kernel reported and the `optlen` out. `Exact` records the
    /// bytes, `Hidden` only the length.
    pub fn getsockopt_bytes(
        &self,
        fd: i32,
        level: i32,
        name: i32,
        cap: usize,
        shown: OptionShown,
    ) -> (i64, Vec<u8>) {
        let mut buf = vec![0u8; cap.max(1)];
        let mut len = cap as u32;
        let result = self.call(
            Syscall::N_getsockopt,
            [
                fd as i64,
                level as i64,
                name as i64,
                buf.as_mut_ptr() as i64,
                &mut len as *mut u32 as i64,
                0,
            ],
        );
        buf.truncate(if result >= 0 {
            (len as usize).min(cap)
        } else {
            0
        });
        let builder = self
            .fd_arg(self.event(Syscall::N_getsockopt, result), "fd", fd)
            .arg("level", level)
            .arg("name", name)
            .arg("cap", cap);
        let builder = if result >= 0 {
            let builder = builder.field("optlen", len);
            match shown {
                OptionShown::Exact => builder.field(
                    "value",
                    buf.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                ),
                OptionShown::Hidden => builder,
            }
        } else {
            builder
        };
        builder.emit();
        (result, buf)
    }

    /// `getsockopt` of an int option whose value is the host's business (a
    /// buffer size the kernel derives from sysctls): the length is recorded,
    /// the value only returned for the scenario's relation checks.
    pub fn getsockopt_hidden(&self, fd: i32, level: i32, name: i32) -> (i64, i32) {
        let (result, bytes) = self.getsockopt_bytes(fd, level, name, 4, OptionShown::Hidden);
        let value = if bytes.len() == 4 {
            i32::from_ne_bytes(bytes[..4].try_into().unwrap())
        } else {
            0
        };
        (result, value)
    }

    /// `SO_PEERCRED`: the peer's pid, uid and gid when the connection was
    /// made, recorded as identities (the host's ids are its business; their
    /// relation to `getpid`/`getuid`/`getgid` is the scenario's check).
    pub fn peercred(&self, fd: i32) -> (i64, Option<(i32, u32, u32)>) {
        let mut creds = [0u8; 12];
        let mut len = creds.len() as u32;
        let result = self.call(
            Syscall::N_getsockopt,
            [
                fd as i64,
                libc::SOL_SOCKET as i64,
                libc::SO_PEERCRED as i64,
                creds.as_mut_ptr() as i64,
                &mut len as *mut u32 as i64,
                0,
            ],
        );
        let value = (result >= 0).then(|| {
            (
                i32::from_ne_bytes(creds[0..4].try_into().unwrap()),
                u32::from_ne_bytes(creds[4..8].try_into().unwrap()),
                u32::from_ne_bytes(creds[8..12].try_into().unwrap()),
            )
        });
        let builder = self
            .fd_arg(self.event(Syscall::N_getsockopt, result), "fd", fd)
            .arg("level", libc::SOL_SOCKET)
            .arg("name", libc::SO_PEERCRED);
        let builder = match value {
            Some((pid, uid, gid)) => builder
                .field("optlen", len)
                .field("pid", pid)
                .norm("fields.pid", Norm::Identity(Id::Process))
                .field("uid", uid)
                .norm("fields.uid", Norm::Identity(Id::User))
                .field("gid", gid)
                .norm("fields.gid", Norm::Identity(Id::Group)),
            None => builder,
        };
        builder.emit();
        (result, value)
    }

    /// `getsockopt` with the length word itself set to `optlen` (a negative
    /// length is an error row), a 16-byte buffer behind it.
    pub fn getsockopt_optlen(&self, fd: i32, level: i32, name: i32, optlen: i32) -> i64 {
        let mut buf = [0u8; 16];
        let mut len = optlen;
        let result = self.call(
            Syscall::N_getsockopt,
            [
                fd as i64,
                level as i64,
                name as i64,
                buf.as_mut_ptr() as i64,
                &mut len as *mut i32 as i64,
                0,
            ],
        );
        self.fd_arg(self.event(Syscall::N_getsockopt, result), "fd", fd)
            .arg("level", level)
            .arg("name", name)
            .arg("optlen", optlen)
            .emit();
        result
    }

    /// `setsockopt` of `optlen` bytes from a NULL `optval`.
    pub fn setsockopt_null(&self, fd: i32, level: i32, name: i32, optlen: usize) -> i64 {
        let result = self.call(
            Syscall::N_setsockopt,
            [fd as i64, level as i64, name as i64, 0, optlen as i64, 0],
        );
        self.fd_arg(self.event(Syscall::N_setsockopt, result), "fd", fd)
            .arg("level", level)
            .arg("name", name)
            .arg("value", "NULL")
            .arg("optlen", optlen)
            .emit();
        result
    }

    /// `getsockopt` into a 16-byte buffer with a NULL `optlen` pointer.
    pub fn getsockopt_null_len(&self, fd: i32, level: i32, name: i32) -> i64 {
        let mut buf = [0u8; 16];
        let result = self.call(
            Syscall::N_getsockopt,
            [
                fd as i64,
                level as i64,
                name as i64,
                buf.as_mut_ptr() as i64,
                0,
                0,
            ],
        );
        self.fd_arg(self.event(Syscall::N_getsockopt, result), "fd", fd)
            .arg("level", level)
            .arg("name", name)
            .arg("optlen", "NULL")
            .emit();
        result
    }
}
