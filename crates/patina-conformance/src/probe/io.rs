//! Descriptor, vectored I/O, durability, ioctl, and in-kernel copy rows.

use super::*;

impl Probe {
    // ---- descriptors --------------------------------------------------------

    pub fn pipe2(&self, flags: i32) -> (i64, [i32; 2]) {
        self.pipe2_wide(i64::from(flags))
    }

    /// `pipe2` with the full syscall register width, for kernel parameters
    /// whose declared prototype is narrower than the register.
    pub fn pipe2_wide(&self, flags: i64) -> (i64, [i32; 2]) {
        let mut fds = [-1i32; 2];
        let result = self.call(
            Syscall::N_pipe2,
            [fds.as_mut_ptr() as i64, flags, 0, 0, 0, 0],
        );
        let builder = self.event(Syscall::N_pipe2, result).arg("flags", flags);
        let builder = if result >= 0 {
            builder
                .field("read_end", fds[0])
                .norm("fields.read_end", Norm::Relative("fd"))
                .field("write_end", fds[1])
                .norm("fields.write_end", Norm::Relative("fd"))
        } else {
            builder
        };
        builder.emit();
        (result, fds)
    }

    /// `pipe2` to a caller-named output address, including NULL and protected
    /// mappings used by the fd copyout conformance cases.
    pub fn pipe2_to(&self, fds: &At, flags: i64) -> i64 {
        let result = self.call(Syscall::N_pipe2, [fds.raw as i64, flags, 0, 0, 0, 0]);
        self.event(Syscall::N_pipe2, result)
            .arg("fds", fds.label.as_str())
            .arg("flags", flags)
            .emit();
        result
    }

    /// `pipe(fds)`, or a NULL array (`null`). An x86_64 legacy row; the
    /// generic table's shape is `pipe2(fds, 0)`, and only the libc vehicle
    /// calls `pipe` itself there.
    pub fn pipe(&self, null: bool) -> (i64, [i32; 2]) {
        let mut fds = [-1i32; 2];
        let array = if null { 0 } else { fds.as_mut_ptr() as i64 };
        #[cfg(target_arch = "x86_64")]
        let result = self.call(Syscall::N_pipe, [array, 0, 0, 0, 0, 0]);
        #[cfg(not(target_arch = "x86_64"))]
        let result = self.legacy(
            // SAFETY: a two-int array, or NULL.
            || unsafe { libc::pipe(array as *mut i32) } as i64,
            Syscall::N_pipe2,
            [array, 0, 0, 0, 0, 0],
        );
        let builder = self
            .rec
            .event("pipe", result)
            .arg("fds", if null { "NULL" } else { "fds" });
        let builder = if result >= 0 && !null {
            builder
                .field("read_end", fds[0])
                .norm("fields.read_end", Norm::Relative("fd"))
                .field("write_end", fds[1])
                .norm("fields.write_end", Norm::Relative("fd"))
        } else {
            builder
        };
        builder.emit();
        (result, fds)
    }

    pub fn dup(&self, fd: i32) -> i64 {
        let result = self.call(Syscall::N_dup, [fd as i64, 0, 0, 0, 0, 0]);
        let builder = self.event(Syscall::N_dup, result);
        self.fd_arg(builder, "fd", fd)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result
    }

    /// `dup2(oldfd, newfd)`. The result IS `newfd` on success (a number the
    /// probe chose, not one the kernel allocated), so it is recorded raw; both
    /// arguments are descriptors and normalized as such — `newfd` when it names
    /// something at the time of the call.
    ///
    /// The generic (arm64) table has no `dup2` row: there the kernel shape is
    /// glibc's — `fcntl(oldfd, F_GETFL)` validating equal numbers, else
    /// `dup3(oldfd, newfd, 0)` — and only the libc vehicle calls `dup2` itself.
    pub fn dup2(&self, oldfd: i32, newfd: i32) -> i64 {
        #[cfg(target_arch = "x86_64")]
        let result = self.call(Syscall::N_dup2, [oldfd as i64, newfd as i64, 0, 0, 0, 0]);
        #[cfg(not(target_arch = "x86_64"))]
        let result = self.legacy(
            // SAFETY: plain descriptor numbers.
            || unsafe { libc::dup2(oldfd, newfd) } as i64,
            if oldfd == newfd {
                Syscall::N_fcntl
            } else {
                Syscall::N_dup3
            },
            if oldfd == newfd {
                [oldfd as i64, libc::F_GETFL as i64, 0, 0, 0, 0]
            } else {
                [oldfd as i64, newfd as i64, 0, 0, 0, 0]
            },
        );
        #[cfg(not(target_arch = "x86_64"))]
        let result = if oldfd == newfd && result >= 0 {
            i64::from(newfd)
        } else {
            result
        };
        let builder = self.rec.event("dup2", result);
        self.fd_arg(builder, "oldfd", oldfd)
            .arg("newfd", newfd)
            .emit();
        result
    }

    /// `dup3(oldfd, newfd, flags)`; recorded like `dup2`.
    pub fn dup3(&self, oldfd: i32, newfd: i32, flags: i32) -> i64 {
        let result = self.call(
            Syscall::N_dup3,
            [oldfd as i64, newfd as i64, flags as i64, 0, 0, 0],
        );
        let builder = self.event(Syscall::N_dup3, result);
        self.fd_arg(builder, "oldfd", oldfd)
            .arg("newfd", newfd)
            .arg("flags", flags)
            .emit();
        result
    }

    /// `close_range(first, last, flags)`: the bounds are numbers the scenario
    /// chose, recorded raw. The comparison's `fd` namespace retires nothing here
    /// (it retires on `close` events), so a scenario closes the range's members
    /// through `close_range` only when it never reuses them observably.
    pub fn close_range(&self, first: u32, last: u32, flags: u32) -> i64 {
        let result = self.call(
            Syscall::N_close_range,
            [first as i64, last as i64, flags as i64, 0, 0, 0],
        );
        self.event(Syscall::N_close_range, result)
            .arg("first", first)
            .arg("last", last)
            .arg("flags", flags)
            .emit();
        result
    }

    /// `fcntl` with an integer argument. `F_DUPFD*` results are descriptors and
    /// normalized as such; every other result is recorded raw.
    pub fn fcntl(&self, fd: i32, cmd: i32, arg: i64) -> i64 {
        let result = self.call(Syscall::N_fcntl, [fd as i64, cmd as i64, arg, 0, 0, 0]);
        let builder = self.event(Syscall::N_fcntl, result);
        let builder = self
            .fd_arg(builder, "fd", fd)
            .arg("cmd", cmd)
            .arg("arg", arg);
        let builder = if cmd == libc::F_DUPFD || cmd == libc::F_DUPFD_CLOEXEC {
            builder.norm("ret", Norm::Relative("fd"))
        } else {
            builder
        };
        builder.emit();
        result
    }

    pub fn flock(&self, fd: i32, operation: i32) -> i64 {
        let result = self.call(Syscall::N_flock, [fd as i64, operation as i64, 0, 0, 0, 0]);
        let builder = self.event(Syscall::N_flock, result);
        self.fd_arg(builder, "fd", fd)
            .arg("operation", operation)
            .emit();
        result
    }

    // ---- positional and vectored I/O ------------------------------------------

    /// `pread64(fd, len, offset)`; the bytes read are recorded.
    pub fn pread64(&self, fd: i32, len: usize, offset: i64) -> (i64, Vec<u8>) {
        let mut buf = vec![0u8; len];
        let result = self.call(
            Syscall::N_pread64,
            [fd as i64, buf.as_mut_ptr() as i64, len as i64, offset, 0, 0],
        );
        buf.truncate(result.max(0) as usize);
        let builder = self.event(Syscall::N_pread64, result);
        let builder = self
            .fd_arg(builder, "fd", fd)
            .arg("len", len)
            .arg("offset", offset);
        let builder = if result >= 0 {
            builder.field("data", printable(&buf))
        } else {
            builder
        };
        builder.emit();
        (result, buf)
    }

    pub fn pwrite64(&self, fd: i32, data: &[u8], offset: i64) -> i64 {
        let result = self.call(
            Syscall::N_pwrite64,
            [
                fd as i64,
                data.as_ptr() as i64,
                data.len() as i64,
                offset,
                0,
                0,
            ],
        );
        let builder = self.event(Syscall::N_pwrite64, result);
        self.fd_arg(builder, "fd", fd)
            .arg("len", data.len())
            .arg("offset", offset)
            .emit();
        result
    }

    /// The trailing arguments of the vectored rows: the position of the
    /// positional ones (`pos_l`; `pos_h` is 0, ignored by a 64-bit kernel) and
    /// the `RWF_*` flags of the `*v2` ones.
    fn vectored_args(
        fd: i32,
        iov: i64,
        count: i64,
        offset: Option<i64>,
        flags: Option<i32>,
    ) -> Args {
        [
            fd as i64,
            iov,
            count,
            offset.unwrap_or(0),
            0,
            flags.unwrap_or(0) as i64,
        ]
    }

    fn vectored_event(
        &self,
        row: Syscall,
        result: i64,
        fd: i32,
        offset: Option<i64>,
        flags: Option<i32>,
    ) -> EventBuilder<'_> {
        let builder = self.fd_arg(self.event(row, result), "fd", fd);
        let builder = match offset {
            Some(offset) => builder.arg("offset", offset),
            None => builder,
        };
        match flags {
            Some(flags) => builder.arg("flags", flags),
            None => builder,
        }
    }

    /// `readv`, `preadv` or `preadv2` into segments of `lens` bytes; what each
    /// segment received is recorded in order.
    pub fn readv_row(
        &self,
        row: Syscall,
        fd: i32,
        lens: &[usize],
        offset: Option<i64>,
        flags: Option<i32>,
    ) -> SegmentsRead {
        let (mut buffers, iov) = read_vector(lens);
        let result = self.call(
            row,
            Self::vectored_args(fd, iov.as_ptr() as i64, iov.len() as i64, offset, flags),
        );
        let segments = filled(&mut buffers, result);
        let builder = self
            .vectored_event(row, result, fd, offset, flags)
            .arg("lens", lens.to_vec());
        let builder = if result >= 0 {
            builder.field("segments", segments)
        } else {
            builder
        };
        builder.emit();
        (result, buffers)
    }

    /// `writev`, `pwritev` or `pwritev2` of `segments`, in order.
    pub fn writev_row(
        &self,
        row: Syscall,
        fd: i32,
        segments: &[&[u8]],
        offset: Option<i64>,
        flags: Option<i32>,
    ) -> i64 {
        let iov = write_vector(segments);
        let result = self.call(
            row,
            Self::vectored_args(fd, iov.as_ptr() as i64, iov.len() as i64, offset, flags),
        );
        let lens = lens_of(segments);
        self.vectored_event(row, result, fd, offset, flags)
            .arg("lens", lens)
            .emit();
        result
    }

    /// A vectored row (`readv`…`pwritev2`, `vmsplice`) over one of the
    /// refusal shapes of its vector.
    pub fn iov_shape(
        &self,
        row: Syscall,
        fd: i32,
        shape: IovShape,
        offset: Option<i64>,
        flags: Option<i32>,
    ) -> i64 {
        let mut scratch = [0u8; 8];
        let (iov, count): (Vec<libc::iovec>, i64) = match shape {
            IovShape::Null(count) => (Vec::new(), count),
            // At least one entry, so even a negative count (judged before the
            // vector is read) hands the kernel a valid pointer.
            IovShape::Empty(count) => (
                (0..count.clamp(1, 2 * libc::UIO_MAXIOV as i64))
                    .map(|_| libc::iovec {
                        iov_base: scratch.as_mut_ptr().cast(),
                        iov_len: 0,
                    })
                    .collect(),
                count,
            ),
            IovShape::NegativeLength => (
                vec![libc::iovec {
                    iov_base: scratch.as_mut_ptr().cast(),
                    iov_len: usize::MAX,
                }],
                1,
            ),
        };
        let pointer = if matches!(shape, IovShape::Null(_)) {
            0
        } else {
            iov.as_ptr() as i64
        };
        let args = if row == Syscall::N_vmsplice {
            [fd as i64, pointer, count, flags.unwrap_or(0) as i64, 0, 0]
        } else {
            Self::vectored_args(fd, pointer, count, offset, flags)
        };
        let result = self.call(row, args);
        self.vectored_event(row, result, fd, offset, flags)
            .arg("iov", shape.label())
            .emit();
        result
    }

    // ---- durability ----------------------------------------------------------

    pub fn fsync(&self, fd: i32) -> i64 {
        self.fd_ints(Syscall::N_fsync, fd, &[], &[])
    }

    pub fn fdatasync(&self, fd: i32) -> i64 {
        self.fd_ints(Syscall::N_fdatasync, fd, &[], &[])
    }

    /// `sync(2)`: never fails; the kernel row answers 0.
    pub fn sync(&self) -> i64 {
        let result = self.call(Syscall::N_sync, [0; 6]);
        self.event(Syscall::N_sync, result).emit();
        result
    }

    pub fn syncfs(&self, fd: i32) -> i64 {
        self.fd_ints(Syscall::N_syncfs, fd, &[], &[])
    }

    pub fn sync_file_range(&self, fd: i32, offset: i64, nbytes: i64, flags: u32) -> i64 {
        self.fd_ints(
            Syscall::N_sync_file_range,
            fd,
            &["offset", "nbytes", "flags"],
            &[offset, nbytes, flags as i64],
        )
    }

    // ---- ioctl ---------------------------------------------------------------

    /// `ioctl(fd, request, arg)`; `name` is the request's name, recorded
    /// beside its number. An `Out` argument's first int is recorded.
    pub fn ioctl(&self, fd: i32, request: u64, name: &str, arg: IoctlArg) -> (i64, Option<i32>) {
        let mut out = [0u8; 64];
        let input: i32 = match arg {
            IoctlArg::In(value) => value,
            _ => 0,
        };
        let pointer = match arg {
            IoctlArg::None | IoctlArg::Null => 0,
            IoctlArg::In(_) => &input as *const i32 as i64,
            IoctlArg::Out => out.as_mut_ptr() as i64,
        };
        let result = self.call(
            Syscall::N_ioctl,
            [fd as i64, request as i64, pointer, 0, 0, 0],
        );
        let value = (result >= 0 && arg == IoctlArg::Out)
            .then(|| i32::from_ne_bytes([out[0], out[1], out[2], out[3]]));
        let builder = self.event(Syscall::N_ioctl, result);
        let builder = self
            .fd_arg(builder, "fd", fd)
            .arg("request", name)
            .arg("number", request)
            .arg(
                "arg",
                match arg {
                    IoctlArg::None => "none".to_string(),
                    IoctlArg::In(value) => format!("&{value}"),
                    IoctlArg::Out => "out".to_string(),
                    IoctlArg::Null => "NULL".to_string(),
                },
            );
        let builder = match value {
            Some(value) => builder.field("value", value),
            None => builder,
        };
        builder.emit();
        (result, value)
    }

    // ---- in-kernel copies ------------------------------------------------------

    fn offset_arg<'a>(
        builder: EventBuilder<'a>,
        key: &str,
        offset: Option<i64>,
    ) -> EventBuilder<'a> {
        match offset {
            Some(offset) => builder.arg(key, offset),
            None => builder.arg(key, "NULL"),
        }
    }

    /// `copy_file_range`; a `Some` offset is passed by pointer and its value
    /// after the call is returned and recorded.
    pub fn copy_file_range(
        &self,
        fd_in: i32,
        off_in: Option<i64>,
        fd_out: i32,
        off_out: Option<i64>,
        len: usize,
        flags: u32,
    ) -> (i64, Option<i64>, Option<i64>) {
        self.two_offsets(
            Syscall::N_copy_file_range,
            fd_in,
            off_in,
            fd_out,
            off_out,
            len,
            flags,
        )
    }

    /// `splice`, shaped like `copy_file_range`.
    pub fn splice(
        &self,
        fd_in: i32,
        off_in: Option<i64>,
        fd_out: i32,
        off_out: Option<i64>,
        len: usize,
        flags: u32,
    ) -> (i64, Option<i64>, Option<i64>) {
        self.two_offsets(
            Syscall::N_splice,
            fd_in,
            off_in,
            fd_out,
            off_out,
            len,
            flags,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn two_offsets(
        &self,
        row: Syscall,
        fd_in: i32,
        off_in: Option<i64>,
        fd_out: i32,
        off_out: Option<i64>,
        len: usize,
        flags: u32,
    ) -> (i64, Option<i64>, Option<i64>) {
        let mut pos_in = off_in.unwrap_or(0);
        let mut pos_out = off_out.unwrap_or(0);
        let result = self.call(
            row,
            [
                fd_in as i64,
                off_in.map_or(0, |_| &mut pos_in as *mut i64 as i64),
                fd_out as i64,
                off_out.map_or(0, |_| &mut pos_out as *mut i64 as i64),
                len as i64,
                flags as i64,
            ],
        );
        let after_in = off_in.map(|_| pos_in);
        let after_out = off_out.map(|_| pos_out);
        let builder = self.fd_arg(self.event(row, result), "fd_in", fd_in);
        let builder = Self::offset_arg(builder, "off_in", off_in);
        let builder = self.fd_arg(builder, "fd_out", fd_out);
        let builder = Self::offset_arg(builder, "off_out", off_out)
            .arg("len", len)
            .arg("flags", flags);
        let builder = match after_in {
            Some(pos) => builder.field("off_in_after", pos),
            None => builder,
        };
        let builder = match after_out {
            Some(pos) => builder.field("off_out_after", pos),
            None => builder,
        };
        builder.emit();
        (result, after_in, after_out)
    }

    /// `sendfile(out_fd, in_fd, offset, count)`; a `Some` offset is passed by
    /// pointer and its value after the call returned and recorded.
    pub fn sendfile(
        &self,
        out_fd: i32,
        in_fd: i32,
        offset: Option<i64>,
        count: usize,
    ) -> (i64, Option<i64>) {
        let mut pos = offset.unwrap_or(0);
        let result = self.call(
            Syscall::N_sendfile,
            [
                out_fd as i64,
                in_fd as i64,
                offset.map_or(0, |_| &mut pos as *mut i64 as i64),
                count as i64,
                0,
                0,
            ],
        );
        let after = offset.map(|_| pos);
        let builder = self.fd_arg(self.event(Syscall::N_sendfile, result), "out_fd", out_fd);
        let builder = self.fd_arg(builder, "in_fd", in_fd);
        let builder = Self::offset_arg(builder, "offset", offset).arg("count", count);
        let builder = match after {
            Some(pos) => builder.field("offset_after", pos),
            None => builder,
        };
        builder.emit();
        (result, after)
    }

    pub fn tee(&self, fd_in: i32, fd_out: i32, len: usize, flags: u32) -> i64 {
        let result = self.call(
            Syscall::N_tee,
            [fd_in as i64, fd_out as i64, len as i64, flags as i64, 0, 0],
        );
        let builder = self.fd_arg(self.event(Syscall::N_tee, result), "fd_in", fd_in);
        self.fd_arg(builder, "fd_out", fd_out)
            .arg("len", len)
            .arg("flags", flags)
            .emit();
        result
    }

    /// `vmsplice` of `segments` into a pipe's write end.
    pub fn vmsplice(&self, fd: i32, segments: &[&[u8]], flags: u32) -> i64 {
        let iov = write_vector(segments);
        let result = self.call(
            Syscall::N_vmsplice,
            [
                fd as i64,
                iov.as_ptr() as i64,
                iov.len() as i64,
                flags as i64,
                0,
                0,
            ],
        );
        let lens = lens_of(segments);
        self.fd_arg(self.event(Syscall::N_vmsplice, result), "fd", fd)
            .arg("lens", lens)
            .arg("flags", flags)
            .emit();
        result
    }

    /// `vmsplice` from a pipe's read end into segments of `lens` bytes (the
    /// copy-out direction).
    pub fn vmsplice_read(&self, fd: i32, lens: &[usize], flags: u32) -> SegmentsRead {
        let (mut buffers, iov) = read_vector(lens);
        let result = self.call(
            Syscall::N_vmsplice,
            [
                fd as i64,
                iov.as_ptr() as i64,
                iov.len() as i64,
                flags as i64,
                0,
                0,
            ],
        );
        let segments = filled(&mut buffers, result);
        let builder = self
            .fd_arg(self.event(Syscall::N_vmsplice, result), "fd", fd)
            .arg("lens", lens.to_vec())
            .arg("flags", flags);
        let builder = if result >= 0 {
            builder.field("segments", segments)
        } else {
            builder
        };
        builder.emit();
        (result, buffers)
    }
}
