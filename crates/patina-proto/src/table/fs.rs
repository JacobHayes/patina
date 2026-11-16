//! Paths, directories, metadata, timestamps, the `/proc` `/sys` `/dev` policy.
use super::misc::n;
use super::*;

const G: Group = Group::Fs;

const OPEN_W: &str = "Sandbox tmpfs (fresh, sandbox history only: inode numbers follow creation order) or read-only host files (host-stable). Listed /proc and /sys files are synthesised (read-only memfd); /proc/self/exe is the guest image; /dev/urandom and /dev/random become entropy descriptors; /dev/tty answers ENXIO. O_DIRECT is dropped and recorded (tmpfs has no direct I/O). A creation stamps the new inode and its directory in the virtual time table; O_TRUNC is a data change.";
const STAT_W: &str = "Passed, then rewritten: st_dev of every sandbox-created (major 0) filesystem becomes a fixed number by mount order; inode numbers of objects on no sandbox mount (pipes, sockets, anonymous inodes, memfds: host-global counters) become virtual numbers in first-seen order; times on sandbox tmpfs come from the virtual time table (epoch for the initial tree), other sandbox mounts read as the epoch; the guest's stdio are memfds the launcher created, so they are objects of this kind with tmpfs block counts. Size, mode, links, tmpfs inode numbers, blocks and host files pass. Synthesised /proc files get fixed identities.";
const STATX_W: &str = "As newfstatat, plus birth time from the virtual time table, and the mount id becomes the mount's index (+1) with the unique mount id withheld (host-global counters).";
const STATFS_W: &str = "Passed; f_fsid is zeroed (random per superblock). On the sandbox tmpfs the counts are a function of the guest's writes and pass; on host and kernel filesystems the free counts change outside the sandbox and are replaced by constants.";
const LINK_R: &str = "Passed for sandbox and host paths. /proc/self/exe names the guest image; /proc/self/fd/N names a synthesised file by its /proc path and rewrites pipe:[n] and socket:[n] to virtual inode numbers; hidden descriptors read as ENOENT. A path that reaches a /proc or /sys object through a /work symlink or .. is refused with ENOENT and recorded (it named the supervisor's links).";
const DIRS: &str = "Directory order on tmpfs is a function of creation and removal order and d_off values are per-directory counters; read-only mounts are host-stable. Directories under /proc and /sys are never handed out.";
const ACCESS: &str = "Permission check against sandbox or host-stable files; synthesised /proc files are readable only.";
const CREATE: &str = "Creates a name on the sandbox tmpfs: inode numbers follow creation order, space is a function of the guest's own writes. Stamps the new inode (all four times) and its directory (mtime, ctime) in the virtual time table; on /work reports the operation to the durability hook.";
const REMOVE: &str = "Removes a name on the sandbox tmpfs; tmpfs has no deferred work. The directory's mtime and ctime, and the inode's ctime if links remain, are stamped in the virtual time table; on /work reported to the durability hook.";
const RENAME: &str = "Renames on the sandbox tmpfs (flags pass). Both directories' mtime and ctime and the moved and replaced inodes' ctime are stamped; on /work reported to the durability hook.";
const LINK: &str = "Adds a name for an existing inode (AT_EMPTY_PATH passes). The inode's ctime and the directory's mtime and ctime are stamped; on /work reported.";
const ATTR: &str = "Attribute change on a sandbox or host file (the user namespace confines ownership). ctime is stamped in the virtual time table; on /work reported to the durability hook.";
const TIMES: &str = "Passed for validation and permission checks; the named times (UTIME_NOW is virtual realtime, UTIME_OMIT leaves) and ctime are stored in the virtual time table, which is what stat reports.";
const XATTR_R: &str = "Extended attributes on tmpfs are sandbox history (user.* in insertion order); on host files host-stable.";
const XATTR_W: &str =
    "Sets or removes an extended attribute on tmpfs (user.*); ctime is stamped; on /work reported.";
const CWD: &str = "Working directory and umask are per-process kernel state changed only by the process; the guest starts with umask 022 whatever the launcher's umask.";
const TRUNC: &str = "Size change on the sandbox tmpfs: a function of the guest's writes. mtime and ctime are stamped; on /work reported.";

const S144: &[Out] = &[out(1, Len::Fixed(144))];

pub const ROWS: &[Row] = &[
    Row::new(G, n(2, "open"), Pass, A, OPEN_W).ins(&[out(0, Len::CStr)]),
    Row::new(G, n(85, "creat"), Pass, A, OPEN_W).ins(&[out(0, Len::CStr)]),
    Row::new(G, n(257, "openat"), Pass, A, OPEN_W)
        .fd(0)
        .ins(&[out(1, Len::CStr)]),
    Row::new(G, n(437, "openat2"), Pass, A, OPEN_W)
        .fd(0)
        .ins(&[out(1, Len::CStr), out(2, Len::Arg(3))]),
    Row::new(G, n(4, "stat"), Rewrite, A, STAT_W)
        .ins(&[out(0, Len::CStr)])
        .outs(S144),
    Row::new(G, n(6, "lstat"), Rewrite, A, STAT_W)
        .ins(&[out(0, Len::CStr)])
        .outs(S144),
    Row::new(G, n(5, "fstat"), Rewrite, A, STAT_W)
        .fd(0)
        .outs(S144),
    Row::new(G, n(262, "newfstatat"), Rewrite, A, STAT_W)
        .fd(0)
        .ins(&[out(1, Len::CStr)])
        .outs(&[out(2, Len::Fixed(144))]),
    Row::new(G, n(332, "statx"), Rewrite, A, STATX_W)
        .fd(0)
        .ins(&[out(1, Len::CStr)])
        .outs(&[out(4, Len::Fixed(256))]),
    Row::new(G, n(137, "statfs"), Rewrite, A, STATFS_W)
        .ins(&[out(0, Len::CStr)])
        .outs(&[out(1, Len::Fixed(120))]),
    Row::new(G, n(138, "fstatfs"), Rewrite, A, STATFS_W)
        .fd(0)
        .outs(&[out(1, Len::Fixed(120))]),
    Row::new(G, n(89, "readlink"), Pass, A, LINK_R)
        .ins(&[out(0, Len::CStr)])
        .outs(&[out(1, Len::Ret)]),
    Row::new(G, n(267, "readlinkat"), Pass, A, LINK_R)
        .fd(0)
        .ins(&[out(1, Len::CStr)])
        .outs(&[out(2, Len::Ret)]),
    Row::new(G, n(217, "getdents64"), Pass, A, DIRS)
        .fd(0)
        .outs(&[out(1, Len::Ret)]),
    Row::new(G, n(78, "getdents"), Pass, A, DIRS)
        .fd(0)
        .outs(&[out(1, Len::Ret)]),
    Row::new(G, n(21, "access"), Pass, A, ACCESS).ins(&[out(0, Len::CStr)]),
    Row::new(G, n(269, "faccessat"), Pass, A, ACCESS)
        .fd(0)
        .ins(&[out(1, Len::CStr)]),
    Row::new(G, n(439, "faccessat2"), Pass, A, ACCESS)
        .fd(0)
        .ins(&[out(1, Len::CStr)]),
    Row::new(G, n(83, "mkdir"), Pass, A, CREATE).ins(&[out(0, Len::CStr)]),
    Row::new(G, n(258, "mkdirat"), Pass, A, CREATE)
        .fd(0)
        .ins(&[out(1, Len::CStr)]),
    Row::new(G, n(133, "mknod"), Pass, A, CREATE).ins(&[out(0, Len::CStr)]),
    Row::new(G, n(259, "mknodat"), Pass, A, CREATE)
        .fd(0)
        .ins(&[out(1, Len::CStr)]),
    Row::new(G, n(88, "symlink"), Pass, A, CREATE).ins(&[out(0, Len::CStr), out(1, Len::CStr)]),
    Row::new(G, n(266, "symlinkat"), Pass, A, CREATE)
        .fd(1)
        .ins(&[out(0, Len::CStr), out(2, Len::CStr)]),
    Row::new(G, n(87, "unlink"), Pass, A, REMOVE).ins(&[out(0, Len::CStr)]),
    Row::new(G, n(84, "rmdir"), Pass, A, REMOVE).ins(&[out(0, Len::CStr)]),
    Row::new(G, n(263, "unlinkat"), Pass, A, REMOVE)
        .fd(0)
        .ins(&[out(1, Len::CStr)]),
    Row::new(G, n(82, "rename"), Pass, A, RENAME).ins(&[out(0, Len::CStr), out(1, Len::CStr)]),
    Row::new(G, n(264, "renameat"), Pass, A, RENAME)
        .fd(0)
        .fd(2)
        .ins(&[out(1, Len::CStr), out(3, Len::CStr)]),
    Row::new(G, n(316, "renameat2"), Pass, A, RENAME)
        .fd(0)
        .fd(2)
        .ins(&[out(1, Len::CStr), out(3, Len::CStr)]),
    Row::new(G, n(86, "link"), Pass, A, LINK).ins(&[out(0, Len::CStr), out(1, Len::CStr)]),
    Row::new(G, n(265, "linkat"), Pass, A, LINK)
        .fd(0)
        .fd(2)
        .ins(&[out(1, Len::CStr), out(3, Len::CStr)]),
    Row::new(G, n(90, "chmod"), Pass, A, ATTR).ins(&[out(0, Len::CStr)]),
    Row::new(G, n(268, "fchmodat"), Pass, A, ATTR)
        .fd(0)
        .ins(&[out(1, Len::CStr)]),
    Row::new(G, n(452, "fchmodat2"), Pass, A, ATTR)
        .fd(0)
        .ins(&[out(1, Len::CStr)]),
    Row::new(G, n(92, "chown"), Pass, A, ATTR).ins(&[out(0, Len::CStr)]),
    Row::new(G, n(94, "lchown"), Pass, A, ATTR).ins(&[out(0, Len::CStr)]),
    Row::new(G, n(260, "fchownat"), Pass, A, ATTR)
        .fd(0)
        .ins(&[out(1, Len::CStr)]),
    Row::new(G, n(76, "truncate"), Pass, A, TRUNC).ins(&[out(0, Len::CStr)]),
    Row::new(G, n(132, "utime"), Virt, C, TIMES).ins(&[out(0, Len::CStr), out(1, Len::Fixed(16))]),
    Row::new(G, n(235, "utimes"), Virt, C, TIMES).ins(&[out(0, Len::CStr), out(1, Len::Fixed(32))]),
    Row::new(G, n(261, "futimesat"), Virt, C, TIMES)
        .fd(0)
        .ins(&[out(1, Len::CStr), out(2, Len::Fixed(32))]),
    Row::new(G, n(280, "utimensat"), Virt, C, TIMES)
        .fd(0)
        .ins(&[out(1, Len::CStr), out(2, Len::Fixed(32))]),
    Row::new(G, n(191, "getxattr"), Pass, A, XATTR_R)
        .ins(&[out(0, Len::CStr), out(1, Len::CStr)])
        .outs(&[out(2, Len::Ret)]),
    Row::new(G, n(192, "lgetxattr"), Pass, A, XATTR_R)
        .ins(&[out(0, Len::CStr), out(1, Len::CStr)])
        .outs(&[out(2, Len::Ret)]),
    Row::new(G, n(194, "listxattr"), Pass, A, XATTR_R)
        .ins(&[out(0, Len::CStr)])
        .outs(&[out(1, Len::Ret)]),
    Row::new(G, n(195, "llistxattr"), Pass, A, XATTR_R)
        .ins(&[out(0, Len::CStr)])
        .outs(&[out(1, Len::Ret)]),
    Row::new(G, n(464, "getxattrat"), Pass, A, XATTR_R)
        .fd(0)
        .ins(&[out(1, Len::CStr), out(3, Len::CStr)]),
    Row::new(G, n(465, "listxattrat"), Pass, A, XATTR_R)
        .fd(0)
        .ins(&[out(1, Len::CStr)])
        .outs(&[out(3, Len::Ret)]),
    Row::new(G, n(188, "setxattr"), Pass, A, XATTR_W).ins(&[
        out(0, Len::CStr),
        out(1, Len::CStr),
        out(2, Len::Arg(3)),
    ]),
    Row::new(G, n(189, "lsetxattr"), Pass, A, XATTR_W).ins(&[
        out(0, Len::CStr),
        out(1, Len::CStr),
        out(2, Len::Arg(3)),
    ]),
    Row::new(G, n(197, "removexattr"), Pass, A, XATTR_W)
        .ins(&[out(0, Len::CStr), out(1, Len::CStr)]),
    Row::new(G, n(198, "lremovexattr"), Pass, A, XATTR_W)
        .ins(&[out(0, Len::CStr), out(1, Len::CStr)]),
    Row::new(G, n(463, "setxattrat"), Pass, A, XATTR_W)
        .fd(0)
        .ins(&[out(1, Len::CStr), out(3, Len::CStr)]),
    Row::new(G, n(466, "removexattrat"), Pass, A, XATTR_W)
        .fd(0)
        .ins(&[out(1, Len::CStr), out(3, Len::CStr)]),
    Row::new(G, n(79, "getcwd"), Pass, A, CWD).outs(&[out(0, Len::Ret)]),
    Row::new(G, n(80, "chdir"), Pass, A, CWD).ins(&[out(0, Len::CStr)]),
    Row::new(G, n(81, "fchdir"), Pass, A, CWD).fd(0),
    Row::new(G, n(95, "umask"), Pass, A, CWD),
];
