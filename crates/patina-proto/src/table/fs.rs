//! Paths, directories, metadata, timestamps, the `/proc` `/sys` `/dev` policy.
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

const STAT_OUT: &[Out] = &[out(1, Len::Fixed(crate::abi::stat::SIZE))];

pub const ROWS: &[Row] = &[
    Row::new(G, nr::OPEN, Pass, A, OPEN_W).ins(&[out(0, Len::CStr)]),
    Row::new(G, nr::CREAT, Pass, A, OPEN_W).ins(&[out(0, Len::CStr)]),
    Row::new(G, nr::OPENAT, Pass, A, OPEN_W)
        .fd(0)
        .ins(&[out(1, Len::CStr)]),
    Row::new(G, nr::OPENAT2, Pass, A, OPEN_W)
        .fd(0)
        .ins(&[out(1, Len::CStr), out(2, Len::Arg(3))]),
    Row::new(G, nr::STAT, Rewrite, A, STAT_W)
        .ins(&[out(0, Len::CStr)])
        .outs(STAT_OUT),
    Row::new(G, nr::LSTAT, Rewrite, A, STAT_W)
        .ins(&[out(0, Len::CStr)])
        .outs(STAT_OUT),
    Row::new(G, nr::FSTAT, Rewrite, A, STAT_W)
        .fd(0)
        .outs(STAT_OUT),
    Row::new(G, nr::NEWFSTATAT, Rewrite, A, STAT_W)
        .fd(0)
        .ins(&[out(1, Len::CStr)])
        .outs(&[out(2, Len::Fixed(crate::abi::stat::SIZE))]),
    Row::new(G, nr::STATX, Rewrite, A, STATX_W)
        .fd(0)
        .ins(&[out(1, Len::CStr)])
        .outs(&[out(4, Len::Fixed(256))]),
    Row::new(G, nr::STATFS, Rewrite, A, STATFS_W)
        .ins(&[out(0, Len::CStr)])
        .outs(&[out(1, Len::Fixed(120))]),
    Row::new(G, nr::FSTATFS, Rewrite, A, STATFS_W)
        .fd(0)
        .outs(&[out(1, Len::Fixed(120))]),
    Row::new(G, nr::READLINK, Pass, A, LINK_R)
        .ins(&[out(0, Len::CStr)])
        .outs(&[out(1, Len::Ret { max: 2 })]),
    Row::new(G, nr::READLINKAT, Pass, A, LINK_R)
        .fd(0)
        .ins(&[out(1, Len::CStr)])
        .outs(&[out(2, Len::Ret { max: 3 })]),
    Row::new(G, nr::GETDENTS64, Pass, A, DIRS)
        .fd(0)
        .outs(&[out(1, Len::Ret { max: 2 })]),
    Row::new(G, nr::GETDENTS, Pass, A, DIRS)
        .fd(0)
        .outs(&[out(1, Len::Ret { max: 2 })]),
    Row::new(G, nr::ACCESS, Pass, A, ACCESS).ins(&[out(0, Len::CStr)]),
    Row::new(G, nr::FACCESSAT, Pass, A, ACCESS)
        .fd(0)
        .ins(&[out(1, Len::CStr)]),
    Row::new(G, nr::FACCESSAT2, Pass, A, ACCESS)
        .fd(0)
        .ins(&[out(1, Len::CStr)]),
    Row::new(G, nr::MKDIR, Pass, A, CREATE).ins(&[out(0, Len::CStr)]),
    Row::new(G, nr::MKDIRAT, Pass, A, CREATE)
        .fd(0)
        .ins(&[out(1, Len::CStr)]),
    Row::new(G, nr::MKNOD, Pass, A, CREATE).ins(&[out(0, Len::CStr)]),
    Row::new(G, nr::MKNODAT, Pass, A, CREATE)
        .fd(0)
        .ins(&[out(1, Len::CStr)]),
    Row::new(G, nr::SYMLINK, Pass, A, CREATE).ins(&[out(0, Len::CStr), out(1, Len::CStr)]),
    Row::new(G, nr::SYMLINKAT, Pass, A, CREATE)
        .fd(1)
        .ins(&[out(0, Len::CStr), out(2, Len::CStr)]),
    Row::new(G, nr::UNLINK, Pass, A, REMOVE).ins(&[out(0, Len::CStr)]),
    Row::new(G, nr::RMDIR, Pass, A, REMOVE).ins(&[out(0, Len::CStr)]),
    Row::new(G, nr::UNLINKAT, Pass, A, REMOVE)
        .fd(0)
        .ins(&[out(1, Len::CStr)]),
    Row::new(G, nr::RENAME, Pass, A, RENAME).ins(&[out(0, Len::CStr), out(1, Len::CStr)]),
    Row::new(G, nr::RENAMEAT, Pass, A, RENAME)
        .fd(0)
        .fd(2)
        .ins(&[out(1, Len::CStr), out(3, Len::CStr)]),
    Row::new(G, nr::RENAMEAT2, Pass, A, RENAME)
        .fd(0)
        .fd(2)
        .ins(&[out(1, Len::CStr), out(3, Len::CStr)]),
    Row::new(G, nr::LINK, Pass, A, LINK).ins(&[out(0, Len::CStr), out(1, Len::CStr)]),
    Row::new(G, nr::LINKAT, Pass, A, LINK)
        .fd(0)
        .fd(2)
        .ins(&[out(1, Len::CStr), out(3, Len::CStr)]),
    Row::new(G, nr::CHMOD, Pass, A, ATTR).ins(&[out(0, Len::CStr)]),
    Row::new(G, nr::FCHMODAT, Pass, A, ATTR)
        .fd(0)
        .ins(&[out(1, Len::CStr)]),
    Row::new(G, nr::FCHMODAT2, Pass, A, ATTR)
        .fd(0)
        .ins(&[out(1, Len::CStr)]),
    Row::new(G, nr::CHOWN, Pass, A, ATTR).ins(&[out(0, Len::CStr)]),
    Row::new(G, nr::LCHOWN, Pass, A, ATTR).ins(&[out(0, Len::CStr)]),
    Row::new(G, nr::FCHOWNAT, Pass, A, ATTR)
        .fd(0)
        .ins(&[out(1, Len::CStr)]),
    Row::new(G, nr::TRUNCATE, Pass, A, TRUNC).ins(&[out(0, Len::CStr)]),
    Row::new(G, nr::UTIME, Virt, C, TIMES).ins(&[out(0, Len::CStr), out(1, Len::Fixed(16))]),
    Row::new(G, nr::UTIMES, Virt, C, TIMES).ins(&[out(0, Len::CStr), out(1, Len::Fixed(32))]),
    Row::new(G, nr::FUTIMESAT, Virt, C, TIMES)
        .fd(0)
        .ins(&[out(1, Len::CStr), out(2, Len::Fixed(32))]),
    Row::new(G, nr::UTIMENSAT, Virt, C, TIMES)
        .fd(0)
        .ins(&[out(1, Len::CStr), out(2, Len::Fixed(32))]),
    Row::new(G, nr::GETXATTR, Pass, A, XATTR_R)
        .ins(&[out(0, Len::CStr), out(1, Len::CStr)])
        .outs(&[out(2, Len::Ret { max: 3 })]),
    Row::new(G, nr::LGETXATTR, Pass, A, XATTR_R)
        .ins(&[out(0, Len::CStr), out(1, Len::CStr)])
        .outs(&[out(2, Len::Ret { max: 3 })]),
    Row::new(G, nr::LISTXATTR, Pass, A, XATTR_R)
        .ins(&[out(0, Len::CStr)])
        .outs(&[out(1, Len::Ret { max: 2 })]),
    Row::new(G, nr::LLISTXATTR, Pass, A, XATTR_R)
        .ins(&[out(0, Len::CStr)])
        .outs(&[out(1, Len::Ret { max: 2 })]),
    Row::new(G, nr::GETXATTRAT, Pass, A, XATTR_R)
        .fd(0)
        .ins(&[out(1, Len::CStr), out(3, Len::CStr)])
        .refs(&[out(4, Len::XattrArgs { size: 5 })]),
    Row::new(G, nr::LISTXATTRAT, Pass, A, XATTR_R)
        .fd(0)
        .ins(&[out(1, Len::CStr)])
        .outs(&[out(3, Len::Ret { max: 4 })]),
    Row::new(G, nr::SETXATTR, Pass, A, XATTR_W).ins(&[
        out(0, Len::CStr),
        out(1, Len::CStr),
        out(2, Len::Arg(3)),
    ]),
    Row::new(G, nr::LSETXATTR, Pass, A, XATTR_W).ins(&[
        out(0, Len::CStr),
        out(1, Len::CStr),
        out(2, Len::Arg(3)),
    ]),
    Row::new(G, nr::REMOVEXATTR, Pass, A, XATTR_W).ins(&[out(0, Len::CStr), out(1, Len::CStr)]),
    Row::new(G, nr::LREMOVEXATTR, Pass, A, XATTR_W).ins(&[out(0, Len::CStr), out(1, Len::CStr)]),
    Row::new(G, nr::SETXATTRAT, Pass, A, XATTR_W)
        .fd(0)
        .ins(&[out(1, Len::CStr), out(3, Len::CStr)])
        .refs(&[out(4, Len::XattrArgs { size: 5 })]),
    Row::new(G, nr::REMOVEXATTRAT, Pass, A, XATTR_W)
        .fd(0)
        .ins(&[out(1, Len::CStr), out(3, Len::CStr)]),
    Row::new(G, nr::GETCWD, Pass, A, CWD).outs(&[out(0, Len::Ret { max: 1 })]),
    Row::new(G, nr::CHDIR, Pass, A, CWD).ins(&[out(0, Len::CStr)]),
    Row::new(G, nr::FCHDIR, Pass, A, CWD).fd(0),
    Row::new(G, nr::UMASK, Pass, A, CWD),
];
