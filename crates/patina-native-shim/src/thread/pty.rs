//! Unix98 pseudoterminals (drivers/tty/pty.c, fs/devpts), for the one
//! virtual process: every open of `/dev/ptmx` makes a pair, numbered as
//! `devpts_new_index` numbers it (the lowest free index; an index is free
//! again once both sides are closed), with its slave node `/dev/pts/<index>`
//! on devpts from the master's open until its close (`devpts_pty_new`,
//! `devpts_pty_kill`): a character device (136:index, inode index + 3)
//! owned by the opener and the `tty` group, mode 0620, as the pinned host
//! mounts devpts (`gid=5,mode=620`).
//!
//! The slave starts locked (`TIOCSPTLCK` unlocks it) and is opened by name
//! or through its master (`TIOCGPTPEER`); a locked slave's open is `EIO`
//! and marks the slave's I/O failed (`pty_open`'s `TTY_IO_ERROR`) until a
//! later open succeeds. The pair has one set of settings, the slave's: the
//! master's termios and window-size requests act on it (`tty_pair_get_tty`),
//! and `pty_set_termios` keeps it 8-bit and receiving. A master whose last
//! slave description closed reads `EIO` once drained and polls hung up
//! (`TTY_OTHER_CLOSED`); the master's close hangs the slave up
//! (`tty_vhangup`): its reads end, its writes and requests are `EIO`.
//!
//! The virtual process never has a controlling terminal: the requests that
//! read one answer as the kernel does for a terminal that is not the
//! caller's, and acquiring one (an open without `O_NOCTTY`, or
//! `TIOCSCTTY`, by a session leader) stops the run by name, as does every
//! tty request not modeled here.
//!
//! Like the pipes, the pairs are in-process state that only changes while
//! the acting task holds the baton, so they carry no trace events of their
//! own.

use super::*;
use crate::{EACCES, EEXIST, EFAULT, EIO, ENOENT, ENOSPC, ENOTDIR, ENOTTY, fail, set_errno};
use crate::{
    O_APPEND, O_CLOEXEC, O_CREATE, O_DIRECTORY, O_EXCLUSIVE, O_NOCTTY, O_OPENED, O_PATH,
    PatinaMetadata, PatinaTimestamp, uaccess,
};

/// The tty group's id on the pinned host (devpts's `gid=5`, udev's group
/// for `/dev/ptmx`).
pub(crate) const TTY_GID: u32 = 5;
/// `UNIX98_PTY_SLAVE_MAJOR`: a slave node is `136:<index>`.
const PTS_MAJOR: u32 = 136;
/// `/dev/ptmx`, `TTYAUX_MAJOR`:2.
pub(crate) const PTMX_DEVICE: (u32, u32) = (5, 2);
/// The multiplexer's inode number on devtmpfs, as the pinned host's
/// `/dev/ptmx` reads live (devtmpfs numbers its nodes as boot makes them).
const PTMX_INO: u64 = 89;
/// `kernel.pty.max` less `kernel.pty.reserve`: an instance mounted without
/// `reserve` makes a pair only while fewer than this many are live
/// (`devpts_new_index`: `ENOSPC`).
const PTY_LIMIT: usize = 4096 - 1024;

/// The termios the `TCGETS`/`TCSETS*` requests copy (asm-generic
/// `struct termios`: 19 control characters, no speeds).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Termios {
    pub(crate) iflag: u32,
    pub(crate) oflag: u32,
    pub(crate) cflag: u32,
    pub(crate) lflag: u32,
    pub(crate) line: u8,
    pub(crate) cc: [u8; NCCS],
}

const NCCS: usize = 19;

// The flags and control-character slots the model reads (asm-generic
// termbits, the same on both Linux architectures).
const VINTR: usize = 0;
const VQUIT: usize = 1;
const VERASE: usize = 2;
const VKILL: usize = 3;
const VEOF: usize = 4;
const VTIME: usize = 5;
const VMIN: usize = 6;
const VSTART: usize = 8;
const VSTOP: usize = 9;
const VSUSP: usize = 10;
const VEOL: usize = 11;
const VREPRINT: usize = 12;
const VDISCARD: usize = 13;
const VWERASE: usize = 14;
const VLNEXT: usize = 15;
const VEOL2: usize = 16;
const ICRNL: u32 = 0o400;
const IXON: u32 = 0o2000;
const OPOST: u32 = 0o1;
const ONLCR: u32 = 0o4;
const B38400: u32 = 0o17;
const CSIZE: u32 = 0o60;
const CS8: u32 = 0o60;
const CREAD: u32 = 0o200;
const PARENB: u32 = 0o400;
/// `ADDRB`: kept from the old settings (`tty_set_termios`; RS-485
/// addressing is the driver's to change).
const ADDRB: u32 = 0o10000000000;
const ISIG: u32 = 0o1;
const ICANON: u32 = 0o2;
const ECHO: u32 = 0o10;
const ECHOE: u32 = 0o20;
const ECHOK: u32 = 0o40;
const ECHOCTL: u32 = 0o1000;
const ECHOKE: u32 = 0o4000;
const IEXTEN: u32 = 0o100000;

impl Termios {
    /// A slave's settings when its pair is made: `tty_std_termios` as the
    /// pts driver installs it (`B38400 | CS8 | CREAD`, no `HUPCL`) and
    /// `INIT_C_CC`.
    fn initial() -> Termios {
        let mut cc = [0; NCCS];
        cc[VINTR] = 0o3;
        cc[VQUIT] = 0o34;
        cc[VERASE] = 0o177;
        cc[VKILL] = 0o25;
        cc[VEOF] = 0o4;
        cc[VTIME] = 0;
        cc[VMIN] = 1;
        cc[VSTART] = 0o21;
        cc[VSTOP] = 0o23;
        cc[VSUSP] = 0o32;
        cc[VEOL] = 0;
        cc[VREPRINT] = 0o22;
        cc[VDISCARD] = 0o17;
        cc[VWERASE] = 0o27;
        cc[VLNEXT] = 0o26;
        cc[VEOL2] = 0;
        Termios {
            iflag: ICRNL | IXON,
            oflag: OPOST | ONLCR,
            cflag: B38400 | CS8 | CREAD,
            lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
            line: 0,
            cc,
        }
    }
}

/// `struct winsize`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Winsize {
    row: u16,
    col: u16,
    xpixel: u16,
    ypixel: u16,
}

/// One pair.
struct Pair {
    /// `TTY_PTY_LOCK` on the master: the slave may not be opened.
    locked: bool,
    /// The pair's one set of settings, the slave's.
    termios: Termios,
    winsize: Winsize,
    /// The master's description is open; its close hangs the slave up and
    /// removes the slave's node.
    master: bool,
    /// Open slave descriptions.
    slaves: usize,
    /// `TTY_OTHER_CLOSED` on the master: the last slave description closed
    /// since the slave was last opened.
    slave_closed: bool,
    /// `TTY_IO_ERROR` on the slave: its last open failed.
    io_error: bool,
    /// The slave node's times, nanoseconds on the filesystem clock.
    node: NodeTimes,
}

/// A node's times.
#[derive(Clone, Copy)]
struct NodeTimes {
    atime: u64,
    mtime: u64,
    ctime: u64,
}

impl NodeTimes {
    fn at(now: u64) -> NodeTimes {
        NodeTimes {
            atime: now,
            mtime: now,
            ctime: now,
        }
    }
}

/// Every live pair, by index, and the multiplexer node's times.
#[derive(Default)]
pub(crate) struct Ptys {
    pairs: BTreeMap<u32, Pair>,
    /// devtmpfs's `ptmx` node: made at boot, which the model takes to be
    /// its first use.
    ptmx: Option<NodeTimes>,
}

/// Which side of a pair a descriptor is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Side {
    Master,
    Slave,
}

impl Side {
    pub(crate) fn of(kind: FdKind) -> Option<Side> {
        match kind {
            FdKind::PtyMaster => Some(Side::Master),
            FdKind::PtySlave => Some(Side::Slave),
            _ => None,
        }
    }
}

fn now() -> u64 {
    crate::fs_time_unrecorded()
}

fn stamp(nanos: u64) -> PatinaTimestamp {
    PatinaTimestamp::from_nanos(i128::from(nanos))
}

/// The multiplexer node's metadata: a root-owned, `tty`-group, `0666`
/// character device (5:2) on devtmpfs.
pub(crate) fn ptmx_metadata() -> PatinaMetadata {
    let now = now();
    let times = *lock_state().ptys.ptmx.get_or_insert(NodeTimes::at(now));
    PatinaMetadata {
        kind: crate::PATINA_ENTRY_CHAR,
        mode: 0o666,
        nlink: 1,
        fs: crate::PATINA_FS_PTMX,
        rdev_major: PTMX_DEVICE.0,
        rdev_minor: PTMX_DEVICE.1,
        length: 0,
        ino: PTMX_INO,
        atime: stamp(times.atime),
        mtime: stamp(times.mtime),
        ctime: stamp(times.ctime),
        btime: stamp(times.ctime),
    }
}

/// A slave node's metadata; `nlink` 0 once the master's close removed it.
fn node_metadata(index: u32, pair: &Pair) -> PatinaMetadata {
    PatinaMetadata {
        kind: crate::PATINA_ENTRY_CHAR,
        mode: 0o620,
        nlink: u32::from(pair.master),
        fs: crate::PATINA_FS_DEVPTS,
        rdev_major: PTS_MAJOR,
        rdev_minor: index,
        length: 0,
        ino: u64::from(index) + 3,
        atime: stamp(pair.node.atime),
        mtime: stamp(pair.node.mtime),
        ctime: stamp(pair.node.ctime),
        btime: PatinaTimestamp::default(),
    }
}

/// The node `/dev/pts/<index>` names: the slave node of a live pair whose
/// master is open.
pub(crate) fn node(index: u32) -> Option<PatinaMetadata> {
    let state = lock_state();
    let pair = state.ptys.pairs.get(&index).filter(|pair| pair.master)?;
    Some(node_metadata(index, pair))
}

/// What a descriptor on a pair has open: the multiplexer node for the
/// master, the slave node (removed or not) for the slave.
pub(crate) fn fd_metadata(side: Side, index: u32) -> Option<PatinaMetadata> {
    match side {
        Side::Master => Some(ptmx_metadata()),
        Side::Slave => {
            let state = lock_state();
            let pair = state.ptys.pairs.get(&index)?;
            Some(node_metadata(index, pair))
        }
    }
}

/// The `/dev/pts` name of a pair's slave, or `/dev/ptmx` for the master.
pub(crate) fn name(side: Side, index: u32) -> String {
    match side {
        Side::Master => crate::paths::PTMX.to_owned(),
        Side::Slave => format!("{}/{index}", crate::paths::DEVPTS),
    }
}

/// The status an open of a device node leaves on its description, after
/// `do_open`'s refusals of an existing node: `O_CREAT|O_EXCL` is `EEXIST`,
/// `O_DIRECTORY` `ENOTDIR`; `O_TRUNC` does nothing to a device.
fn device_open_status(path: &str, flags: u32) -> Result<u32, c_int> {
    if flags & O_PATH != 0 {
        crate::trap_fatal(&format!(
            "an O_PATH open of {path} is not modeled; failing closed"
        ));
    }
    if flags & (O_CREATE | O_EXCLUSIVE) == O_CREATE | O_EXCLUSIVE {
        return Err(EEXIST);
    }
    if flags & O_DIRECTORY != 0 {
        return Err(ENOTDIR);
    }
    Ok((flags & (O_READ | O_WRITE | O_APPEND | O_NONBLOCK)) | O_OPENED)
}

/// Install a descriptor, answering the C door's way.
fn answer_install(kind: FdKind, index: u32, status: u32, cloexec: bool) -> Result<c_int, c_int> {
    crate::install_fd(kind, u64::from(index), status, cloexec)
}

/// `open("/dev/ptmx")` (`ptmx_open`): a new pair, its slave locked, and its
/// master's descriptor. The master never becomes a controlling terminal.
pub(crate) fn open_master(flags: u32, cloexec: bool) -> c_int {
    let status = match device_open_status(crate::paths::PTMX, flags) {
        Ok(status) => status,
        Err(errno) => return fail(errno),
    };
    // The number comes before the pair (`get_unused_fd_flags` before
    // `ptmx_open`), so a full table is `EMFILE` even with no index free.
    if let Err(errno) = crate::fd_table().lock().has_free() {
        return fail(errno);
    }
    let now = now();
    let index = {
        let mut state = lock_state();
        if let Err(error) = state.ensure_active() {
            return fail(error.into_posix());
        }
        let ptys = &mut state.ptys;
        ptys.ptmx.get_or_insert(NodeTimes::at(now));
        if ptys.pairs.len() + 1 >= PTY_LIMIT {
            return fail(ENOSPC);
        }
        let index = (0..)
            .find(|index| !ptys.pairs.contains_key(index))
            .expect("a free index");
        ptys.pairs.insert(
            index,
            Pair {
                locked: true,
                termios: Termios::initial(),
                winsize: Winsize::default(),
                master: true,
                slaves: 0,
                slave_closed: false,
                io_error: false,
                node: NodeTimes::at(now),
            },
        );
        index
    };
    match answer_install(FdKind::PtyMaster, index, status, cloexec) {
        Ok(fd) => {
            set_errno(0);
            fd
        }
        Err(errno) => {
            lock_state().ptys.pairs.remove(&index);
            fail(errno)
        }
    }
}

/// `open("/dev/tty")`: `tty_open_current_tty` finds no controlling terminal,
/// which the virtual process never has (`ENXIO`), after `do_open`'s
/// refusals of an existing node.
pub(crate) fn open_tty(flags: u32) -> c_int {
    match device_open_status(crate::paths::TTY, flags) {
        Ok(_) => fail(crate::ENXIO),
        Err(errno) => fail(errno),
    }
}

/// `pty_open` of a pair's slave: `EIO` while the slave is locked (which
/// fails the slave's I/O until an open succeeds); otherwise the master no
/// longer sees its slave closed. An open that would make the slave the
/// caller's controlling terminal (`tty_open`: a session leader with none,
/// without `O_NOCTTY`) stops by name.
fn open_slave_side(index: u32, noctty: bool) -> Result<(), c_int> {
    let mut state = lock_state();
    let Some(pair) = state.ptys.pairs.get_mut(&index).filter(|pair| pair.master) else {
        return Err(ENOENT);
    };
    if pair.locked {
        pair.io_error = true;
        return Err(EIO);
    }
    if !noctty && crate::identity::session_leader() {
        drop(state);
        crate::trap_fatal(&format!(
            "opening /dev/pts/{index} without O_NOCTTY as a session leader would acquire a \
             controlling terminal, which is not modeled; failing closed"
        ));
    }
    pair.io_error = false;
    pair.slave_closed = false;
    pair.slaves += 1;
    Ok(())
}

/// Bind a slave description whose open succeeded, or undo the open.
fn install_slave(index: u32, status: u32, cloexec: bool) -> c_int {
    match answer_install(FdKind::PtySlave, index, status, cloexec) {
        Ok(fd) => {
            set_errno(0);
            fd
        }
        Err(errno) => {
            release(Side::Slave, index);
            fail(errno)
        }
    }
}

/// `open("/dev/pts/<index>")`. A name no live pair has is `ENOENT`, or
/// `EACCES` for a creating open (devpts's root is root's `0755`).
pub(crate) fn open_slave(index: u32, flags: u32, cloexec: bool) -> c_int {
    let path = name(Side::Slave, index);
    if node(index).is_none() {
        return fail(if flags & O_CREATE != 0 && flags & O_PATH == 0 {
            EACCES
        } else {
            ENOENT
        });
    }
    let status = match device_open_status(&path, flags) {
        Ok(status) => status,
        Err(errno) => return fail(errno),
    };
    // The number comes before the open (`do_sys_openat2`), so a full table
    // leaves the pair as it was.
    if let Err(errno) = crate::fd_table().lock().has_free() {
        return fail(errno);
    }
    match open_slave_side(index, flags & O_NOCTTY != 0) {
        Ok(()) => install_slave(index, status, cloexec),
        Err(errno) => fail(errno),
    }
}

/// The kernel's open-flag bits `TIOCGPTPEER` takes (asm-generic fcntl, the
/// same on both Linux architectures).
mod kernel_open {
    pub(super) const O_ACCMODE: i32 = 0o3;
    pub(super) const O_WRONLY: i32 = 0o1;
    pub(super) const O_RDWR: i32 = 0o2;
    pub(super) const O_CREAT: i32 = 0o100;
    pub(super) const O_EXCL: i32 = 0o200;
    pub(super) const O_NOCTTY: i32 = 0o400;
    pub(super) const O_TRUNC: i32 = 0o1000;
    pub(super) const O_NONBLOCK: i32 = 0o4000;
    pub(super) const O_CLOEXEC: i32 = 0o2000000;
}

/// `TIOCGPTPEER` (`ptm_open_peer`): open the master's slave through its
/// node with `flags`, the kernel's open flags. The descriptor comes first
/// (`EMFILE`), then the slave's open (`EIO` while locked); `dentry_open`
/// checks no permission, keeps the flags as given in the description (so
/// `O_CLOEXEC` shows in `F_GETFL`) less `O_CREAT`, `O_EXCL`, `O_NOCTTY`
/// and `O_TRUNC`, and does not force `O_LARGEFILE`.
fn open_peer(index: u32, flags: i32) -> c_int {
    use kernel_open as k;
    let known = k::O_ACCMODE
        | k::O_CREAT
        | k::O_EXCL
        | k::O_NOCTTY
        | k::O_TRUNC
        | k::O_NONBLOCK
        | k::O_CLOEXEC;
    if flags & !known != 0 || flags & k::O_ACCMODE == k::O_ACCMODE {
        crate::trap_fatal(&format!(
            "TIOCGPTPEER with open flags {flags:#o} is not modeled; failing closed"
        ));
    }
    let mut status = match flags & k::O_ACCMODE {
        k::O_WRONLY => O_WRITE,
        k::O_RDWR => O_READ | O_WRITE,
        _ => O_READ,
    };
    if flags & k::O_NONBLOCK != 0 {
        status |= O_NONBLOCK;
    }
    let cloexec = flags & k::O_CLOEXEC != 0;
    if cloexec {
        status |= O_CLOEXEC;
    }
    // The number comes first, as `get_unused_fd_flags` does.
    if let Err(errno) = crate::fd_table().lock().has_free() {
        return fail(errno);
    }
    match open_slave_side(index, flags & k::O_NOCTTY != 0) {
        Ok(()) => install_slave(index, status, cloexec),
        Err(errno) => fail(errno),
    }
}

/// A description's last reference went (`tty_release`): a slave's last
/// description marks the master's slave closed; the master's hangs the slave
/// up and removes its node. The pair and its index go with the last
/// description of either side.
pub(crate) fn release(side: Side, index: u32) {
    let mut state = lock_state();
    let Some(pair) = state.ptys.pairs.get_mut(&index) else {
        return;
    };
    match side {
        Side::Master => pair.master = false,
        Side::Slave => {
            pair.slaves -= 1;
            // `pty_close` of a slave whose last open failed leaves the
            // master's flag alone.
            if pair.slaves == 0 && !pair.io_error {
                pair.slave_closed = true;
            }
        }
    }
    if !pair.master && pair.slaves == 0 {
        state.ptys.pairs.remove(&index);
    }
}

/// Whether the pair's slave is hung up: its master closed.
fn hung_up(pair: &Pair) -> bool {
    !pair.master
}

// ---- requests ----------------------------------------------------------

const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TCSETSW: u64 = 0x5403;
const TCSETSF: u64 = 0x5404;
const TCSBRK: u64 = 0x5409;
const TIOCSCTTY: u64 = 0x540E;
const TIOCGPGRP: u64 = 0x540F;
const TIOCSPGRP: u64 = 0x5410;
const TIOCOUTQ: u64 = 0x5411;
const TIOCGWINSZ: u64 = 0x5413;
const TIOCSWINSZ: u64 = 0x5414;
const TIOCNOTTY: u64 = 0x5422;
const TIOCGETD: u64 = 0x5424;
const TCSBRKP: u64 = 0x5425;
const TIOCGSID: u64 = 0x5429;
const TIOCGPTN: u64 = 0x8004_5430;
const TIOCSPTLCK: u64 = 0x4004_5431;
const TIOCGPTLCK: u64 = 0x8004_5439;
const TIOCGPTPEER: u64 = 0x5441;

/// Stop the run: the tty request is not modeled.
fn stop(request: u64) -> ! {
    crate::trap_fatal(&format!(
        "ioctl: tty request {request:#x} on a pseudoterminal is not modeled; failing closed"
    ))
}

fn put<T: Copy>(arg: usize, value: T) -> c_int {
    match uaccess::write(arg, &value) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

fn done() -> c_int {
    set_errno(0);
    0
}

/// `tty_ioctl` for a pair's descriptor, past the requests every descriptor
/// takes (`do_vfs_ioctl`). A hung-up slave answers every request `EIO`
/// (`hung_up_tty_ioctl`), `TIOCSPGRP` `ENOTTY`.
pub(crate) fn ioctl(side: Side, index: u32, request: u64, arg: usize) -> c_int {
    // Requests of another type go on to the line discipline, which knows
    // none of them.
    let tty_request = (request >> 8) & 0xff == u64::from(b'T');
    let mut state = lock_state();
    let Some(pair) = state.ptys.pairs.get_mut(&index) else {
        return fail(crate::EBADF);
    };
    if side == Side::Slave && hung_up(pair) {
        return fail(if request == TIOCSPGRP { ENOTTY } else { EIO });
    }
    if !tty_request {
        return fail(ENOTTY);
    }
    match request {
        TCGETS => {
            let termios = pair.termios;
            drop(state);
            put(arg, termios)
        }
        TCSETS | TCSETSW | TCSETSF => {
            let Ok(new) = uaccess::read::<Termios>(arg) else {
                return fail(EFAULT);
            };
            set_termios(pair, new);
            done()
        }
        TIOCGWINSZ => {
            let winsize = pair.winsize;
            drop(state);
            put(arg, winsize)
        }
        // `tty_do_resize` (a Unix98 slave has no `.resize`): the foreground
        // group a change signals is the controlling terminal's, which this
        // pair never is.
        TIOCSWINSZ => match uaccess::read::<Winsize>(arg) {
            Ok(winsize) => {
                pair.winsize = winsize;
                done()
            }
            Err(errno) => fail(errno),
        },
        TIOCGPTN if side == Side::Master => {
            drop(state);
            put(arg, index)
        }
        TIOCSPTLCK if side == Side::Master => match uaccess::read::<i32>(arg) {
            Ok(value) => {
                pair.locked = value != 0;
                done()
            }
            Err(errno) => fail(errno),
        },
        TIOCGPTLCK if side == Side::Master => {
            let locked = i32::from(pair.locked);
            drop(state);
            put(arg, locked)
        }
        TIOCGPTPEER if side == Side::Master => {
            drop(state);
            open_peer(index, arg as i32)
        }
        // `ptm_open_peer` of a slave; the other master requests fall to
        // the line discipline.
        TIOCGPTPEER => fail(EIO),
        TIOCGPTN | TIOCSPTLCK | TIOCGPTLCK => fail(ENOTTY),
        // `tty_wait_until_sent` finds nothing queued in a pty, and a pty
        // has no break to send.
        TCSBRK | TCSBRKP => done(),
        // `n_tty_ioctl`: the driver holds nothing unsent.
        TIOCOUTQ => {
            drop(state);
            put(arg, 0i32)
        }
        TIOCGETD => {
            drop(state);
            put(arg, 0i32)
        }
        // The job-control requests, for a terminal that is not the
        // caller's controlling one (`tty_jobctrl_ioctl`).
        TIOCGPGRP if side == Side::Master => {
            drop(state);
            put(arg, 0i32)
        }
        TIOCGPGRP | TIOCGSID | TIOCNOTTY => fail(ENOTTY),
        TIOCSPGRP => {
            drop(state);
            match uaccess::read::<i32>(arg) {
                Err(errno) => fail(errno),
                Ok(pgrp) if pgrp < 0 => fail(crate::EINVAL),
                Ok(_) => fail(ENOTTY),
            }
        }
        TIOCSCTTY if !crate::identity::session_leader() => fail(crate::EPERM),
        _ => {
            drop(state);
            stop(request)
        }
    }
}

/// `set_termios` → `tty_set_termios` → `pty_set_termios` on the pair's
/// slave: `ADDRB` stays, and the character size and receiver are forced
/// to 8 bits, no parity.
fn set_termios(pair: &mut Pair, mut new: Termios) {
    new.cflag ^= (new.cflag ^ pair.termios.cflag) & ADDRB;
    new.cflag &= !(CSIZE | PARENB);
    new.cflag |= CS8 | CREAD;
    pair.termios = new;
}

// ---- transfer and readiness ----------------------------------------------

/// `tty_read` on a pair's descriptor.
///
/// # Safety
/// `destination` must be writable for `length` bytes when nonzero.
pub(crate) unsafe fn read(
    resolved: crate::fdtable::Resolved,
    destination: *mut c_void,
    length: usize,
    nonblocking: bool,
) -> isize {
    let _ = (resolved, destination, length, nonblocking);
    crate::trap_fatal("reading a pseudoterminal is not modeled; failing closed")
}

/// `tty_write` on a pair's descriptor.
///
/// # Safety
/// `source` must be readable for `length` bytes when nonzero.
pub(crate) unsafe fn write(
    resolved: crate::fdtable::Resolved,
    source: *const c_void,
    length: usize,
    nonblocking: bool,
) -> isize {
    let _ = (resolved, source, length, nonblocking);
    crate::trap_fatal("writing a pseudoterminal is not modeled; failing closed")
}

/// `n_tty_poll`, or `hung_up_tty_poll` for a hung-up slave: every event.
/// A master polls hung up once its last slave description closed; either
/// side takes a write while the pair is live.
pub(in crate::thread) fn poll(state: &ThreadRuntime, side: Side, index: u32) -> (u32, (u64, u64)) {
    use super::net::abi::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM};
    let Some(pair) = state.ptys.pairs.get(&index) else {
        return (POLLERR | POLLHUP, (0, 0));
    };
    if side == Side::Slave && hung_up(pair) {
        return (
            POLLIN | POLLOUT | POLLERR | POLLHUP | POLLRDNORM | POLLWRNORM,
            (0, 0),
        );
    }
    let mut mask = POLLOUT | POLLWRNORM;
    if side == Side::Master && pair.slave_closed {
        mask |= POLLHUP;
    }
    (mask, (0, 0))
}

/// `TIOCINQ` (`FIONREAD`): the bytes a read would take now; `EIO` on a
/// hung-up slave.
pub(crate) fn inq(side: Side, index: u32) -> Result<i32, c_int> {
    let state = lock_state();
    let pair = state.ptys.pairs.get(&index).ok_or(crate::EBADF)?;
    if side == Side::Slave && hung_up(pair) {
        return Err(EIO);
    }
    Ok(0)
}

/// The name `/proc/self/fd` reads for a pseudoterminal descriptor
/// (`ttyname`'s answer): its length, written with its terminator when `len`
/// has room; `ENOTTY` for any other descriptor, `EBADF` for none.
///
/// # Safety
/// `buf` must be writable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_pty_name(fd: c_int, buf: *mut c_char, len: usize) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let resolved = match crate::resolve_fd(fd) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno) as isize,
    };
    let Some(side) = Side::of(resolved.kind) else {
        return fail(ENOTTY) as isize;
    };
    let name = name(side, resolved.handle as u32);
    if name.len() < len {
        // SAFETY: writable for `len` bytes per this function's contract.
        unsafe {
            std::ptr::copy_nonoverlapping(name.as_ptr(), buf.cast::<u8>(), name.len());
            buf.add(name.len()).write(0);
        }
    }
    set_errno(0);
    name.len() as isize
}
