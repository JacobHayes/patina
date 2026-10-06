//! PTY line discipline, transformations, queues, and timestamps.

use super::*;

// ---- the line discipline -------------------------------------------------

/// A byte in the slave's read buffer (n_tty's `read_buf`) and whether it
/// ends a line (`read_flags`): a newline, `VEOL`/`VEOL2`, or an end of file,
/// stored as the disabled character 0 and never copied out.
#[derive(Clone, Copy)]
pub(super) struct Cell {
    pub(super) byte: u8,
    delim: bool,
}

/// `N_TTY_BUF_SIZE` less one: the most a direction holds unread before the
/// kernel's flow control (a throttled line discipline, a full flip buffer,
/// canonical-mode discards) decides what happens to more, which the model
/// does not.
pub(super) const ROOM: usize = 4095;

const VDISABLE: u8 = 0;
const ISTRIP: u32 = 0o40;
const INLCR: u32 = 0o100;
const IGNCR: u32 = 0o200;
const IUCLC: u32 = 0o1000;
const PARMRK: u32 = 0o10;
const IUTF8: u32 = 0o40000;
const OLCUC: u32 = 0o2;
const OCRNL: u32 = 0o10;
const ONOCR: u32 = 0o20;
const ONLRET: u32 = 0o40;
const TABDLY: u32 = 0o14000;
const XTABS: u32 = 0o14000;
const ECHONL: u32 = 0o100;
pub(super) const EXTPROC: u32 = 0o200000;

/// The kernel's `iscntrl`: lib/ctype.c's `_C` class is C0 and DEL; its
/// table marks nothing from 0x80 up as a control character.
fn iscntrl(byte: u8) -> bool {
    byte < 0x20 || byte == 0x7f
}

/// n_tty's `is_continuation`: a UTF-8 continuation byte under `IUTF8`.
fn is_continuation(byte: u8, t: &Termios) -> bool {
    t.iflag & IUTF8 != 0 && byte & 0xc0 == 0x80
}

/// Whether n_tty's `char_map` holds `c` under `t` (`n_tty_set_termios`): the
/// bytes its receive takes through `n_tty_receive_char_special`. The
/// disabled character 0 never is.
fn special(t: &Termios, c: u8) -> bool {
    let is = |slot: usize| t.cc[slot] == c;
    let canonical = t.lflag & ICANON != 0;
    let extended = t.lflag & IEXTEN != 0;
    c != VDISABLE
        && ((c == b'\r' && t.iflag & (IGNCR | ICRNL) != 0)
            || (c == b'\n' && t.iflag & INLCR != 0)
            || (canonical && (is(VERASE) || is(VKILL) || is(VEOF) || c == b'\n' || is(VEOL)))
            || (canonical && extended && (is(VWERASE) || is(VLNEXT) || is(VEOL2)))
            || (canonical && extended && t.lflag & ECHO != 0 && is(VREPRINT))
            || (t.iflag & IXON != 0 && (is(VSTART) || is(VSTOP)))
            || (t.lflag & ISIG != 0 && (is(VINTR) || is(VQUIT) || is(VSUSP))))
}

/// Stop the run: `what` in the line discipline is not modeled.
pub(super) fn unmodeled(what: &str) -> ! {
    crate::trap_fatal(&format!(
        "a pseudoterminal's line discipline: {what} is not modeled; failing closed"
    ))
}

impl Pair {
    pub(super) fn canonical(&self) -> bool {
        self.termios.lflag & ICANON != 0
    }

    /// n_tty's `do_output_char` for one byte the slave writes or echoes,
    /// under `OPOST`, onto the master's read buffer; the column it keeps.
    pub(super) fn output(&mut self, byte: u8) {
        let t = self.termios;
        if t.oflag & OPOST == 0 {
            self.to_master.push_back(byte);
            return;
        }
        match byte {
            b'\n' => {
                if t.oflag & ONLRET != 0 {
                    self.column = 0;
                }
                if t.oflag & ONLCR != 0 {
                    self.column = 0;
                    self.to_master.extend(b"\r\n");
                    return;
                }
                self.to_master.push_back(b'\n');
            }
            b'\r' => {
                if t.oflag & ONOCR != 0 && self.column == 0 {
                    return;
                }
                if t.oflag & OCRNL != 0 {
                    if t.oflag & ONLRET != 0 {
                        self.column = 0;
                    }
                    self.to_master.push_back(b'\n');
                    return;
                }
                self.column = 0;
                self.to_master.push_back(b'\r');
            }
            b'\t' => {
                let spaces = 8 - (self.column & 7);
                self.column += spaces;
                if t.oflag & TABDLY == XTABS {
                    self.to_master.extend(std::iter::repeat_n(b' ', spaces));
                } else {
                    self.to_master.push_back(b'\t');
                }
            }
            8 => {
                self.column = self.column.saturating_sub(1);
                self.to_master.push_back(8);
            }
            _ => {
                if !iscntrl(byte) {
                    if t.oflag & OLCUC != 0 {
                        unmodeled("OLCUC output");
                    }
                    if !is_continuation(byte, &t) {
                        self.column += 1;
                    }
                }
                self.to_master.push_back(byte);
            }
        }
    }

    /// n_tty's `echo_char`: a control character (not a tab) as `^X` under
    /// `ECHOCTL`, written as it is; any other byte through the output
    /// processing. 0377 is written as it is.
    fn echo(&mut self, byte: u8) {
        if byte == 0xff {
            self.column += 1;
            self.to_master.push_back(byte);
        } else if self.termios.lflag & ECHOCTL != 0 && iscntrl(byte) && byte != b'\t' {
            self.column += 2;
            self.to_master.extend([b'^', byte ^ 0o100]);
        } else {
            self.output(byte);
        }
    }

    /// A line-ending cell: the readable part of a canonical buffer ends
    /// after it (`canon_head`).
    fn end_line(&mut self, byte: u8) {
        self.to_slave.push_back(Cell { byte, delim: true });
        self.canon = self.to_slave.len();
    }

    /// n_tty's receive of one byte the master wrote, under the slave's
    /// settings (`n_tty_receive_buf_standard`): `ISTRIP`, then a byte in the
    /// `char_map` takes the special path, any other the plain one. `IUCLC`
    /// stops by name.
    pub(super) fn receive(&mut self, byte: u8) {
        let t = self.termios;
        let mut c = byte;
        if t.iflag & ISTRIP != 0 {
            c &= 0x7f;
        }
        if t.iflag & IUCLC != 0 && t.lflag & IEXTEN != 0 {
            unmodeled("IUCLC input");
        }
        if special(&t, c) {
            self.receive_special(c);
        } else {
            self.receive_plain(c);
        }
    }

    /// `n_tty_receive_char`: the echo (`echo_char`), and the byte queued.
    fn receive_plain(&mut self, c: u8) {
        if self.termios.lflag & ECHO != 0 {
            self.echo(c);
        }
        self.queue(c);
    }

    /// `n_tty_receive_char_special`: flow control's start character is
    /// consumed; the input translations; the canonical line endings; and the
    /// echo, a translated newline written as it is (`echo_char_raw`). Flow
    /// control's stop, the signal characters, line editing and literal-next
    /// stop by name.
    fn receive_special(&mut self, byte: u8) {
        let t = self.termios;
        let mut c = byte;
        let is = |slot: usize| t.cc[slot] == c;
        if t.iflag & IXON != 0 {
            if is(VSTART) {
                return;
            }
            if is(VSTOP) {
                unmodeled("flow control's stop character (IXON)");
            }
        }
        if t.lflag & ISIG != 0 && (is(VINTR) || is(VQUIT) || is(VSUSP)) {
            unmodeled("a signal character (ISIG)");
        }
        if c == b'\r' {
            if t.iflag & IGNCR != 0 {
                return;
            }
            if t.iflag & ICRNL != 0 {
                c = b'\n';
            }
        } else if c == b'\n' && t.iflag & INLCR != 0 {
            c = b'\r';
        }
        if self.canonical() && self.receive_canonical(c) {
            return;
        }
        if t.lflag & ECHO != 0 {
            if c == b'\n' {
                self.output(b'\n');
            } else {
                self.echo(c);
            }
        }
        self.queue(c);
    }

    /// `n_tty_receive_char_canon`: whether `c` was a canonical line ending
    /// (or editing, which stops by name).
    fn receive_canonical(&mut self, c: u8) -> bool {
        let t = self.termios;
        let is = |slot: usize| c != VDISABLE && t.cc[slot] == c;
        let extended = t.lflag & IEXTEN != 0;
        if is(VERASE) || is(VKILL) || (is(VWERASE) && extended) {
            unmodeled("canonical line editing (VERASE, VKILL, VWERASE)");
        }
        if is(VLNEXT) && extended {
            unmodeled("the literal-next character (VLNEXT)");
        }
        if is(VREPRINT) && t.lflag & ECHO != 0 && extended {
            unmodeled("the reprint character (VREPRINT)");
        }
        if c == b'\n' {
            if t.lflag & (ECHO | ECHONL) != 0 {
                self.output(b'\n');
            }
            self.end_line(b'\n');
            return true;
        }
        if is(VEOF) {
            self.end_line(VDISABLE);
            return true;
        }
        if is(VEOL) || (is(VEOL2) && extended) {
            if t.lflag & ECHO != 0 {
                self.echo(c);
            }
            if c == 0xff && t.iflag & PARMRK != 0 {
                unmodeled("PARMRK's doubled 0377");
            }
            self.end_line(c);
            return true;
        }
        false
    }

    /// `put_tty_queue` of a byte that ends no line; `PARMRK`'s doubling of
    /// 0377 stops by name.
    pub(super) fn queue(&mut self, c: u8) {
        if c == 0xff && self.termios.iflag & PARMRK != 0 {
            unmodeled("PARMRK's doubled 0377");
        }
        self.to_slave.push_back(Cell {
            byte: c,
            delim: false,
        });
    }

    /// `n_tty_set_termios` switching canonical mode: the line endings are
    /// forgotten; entering canonical mode with bytes waiting makes them one
    /// line.
    pub(super) fn recanonicalize(&mut self, was_canonical: bool) {
        if was_canonical == self.canonical() {
            return;
        }
        for cell in &mut self.to_slave {
            cell.delim = false;
        }
        self.canon = 0;
        if self.canonical() {
            if let Some(last) = self.to_slave.back_mut() {
                last.delim = true;
                self.canon = self.to_slave.len();
            }
        }
    }

    /// Whether a read of this side takes something now (`input_available_p`
    /// with `poll` saying whether the raw minimum counts).
    pub(super) fn readable(&self, side: Side, poll: bool) -> bool {
        match side {
            Side::Master => !self.to_master.is_empty(),
            Side::Slave if self.canonical() => self.canon > 0,
            Side::Slave => {
                let (min, time) = (self.termios.cc[VMIN], self.termios.cc[VTIME]);
                let amount = if poll && time == 0 && min != 0 {
                    usize::from(min)
                } else {
                    1
                };
                self.to_slave.len() >= amount
            }
        }
    }

    /// `canon_copy_from_read_buf`: one line, or as much of it as `room`
    /// takes; the line ending is copied unless it is an end of file. A read
    /// that fills its room exactly before an end of file also takes the end
    /// of file (`canon_skip_eof`).
    pub(super) fn take_line(&mut self, room: usize) -> Vec<u8> {
        let mut taken = Vec::new();
        let mut consumed = 0;
        while consumed < self.canon && taken.len() < room {
            let cell = self.to_slave[consumed];
            consumed += 1;
            if cell.delim {
                if cell.byte != VDISABLE {
                    taken.push(cell.byte);
                }
                self.drain_slave(consumed);
                return taken;
            }
            taken.push(cell.byte);
        }
        if consumed < self.canon {
            let next = self.to_slave[consumed];
            if next.delim && next.byte == VDISABLE {
                consumed += 1;
            }
        }
        self.drain_slave(consumed);
        taken
    }

    fn drain_slave(&mut self, count: usize) {
        self.to_slave.drain(..count);
        self.canon = self.canon.saturating_sub(count);
    }

    /// n_tty's `chars_in_buffer`: a canonical slave's complete lines (their
    /// ends and ends of file included), otherwise everything queued.
    pub(super) fn in_buffer(&self, side: Side) -> usize {
        match side {
            Side::Master => self.to_master.len(),
            Side::Slave if self.canonical() => self.canon,
            Side::Slave => self.to_slave.len(),
        }
    }

    /// `inq_canon` / `read_cnt`: what `FIONREAD` reports for a side.
    pub(super) fn queued(&self, side: Side) -> usize {
        match side {
            Side::Master => self.to_master.len(),
            Side::Slave if self.canonical() => self
                .to_slave
                .iter()
                .take(self.canon)
                .filter(|cell| !(cell.delim && cell.byte == VDISABLE))
                .count(),
            Side::Slave => self.to_slave.len(),
        }
    }
}

/// `tty_update_time`: a transfer through a side moves its node's access
/// (a read) or modification (a write) time to the current second, once the
/// second differs from the recorded one past its low three bits.
fn touch(times: &mut NodeTimes, write: bool) {
    let second = now() / 1_000_000_000;
    let stamp = if write {
        &mut times.mtime
    } else {
        &mut times.atime
    };
    if (second ^ (*stamp / 1_000_000_000)) & !7 != 0 {
        *stamp = second * 1_000_000_000;
    }
}

impl Pair {
    /// A wakeup of a side's queues: `input` when it reaches an epoll
    /// interest in input (a wakeup keyed `EPOLLIN`, or one with no key),
    /// `output` when it reaches one in output (keyed `EPOLLOUT`, or no
    /// key). The tasks waiting on the side wake to look.
    pub(super) fn wake(&mut self, side: Side, input: bool, output: bool) -> Vec<TaskId> {
        let edges = &mut self.edges[side.slot()];
        if input {
            edges.0 = edges.0.wrapping_add(1);
        }
        if output {
            edges.1 = edges.1.wrapping_add(1);
        }
        self.waiters[side.slot()].drain(..).collect()
    }

    /// n_tty's `flush_buffer` of a side: its unread input goes.
    pub(super) fn flush(&mut self, side: Side) {
        match side {
            Side::Master => self.to_master.clear(),
            Side::Slave => {
                self.to_slave.clear();
                self.canon = 0;
            }
        }
    }
}

/// `tty_update_time` for a transfer through `side` of the pair `index`.
pub(super) fn touch_side(ptys: &mut Ptys, side: Side, index: u32, write: bool) {
    match side {
        Side::Master => touch(ptys.ptmx.get_or_insert(NodeTimes::at(now())), write),
        Side::Slave => {
            if let Some(pair) = ptys.pairs.get_mut(&index) {
                touch(&mut pair.node, write);
            }
        }
    }
}
