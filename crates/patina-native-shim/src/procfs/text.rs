//! The text of procfs's files, made from the virtual machine's state in the
//! pinned 6.8's formats (fs/proc/{uptime,loadavg,stat,meminfo,array}.c,
//! mm/vmstat.c). The model's sources are the ones `sysinfo(2)` answers
//! from: the boot clock, the CPU count, the machine's memory
//! (`limits::MACHINE_MEMORY`, half of it free, no swap, no buffer or shared
//! pages), an idle load, the CPU time each process was charged, the threads
//! the scheduler holds, and the pid namespace's processes and credentials.
//!
//! What the model cannot answer is left out: `stat`'s per-CPU lines (the
//! charges are not kept per CPU), its interrupt, context-switch and softirq
//! counts; `meminfo`'s cache and LRU breakdown and `MemAvailable`;
//! `vmstat`'s paging counts (`pgpgin`, `pgpgout`); and the memory, signal,
//! descriptor and seccomp lines of a process's files. The load is the
//! idle one `sysinfo` reports. A thread's user time counts as niced while
//! its nice value is positive (the kernel files each tick under the value
//! of the moment); a finished thread's counts as user time.

use super::{Machine, Node, OfProcess, PF_RANDOMIZE};
use crate::clocks::{CpuOf, NANOS, USER_HZ, cpu_time_unrecorded};
use crate::identity::{Listed, Process};
use crate::thread::Census;
use crate::thread::sched::Scheduling;
use crate::{ENOENT, ESRCH, with_context};
use patina_dst_abi::{ClockKind, CpuCharge};
use std::ffi::c_int;
use std::fmt::Write as _;

/// What a file's text is made from, read in one step: the boot clock now,
/// the CPU charges, and the boot instant.
struct Reading {
    /// The boot clock, in nanoseconds.
    uptime: u64,
    /// The boot clock when the guest started.
    origin: u64,
    /// The guest process's CPU time.
    guest: CpuCharge,
    /// Init's.
    init: CpuCharge,
    /// The user time of the guest's live threads at a positive nice value.
    niced_user: u64,
    /// The realtime clock's reading at boot, in seconds (`btime`).
    boot_seconds: u64,
}

/// Read the clocks and the charges (behind the call's scheduling point),
/// then the threads, then the niced threads' charges: the thread runtime's
/// lock is never held under the context's.
#[expect(
    clippy::disallowed_methods,
    reason = "a procfs read is the guest's reading of the boot clock, recorded as its clock reads are"
)]
fn read() -> Result<(Reading, Census), c_int> {
    let mut reading = with_context(|context| {
        let uptime = context.now(ClockKind::Monotonic)?;
        let realtime = context.fs_time_unrecorded()?;
        let monotonic = context.monotonic_now_unrecorded()?;
        Ok(Reading {
            uptime,
            origin: context.boot_origin_nanos(),
            guest: cpu_time_unrecorded(context, CpuOf::Process),
            init: cpu_time_unrecorded(context, CpuOf::Init),
            niced_user: 0,
            boot_seconds: realtime.saturating_sub(monotonic) / NANOS,
        })
    })?;
    let census = crate::thread::census();
    if !census.niced.is_empty() {
        reading.niced_user = crate::with_context_raw(|context| {
            Ok(census
                .niced
                .iter()
                .map(|task| cpu_time_unrecorded(context, CpuOf::Thread(*task)).user_ns)
                .sum())
        })?;
    }
    Ok((reading, census))
}

/// `nsec_to_clock_t`: nanoseconds in `USER_HZ` ticks.
fn ticks(nanos: u64) -> u64 {
    nanos / (NANOS / USER_HZ)
}

/// `seconds.centiseconds`, as `/proc/uptime` prints a duration.
fn centiseconds(nanos: u64) -> String {
    format!("{}.{:02}", nanos / NANOS, (nanos % NANOS) / (NANOS / 100))
}

impl Reading {
    /// The machine's busy time: every process's CPU time.
    fn busy(&self) -> u64 {
        self.guest.total_ns() + self.init.total_ns()
    }

    /// The machine's idle time: every CPU's uptime but the busy time.
    fn idle(&self) -> u64 {
        (u64::from(crate::cpus::count()) * self.uptime).saturating_sub(self.busy())
    }
}

/// The threads running or runnable: the guest's that do not wait (init
/// sleeps).
fn running(census: &Census) -> usize {
    census.live - census.waiting
}

/// A file's text now.
pub(super) fn generate(node: Node) -> Result<Vec<u8>, c_int> {
    let (reading, census) = read()?;
    let memory = crate::limits::MACHINE_MEMORY;
    let free = memory / 2;
    let text = match node {
        Node::Machine(Machine::Uptime) => format!(
            "{} {}\n",
            centiseconds(reading.uptime),
            centiseconds(reading.idle())
        ),
        Node::Machine(Machine::Loadavg) => format!(
            "0.00 0.00 0.00 {}/{} {}\n",
            running(&census),
            census.live + 1,
            census.last_tid
        ),
        Node::Machine(Machine::Stat) => {
            let user = reading.guest.user_ns + reading.init.user_ns - reading.niced_user;
            let system = reading.guest.system_ns + reading.init.system_ns;
            format!(
                "cpu  {} {} {} {} 0 0 0 0 0 0\nbtime {}\nprocesses {}\nprocs_running {}\n\
                 procs_blocked 0\n",
                ticks(user),
                ticks(reading.niced_user),
                ticks(system),
                ticks(reading.idle()),
                reading.boot_seconds,
                census.last_tid,
                running(&census)
            )
        }
        Node::Machine(Machine::Meminfo) => {
            let mut text = String::new();
            for (key, bytes) in [
                ("MemTotal:", memory),
                ("MemFree:", free),
                ("Buffers:", 0),
                ("SwapTotal:", 0),
                ("SwapFree:", 0),
                ("Shmem:", 0),
            ] {
                let _ = writeln!(text, "{key:<16}{:>8} kB", bytes / 1024);
            }
            text
        }
        Node::Machine(Machine::Vmstat) => format!(
            "nr_free_pages {}\npswpin 0\npswpout 0\n",
            free / crate::PAGE_SIZE as u64
        ),
        Node::Of(pid, file) => {
            let task = Task::of(pid, &census, &reading)?;
            return Ok(task.text(file));
        }
        Node::OfThread(pid, tid, file) => {
            let task = Task::of_thread(pid, tid, &census, &reading)?;
            return Ok(task.text(file));
        }
        Node::NetFile(pid, file) => return Ok(super::net::text(pid, file)),
        Node::Root
        | Node::SelfLink
        | Node::NetLink
        | Node::Process(_)
        | Node::Tasks(_)
        | Node::Thread(..)
        | Node::Net(_) => crate::trap_fatal("a procfs directory or link has no text"),
    };
    Ok(text.into_bytes())
}

/// A process as its procfs files describe it: its thread-group leader's
/// state and scheduling, the group's CPU time and thread count.
struct Task {
    listed: Listed,
    /// The thread it describes (the leader's for a process's files).
    tid: i32,
    comm: Vec<u8>,
    running: bool,
    scheduling: Scheduling,
    threads: usize,
    charge: CpuCharge,
    /// When it started, on the boot clock, where the model keeps it (the
    /// process's start, its first thread's).
    start: Option<u64>,
    /// Its umask, where the model holds one (the guest's).
    umask: Option<u32>,
}

/// Init's name: the model's init runs no program of its own.
const INIT_COMM: &[u8] = b"init";

impl Task {
    fn of(pid: i32, census: &Census, reading: &Reading) -> Result<Task, c_int> {
        let listed = crate::identity::processes()
            .into_iter()
            .find(|listed| listed.process.pid() == pid)
            .ok_or(ENOENT)?;
        if listed.process == Process::INIT {
            return Ok(Task {
                listed,
                tid: pid,
                comm: INIT_COMM.to_vec(),
                running: false,
                scheduling: Scheduling {
                    comm: [0; 16],
                    nice: 0,
                    prio: 20,
                    policy: 0,
                    rt_priority: 0,
                },
                threads: 1,
                charge: reading.init,
                start: Some(0),
                umask: None,
            });
        }
        let scheduling = crate::thread::sched::scheduling(pid);
        let comm = scheduling
            .comm
            .iter()
            .copied()
            .take_while(|byte| *byte != 0)
            .collect();
        Ok(Task {
            listed,
            tid: pid,
            comm,
            // The leader runs while the caller is it, and otherwise unless it
            // sleeps in a wait.
            running: crate::thread::current_tid() == pid || !census.main_waiting,
            scheduling,
            threads: census.live,
            charge: reading.guest,
            start: Some(reading.origin),
            umask: Some(crate::paths::umask()),
        })
    }

    /// Thread `tid` of process `pid`, as its `task/<tid>` files describe
    /// it: the process's, with the thread's own name, state, scheduling and
    /// CPU time (`ESRCH` for a thread gone since its directory was found).
    fn of_thread(pid: i32, tid: i32, census: &Census, reading: &Reading) -> Result<Task, c_int> {
        let mut task = Task::of(pid, census, reading)?;
        if pid == Process::INIT.pid() {
            return if tid == pid { Ok(task) } else { Err(ESRCH) };
        }
        let thread = census
            .threads
            .iter()
            .find(|thread| thread.tid == tid)
            .copied()
            .ok_or(ESRCH)?;
        let scheduling = crate::thread::sched::scheduling(tid);
        task.comm = scheduling
            .comm
            .iter()
            .copied()
            .take_while(|byte| *byte != 0)
            .collect();
        task.tid = tid;
        task.running = crate::thread::current_tid() == tid || !thread.waiting;
        task.scheduling = scheduling;
        task.charge = match thread.task {
            Some(id) => crate::with_context_raw(|context| {
                Ok(cpu_time_unrecorded(context, CpuOf::Thread(id)))
            })?,
            None => reading.guest,
        };
        if tid != pid {
            task.start = None;
        }
        Ok(task)
    }

    fn text(&self, file: OfProcess) -> Vec<u8> {
        match file {
            OfProcess::Stat => self.stat(),
            OfProcess::Status => self.status(),
        }
    }

    /// `<pid>/stat` (`do_task_stat`), through `starttime` where the model
    /// keeps one (`itrealvalue` otherwise): it has no figure for the memory
    /// fields that follow.
    fn stat(&self) -> Vec<u8> {
        let listed = self.listed;
        let mut text = format!("{} (", self.tid).into_bytes();
        text.extend_from_slice(&self.comm);
        text.extend_from_slice(
            format!(
                ") {} {} {} {} 0 -1 {} 0 0 0 0 {} {} 0 0 {} {} {} 0{}\n",
                if self.running { 'R' } else { 'S' },
                listed.parent,
                listed.pgid,
                listed.sid,
                PF_RANDOMIZE,
                ticks(self.charge.user_ns),
                ticks(self.charge.system_ns),
                self.scheduling.prio,
                self.scheduling.nice,
                self.threads,
                self.start
                    .map_or_else(String::new, |start| format!(" {}", ticks(start))),
            )
            .as_bytes(),
        );
        text
    }

    /// `<pid>/status` (`proc_pid_status`): the lines the model answers, in
    /// the kernel's order.
    fn status(&self) -> Vec<u8> {
        let listed = self.listed;
        let pid = listed.process.pid();
        let tid = self.tid;
        let credential = listed.process.credential();
        let mut text = b"Name:\t".to_vec();
        // `proc_task_name` escapes a newline and a backslash.
        for byte in &self.comm {
            match byte {
                b'\n' => text.extend_from_slice(b"\\n"),
                b'\\' => text.extend_from_slice(b"\\\\"),
                other => text.push(*other),
            }
        }
        let mut rest = String::from("\n");
        if let Some(umask) = self.umask {
            let _ = writeln!(rest, "Umask:\t{umask:04o}");
        }
        let state = if self.running {
            "R (running)"
        } else {
            "S (sleeping)"
        };
        let ids = |id: u32| format!("{id}\t{id}\t{id}\t{id}");
        let groups: Vec<String> = credential.groups.iter().map(u32::to_string).collect();
        let _ = write!(
            rest,
            "State:\t{state}\nTgid:\t{pid}\nPid:\t{tid}\nPPid:\t{}\nTracerPid:\t0\nUid:\t{}\n\
             Gid:\t{}\nGroups:\t{} \nNStgid:\t{pid}\nNSpid:\t{tid}\nNSpgid:\t{}\nNSsid:\t{}\n\
             Threads:\t{}\nCapInh:\t{:016x}\nCapPrm:\t{:016x}\nCapEff:\t{:016x}\n\
             CapBnd:\t{:016x}\nCapAmb:\t{:016x}\n",
            listed.parent,
            ids(credential.uid),
            ids(credential.gid),
            groups.join(" "),
            listed.pgid,
            listed.sid,
            self.threads,
            credential.inheritable,
            credential.permitted,
            credential.effective,
            credential.bounding,
            credential.ambient,
        );
        text.extend_from_slice(rest.as_bytes());
        text
    }
}
