//! The identity, scheduling and limit rows: credentials (`set*id`,
//! `get*id`, groups, `fsuid`, capabilities), process groups and sessions,
//! scheduling policy, priority and affinity, I/O priority, resource limits
//! (every one but `RLIMIT_MEMLOCK`, which the memory family owns), and the
//! host-description rows (`uname`, `sysinfo`, `personality`, `sysfs`).
//!
//! What is the host's business is never recorded as a value: user and group
//! ids are labeled by first appearance (`Norm::Identity`), so a virtual
//! kernel running the guest as uid 1000 compares with a host running it as
//! anything; a count of supplementary groups is labeled the same way
//! (`Norm::Relative("ngroups")`), so the relation between the count and the
//! calls that take it survives and the count itself does not; the CPU set,
//! memory sizes, the host's hard limits, its kernel release and its node name
//! are recorded as relations the kernel guarantees (a mask is nonempty, free
//! memory is at most total memory, a soft limit is at most its hard one).

use super::Probe;
use crate::observe::{Id, Norm};
use crate::record::EventBuilder;
use crate::vehicle::Vehicle;
use patina_dst_syscalls::Syscall;
use serde_json::Value;

/// A pid argument: the caller (`0`), a pid of this process (recorded by
/// relation), or one no process has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Who {
    Caller,
    Own(i32),
    Missing,
    /// A value the row refuses as a pid (a negative one), recorded as it is.
    Raw(i32),
}

impl Who {
    fn raw(self) -> i64 {
        match self {
            Who::Caller => 0,
            Who::Own(pid) | Who::Raw(pid) => i64::from(pid),
            Who::Missing => i64::from(super::timers::MISSING_PID),
        }
    }

    fn record<'a>(self, builder: EventBuilder<'a>, key: &str) -> EventBuilder<'a> {
        match self {
            Who::Caller => builder.arg(key, 0),
            Who::Own(pid) => builder
                .arg(key, pid)
                .norm(&format!("args.{key}"), Norm::Identity(Id::Process)),
            Who::Missing => builder.arg(key, "missing"),
            Who::Raw(value) => builder.arg(key, value),
        }
    }
}

/// A user or group id argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cred {
    /// This id (the caller's own, or another), recorded by relation.
    Id(u32),
    /// `-1`: "unchanged" to the `setre*`/`setres*` rows, invalid elsewhere.
    Unchanged,
}

impl Cred {
    fn raw(self) -> i64 {
        match self {
            Cred::Id(id) => i64::from(id),
            Cred::Unchanged => i64::from(u32::MAX),
        }
    }

    fn record<'a>(self, builder: EventBuilder<'a>, key: &str, kind: Id) -> EventBuilder<'a> {
        match self {
            Cred::Id(id) => builder
                .arg(key, id)
                .norm(&format!("args.{key}"), Norm::Identity(kind)),
            Cred::Unchanged => builder.arg(key, -1),
        }
    }
}

/// The `size` of a `getgroups` call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupsSize {
    /// The count a previous call answered (recorded by relation).
    Count(i32),
    /// One less than that count (recorded as `count-1`, the answer by
    /// whether it follows the kernel's rule: `EINVAL` below the count, the
    /// count itself when one short is 0, the count query).
    Short(i32),
    /// A size the scenario chose, recorded as it is (0: the count query).
    Raw(i32),
}

impl GroupsSize {
    fn raw(self) -> i32 {
        match self {
            GroupsSize::Count(count) => count,
            GroupsSize::Short(count) => count - 1,
            GroupsSize::Raw(value) => value,
        }
    }
}

/// How a limit read back is recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shown {
    /// Both values are ones the scenario set: recorded as they are.
    Both,
    /// The soft value is one the virtual kernel and the harness pin (the
    /// descriptor limit); the hard one is the host's: recorded as the
    /// relation `soft <= hard`.
    Soft,
    /// Both are the host's: only `soft <= hard`.
    Relation,
}

/// glibc's `getrlimit64`, by its documented type.
pub type GetRlimit64 = unsafe extern "C" fn(libc::c_int, *mut libc::rlimit64) -> libc::c_int;
/// glibc's `setrlimit64`, by its documented type.
pub type SetRlimit64 = unsafe extern "C" fn(libc::c_int, *const libc::rlimit64) -> libc::c_int;

/// `RLIM_INFINITY` as the kernel ABI spells it.
pub const INFINITY: u64 = u64::MAX;

fn limit_label(value: u64) -> Value {
    if value == INFINITY {
        Value::from("infinity")
    } else {
        Value::from(value)
    }
}

/// `struct sched_attr` (include/uapi/linux/sched/types.h), `SCHED_ATTR_SIZE_VER1`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SchedAttr {
    pub size: u32,
    pub policy: u32,
    pub flags: u64,
    pub nice: i32,
    pub priority: u32,
    pub runtime: u64,
    pub deadline: u64,
    pub period: u64,
    pub util_min: u32,
    pub util_max: u32,
}

/// `SCHED_ATTR_SIZE_VER0`: the attribute without the utilization clamps.
pub const SCHED_ATTR_SIZE_VER0: u32 = 48;
/// `SCHED_ATTR_SIZE_VER1`, `sizeof(struct sched_attr)` as the kernel knows it.
pub const SCHED_ATTR_SIZE_VER1: u32 = 56;

/// The capability header and data rows (include/uapi/linux/capability.h).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapData {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}

/// `_LINUX_CAPABILITY_VERSION_3`, the version the kernel writes back.
pub const CAPABILITY_V3: u32 = 0x2008_0522;

/// The `uname` members a scenario relates (the release and node name are
/// host facts, never recorded).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Uts {
    pub sysname: String,
    pub nodename: String,
    pub release: String,
    pub machine: String,
}

fn text(field: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = field
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| c.to_ne_bytes()[0])
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The `sysinfo` members a scenario relates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sysinfo {
    pub uptime: i64,
}

impl Probe {
    // ---- the host description ------------------------------------------------

    /// `uname(&buf)`: records the kernel's name, the machine (an architecture
    /// fact), and relations of the host facts: the release parses as one, the
    /// node name is nonempty. Returns the members for the scenario's checks.
    pub fn uname(&self) -> (i64, Uts) {
        // SAFETY: all-zero is a valid utsname.
        let mut buf: libc::utsname = unsafe { std::mem::zeroed() };
        let result = self.call(
            Syscall::N_uname,
            [&mut buf as *mut libc::utsname as i64, 0, 0, 0, 0, 0],
        );
        let uts = Uts {
            sysname: text(&buf.sysname),
            nodename: text(&buf.nodename),
            release: text(&buf.release),
            machine: text(&buf.machine),
        };
        let builder = self.event(Syscall::N_uname, result);
        let builder = if result == 0 {
            builder
                .field("sysname", uts.sysname.as_str())
                .field("machine", uts.machine.as_str())
                .field(
                    "release_parses",
                    patina_dst_syscalls::parse_release(&uts.release).is_some(),
                )
                .field("version_nonempty", !text(&buf.version).is_empty())
                .field("nodename_nonempty", !uts.nodename.is_empty())
        } else {
            builder
        };
        builder.emit();
        (result, uts)
    }

    /// `sysinfo(&info)` (or NULL): records the members that are kernel facts
    /// on a 64-bit kernel (`mem_unit` 1, no high memory) and relations of the
    /// rest; returns the uptime.
    pub fn sysinfo(&self, null: bool) -> (i64, Sysinfo) {
        // SAFETY: all-zero is a valid sysinfo.
        let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
        let out = if null {
            0
        } else {
            &mut info as *mut libc::sysinfo as i64
        };
        let result = self.call(Syscall::N_sysinfo, [out, 0, 0, 0, 0, 0]);
        let builder = self
            .event(Syscall::N_sysinfo, result)
            .arg("info", if null { "NULL" } else { "buffer" });
        let builder = if result == 0 && !null {
            builder
                .field("mem_unit", info.mem_unit)
                .field("totalhigh", info.totalhigh)
                .field("freehigh", info.freehigh)
                .field("totalram_positive", info.totalram > 0)
                .field("freeram_le_totalram", info.freeram <= info.totalram)
                .field(
                    "free_and_buffers_le_totalram",
                    info.freeram.saturating_add(info.bufferram) <= info.totalram,
                )
                .field("sharedram_le_totalram", info.sharedram <= info.totalram)
                .field("bufferram_le_totalram", info.bufferram <= info.totalram)
                .field("freeswap_le_totalswap", info.freeswap <= info.totalswap)
                .field("procs_positive", info.procs > 0)
                .field("uptime_nonnegative", info.uptime >= 0)
        } else {
            builder
        };
        builder.emit();
        (
            result,
            Sysinfo {
                uptime: info.uptime,
            },
        )
    }

    /// `personality(persona)`: the previous persona.
    pub fn personality(&self, persona: u32) -> i64 {
        let result = self.call(Syscall::N_personality, [i64::from(persona), 0, 0, 0, 0, 0]);
        self.event(Syscall::N_personality, result)
            .arg("persona", format!("{persona:#x}"))
            .emit();
        result
    }

    /// `sysfs(1, name)`: the index of a filesystem type; `label` records
    /// what the name is (a registered type's name is the host's).
    #[cfg(target_arch = "x86_64")]
    pub fn sysfs_index(&self, name: &str, label: &str) -> i64 {
        let c = super::cstr(name);
        let result = self.call(Syscall::N_sysfs, [1, c.as_ptr() as i64, 0, 0, 0, 0]);
        self.event(Syscall::N_sysfs, result)
            .arg("option", 1)
            .arg("name", label)
            .emit();
        result
    }

    /// `sysfs(2, index, buf)`: the name of the type at `index`, which is a
    /// number the scenario chose (`label` records what it means).
    #[cfg(target_arch = "x86_64")]
    pub fn sysfs_name(&self, index: i64, label: &str) -> (i64, String) {
        // The kernel copies at most a filesystem type name (no length given).
        let mut buf = [0u8; 256];
        let result = self.call(
            Syscall::N_sysfs,
            [2, index, buf.as_mut_ptr() as i64, 0, 0, 0],
        );
        let name = String::from_utf8_lossy(&buf[..buf.iter().position(|b| *b == 0).unwrap_or(0)])
            .into_owned();
        let builder = self
            .event(Syscall::N_sysfs, result)
            .arg("option", 2)
            .arg("index", label);
        let builder = if result == 0 {
            builder.field("name_nonempty", !name.is_empty())
        } else {
            builder
        };
        builder.emit();
        (result, name)
    }

    /// `sysfs(option)` with no further argument: `3` answers the number of
    /// filesystem types (a host fact, recorded as whether it is positive).
    #[cfg(target_arch = "x86_64")]
    pub fn sysfs_count(&self, option: i64) -> i64 {
        let result = self.call(Syscall::N_sysfs, [option, 0, 0, 0, 0, 0]);
        let builder = self
            .event(Syscall::N_sysfs, if result >= 0 { 0 } else { result })
            .arg("option", option);
        let builder = if result >= 0 {
            builder.field("positive", result > 0)
        } else {
            builder
        };
        builder.emit();
        result
    }

    // ---- resource limits --------------------------------------------------------

    fn limits<'a>(
        builder: EventBuilder<'a>,
        result: i64,
        cur: u64,
        max: u64,
        shown: Shown,
    ) -> EventBuilder<'a> {
        if result != 0 {
            return builder;
        }
        let le = cur <= max;
        match shown {
            Shown::Both => builder
                .field("cur", limit_label(cur))
                .field("max", limit_label(max)),
            Shown::Soft => builder
                .field("cur", limit_label(cur))
                .field("cur_le_max", le),
            Shown::Relation => builder.field("cur_le_max", le),
        }
    }

    /// `getrlimit(resource, &limit)`; returns `(soft, hard)`.
    pub fn getrlimit(&self, resource: i32, shown: Shown) -> (i64, u64, u64) {
        let mut limit = [u64::MAX - 1; 2];
        let result = self.call(
            Syscall::N_getrlimit,
            [resource as i64, limit.as_mut_ptr() as i64, 0, 0, 0, 0],
        );
        let builder = self
            .event(Syscall::N_getrlimit, result)
            .arg("resource", resource);
        Self::limits(builder, result, limit[0], limit[1], shown).emit();
        (result, limit[0], limit[1])
    }

    /// `setrlimit(resource, {soft, hard})`.
    pub fn setrlimit(&self, resource: i32, soft: u64, hard: u64) -> i64 {
        let limit = [soft, hard];
        let result = self.call(
            Syscall::N_setrlimit,
            [resource as i64, limit.as_ptr() as i64, 0, 0, 0, 0],
        );
        self.event(Syscall::N_setrlimit, result)
            .arg("resource", resource)
            .arg("cur", limit_label(soft))
            .arg("max", limit_label(hard))
            .emit();
        result
    }

    /// glibc's `getrlimit64(resource, &limit)` through its definition `f`
    /// (reached by `dlsym`: the shim does not define it), recorded like
    /// `getrlimit`; returns `(soft, hard)`.
    pub fn getrlimit64(&self, f: GetRlimit64, resource: i32, shown: Shown) -> (i64, u64, u64) {
        let mut limit = libc::rlimit64 {
            rlim_cur: u64::MAX - 1,
            rlim_max: u64::MAX - 1,
        };
        // SAFETY: glibc's definition and a live rlimit64.
        let result = crate::vehicle::fold_errno(unsafe { f(resource, &mut limit) }.into());
        let builder = self
            .rec
            .event("getrlimit64", result)
            .arg("resource", resource);
        Self::limits(builder, result, limit.rlim_cur, limit.rlim_max, shown).emit();
        (result, limit.rlim_cur, limit.rlim_max)
    }

    /// `getrlimit64(resource, NULL)` through `f`.
    pub fn getrlimit64_null(&self, f: GetRlimit64, resource: i32) -> i64 {
        // SAFETY: glibc's definition; a NULL limit.
        let result =
            crate::vehicle::fold_errno(unsafe { f(resource, std::ptr::null_mut()) }.into());
        self.rec
            .event("getrlimit64", result)
            .arg("resource", resource)
            .arg("rlim", "NULL")
            .emit();
        result
    }

    /// glibc's `setrlimit64(resource, {soft, hard})` through its definition
    /// `f` (`None`: a NULL limit), recorded like `setrlimit`.
    pub fn setrlimit64(&self, f: SetRlimit64, resource: i32, limit: Option<(u64, u64)>) -> i64 {
        let result = Self::set64(f, resource, limit);
        let builder = self
            .rec
            .event("setrlimit64", result)
            .arg("resource", resource);
        match limit {
            Some((soft, hard)) => builder
                .arg("cur", limit_label(soft))
                .arg("max", limit_label(hard)),
            None => builder.arg("rlim", "NULL"),
        }
        .emit();
        result
    }

    /// `setrlimit64` through `f` where `hard` is the host's own hard limit
    /// handed back unchanged (recorded as `kept`).
    pub fn setrlimit64_kept(&self, f: SetRlimit64, resource: i32, soft: u64, hard: u64) -> i64 {
        let result = Self::set64(f, resource, Some((soft, hard)));
        self.rec
            .event("setrlimit64", result)
            .arg("resource", resource)
            .arg("cur", limit_label(soft))
            .arg("max", "kept")
            .emit();
        result
    }

    fn set64(f: SetRlimit64, resource: i32, limit: Option<(u64, u64)>) -> i64 {
        let limit = limit.map(|(soft, hard)| libc::rlimit64 {
            rlim_cur: soft,
            rlim_max: hard,
        });
        let pointer = limit
            .as_ref()
            .map_or(std::ptr::null(), |limit| limit as *const libc::rlimit64);
        // SAFETY: glibc's definition and a live rlimit64, or NULL.
        crate::vehicle::fold_errno(unsafe { f(resource, pointer) }.into())
    }

    /// `setrlimit(resource, {soft, hard})` where `hard` is the host's own
    /// hard limit handed back unchanged (recorded as `kept`).
    pub fn setrlimit_kept(&self, resource: i32, soft: u64, hard: u64) -> i64 {
        let limit = [soft, hard];
        let result = self.call(
            Syscall::N_setrlimit,
            [resource as i64, limit.as_ptr() as i64, 0, 0, 0, 0],
        );
        self.event(Syscall::N_setrlimit, result)
            .arg("resource", resource)
            .arg("cur", limit_label(soft))
            .arg("max", "kept")
            .emit();
        result
    }

    /// `prlimit64(pid, resource, new, &old)` (`new` NULL when `None`, `old`
    /// NULL unless `old`); returns the old `(soft, hard)`.
    pub fn prlimit64(
        &self,
        pid: Who,
        resource: i32,
        new: Option<(u64, u64)>,
        old: bool,
        shown: Shown,
    ) -> (i64, u64, u64) {
        let limit = new.map(|(soft, hard)| [soft, hard]);
        let mut previous = [u64::MAX - 1; 2];
        let result = self.call(
            Syscall::N_prlimit64,
            [
                pid.raw(),
                resource as i64,
                limit.as_ref().map_or(0, |limit| limit.as_ptr() as i64),
                if old { previous.as_mut_ptr() as i64 } else { 0 },
                0,
                0,
            ],
        );
        let builder = pid.record(self.event(Syscall::N_prlimit64, result), "pid");
        let builder = builder.arg("resource", resource);
        let builder = match new {
            Some((soft, hard)) => builder
                .arg("new_cur", limit_label(soft))
                .arg("new_max", limit_label(hard)),
            None => builder.arg("new", "NULL"),
        };
        let builder = builder.arg("old", if old { "buffer" } else { "NULL" });
        let builder = if old {
            Self::limits(builder, result, previous[0], previous[1], shown)
        } else {
            builder
        };
        builder.emit();
        (result, previous[0], previous[1])
    }

    // ---- priority ---------------------------------------------------------------

    /// `getpriority(which, who)`: the raw row answers `20 - nice` (glibc's
    /// wrapper converts it; the libc spelling here is `syscall(2)`).
    pub fn getpriority(&self, which: i32, who: Who) -> i64 {
        let result = self.call(
            Syscall::N_getpriority,
            [which as i64, who.raw(), 0, 0, 0, 0],
        );
        who.record(
            self.event(Syscall::N_getpriority, result)
                .arg("which", which),
            "who",
        )
        .emit();
        result
    }

    /// `setpriority(which, who, nice)`.
    pub fn setpriority(&self, which: i32, who: Who, nice: i32) -> i64 {
        let result = self.call(
            Syscall::N_setpriority,
            [which as i64, who.raw(), nice as i64, 0, 0, 0],
        );
        who.record(
            self.event(Syscall::N_setpriority, result)
                .arg("which", which),
            "who",
        )
        .arg("nice", nice)
        .emit();
        result
    }

    /// `ioprio_get(which, who)`: records the class and, when `level`, the
    /// level (a fresh task's default level differs across kernel releases).
    pub fn ioprio_get(&self, which: i32, who: Who, level: bool) -> i64 {
        let result = self.call(Syscall::N_ioprio_get, [which as i64, who.raw(), 0, 0, 0, 0]);
        let builder = self.event(Syscall::N_ioprio_get, if result >= 0 { 0 } else { result });
        let builder = who.record(builder.arg("which", which), "who");
        let builder = if result >= 0 {
            let builder = builder.field("class", result >> 13);
            if level {
                builder.field("data", result & 0x1fff)
            } else {
                builder
            }
        } else {
            builder
        };
        builder.emit();
        result
    }

    /// `ioprio_set(which, who, IOPRIO_PRIO_VALUE(class, data))`.
    pub fn ioprio_set(&self, which: i32, who: Who, class: i64, data: i64) -> i64 {
        let result = self.call(
            Syscall::N_ioprio_set,
            [which as i64, who.raw(), (class << 13) | data, 0, 0, 0],
        );
        who.record(
            self.event(Syscall::N_ioprio_set, result)
                .arg("which", which),
            "who",
        )
        .arg("class", class)
        .arg("data", data)
        .emit();
        result
    }

    // ---- scheduling policy -------------------------------------------------------

    pub fn sched_yield(&self) -> i64 {
        let result = self.call(Syscall::N_sched_yield, [0; 6]);
        self.event(Syscall::N_sched_yield, result).emit();
        result
    }

    pub fn sched_getscheduler(&self, pid: Who) -> i64 {
        let result = self.call(Syscall::N_sched_getscheduler, [pid.raw(), 0, 0, 0, 0, 0]);
        pid.record(self.event(Syscall::N_sched_getscheduler, result), "pid")
            .emit();
        result
    }

    /// `sched_setscheduler(pid, policy, &{priority})`.
    pub fn sched_setscheduler(&self, pid: Who, policy: i32, priority: i32) -> i64 {
        let param = libc::sched_param {
            sched_priority: priority,
        };
        let result = self.call(
            Syscall::N_sched_setscheduler,
            [
                pid.raw(),
                policy as i64,
                &param as *const libc::sched_param as i64,
                0,
                0,
                0,
            ],
        );
        pid.record(self.event(Syscall::N_sched_setscheduler, result), "pid")
            .arg("policy", policy)
            .arg("priority", priority)
            .emit();
        result
    }

    /// `sched_getparam(pid, &param)` (or NULL); returns the priority.
    pub fn sched_getparam(&self, pid: Who, null: bool) -> (i64, i32) {
        let mut param = libc::sched_param { sched_priority: -1 };
        let result = self.call(
            Syscall::N_sched_getparam,
            [
                pid.raw(),
                if null {
                    0
                } else {
                    &mut param as *mut libc::sched_param as i64
                },
                0,
                0,
                0,
                0,
            ],
        );
        let builder = pid
            .record(self.event(Syscall::N_sched_getparam, result), "pid")
            .arg("param", if null { "NULL" } else { "buffer" });
        let builder = if result == 0 {
            builder.field("priority", param.sched_priority)
        } else {
            builder
        };
        builder.emit();
        (result, param.sched_priority)
    }

    /// `sched_setparam(pid, &{priority})` (or NULL).
    pub fn sched_setparam(&self, pid: Who, priority: Option<i32>) -> i64 {
        let param = libc::sched_param {
            sched_priority: priority.unwrap_or(0),
        };
        let result = self.call(
            Syscall::N_sched_setparam,
            [
                pid.raw(),
                if priority.is_some() {
                    &param as *const libc::sched_param as i64
                } else {
                    0
                },
                0,
                0,
                0,
                0,
            ],
        );
        pid.record(self.event(Syscall::N_sched_setparam, result), "pid")
            .arg(
                "priority",
                priority.map_or(Value::from("NULL"), Value::from),
            )
            .emit();
        result
    }

    pub fn sched_get_priority_max(&self, policy: i32) -> i64 {
        let result = self.call(
            Syscall::N_sched_get_priority_max,
            [policy as i64, 0, 0, 0, 0, 0],
        );
        self.event(Syscall::N_sched_get_priority_max, result)
            .arg("policy", policy)
            .emit();
        result
    }

    pub fn sched_get_priority_min(&self, policy: i32) -> i64 {
        let result = self.call(
            Syscall::N_sched_get_priority_min,
            [policy as i64, 0, 0, 0, 0, 0],
        );
        self.event(Syscall::N_sched_get_priority_min, result)
            .arg("policy", policy)
            .emit();
        result
    }

    /// `sched_rr_get_interval(pid, &ts)`: a normal task's slice is the host
    /// scheduler's business, recorded as whether it is under a second.
    pub fn sched_rr_get_interval(&self, pid: Who) -> (i64, i64) {
        let mut ts = libc::timespec {
            tv_sec: -1,
            tv_nsec: -1,
        };
        let result = self.call(
            Syscall::N_sched_rr_get_interval,
            [pid.raw(), &mut ts as *mut libc::timespec as i64, 0, 0, 0, 0],
        );
        let ns = ts.tv_sec * 1_000_000_000 + ts.tv_nsec;
        let builder = pid.record(self.event(Syscall::N_sched_rr_get_interval, result), "pid");
        let builder = if result == 0 {
            builder.field(
                "under_a_second",
                ts.tv_sec == 0 && (0..1_000_000_000).contains(&ts.tv_nsec),
            )
        } else {
            builder
        };
        builder.emit();
        (result, ns)
    }

    /// `sched_getattr(pid, buf, size, flags)` into a buffer of `buffer` bytes
    /// filled with `0xa5`: records the attribute's size, policy, flags, nice
    /// and priority, and whether the bytes past what the kernel says it wrote
    /// kept their fill.
    pub fn sched_getattr(
        &self,
        pid: Who,
        size: u32,
        buffer: usize,
        flags: u32,
    ) -> (i64, SchedAttr) {
        let mut buf = vec![0xa5u8; buffer.max(std::mem::size_of::<SchedAttr>())];
        let result = self.call(
            Syscall::N_sched_getattr,
            [
                pid.raw(),
                buf.as_mut_ptr() as i64,
                i64::from(size),
                i64::from(flags),
                0,
                0,
            ],
        );
        // SAFETY: `buf` holds at least one SchedAttr; read unaligned.
        let attr: SchedAttr = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast()) };
        let builder = pid
            .record(self.event(Syscall::N_sched_getattr, result), "pid")
            .arg("size", size)
            .arg("flags", flags);
        let builder = if result == 0 {
            let written = (attr.size as usize).min(buf.len());
            builder
                .field("attr_size", attr.size)
                .field("policy", attr.policy)
                .field("sched_flags", attr.flags)
                .field("nice", attr.nice)
                .field("priority", attr.priority)
                .field(
                    "tail_untouched",
                    buf[written..buffer.max(written)].iter().all(|b| *b == 0xa5),
                )
        } else {
            builder
        };
        builder.emit();
        (result, attr)
    }

    /// `sched_setattr(pid, attr, flags)` from a buffer of `buffer` bytes
    /// (the attribute, then zeros, then `tail` at the last byte when given):
    /// records the attribute and the size the kernel wrote back into it.
    pub fn sched_setattr(
        &self,
        pid: Who,
        attr: SchedAttr,
        buffer: usize,
        tail: Option<u8>,
        flags: u32,
    ) -> (i64, u32) {
        let mut buf = vec![0u8; buffer.max(std::mem::size_of::<SchedAttr>())];
        // SAFETY: `buf` holds at least one SchedAttr; write unaligned.
        unsafe { std::ptr::write_unaligned(buf.as_mut_ptr().cast(), attr) };
        if let Some(tail) = tail {
            buf[buffer - 1] = tail;
        }
        let result = self.call(
            Syscall::N_sched_setattr,
            [
                pid.raw(),
                buf.as_mut_ptr() as i64,
                i64::from(flags),
                0,
                0,
                0,
            ],
        );
        let written = u32::from_ne_bytes(buf[..4].try_into().expect("four bytes"));
        pid.record(self.event(Syscall::N_sched_setattr, result), "pid")
            .arg("attr_size", attr.size)
            .arg("policy", attr.policy)
            .arg("sched_flags", attr.flags)
            .arg("nice", attr.nice)
            .arg("priority", attr.priority)
            .arg("tail", tail.map_or(Value::Null, Value::from))
            .arg("flags", flags)
            .field("size_after", written)
            .emit();
        (result, written)
    }

    // ---- CPU affinity -------------------------------------------------------------

    /// `sched_getaffinity(pid, len, mask)`. The raw row answers the bytes it
    /// wrote (the kernel's `cpumask_size()`, a host fact); glibc's wrapper
    /// answers 0 and zeroes the rest: both are recorded as 0 with a
    /// `size_ok` relation (a whole number of longs, at most `len`). Returns
    /// the mask bytes; `len_label` records the buffer's length (a buffer
    /// sized for the host's CPUs is the host's business).
    pub fn sched_getaffinity(&self, pid: Who, len: usize, len_label: &str) -> (i64, Vec<u8>) {
        let mut mask = vec![0xffu8; len.max(1)];
        let result = self.call(
            Syscall::N_sched_getaffinity,
            [pid.raw(), len as i64, mask.as_mut_ptr() as i64, 0, 0, 0],
        );
        let long = std::mem::size_of::<libc::c_ulong>() as i64;
        let size_ok = match self.vehicle {
            Vehicle::Libc => result == 0,
            _ => result > 0 && result % long == 0 && result <= len as i64,
        };
        if result > 0 {
            // The raw row leaves the bytes past its answer untouched.
            for byte in &mut mask[result as usize..] {
                *byte = 0;
            }
        }
        let builder = pid
            .record(
                self.event(
                    Syscall::N_sched_getaffinity,
                    if result >= 0 { 0 } else { result },
                ),
                "pid",
            )
            .arg("len", len_label);
        let builder = if result >= 0 {
            builder
                .field("size_ok", size_ok)
                .field("nonempty", mask.iter().any(|b| *b != 0))
        } else {
            builder
        };
        builder.emit();
        (result, mask)
    }

    /// `sched_setaffinity(pid, len, mask)`; `label` records what the mask is
    /// and `len_label` its length (the CPUs, and so a buffer sized for them,
    /// are the host's).
    pub fn sched_setaffinity(&self, pid: Who, mask: &[u8], len_label: &str, label: &str) -> i64 {
        let result = self.call(
            Syscall::N_sched_setaffinity,
            [pid.raw(), mask.len() as i64, mask.as_ptr() as i64, 0, 0, 0],
        );
        pid.record(self.event(Syscall::N_sched_setaffinity, result), "pid")
            .arg("len", len_label)
            .arg("mask", label)
            .emit();
        result
    }

    /// `getcpu(&cpu, &node, NULL)` (or all NULL): returns `(cpu, node)`, host
    /// facts the scenario relates to the affinity mask.
    pub fn getcpu(&self, null: bool) -> (i64, u32, u32) {
        let (mut cpu, mut node) = (u32::MAX, u32::MAX);
        let args = if null {
            [0; 6]
        } else {
            [
                &mut cpu as *mut u32 as i64,
                &mut node as *mut u32 as i64,
                0,
                0,
                0,
                0,
            ]
        };
        let result = self.call(Syscall::N_getcpu, args);
        self.event(Syscall::N_getcpu, result)
            .arg("out", if null { "NULL" } else { "buffers" })
            .emit();
        (result, cpu, node)
    }

    // ---- credentials ---------------------------------------------------------------

    /// Go no further unless this caller is unprivileged: a nonzero effective
    /// uid and empty effective and permitted capability sets, read without
    /// recording. The harness runs a scenario that needs `Need::Unprivileged`
    /// only for such a caller; this second guard stops a probe binary started
    /// by hand as root before any call whose capability check would pass
    /// (rebooting, loading modules, swapping, changing namespaces).
    pub fn require_unprivileged(&self) {
        let (euid, (read, _, sets)) = self.rec.quiet(|| {
            (
                self.geteuid(),
                self.capget(CAPABILITY_V3, Who::Caller, true),
            )
        });
        self.require(
            "an unprivileged caller: euid is not 0 and no capability is effective or permitted",
            euid > 0
                && read == 0
                && sets
                    .iter()
                    .all(|set| set.effective == 0 && set.permitted == 0),
        );
    }

    pub fn geteuid(&self) -> i64 {
        let result = self.call(Syscall::N_geteuid, [0; 6]);
        self.event(Syscall::N_geteuid, result)
            .norm("ret", Norm::Identity(Id::User))
            .emit();
        result
    }

    pub fn getegid(&self) -> i64 {
        let result = self.call(Syscall::N_getegid, [0; 6]);
        self.event(Syscall::N_getegid, result)
            .norm("ret", Norm::Identity(Id::Group))
            .emit();
        result
    }

    /// `getresuid`/`getresgid` (`row`): the real, effective and saved ids.
    pub fn getres(&self, row: Syscall, kind: Id) -> (i64, [u32; 3]) {
        let mut ids = [u32::MAX - 1; 3];
        let result = self.call(
            row,
            [
                &mut ids[0] as *mut u32 as i64,
                &mut ids[1] as *mut u32 as i64,
                &mut ids[2] as *mut u32 as i64,
                0,
                0,
                0,
            ],
        );
        let mut builder = self.event(row, result);
        if result == 0 {
            for (key, id) in ["real", "effective", "saved"].iter().zip(ids) {
                builder = builder
                    .field(key, id)
                    .norm(&format!("fields.{key}"), Norm::Identity(kind));
            }
        }
        builder.emit();
        (result, ids)
    }

    /// `setuid`/`setgid`/`setfsuid`/`setfsgid` (`row`) with one id. The
    /// `setfs*` rows answer the previous id, recorded by relation.
    pub fn set_id(&self, row: Syscall, id: Cred, kind: Id) -> i64 {
        let result = self.call(row, [id.raw(), 0, 0, 0, 0, 0]);
        let builder = id.record(self.event(row, result), "id", kind);
        let builder = if matches!(row, Syscall::N_setfsuid | Syscall::N_setfsgid) {
            builder.norm("ret", Norm::Identity(kind))
        } else {
            builder
        };
        builder.emit();
        result
    }

    /// `setreuid`/`setregid` (`row`).
    pub fn set_re(&self, row: Syscall, real: Cred, effective: Cred, kind: Id) -> i64 {
        let result = self.call(row, [real.raw(), effective.raw(), 0, 0, 0, 0]);
        let builder = real.record(self.event(row, result), "real", kind);
        effective.record(builder, "effective", kind).emit();
        result
    }

    /// `setresuid`/`setresgid` (`row`).
    pub fn set_res(&self, row: Syscall, ids: [Cred; 3], kind: Id) -> i64 {
        let result = self.call(row, [ids[0].raw(), ids[1].raw(), ids[2].raw(), 0, 0, 0]);
        let mut builder = self.event(row, result);
        for (key, id) in ["real", "effective", "saved"].iter().zip(ids) {
            builder = id.record(builder, key, kind);
        }
        builder.emit();
        result
    }

    /// `getgroups(size, list)` (a NULL list when `size` is 0). The count is
    /// the host's: `ret` and a `size` equal to it share one label
    /// (`Norm::Relative("ngroups")`), so the relation survives the value.
    pub fn getgroups(&self, size: GroupsSize) -> (i64, Vec<u32>) {
        let raw = size.raw();
        let mut list = vec![u32::MAX; raw.max(0) as usize];
        let result = self.call(
            Syscall::N_getgroups,
            [
                i64::from(raw),
                if raw > 0 { list.as_mut_ptr() as i64 } else { 0 },
                0,
                0,
                0,
                0,
            ],
        );
        let builder = match size {
            GroupsSize::Count(count) => self
                .event(Syscall::N_getgroups, result)
                .arg("size", count)
                .norm("args.size", Norm::Relative("ngroups")),
            // What one short of the count answers depends on the count (a
            // size of 0 is the count query), so the event records whether the
            // answer follows the kernel's rule for this host's count.
            GroupsSize::Short(count) => self
                .event(Syscall::N_getgroups, 0)
                .arg("size", "count-1")
                .field(
                    "per_rule",
                    if count == 1 {
                        result == i64::from(count)
                    } else {
                        result == -i64::from(libc::EINVAL)
                    },
                ),
            GroupsSize::Raw(value) => self.event(Syscall::N_getgroups, result).arg("size", value),
        };
        let builder = if result >= 0 && !matches!(size, GroupsSize::Short(_)) {
            builder.norm("ret", Norm::Relative("ngroups"))
        } else {
            builder
        };
        builder.emit();
        list.truncate(result.max(0) as usize);
        (result, list)
    }

    /// `setgroups(size, list)` (NULL when `list` is `None`).
    /// A `size` equal to the count a `getgroups` answered is recorded by
    /// relation (`GroupsSize::Count`).
    pub fn setgroups(&self, size: GroupsSize, list: Option<&[u32]>) -> i64 {
        let result = self.call(
            Syscall::N_setgroups,
            [
                i64::from(size.raw()),
                list.map_or(0, |list| list.as_ptr() as i64),
                0,
                0,
                0,
                0,
            ],
        );
        let builder = self.event(Syscall::N_setgroups, result);
        let builder = match size {
            GroupsSize::Count(count) => builder
                .arg("size", count)
                .norm("args.size", Norm::Relative("ngroups")),
            GroupsSize::Short(_) => builder.arg("size", "count-1"),
            GroupsSize::Raw(value) => builder.arg("size", value),
        };
        builder
            .arg("list", if list.is_some() { "buffer" } else { "NULL" })
            .emit();
        result
    }

    /// `capget(&{version, pid}, data)`: records the version the kernel wrote
    /// back and, with `data`, both capability words of each set.
    pub fn capget(&self, version: u32, pid: Who, data: bool) -> (i64, u32, [CapData; 2]) {
        let mut header = CapHeader {
            version,
            pid: pid.raw() as i32,
        };
        let mut sets = [CapData {
            effective: u32::MAX,
            permitted: u32::MAX,
            inheritable: u32::MAX,
        }; 2];
        let result = self.call(
            Syscall::N_capget,
            [
                &mut header as *mut CapHeader as i64,
                if data { sets.as_mut_ptr() as i64 } else { 0 },
                0,
                0,
                0,
                0,
            ],
        );
        let builder = pid
            .record(self.event(Syscall::N_capget, result), "pid")
            .arg("version", format!("{version:#x}"))
            .arg("data", if data { "buffer" } else { "NULL" })
            .field("version_after", format!("{:#x}", header.version));
        let builder = if result == 0 && data {
            builder
                .field(
                    "effective",
                    format!("{:#x}/{:#x}", sets[0].effective, sets[1].effective),
                )
                .field(
                    "permitted",
                    format!("{:#x}/{:#x}", sets[0].permitted, sets[1].permitted),
                )
                .field(
                    "inheritable",
                    format!("{:#x}/{:#x}", sets[0].inheritable, sets[1].inheritable),
                )
        } else {
            builder
        };
        builder.emit();
        (result, header.version, sets)
    }

    /// `capset(&{version, pid}, data)` with the low words of each set (the
    /// high words zero).
    pub fn capset(&self, version: u32, pid: Who, low: CapData) -> i64 {
        let mut header = CapHeader {
            version,
            pid: pid.raw() as i32,
        };
        let sets = [low, CapData::default()];
        let result = self.call(
            Syscall::N_capset,
            [
                &mut header as *mut CapHeader as i64,
                sets.as_ptr() as i64,
                0,
                0,
                0,
                0,
            ],
        );
        pid.record(self.event(Syscall::N_capset, result), "pid")
            .arg("version", format!("{version:#x}"))
            .arg("effective", format!("{:#x}", low.effective))
            .arg("permitted", format!("{:#x}", low.permitted))
            .arg("inheritable", format!("{:#x}", low.inheritable))
            .emit();
        result
    }

    /// `sethostname`/`setdomainname` (`row`) of `name` with length `len`.
    pub fn set_uts_name(&self, row: Syscall, name: &str, len: i64) -> i64 {
        let c = super::cstr(name);
        let result = self.call(row, [c.as_ptr() as i64, len, 0, 0, 0, 0]);
        self.event(row, result)
            .arg("name", name)
            .arg("len", len)
            .emit();
        result
    }

    // ---- process groups and sessions ------------------------------------------------

    /// `getpgrp()` (x86_64: the generic table has no `getpgrp` row, and glibc
    /// spells it `getpgid(0)` there).
    #[cfg(target_arch = "x86_64")]
    pub fn getpgrp(&self) -> i64 {
        let result = self.call(Syscall::N_getpgrp, [0; 6]);
        self.event(Syscall::N_getpgrp, result)
            .norm("ret", Norm::Identity(Id::Process))
            .emit();
        result
    }

    /// `setpgid(pid, pgid)`.
    pub fn setpgid(&self, pid: Who, pgid: Who) -> i64 {
        let result = self.call(Syscall::N_setpgid, [pid.raw(), pgid.raw(), 0, 0, 0, 0]);
        let builder = pid.record(self.event(Syscall::N_setpgid, result), "pid");
        pgid.record(builder, "pgid").emit();
        result
    }

    /// `setsid()`: the new session id (the caller's pid), by relation.
    pub fn setsid(&self) -> i64 {
        let result = self.call(Syscall::N_setsid, [0; 6]);
        self.event(Syscall::N_setsid, result)
            .norm("ret", Norm::Identity(Id::Process))
            .emit();
        result
    }
}
