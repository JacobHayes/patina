//! The rows whose answer is the virtual kernel's configuration
//! (`registry::KERNEL_CONFIG`) as much as the credential: the kernel log,
//! performance events, BPF and userfaultfd. Each follows the declared
//! configuration, never the host's sysctls; where a configuration the
//! declaration rules out would allow the call, the model ends by name.

use super::{Answer, Unmodeled, gate, lookup_at, refuse};
use crate::identity::Credential;
use crate::registry::{Capability, KERNEL_CONFIG};
use linux_raw_sys::errno;
use linux_raw_sys::general::{O_CLOEXEC, O_NONBLOCK, UFFD_USER_MODE_ONLY};
use std::ffi::c_int;

/// `SYSLOG_ACTION_READ_ALL` and `SYSLOG_ACTION_SIZE_BUFFER`: the actions
/// `kernel.dmesg_restrict` 0 leaves to everyone.
const SYSLOG_ACTION_READ_ALL: i32 = 3;
const SYSLOG_ACTION_SIZE_BUFFER: i32 = 10;

/// `syslog(action, buf, len)` (`check_syslog_permissions`): a restricted
/// action — every one under `kernel.dmesg_restrict` — needs `CAP_SYSLOG`
/// (or, historically, `CAP_SYS_ADMIN`), before the action is looked at.
pub(in crate::sud) fn syslog(credential: &Credential, a: &[u64; 6]) -> Answer {
    let action = a[0] as i32;
    let restricted = KERNEL_CONFIG.dmesg_restrict
        || (action != SYSLOG_ACTION_READ_ALL && action != SYSLOG_ACTION_SIZE_BUFFER);
    if !restricted {
        return Err(Unmodeled::Path(format!(
            "syslog action {action}, which kernel.dmesg_restrict 0 allows any caller"
        )));
    }
    if credential.capable(Capability::Syslog) {
        return Err(Unmodeled::Granted(Capability::Syslog));
    }
    gate(credential, Capability::SysAdmin, errno::EPERM)
}

/// `PERF_FLAG_ALL`: the flags `perf_event_open` takes.
const PERF_FLAG_ALL: u64 = 0xf;
/// `PERF_SECURITY_MAX`: the `kernel.perf_event_paranoid` from which Ubuntu's
/// kernel refuses every event (`perf_paranoid_any`).
const PERF_SECURITY_MAX: i32 = 4;

/// `perf_event_open(attr, pid, cpu, group_fd, flags)`: an unknown flag, then
/// — at a `kernel.perf_event_paranoid` of 4 or more, Ubuntu's patch —
/// `perfmon_capable` (`CAP_PERFMON`, or `CAP_SYS_ADMIN`), refused as
/// `EACCES` before the attribute is read.
pub(in crate::sud) fn perf_event_open(credential: &Credential, a: &[u64; 6]) -> Answer {
    if a[4] & !PERF_FLAG_ALL != 0 {
        return refuse(errno::EINVAL);
    }
    if KERNEL_CONFIG.perf_event_paranoid < PERF_SECURITY_MAX {
        return Err(Unmodeled::Path(
            "a performance event at kernel.perf_event_paranoid 3 or below".into(),
        ));
    }
    if credential.capable(Capability::Perfmon) {
        return Err(Unmodeled::Granted(Capability::Perfmon));
    }
    gate(credential, Capability::SysAdmin, errno::EACCES)
}

/// `sizeof(union bpf_attr)` in the pinned kernel: `BPF_PROG_LOAD`'s
/// attributes, which end at `log_true_size`.
const BPF_ATTR_SIZE: usize = 144;

/// The pinned kernel's commands (`enum bpf_cmd`), `BPF_PROG_BIND_MAP` the
/// last.
const BPF_MAP_CREATE: i32 = 0;
const BPF_MAP_LOOKUP_ELEM: i32 = 1;
const BPF_MAP_UPDATE_ELEM: i32 = 2;
const BPF_MAP_DELETE_ELEM: i32 = 3;
const BPF_MAP_GET_NEXT_KEY: i32 = 4;
const BPF_PROG_LOAD: i32 = 5;
const BPF_OBJ_PIN: i32 = 6;
const BPF_OBJ_GET: i32 = 7;
const BPF_PROG_ATTACH: i32 = 8;
const BPF_PROG_DETACH: i32 = 9;
const BPF_PROG_TEST_RUN: i32 = 10;
const BPF_PROG_GET_NEXT_ID: i32 = 11;
const BPF_MAP_GET_NEXT_ID: i32 = 12;
const BPF_PROG_GET_FD_BY_ID: i32 = 13;
const BPF_MAP_GET_FD_BY_ID: i32 = 14;
const BPF_OBJ_GET_INFO_BY_FD: i32 = 15;
const BPF_PROG_QUERY: i32 = 16;
const BPF_RAW_TRACEPOINT_OPEN: i32 = 17;
const BPF_BTF_LOAD: i32 = 18;
const BPF_BTF_GET_FD_BY_ID: i32 = 19;
const BPF_TASK_FD_QUERY: i32 = 20;
const BPF_MAP_LOOKUP_AND_DELETE_ELEM: i32 = 21;
const BPF_MAP_FREEZE: i32 = 22;
const BPF_BTF_GET_NEXT_ID: i32 = 23;
const BPF_MAP_LOOKUP_BATCH: i32 = 24;
const BPF_MAP_DELETE_BATCH: i32 = 27;
const BPF_LINK_CREATE: i32 = 28;
const BPF_LINK_UPDATE: i32 = 29;
const BPF_LINK_GET_FD_BY_ID: i32 = 30;
const BPF_LINK_GET_NEXT_ID: i32 = 31;
const BPF_ENABLE_STATS: i32 = 32;
const BPF_ITER_CREATE: i32 = 33;
const BPF_LINK_DETACH: i32 = 34;
const BPF_PROG_BIND_MAP: i32 = 35;

/// The attribute flags the commands' own checks read.
const BPF_F_LOCK: u64 = 1 << 2;
const BPF_F_REPLACE: u32 = 1 << 2;
const BPF_F_PATH_FD: u32 = 1 << 14;
/// `BPF_F_ATTACH_MASK_BASE` (Ubuntu's kernel carries `BPF_F_PREORDER`) and
/// `BPF_F_ATTACH_MASK_MPROG`.
const ATTACH_FLAGS_BASE: u32 = 1 | 1 << 1 | 1 << 2 | 1 << 6;
const ATTACH_FLAGS_MPROG: u32 = 1 << 2 | 1 << 3 | 1 << 4 | 1 << 5 | 1 << 13;

/// `bpf(cmd, attr, size)` (`__sys_bpf`): an attribute size past a page, or
/// past the kernel's with a nonzero tail, is `E2BIG`; the attribute is
/// copied (`EFAULT`); no module of the virtual kernel's stack hooks
/// `security_bpf`; an unknown command is `EINVAL`. Each command's checks
/// follow, up to its capability check or the BPF object it names: the model
/// holds no BPF object, so a descriptor is `EBADF` when not open and
/// `EINVAL` otherwise. Detaching a program from its attach point is where
/// the model ends.
pub(in crate::sud) fn bpf(credential: &Credential, a: &[u64; 6]) -> Answer {
    let (command, address, size) = (a[0] as i32, a[1] as usize, a[2] as u32 as usize);
    if size > crate::PAGE_SIZE {
        return refuse(errno::E2BIG);
    }
    if size > BPF_ATTR_SIZE {
        match crate::uaccess::read_bytes(address.wrapping_add(BPF_ATTR_SIZE), size - BPF_ATTR_SIZE)
        {
            Err(code) => return refuse(code),
            Ok(tail) if tail.iter().any(|byte| *byte != 0) => return refuse(errno::E2BIG),
            Ok(_) => {}
        }
    }
    let mut attr = [0u8; BPF_ATTR_SIZE];
    let copied = size.min(BPF_ATTR_SIZE);
    if copied > 0 && crate::uaccess::read_into(address, &mut attr[..copied]).is_err() {
        return refuse(errno::EFAULT);
    }
    let attr = &attr;
    // `CHECK_ATTR`, before anything else a command reads, unless noted.
    let check = |end: usize| check_attr(attr, end);
    match command {
        BPF_MAP_CREATE => map_create(credential, attr),
        BPF_PROG_LOAD => prog_load(credential, attr),
        BPF_MAP_LOOKUP_ELEM | BPF_MAP_LOOKUP_AND_DELETE_ELEM => {
            if !check(32) || u64_at(attr, 24) & !BPF_F_LOCK != 0 {
                return refuse(errno::EINVAL);
            }
            no_object(u32_at(attr, 0))
        }
        BPF_MAP_UPDATE_ELEM | BPF_MAP_DELETE_ELEM | BPF_MAP_GET_NEXT_KEY | BPF_MAP_FREEZE => {
            let end = match command {
                BPF_MAP_UPDATE_ELEM => 32,
                BPF_MAP_DELETE_ELEM => 16,
                BPF_MAP_GET_NEXT_KEY => 24,
                _ => 4,
            };
            object_at(attr, end, 0)
        }
        BPF_MAP_LOOKUP_BATCH..=BPF_MAP_DELETE_BATCH => object_at(attr, 56, 36),
        BPF_OBJ_PIN => {
            let flags = u32_at(attr, 12);
            if !check(20)
                || flags & !BPF_F_PATH_FD != 0
                || (flags & BPF_F_PATH_FD == 0 && u32_at(attr, 16) != 0)
            {
                return refuse(errno::EINVAL);
            }
            // `bpf_fd_probe_obj`: no map, program or link, whatever the
            // descriptor.
            refuse(errno::EINVAL)
        }
        BPF_OBJ_GET => obj_get(attr),
        BPF_PROG_ATTACH | BPF_PROG_DETACH => attach(attr, command == BPF_PROG_ATTACH),
        BPF_PROG_TEST_RUN => {
            let paired = |size: usize, pointer: usize| {
                (u32_at(attr, size) == 0) == (u64_at(attr, pointer) == 0)
            };
            if !check(76) || !paired(40, 48) || !paired(44, 56) {
                return refuse(errno::EINVAL);
            }
            no_object(u32_at(attr, 0))
        }
        BPF_PROG_GET_NEXT_ID | BPF_MAP_GET_NEXT_ID | BPF_BTF_GET_NEXT_ID | BPF_LINK_GET_NEXT_ID => {
            get_next_id(credential, attr)
        }
        BPF_PROG_GET_FD_BY_ID | BPF_BTF_GET_FD_BY_ID | BPF_LINK_GET_FD_BY_ID | BPF_ENABLE_STATS => {
            admin(credential, check(4))
        }
        BPF_MAP_GET_FD_BY_ID => admin(credential, check(12) && u32_at(attr, 8) & !ACCESS == 0),
        BPF_TASK_FD_QUERY => admin(credential, check(48)),
        BPF_OBJ_GET_INFO_BY_FD => {
            if !check(16) {
                return refuse(errno::EINVAL);
            }
            // `fdget`'s empty slot is `EBADFD` here, not `EBADF`.
            match crate::fdget(u32_at(attr, 0) as c_int) {
                Err(_) => refuse(errno::EBADFD),
                Ok(_) => refuse(errno::EINVAL),
            }
        }
        // `CAP_NET_ADMIN` before the attribute is checked.
        BPF_PROG_QUERY => gate(credential, Capability::NetAdmin, errno::EPERM),
        BPF_RAW_TRACEPOINT_OPEN => object_at(attr, 12, 8),
        BPF_BTF_LOAD => {
            if !check(32) {
                return refuse(errno::EINVAL);
            }
            match bpf_capable(credential) {
                Some(capability) => Err(Unmodeled::Granted(capability)),
                None => refuse(errno::EPERM),
            }
        }
        // A struct_ops link's map and any other link's program share the
        // first word.
        BPF_LINK_CREATE => object_at(attr, 60, 0),
        BPF_LINK_UPDATE => {
            if !check(16) || u32_at(attr, 8) & !BPF_F_REPLACE != 0 {
                return refuse(errno::EINVAL);
            }
            no_object(u32_at(attr, 0))
        }
        BPF_LINK_DETACH => object_at(attr, 4, 0),
        BPF_ITER_CREATE | BPF_PROG_BIND_MAP => {
            let (end, flags) = if command == BPF_ITER_CREATE {
                (8, 4)
            } else {
                (12, 8)
            };
            if !check(end) || u32_at(attr, flags) != 0 {
                return refuse(errno::EINVAL);
            }
            no_object(u32_at(attr, 0))
        }
        _ => refuse(errno::EINVAL),
    }
}

fn u32_at(attr: &[u8; BPF_ATTR_SIZE], offset: usize) -> u32 {
    u32::from_ne_bytes(attr[offset..offset + 4].try_into().expect("four bytes"))
}

fn u64_at(attr: &[u8; BPF_ATTR_SIZE], offset: usize) -> u64 {
    u64::from_ne_bytes(attr[offset..offset + 8].try_into().expect("eight bytes"))
}

/// `CHECK_ATTR`: every byte past the command's last field is zero.
fn check_attr(attr: &[u8; BPF_ATTR_SIZE], end: usize) -> bool {
    attr[end..].iter().all(|byte| *byte == 0)
}

/// `__bpf_map_get`, `____bpf_prog_get`, `bpf_link_get_from_fd`: a
/// descriptor not open (`O_PATH` included: `fdget`) is `EBADF`, and every
/// other one names no BPF object (`EINVAL`) — the model holds none.
fn no_object(fd: u32) -> Answer {
    match crate::fdget(fd as c_int) {
        Err(code) => refuse(code),
        Ok(_) => refuse(errno::EINVAL),
    }
}

/// A command whose checks are `CHECK_ATTR` (nothing past `end`), then the
/// BPF object named by the descriptor at `fd`.
fn object_at(attr: &[u8; BPF_ATTR_SIZE], end: usize, fd: usize) -> Answer {
    if !check_attr(attr, end) {
        return refuse(errno::EINVAL);
    }
    no_object(u32_at(attr, fd))
}

/// A command that needs `CAP_SYS_ADMIN` once its attribute is `valid`.
fn admin(credential: &Credential, valid: bool) -> Answer {
    if !valid {
        return refuse(errno::EINVAL);
    }
    gate(credential, Capability::SysAdmin, errno::EPERM)
}

/// `bpf_obj_get`: `CHECK_ATTR`, no descriptor, known file flags and a path
/// descriptor only under `BPF_F_PATH_FD`, not both access flags
/// (`bpf_get_file_flag`), then the path is looked up; whatever it names
/// holds no pinned BPF object (`bpf_inode_type`: `EACCES`).
fn obj_get(attr: &[u8; BPF_ATTR_SIZE]) -> Answer {
    let flags = u32_at(attr, 12);
    if !check_attr(attr, 20)
        || u32_at(attr, 8) != 0
        || flags & !(ACCESS | BPF_F_PATH_FD) != 0
        || (flags & BPF_F_PATH_FD == 0 && u32_at(attr, 16) != 0)
        || flags & ACCESS == ACCESS
    {
        return refuse(errno::EINVAL);
    }
    let dirfd = if flags & BPF_F_PATH_FD != 0 {
        u32_at(attr, 16) as c_int
    } else {
        crate::paths::AT_FDCWD
    };
    match lookup_at(dirfd, u64_at(attr, 0), true) {
        Err(code) => refuse(code),
        Ok(_) => refuse(errno::EACCES),
    }
}

/// What `attach_type_to_prog_type` makes of an attach type, as far as
/// `BPF_PROG_ATTACH`/`BPF_PROG_DETACH` read it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AttachPoint {
    /// No program type (`BPF_PROG_TYPE_UNSPEC`).
    None,
    /// `BPF_PROG_TYPE_SCHED_CLS` (tcx, netkit): `bpf_mprog_supported`.
    Multi,
    /// A tracing, `SK_LOOKUP` or `XDP` program, which detach does not take.
    Undetachable,
    /// A cgroup, socket map, device or network namespace attach point.
    Target,
}

fn attach_point(attach_type: u32) -> AttachPoint {
    match attach_type {
        33 | 35 | 39..=42 | 44 | 45 | 48 | 56.. => AttachPoint::None,
        46 | 47 | 54 | 55 => AttachPoint::Multi,
        23..=26 | 28 | 36 | 37 => AttachPoint::Undetachable,
        _ => AttachPoint::Target,
    }
}

/// `bpf_prog_attach`/`bpf_prog_detach`: `CHECK_ATTR`, the attach type's
/// program type and the flags it takes, then the program descriptor
/// (attaching always; detaching a multi-program point when one is named).
/// Detaching otherwise answers from the attach point itself, which the
/// model does not have, but for the types detach refuses (`EINVAL`).
fn attach(attr: &[u8; BPF_ATTR_SIZE], attaching: bool) -> Answer {
    if !check_attr(attr, 32) {
        return refuse(errno::EINVAL);
    }
    let point = attach_point(u32_at(attr, 8));
    let (flags, program) = (u32_at(attr, 12), u32_at(attr, 4));
    if attaching && point == AttachPoint::None {
        return refuse(errno::EINVAL);
    }
    if point == AttachPoint::Multi {
        if flags & !ATTACH_FLAGS_MPROG != 0 {
            return refuse(errno::EINVAL);
        }
    } else if (attaching && flags & !ATTACH_FLAGS_BASE != 0)
        || (!attaching && flags != 0)
        || u32_at(attr, 20) != 0
        || u64_at(attr, 24) != 0
    {
        return refuse(errno::EINVAL);
    }
    if attaching || (point == AttachPoint::Multi && program != 0) {
        return no_object(program);
    }
    match point {
        AttachPoint::None | AttachPoint::Undetachable => refuse(errno::EINVAL),
        AttachPoint::Multi | AttachPoint::Target => Err(Unmodeled::Path(format!(
            "detaching a BPF program from attach type {} (its attach point's own lookup)",
            u32_at(attr, 8)
        ))),
    }
}

/// `bpf_capable`: `CAP_BPF`, or `CAP_SYS_ADMIN`.
fn bpf_capable(credential: &Credential) -> Option<Capability> {
    [Capability::Bpf, Capability::SysAdmin]
        .into_iter()
        .find(|capability| credential.capable(*capability))
}

/// `kernel.unprivileged_bpf_disabled`'s check, which map creation and
/// program loading make after their own: `EPERM` without `bpf_capable`.
fn unprivileged_bpf(credential: &Credential, what: &str) -> Answer {
    if KERNEL_CONFIG.unprivileged_bpf_disabled == 0 {
        return Err(Unmodeled::Path(format!(
            "{what} at kernel.unprivileged_bpf_disabled 0"
        )));
    }
    match bpf_capable(credential) {
        Some(capability) => Err(Unmodeled::Granted(capability)),
        None => refuse(errno::EPERM),
    }
}

/// Map types, and the map flags the array maps' checks read.
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
const BPF_MAP_TYPE_STRUCT_OPS: u32 = 26;
const BPF_MAP_TYPE_BLOOM_FILTER: u32 = 30;
/// `BPF_MAP_TYPE_CGRP_STORAGE`, the pinned kernel's last map type.
const BPF_MAP_TYPE_LAST: u32 = 32;
const BPF_F_NUMA_NODE: u32 = 1 << 2;
const BPF_F_RDONLY: u32 = 1 << 3;
const BPF_F_WRONLY: u32 = 1 << 4;
/// `BPF_OBJ_FLAG_MASK`: the access flags.
const ACCESS: u32 = BPF_F_RDONLY | BPF_F_WRONLY;
const BPF_F_RDONLY_PROG: u32 = 1 << 7;
const BPF_F_WRONLY_PROG: u32 = 1 << 8;
const BPF_F_MMAPABLE: u32 = 1 << 10;
const BPF_F_PRESERVE_ELEMS: u32 = 1 << 11;
const BPF_F_INNER_MAP: u32 = 1 << 12;
/// `ARRAY_CREATE_FLAG_MASK`.
const ARRAY_CREATE_FLAGS: u32 = BPF_F_NUMA_NODE
    | BPF_F_MMAPABLE
    | BPF_F_RDONLY
    | BPF_F_WRONLY
    | BPF_F_RDONLY_PROG
    | BPF_F_WRONLY_PROG
    | BPF_F_PRESERVE_ELEMS
    | BPF_F_INNER_MAP;
/// `PCPU_MIN_UNIT_SIZE`: the largest per-CPU value.
const PCPU_MIN_UNIT_SIZE: u32 = 32 << 10;

/// `map_create` up to its privilege check: `CHECK_ATTR` (nothing past
/// `map_extra`), the BTF type ids, `map_extra` outside a bloom filter, both
/// access flags, a NUMA node past the one the machine has, a type the
/// kernel lacks, then the type's own checks — modeled for the array maps,
/// named for the rest — then `kernel.unprivileged_bpf_disabled`.
fn map_create(credential: &Credential, attr: &[u8; BPF_ATTR_SIZE]) -> Answer {
    let map_type = u32_at(attr, 0);
    let (key_size, value_size, max_entries) = (u32_at(attr, 4), u32_at(attr, 8), u32_at(attr, 12));
    let flags = u32_at(attr, 16);
    let (btf_key, btf_value, btf_vmlinux) = (u32_at(attr, 52), u32_at(attr, 56), u32_at(attr, 60));
    if !check_attr(attr, 72) {
        return refuse(errno::EINVAL);
    }
    if btf_vmlinux != 0 {
        if map_type != BPF_MAP_TYPE_STRUCT_OPS || btf_key != 0 || btf_value != 0 {
            return refuse(errno::EINVAL);
        }
    } else if btf_key != 0 && btf_value == 0 {
        return refuse(errno::EINVAL);
    }
    if map_type != BPF_MAP_TYPE_BLOOM_FILTER && u64_at(attr, 64) != 0 {
        return refuse(errno::EINVAL);
    }
    if flags & BPF_F_RDONLY != 0 && flags & BPF_F_WRONLY != 0 {
        return refuse(errno::EINVAL);
    }
    // `bpf_map_attr_numa_node`: a node only under `BPF_F_NUMA_NODE`, where
    // -1 is still no node; the machine has node 0 alone.
    let node = (flags & BPF_F_NUMA_NODE != 0)
        .then(|| u32_at(attr, 24) as i32)
        .filter(|node| *node != -1);
    if node.is_some_and(|node| node as u32 >= 1) {
        return refuse(errno::EINVAL);
    }
    if map_type == 0 || map_type > BPF_MAP_TYPE_LAST {
        return refuse(errno::EINVAL);
    }
    if map_type != BPF_MAP_TYPE_ARRAY && map_type != BPF_MAP_TYPE_PERCPU_ARRAY {
        return Err(Unmodeled::Path(format!(
            "the attribute checks of BPF map type {map_type}"
        )));
    }
    // `array_map_alloc_check`.
    let percpu = map_type == BPF_MAP_TYPE_PERCPU_ARRAY;
    let both_prog = BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG;
    if max_entries == 0
        || key_size != 4
        || value_size == 0
        || flags & !ARRAY_CREATE_FLAGS != 0
        || flags & both_prog == both_prog
        || (percpu && node.is_some())
    {
        return refuse(errno::EINVAL);
    }
    if map_type != BPF_MAP_TYPE_ARRAY && flags & (BPF_F_MMAPABLE | BPF_F_INNER_MAP) != 0 {
        return refuse(errno::EINVAL);
    }
    if flags & BPF_F_PRESERVE_ELEMS != 0 {
        return refuse(errno::EINVAL);
    }
    if value_size > i32::MAX as u32 {
        return refuse(errno::E2BIG);
    }
    if percpu && value_size.next_multiple_of(8) > PCPU_MIN_UNIT_SIZE {
        return refuse(errno::E2BIG);
    }
    unprivileged_bpf(credential, "creating a BPF map")
}

/// The program flags the pinned kernel knows (`BPF_F_STRICT_ALIGNMENT`
/// through `BPF_F_TEST_REG_INVARIANTS`).
const BPF_PROG_FLAGS: u32 = 0xff;

/// `bpf_prog_load` up to its privilege check: `CHECK_ATTR` (its last field
/// ends the attributes), an unknown flag, then
/// `kernel.unprivileged_bpf_disabled`. Both architectures have efficient
/// unaligned access, so `BPF_F_ANY_ALIGNMENT` needs nothing more.
fn prog_load(credential: &Credential, attr: &[u8; BPF_ATTR_SIZE]) -> Answer {
    if u32_at(attr, 44) & !BPF_PROG_FLAGS != 0 {
        return refuse(errno::EINVAL);
    }
    unprivileged_bpf(credential, "loading a BPF program")
}

/// `bpf_obj_get_next_id`: `CHECK_ATTR` (nothing past `next_id`) and a start
/// id below `INT_MAX`, then `CAP_SYS_ADMIN`, whatever the sysctl.
fn get_next_id(credential: &Credential, attr: &[u8; BPF_ATTR_SIZE]) -> Answer {
    if !check_attr(attr, 8) || u32_at(attr, 0) >= i32::MAX as u32 {
        return refuse(errno::EINVAL);
    }
    gate(credential, Capability::SysAdmin, errno::EPERM)
}

/// `userfaultfd(flags)`: handling kernel faults (no
/// `UFFD_USER_MODE_ONLY`) needs `CAP_SYS_PTRACE` or
/// `vm.unprivileged_userfaultfd`, before the flags are checked; then an
/// unknown flag is `EINVAL`. The descriptor any caller then gets is not
/// modeled yet.
pub(in crate::sud) fn userfaultfd(credential: &Credential, a: &[u64; 6]) -> Answer {
    let flags = a[0] as u32;
    let kernel_faults = flags & UFFD_USER_MODE_ONLY == 0;
    let privileged = credential.capable(Capability::SysPtrace);
    if kernel_faults && !privileged && !KERNEL_CONFIG.unprivileged_userfaultfd {
        return refuse(errno::EPERM);
    }
    if flags & !(UFFD_USER_MODE_ONLY | O_CLOEXEC | O_NONBLOCK) != 0 {
        return refuse(errno::EINVAL);
    }
    if kernel_faults && privileged {
        return Err(Unmodeled::Granted(Capability::SysPtrace));
    }
    Err(Unmodeled::Path("a userfaultfd descriptor".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::credential;

    /// A `union bpf_attr` with room for a tail, zeroed past what a case sets.
    #[derive(Clone)]
    #[repr(C, align(8))]
    struct Attr([u8; 256]);

    impl Attr {
        fn new() -> Attr {
            Attr([0; 256])
        }
        fn u32(mut self, offset: usize, value: u32) -> Attr {
            self.0[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
            self
        }
        fn u64(mut self, offset: usize, value: u64) -> Attr {
            self.0[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
            self
        }
    }

    /// `BPF_MAP_CREATE`'s attribute for a map of `kind` with four-byte keys
    /// and values and one entry.
    fn map(kind: u32) -> Attr {
        Attr::new().u32(0, kind).u32(4, 4).u32(8, 4).u32(12, 1)
    }

    const PERCPU: u32 = BPF_MAP_TYPE_PERCPU_ARRAY;
    const ARRAY: u32 = BPF_MAP_TYPE_ARRAY;
    /// A descriptor number the model's table never holds.
    const CLOSED: u32 = 9999;

    /// The bpf model's rules, one row each: the attribute's size and copy,
    /// map creation's checks in the kernel's order, and each command's
    /// refusal for the guest's credential.
    #[test]
    fn bpf_answers_as_the_pinned_kernel() {
        let refused = |code: u32| refuse(code);
        let cases: Vec<(&str, i32, Attr, usize, Answer)> = vec![
            (
                "a size past a page",
                BPF_MAP_CREATE,
                map(ARRAY),
                4097,
                refused(errno::E2BIG),
            ),
            (
                "a nonzero tail past the kernel's size",
                BPF_MAP_CREATE,
                map(ARRAY).u32(200, 1),
                256,
                refused(errno::E2BIG),
            ),
            (
                "a zero tail",
                BPF_MAP_CREATE,
                map(ARRAY),
                256,
                refused(errno::EPERM),
            ),
            (
                "an unknown command",
                36,
                Attr::new(),
                144,
                refused(errno::EINVAL),
            ),
            (
                "a negative command",
                -1,
                Attr::new(),
                144,
                refused(errno::EINVAL),
            ),
            (
                "a map past map_extra",
                BPF_MAP_CREATE,
                map(ARRAY).u32(72, 1),
                144,
                refused(errno::EINVAL),
            ),
            (
                "a vmlinux BTF value outside struct_ops",
                BPF_MAP_CREATE,
                map(ARRAY).u32(60, 1),
                144,
                refused(errno::EINVAL),
            ),
            (
                "a BTF key without a value",
                BPF_MAP_CREATE,
                map(ARRAY).u32(52, 1),
                144,
                refused(errno::EINVAL),
            ),
            (
                "map_extra outside a bloom filter",
                BPF_MAP_CREATE,
                map(ARRAY).u64(64, 1),
                144,
                refused(errno::EINVAL),
            ),
            (
                "both access flags",
                BPF_MAP_CREATE,
                map(ARRAY).u32(16, BPF_F_RDONLY | BPF_F_WRONLY),
                144,
                refused(errno::EINVAL),
            ),
            (
                "a NUMA node the machine lacks",
                BPF_MAP_CREATE,
                map(ARRAY).u32(16, BPF_F_NUMA_NODE).u32(24, 1),
                144,
                refused(errno::EINVAL),
            ),
            (
                "NUMA node -1 is no node",
                BPF_MAP_CREATE,
                map(ARRAY).u32(16, BPF_F_NUMA_NODE).u32(24, u32::MAX),
                144,
                refused(errno::EPERM),
            ),
            (
                "no map type",
                BPF_MAP_CREATE,
                map(0),
                144,
                refused(errno::EINVAL),
            ),
            (
                "a type past the last",
                BPF_MAP_CREATE,
                map(33),
                144,
                refused(errno::EINVAL),
            ),
            (
                "an array key not four bytes",
                BPF_MAP_CREATE,
                map(ARRAY).u32(4, 8),
                144,
                refused(errno::EINVAL),
            ),
            (
                "no entries",
                BPF_MAP_CREATE,
                map(ARRAY).u32(12, 0),
                144,
                refused(errno::EINVAL),
            ),
            (
                "no value",
                BPF_MAP_CREATE,
                map(ARRAY).u32(8, 0),
                144,
                refused(errno::EINVAL),
            ),
            (
                "a percpu array on a NUMA node",
                BPF_MAP_CREATE,
                map(PERCPU).u32(16, BPF_F_NUMA_NODE).u32(24, 0),
                144,
                refused(errno::EINVAL),
            ),
            (
                "a mmapable percpu array",
                BPF_MAP_CREATE,
                map(PERCPU).u32(16, BPF_F_MMAPABLE),
                144,
                refused(errno::EINVAL),
            ),
            (
                "an array preserving its elements",
                BPF_MAP_CREATE,
                map(ARRAY).u32(16, BPF_F_PRESERVE_ELEMS),
                144,
                refused(errno::EINVAL),
            ),
            (
                "an array value past INT_MAX",
                BPF_MAP_CREATE,
                map(ARRAY).u32(8, 0x8000_0000),
                144,
                refused(errno::E2BIG),
            ),
            (
                "a percpu value past PCPU_MIN_UNIT_SIZE",
                BPF_MAP_CREATE,
                map(PERCPU).u32(8, 40_000),
                144,
                refused(errno::E2BIG),
            ),
            (
                "an array map",
                BPF_MAP_CREATE,
                map(ARRAY),
                144,
                refused(errno::EPERM),
            ),
            (
                "a program flag it lacks",
                BPF_PROG_LOAD,
                Attr::new().u32(44, 1 << 30),
                144,
                refused(errno::EINVAL),
            ),
            (
                "a program",
                BPF_PROG_LOAD,
                Attr::new(),
                144,
                refused(errno::EPERM),
            ),
            (
                "an id walk from INT_MAX",
                BPF_MAP_GET_NEXT_ID,
                Attr::new().u32(0, i32::MAX as u32),
                144,
                refused(errno::EINVAL),
            ),
            (
                "an id walk",
                BPF_LINK_GET_NEXT_ID,
                Attr::new(),
                144,
                refused(errno::EPERM),
            ),
            (
                "loading BTF",
                BPF_BTF_LOAD,
                Attr::new(),
                144,
                refused(errno::EPERM),
            ),
            (
                "loading BTF past its fields",
                BPF_BTF_LOAD,
                Attr::new().u32(32, 1),
                144,
                refused(errno::EINVAL),
            ),
            (
                "a program by id",
                BPF_PROG_GET_FD_BY_ID,
                Attr::new(),
                144,
                refused(errno::EPERM),
            ),
            (
                "a map by id",
                BPF_MAP_GET_FD_BY_ID,
                Attr::new(),
                144,
                refused(errno::EPERM),
            ),
            (
                "a map by id, flags unknown",
                BPF_MAP_GET_FD_BY_ID,
                Attr::new().u32(8, 1),
                144,
                refused(errno::EINVAL),
            ),
            (
                "statistics",
                BPF_ENABLE_STATS,
                Attr::new(),
                144,
                refused(errno::EPERM),
            ),
            (
                "a task's descriptor",
                BPF_TASK_FD_QUERY,
                Attr::new(),
                144,
                refused(errno::EPERM),
            ),
            (
                "a program query, before its fields",
                BPF_PROG_QUERY,
                Attr::new().u32(100, 1),
                144,
                refused(errno::EPERM),
            ),
            (
                "a lookup on a closed descriptor",
                BPF_MAP_LOOKUP_ELEM,
                Attr::new().u32(0, CLOSED),
                144,
                refused(errno::EBADF),
            ),
            (
                "a lookup flag it lacks",
                BPF_MAP_LOOKUP_ELEM,
                Attr::new().u64(24, 1),
                144,
                refused(errno::EINVAL),
            ),
            (
                "a batch on a closed descriptor",
                BPF_MAP_LOOKUP_BATCH,
                Attr::new().u32(36, CLOSED),
                144,
                refused(errno::EBADF),
            ),
            (
                "a test run of a closed descriptor",
                BPF_PROG_TEST_RUN,
                Attr::new().u32(0, CLOSED),
                144,
                refused(errno::EBADF),
            ),
            (
                "a test run context without its size",
                BPF_PROG_TEST_RUN,
                Attr::new().u64(48, 1),
                144,
                refused(errno::EINVAL),
            ),
            (
                "pinning",
                BPF_OBJ_PIN,
                Attr::new().u32(8, CLOSED),
                144,
                refused(errno::EINVAL),
            ),
            (
                "pinning with a stray path descriptor",
                BPF_OBJ_PIN,
                Attr::new().u32(16, 3),
                144,
                refused(errno::EINVAL),
            ),
            (
                "a pinned object at no path",
                BPF_OBJ_GET,
                Attr::new(),
                144,
                refused(errno::EFAULT),
            ),
            (
                "a pinned object with a descriptor",
                BPF_OBJ_GET,
                Attr::new().u32(8, 1),
                144,
                refused(errno::EINVAL),
            ),
            (
                "information on a closed descriptor",
                BPF_OBJ_GET_INFO_BY_FD,
                Attr::new().u32(0, CLOSED),
                144,
                refused(errno::EBADFD),
            ),
            (
                "attaching to no program type",
                BPF_PROG_ATTACH,
                Attr::new().u32(8, 33),
                144,
                refused(errno::EINVAL),
            ),
            (
                "attaching a closed descriptor",
                BPF_PROG_ATTACH,
                Attr::new().u32(4, CLOSED),
                144,
                refused(errno::EBADF),
            ),
            (
                "attaching with a relative descriptor",
                BPF_PROG_ATTACH,
                Attr::new().u32(20, 1),
                144,
                refused(errno::EINVAL),
            ),
            (
                "detaching a tracing program",
                BPF_PROG_DETACH,
                Attr::new().u32(8, 24),
                144,
                refused(errno::EINVAL),
            ),
            (
                "a link on a closed descriptor",
                BPF_LINK_CREATE,
                Attr::new().u32(0, CLOSED),
                144,
                refused(errno::EBADF),
            ),
            (
                "a link update flag it lacks",
                BPF_LINK_UPDATE,
                Attr::new().u32(8, 1),
                144,
                refused(errno::EINVAL),
            ),
            (
                "an iterator with flags",
                BPF_ITER_CREATE,
                Attr::new().u32(4, 1),
                144,
                refused(errno::EINVAL),
            ),
            (
                "binding a closed program",
                BPF_PROG_BIND_MAP,
                Attr::new().u32(0, CLOSED),
                144,
                refused(errno::EBADF),
            ),
        ];
        for (what, command, attr, size, expected) in cases {
            let args = [command as u64, attr.0.as_ptr() as u64, size as u64, 0, 0, 0];
            assert_eq!(bpf(credential(), &args), expected, "{what}");
        }
        let unreadable = [BPF_MAP_CREATE as u64, 0, 144, 0, 0, 0];
        assert_eq!(bpf(credential(), &unreadable), refused(errno::EFAULT));
    }

    /// Where the model ends: a map type whose own checks are not modeled,
    /// and detaching from an attach point.
    #[test]
    fn bpf_names_where_its_model_ends() {
        for (command, attr) in [(BPF_MAP_CREATE, map(1)), (BPF_PROG_DETACH, Attr::new())] {
            let args = [command as u64, attr.0.as_ptr() as u64, 144, 0, 0, 0];
            assert!(matches!(bpf(credential(), &args), Err(Unmodeled::Path(_))));
        }
    }
}
