//! The memory rows: mappings and their protection, advice, residency and
//! locking; the program break; memfds and secret memory; memory barriers;
//! protection keys; shadow stacks; NUMA policy.
//!
//! An address is the host's business (ASLR, and the runtime's own mappings
//! under patina), so no event records one: a successful call that answers an
//! address records `ret` 0, and the address itself only through relations the
//! kernel guarantees (page alignment, landing on a `MAP_FIXED` hint, whether
//! `mremap` moved). Addresses a scenario PASSES are recorded by the labels of
//! the scenario's own regions ([`At`]: `NULL`, `a`, `a+4096`).

use super::{Probe, cstr, page_size};
use crate::observe::{Id, Norm};
use crate::record::EventBuilder;
use crate::vehicle::{Vehicle, fold_errno};
use patina_dst_syscalls::Syscall;
use serde_json::Value;

/// `mmap`'s `(len, prot, flags, fd, offset)`.
pub type MapSpec = (usize, i32, i32, i32, i64);

/// An address a scenario passes, with the label a stream records for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct At {
    pub raw: usize,
    pub label: String,
}

impl At {
    pub fn null() -> At {
        At {
            raw: 0,
            label: "NULL".to_string(),
        }
    }

    /// An address outside the scenario's regions, named for what it is
    /// (`unmapped`, `bad-pointer`).
    pub fn named(raw: usize, label: &str) -> At {
        At {
            raw,
            label: label.to_string(),
        }
    }
}

/// A range the scenario mapped (or attached), named for the stream. Its bytes
/// are read and written unobserved, volatile; what they hold is recorded
/// through the scenario's checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub base: usize,
    pub len: usize,
    pub name: &'static str,
}

impl Region {
    /// The address `offset` bytes into the region.
    pub fn at(&self, offset: usize) -> At {
        At {
            raw: self.base + offset,
            label: if offset == 0 {
                self.name.to_string()
            } else {
                format!("{}+{offset}", self.name)
            },
        }
    }

    /// The address just past the region.
    pub fn end(&self) -> At {
        self.at(self.len)
    }

    fn ptr(&self, offset: usize) -> *mut u8 {
        (self.base + offset) as *mut u8
    }

    pub fn load(&self, offset: usize) -> u8 {
        // SAFETY: the scenario reads only bytes of a region it mapped readable
        // (or, in a fault scenario, bytes whose fault its handler repairs).
        unsafe { std::ptr::read_volatile(self.ptr(offset)) }
    }

    pub fn store(&self, offset: usize, byte: u8) {
        // SAFETY: as for `load`, for writable bytes.
        unsafe { std::ptr::write_volatile(self.ptr(offset), byte) }
    }

    pub fn fill(&self, offset: usize, bytes: &[u8]) {
        for (index, byte) in bytes.iter().enumerate() {
            self.store(offset + index, *byte);
        }
    }

    pub fn bytes(&self, offset: usize, len: usize) -> Vec<u8> {
        (offset..offset + len).map(|at| self.load(at)).collect()
    }

    /// `mapped`, or — when that mapping failed — `spare` (a region the
    /// scenario mapped beforehand for the purpose) standing in under the
    /// same name, so the scenario's later calls and events stay aligned with
    /// the native run's and only its checks differ. The scenario unmaps
    /// the result once and never the spare itself.
    pub fn or_spare(mapped: Option<Region>, spare: Region, name: &'static str) -> Region {
        mapped.unwrap_or(Region { name, ..spare })
    }

    /// Whether every byte of `[offset, offset + len)` is zero.
    pub fn zeroed(&self, offset: usize, len: usize) -> bool {
        (offset..offset + len).all(|at| self.load(at) == 0)
    }
}

/// The words of a NUMA node mask the NUMA rows pass (1024 nodes, the largest
/// `MAX_NUMNODES` a distribution kernel builds with).
const NODE_WORDS: usize = 16;
/// `maxnode` for a mask the kernel reads: `get_nodes` (mm/mempolicy.c) takes
/// one bit fewer than it is told, the historical off-by-one every caller
/// (libnuma included) passes `+ 1` for.
const MAXNODE_IN: i64 = (NODE_WORDS * 64 + 1) as i64;
/// `maxnode` for a mask the kernel writes (`get_mempolicy`).
const MAXNODE_OUT: i64 = (NODE_WORDS * 64) as i64;

fn node_mask(nodes: &[u32]) -> [u64; NODE_WORDS] {
    let mut mask = [0u64; NODE_WORDS];
    for node in nodes {
        mask[*node as usize / 64] |= 1 << (node % 64);
    }
    mask
}

fn nodes_of(mask: &[u64; NODE_WORDS]) -> Vec<u32> {
    (0..(NODE_WORDS * 64) as u32)
        .filter(|node| mask[*node as usize / 64] & (1 << (node % 64)) != 0)
        .collect()
}

fn node_list(nodes: Option<&[u32]>) -> Value {
    match nodes {
        None => Value::from("NULL"),
        Some(nodes) => Value::from(nodes.to_vec()),
    }
}

impl Probe {
    /// An event for a row whose success answers an address: `ret` 0.
    fn address_event(&self, row: Syscall, result: i64) -> EventBuilder<'_> {
        self.event(row, result.min(0))
    }

    fn mapped(
        &self,
        result: i64,
        name: &'static str,
        len: usize,
        builder: EventBuilder<'_>,
    ) -> (i64, Option<Region>) {
        let builder = if result >= 0 {
            builder.field("aligned", result as usize % page_size() == 0)
        } else {
            builder
        };
        builder.emit();
        let region = (result >= 0).then_some(Region {
            base: result as usize,
            len,
            name,
        });
        (result, region)
    }

    /// The arguments of `mmap(hint, len, prot, flags, fd, offset)` for a
    /// call issued unrecorded ([`Probe::call_unrecorded`]) and recorded after
    /// with [`Probe::record_mmap`].
    pub fn mmap_args(hint: &At, spec: MapSpec) -> crate::vehicle::Args {
        let (len, prot, flags, fd, offset) = spec;
        [
            hint.raw as i64,
            len as i64,
            prot as i64,
            flags as i64,
            fd as i64,
            offset,
        ]
    }

    /// Record an `mmap` issued unrecorded; a success is the region `name`.
    pub fn record_mmap(
        &self,
        result: i64,
        name: &'static str,
        hint: &At,
        spec: MapSpec,
    ) -> (i64, Option<Region>) {
        let (len, prot, flags, fd, offset) = spec;
        let builder = self
            .address_event(Syscall::N_mmap, result)
            .arg("addr", hint.label.as_str())
            .arg("len", len)
            .arg("prot", prot)
            .arg("flags", flags);
        let builder = self
            .fd_arg(builder, "fd", fd)
            .arg("offset", offset)
            .arg("region", name);
        // Only a fixed placement is a kernel guarantee; a plain hint is advice
        // the kernel (and a model) may ignore.
        let builder = if result >= 0 && flags & (libc::MAP_FIXED | libc::MAP_FIXED_NOREPLACE) != 0 {
            builder.field("at_hint", result as usize == hint.raw)
        } else {
            builder
        };
        self.mapped(result, name, len, builder)
    }

    /// `mmap`; a success is the region `name`.
    #[allow(clippy::too_many_arguments)]
    pub fn mmap(
        &self,
        name: &'static str,
        hint: &At,
        len: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> (i64, Option<Region>) {
        let result = self.call(
            Syscall::N_mmap,
            [
                hint.raw as i64,
                len as i64,
                prot as i64,
                flags as i64,
                fd as i64,
                offset,
            ],
        );
        self.record_mmap(result, name, hint, (len, prot, flags, fd, offset))
    }

    /// `mmap` through glibc's LFS alias `mmap64` on the libc vehicle (the same
    /// row; recorded as `mmap`).
    #[allow(clippy::too_many_arguments)]
    pub fn mmap64(
        &self,
        name: &'static str,
        hint: &At,
        len: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> (i64, Option<Region>) {
        let result = match self.vehicle {
            // SAFETY: the scenario owns the hint and the descriptor.
            Vehicle::Libc => fold_errno(unsafe {
                libc::mmap64(
                    hint.raw as *mut libc::c_void,
                    len,
                    prot,
                    flags,
                    fd,
                    offset as libc::off64_t,
                )
            } as i64),
            _ => self.call(
                Syscall::N_mmap,
                [
                    hint.raw as i64,
                    len as i64,
                    prot as i64,
                    flags as i64,
                    fd as i64,
                    offset,
                ],
            ),
        };
        self.record_mmap(result, name, hint, (len, prot, flags, fd, offset))
    }

    fn range_call(&self, row: Syscall, at: &At, len: usize, extra: Option<(&str, i64)>) -> i64 {
        let result = self.call(
            row,
            [
                at.raw as i64,
                len as i64,
                extra.map_or(0, |(_, value)| value),
                0,
                0,
                0,
            ],
        );
        self.record_range(row, at, len, extra, result)
    }

    /// Record a range row (`munmap`, `madvise`, `mlock`, …) issued unrecorded
    /// with `[addr, len, extra]`; `extra` names its third argument.
    pub fn record_range(
        &self,
        row: Syscall,
        at: &At,
        len: usize,
        extra: Option<(&str, i64)>,
        result: i64,
    ) -> i64 {
        let builder = self
            .event(row, result)
            .arg("addr", at.label.as_str())
            .arg("len", len);
        let builder = match extra {
            Some((key, value)) => builder.arg(key, value),
            None => builder,
        };
        builder.emit();
        result
    }

    pub fn munmap(&self, at: &At, len: usize) -> i64 {
        self.range_call(Syscall::N_munmap, at, len, None)
    }

    pub fn mprotect(&self, at: &At, len: usize, prot: i32) -> i64 {
        self.range_call(
            Syscall::N_mprotect,
            at,
            len,
            Some(("prot", i64::from(prot))),
        )
    }

    pub fn madvise(&self, at: &At, len: usize, advice: i32) -> i64 {
        self.range_call(
            Syscall::N_madvise,
            at,
            len,
            Some(("advice", i64::from(advice))),
        )
    }

    pub fn msync(&self, at: &At, len: usize, flags: i32) -> i64 {
        self.range_call(Syscall::N_msync, at, len, Some(("flags", i64::from(flags))))
    }

    pub fn mlock(&self, at: &At, len: usize) -> i64 {
        self.range_call(Syscall::N_mlock, at, len, None)
    }

    pub fn munlock(&self, at: &At, len: usize) -> i64 {
        self.range_call(Syscall::N_munlock, at, len, None)
    }

    pub fn mlock2(&self, at: &At, len: usize, flags: u32) -> i64 {
        self.range_call(
            Syscall::N_mlock2,
            at,
            len,
            Some(("flags", i64::from(flags))),
        )
    }

    pub fn mlockall(&self, flags: i32) -> i64 {
        let result = self.call(Syscall::N_mlockall, [flags as i64, 0, 0, 0, 0, 0]);
        self.record_mlockall(flags, result)
    }

    /// Record an `mlockall(flags)` issued unrecorded.
    pub fn record_mlockall(&self, flags: i32, result: i64) -> i64 {
        self.event(Syscall::N_mlockall, result)
            .arg("flags", flags)
            .emit();
        result
    }

    pub fn munlockall(&self) -> i64 {
        let result = self.call(Syscall::N_munlockall, [0; 6]);
        self.event(Syscall::N_munlockall, result).emit();
        result
    }

    /// `mremap`; `new` is read only with `MREMAP_FIXED`. A success is the
    /// region `name`, recorded with whether it `moved` off `old` (and, fixed,
    /// whether it landed `at_new`).
    pub fn mremap(
        &self,
        name: &'static str,
        old: &At,
        old_len: usize,
        new_len: usize,
        flags: i32,
        new: &At,
    ) -> (i64, Option<Region>) {
        let result = self.call(
            Syscall::N_mremap,
            [
                old.raw as i64,
                old_len as i64,
                new_len as i64,
                flags as i64,
                new.raw as i64,
                0,
            ],
        );
        self.record_mremap(result, name, old, (old_len, new_len, flags), new)
    }

    /// Record an `mremap(old, old_len, new_len, flags, new)` issued
    /// unrecorded; a success is the region `name`.
    pub fn record_mremap(
        &self,
        result: i64,
        name: &'static str,
        old: &At,
        (old_len, new_len, flags): (usize, usize, i32),
        new: &At,
    ) -> (i64, Option<Region>) {
        let builder = self
            .address_event(Syscall::N_mremap, result)
            .arg("old", old.label.as_str())
            .arg("old_len", old_len)
            .arg("new_len", new_len)
            .arg("flags", flags)
            .arg("new", new.label.as_str())
            .arg("region", name);
        let builder = if result >= 0 {
            let builder = builder.field("moved", result as usize != old.raw);
            if flags & libc::MREMAP_FIXED != 0 {
                builder.field("at_new", result as usize == new.raw)
            } else {
                builder
            }
        } else {
            builder
        };
        self.mapped(result, name, new_len, builder)
    }

    /// `mincore` over `[at, at + len)` into a vector of `entries` bytes
    /// (`None`: a NULL vector). Records bit 0 of each entry (`resident`); the
    /// other bits are reserved.
    pub fn mincore(&self, at: &At, len: usize, entries: Option<usize>) -> (i64, Vec<u8>) {
        let mut vector = vec![0u8; entries.unwrap_or(0)];
        let pointer = entries.map_or(0, |_| vector.as_mut_ptr() as i64);
        let result = self.call(
            Syscall::N_mincore,
            [at.raw as i64, len as i64, pointer, 0, 0, 0],
        );
        self.record_mincore(at, len, entries.map(|_| vector.as_slice()), result)
    }

    /// Record a `mincore` issued unrecorded into `vector` (`None`: NULL).
    pub fn record_mincore(
        &self,
        at: &At,
        len: usize,
        vector: Option<&[u8]>,
        result: i64,
    ) -> (i64, Vec<u8>) {
        let entries = vector.map(<[u8]>::len);
        let resident: Vec<u8> = vector
            .unwrap_or_default()
            .iter()
            .map(|entry| entry & 1)
            .collect();
        let builder = self
            .event(Syscall::N_mincore, result)
            .arg("addr", at.label.as_str())
            .arg("len", len)
            .arg("vec", entries.map_or(Value::from("NULL"), Value::from));
        let builder = if result >= 0 {
            builder.field("resident", resident.clone())
        } else {
            builder
        };
        builder.emit();
        (result, resident)
    }

    /// Record a `brk(addr)` the scenario issued unrecorded (`call_unrecorded`:
    /// a break moved while the recorder allocates would race glibc's own
    /// `sbrk`). The kernel answers the (possibly unchanged) break, never an
    /// errno; recorded as which of the scenario's `named` addresses it is
    /// (`answer`, or `other`).
    pub fn record_brk(&self, at: &At, result: i64, named: &[(&str, usize)]) {
        let answer = named
            .iter()
            .find(|(_, address)| *address as i64 == result)
            .map_or("other", |(label, _)| label);
        self.address_event(Syscall::N_brk, result)
            .arg("addr", at.label.as_str())
            .field("answer", answer)
            .emit();
    }

    // ---- memfds -------------------------------------------------------------

    pub fn memfd_create(&self, name: &str, flags: u32) -> i32 {
        let c = cstr(name);
        let result = self.call(
            Syscall::N_memfd_create,
            [c.as_ptr() as i64, flags as i64, 0, 0, 0, 0],
        );
        self.event(Syscall::N_memfd_create, result)
            .arg("name", name)
            .arg("flags", flags)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    pub fn memfd_secret(&self, flags: u32) -> i32 {
        let result = self.call(Syscall::N_memfd_secret, [flags as i64, 0, 0, 0, 0, 0]);
        self.event(Syscall::N_memfd_secret, result)
            .arg("flags", flags)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    /// `fstat` recording the kind, the size, and the permission bits within
    /// `perm_mask` (a memfd's execute bits follow the `vm.memfd_noexec`
    /// sysctl, a host setting).
    pub fn fstat_masked(&self, fd: i32, perm_mask: u32) -> (i64, Option<libc::stat>) {
        // SAFETY: a zeroed stat is a valid out-buffer.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let result = self.call(
            Syscall::N_fstat,
            [fd as i64, &mut st as *mut libc::stat as i64, 0, 0, 0, 0],
        );
        let builder = self.event(Syscall::N_fstat, result);
        let builder = self.fd_arg(builder, "fd", fd);
        let builder = if result >= 0 {
            builder
                .field("kind", super::kind_of(st.st_mode))
                .field("size", st.st_size)
                .field("perm", st.st_mode & 0o7777)
                .norm("fields.perm", Norm::Mask(u64::from(perm_mask)))
        } else {
            builder
        };
        builder.emit();
        (result, (result >= 0).then_some(st))
    }

    // ---- barriers -----------------------------------------------------------

    /// `membarrier(cmd, flags, cpu_id)`. `MEMBARRIER_CMD_QUERY`'s answer is the
    /// host's supported-command mask, compared within `query_mask` (the
    /// commands every kernel with the row supports).
    pub fn membarrier(&self, cmd: i32, flags: u32, query_mask: Option<u64>) -> i64 {
        let result = self.call(
            Syscall::N_membarrier,
            [cmd as i64, flags as i64, 0, 0, 0, 0],
        );
        let builder = self
            .event(Syscall::N_membarrier, result)
            .arg("cmd", cmd)
            .arg("flags", flags);
        let builder = match query_mask {
            Some(mask) if result >= 0 => builder.norm("ret", Norm::Mask(mask)),
            _ => builder,
        };
        builder.emit();
        result
    }

    // ---- protection keys ----------------------------------------------------

    pub fn pkey_alloc(&self, flags: u32, access_rights: u32) -> i64 {
        let result = self.call(
            Syscall::N_pkey_alloc,
            [flags as i64, access_rights as i64, 0, 0, 0, 0],
        );
        self.event(Syscall::N_pkey_alloc, result)
            .arg("flags", flags)
            .arg("access_rights", access_rights)
            .emit();
        result
    }

    pub fn pkey_free(&self, key: i32) -> i64 {
        let result = self.call(Syscall::N_pkey_free, [key as i64, 0, 0, 0, 0, 0]);
        self.event(Syscall::N_pkey_free, result)
            .arg("pkey", key)
            .emit();
        result
    }

    pub fn pkey_mprotect(&self, at: &At, len: usize, prot: i32, key: i32) -> i64 {
        let result = self.call(
            Syscall::N_pkey_mprotect,
            [at.raw as i64, len as i64, prot as i64, key as i64, 0, 0],
        );
        self.event(Syscall::N_pkey_mprotect, result)
            .arg("addr", at.label.as_str())
            .arg("len", len)
            .arg("prot", prot)
            .arg("pkey", key)
            .emit();
        result
    }

    // ---- shadow stacks and legacy remapping ----------------------------------

    /// `map_shadow_stack(addr, size, flags)`; a success is the region `name`.
    pub fn map_shadow_stack(
        &self,
        name: &'static str,
        hint: &At,
        size: usize,
        flags: u32,
    ) -> (i64, Option<Region>) {
        let result = self.call(
            Syscall::N_map_shadow_stack,
            [hint.raw as i64, size as i64, flags as i64, 0, 0, 0],
        );
        let builder = self
            .address_event(Syscall::N_map_shadow_stack, result)
            .arg("addr", hint.label.as_str())
            .arg("size", size)
            .arg("flags", flags)
            .arg("region", name);
        let builder = if result >= 0 && hint.raw != 0 {
            builder.field("at_hint", result as usize == hint.raw)
        } else {
            builder
        };
        self.mapped(result, name, size, builder)
    }

    pub fn remap_file_pages(
        &self,
        at: &At,
        size: usize,
        prot: i32,
        pgoff: usize,
        flags: i32,
    ) -> i64 {
        let result = self.call(
            Syscall::N_remap_file_pages,
            [
                at.raw as i64,
                size as i64,
                prot as i64,
                pgoff as i64,
                flags as i64,
                0,
            ],
        );
        self.event(Syscall::N_remap_file_pages, result)
            .arg("addr", at.label.as_str())
            .arg("size", size)
            .arg("prot", prot)
            .arg("pgoff", pgoff)
            .arg("flags", flags)
            .emit();
        result
    }

    // ---- advice through a pidfd ----------------------------------------------

    pub fn pidfd_open(&self, pid: i32, flags: u32) -> i32 {
        let result = self.call(
            Syscall::N_pidfd_open,
            [pid as i64, flags as i64, 0, 0, 0, 0],
        );
        self.event(Syscall::N_pidfd_open, result)
            .arg("pid", pid)
            .norm("args.pid", Norm::Identity(Id::Process))
            .arg("flags", flags)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    /// `process_madvise(pidfd, iov, vlen, advice, flags)` over `ranges`.
    pub fn process_madvise(
        &self,
        pidfd: i32,
        ranges: &[(At, usize)],
        advice: i32,
        flags: u32,
    ) -> i64 {
        let iov: Vec<libc::iovec> = ranges
            .iter()
            .map(|(at, len)| libc::iovec {
                iov_base: at.raw as *mut libc::c_void,
                iov_len: *len,
            })
            .collect();
        let result = self.call(
            Syscall::N_process_madvise,
            [
                pidfd as i64,
                iov.as_ptr() as i64,
                iov.len() as i64,
                advice as i64,
                flags as i64,
                0,
            ],
        );
        let labels: Vec<Value> = ranges
            .iter()
            .map(|(at, len)| Value::from(format!("{}:{len}", at.label)))
            .collect();
        let builder = self.event(Syscall::N_process_madvise, result);
        self.fd_arg(builder, "pidfd", pidfd)
            .arg("iov", labels)
            .arg("advice", advice)
            .arg("flags", flags)
            .emit();
        result
    }

    // ---- NUMA policy --------------------------------------------------------

    /// `get_mempolicy(&mode, nodemask, maxnode, addr, flags)`; `with_mask`
    /// passes a mask (else NULL and maxnode 0). Returns the result, the mode
    /// (a node with `MPOL_F_NODE`) and the mask's nodes.
    pub fn get_mempolicy(&self, at: &At, flags: u64, with_mask: bool) -> (i64, i32, Vec<u32>) {
        let mut mode: i32 = -1;
        let mut mask = [0u64; NODE_WORDS];
        let result = self.call(
            Syscall::N_get_mempolicy,
            [
                &mut mode as *mut i32 as i64,
                if with_mask {
                    mask.as_mut_ptr() as i64
                } else {
                    0
                },
                if with_mask { MAXNODE_OUT } else { 0 },
                at.raw as i64,
                flags as i64,
                0,
            ],
        );
        let nodes = nodes_of(&mask);
        let builder = self
            .event(Syscall::N_get_mempolicy, result)
            .arg("addr", at.label.as_str())
            .arg("flags", flags)
            .arg("mask", with_mask);
        let builder = if result >= 0 {
            let builder = builder.field("mode", mode);
            if with_mask {
                builder.field("nodes", nodes.clone())
            } else {
                builder
            }
        } else {
            builder
        };
        builder.emit();
        (result, mode, nodes)
    }

    /// `set_mempolicy(mode, nodemask, maxnode)`; `None` is a NULL mask.
    pub fn set_mempolicy(&self, mode: i32, nodes: Option<&[u32]>) -> i64 {
        let mask = nodes.map(node_mask);
        let result = self.call(
            Syscall::N_set_mempolicy,
            [
                mode as i64,
                mask.as_ref().map_or(0, |mask| mask.as_ptr() as i64),
                if mask.is_some() { MAXNODE_IN } else { 0 },
                0,
                0,
                0,
            ],
        );
        self.event(Syscall::N_set_mempolicy, result)
            .arg("mode", mode)
            .arg("nodes", node_list(nodes))
            .emit();
        result
    }

    pub fn mbind(&self, at: &At, len: usize, mode: i32, nodes: Option<&[u32]>, flags: u32) -> i64 {
        let mask = nodes.map(node_mask);
        let result = self.call(
            Syscall::N_mbind,
            [
                at.raw as i64,
                len as i64,
                mode as i64,
                mask.as_ref().map_or(0, |mask| mask.as_ptr() as i64),
                if mask.is_some() { MAXNODE_IN } else { 0 },
                flags as i64,
            ],
        );
        self.event(Syscall::N_mbind, result)
            .arg("addr", at.label.as_str())
            .arg("len", len)
            .arg("mode", mode)
            .arg("nodes", node_list(nodes))
            .arg("flags", flags)
            .emit();
        result
    }

    pub fn migrate_pages(&self, pid: i32, old: &[u32], new: &[u32]) -> i64 {
        let (old_mask, new_mask) = (node_mask(old), node_mask(new));
        let result = self.call(
            Syscall::N_migrate_pages,
            [
                pid as i64,
                MAXNODE_IN,
                old_mask.as_ptr() as i64,
                new_mask.as_ptr() as i64,
                0,
                0,
            ],
        );
        let builder = self.event(Syscall::N_migrate_pages, result).arg("pid", pid);
        let builder = if pid != 0 {
            builder.norm("args.pid", Norm::Identity(Id::Process))
        } else {
            builder
        };
        builder
            .arg("old", old.to_vec())
            .arg("new", new.to_vec())
            .emit();
        result
    }

    /// `move_pages(pid, count, pages, nodes, status, flags)`; `nodes: None`
    /// only queries. Returns the result and the per-page status.
    pub fn move_pages(
        &self,
        pid: i32,
        pages: &[At],
        nodes: Option<&[i32]>,
        flags: i32,
    ) -> (i64, Vec<i32>) {
        let pointers: Vec<usize> = pages.iter().map(|at| at.raw).collect();
        let mut status = vec![i32::MIN; pages.len()];
        let result = self.call(
            Syscall::N_move_pages,
            [
                pid as i64,
                pages.len() as i64,
                pointers.as_ptr() as i64,
                nodes.map_or(0, |nodes| nodes.as_ptr() as i64),
                status.as_mut_ptr() as i64,
                flags as i64,
            ],
        );
        let labels: Vec<Value> = pages
            .iter()
            .map(|at| Value::from(at.label.as_str()))
            .collect();
        let builder = self
            .event(Syscall::N_move_pages, result)
            .arg("pid", pid)
            .arg("pages", labels)
            .arg(
                "nodes",
                nodes.map_or(Value::from("NULL"), |nodes| Value::from(nodes.to_vec())),
            )
            .arg("flags", flags);
        let builder = if result >= 0 {
            builder.field("status", status.clone())
        } else {
            builder
        };
        builder.emit();
        (result, status)
    }

    pub fn set_mempolicy_home_node(&self, at: &At, len: usize, home: u64, flags: u64) -> i64 {
        let result = self.call(
            Syscall::N_set_mempolicy_home_node,
            [at.raw as i64, len as i64, home as i64, flags as i64, 0, 0],
        );
        self.event(Syscall::N_set_mempolicy_home_node, result)
            .arg("addr", at.label.as_str())
            .arg("len", len)
            .arg("home_node", home)
            .arg("flags", flags)
            .emit();
        result
    }
}
