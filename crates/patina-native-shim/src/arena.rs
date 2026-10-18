//! The runtime's own memory, apart from the guest's heap.
//!
//! The runtime is linked into the guest and allocates as it runs: a recording
//! grows its trace, a replay holds the trace it loaded, and every boundary
//! operation builds and drops values of its own. On the guest's heap those
//! allocations would move every later guest block, and every mapping placed
//! after one of the runtime's large blocks, between a seeded run, a recording
//! and its replay. So on Linux the runtime allocates from an arena of its own:
//! one region, at a fixed address far from where the kernel puts the guest's
//! heap and mappings, which the guest's allocator never sees.
//!
//! The link routes Rust's allocator entry points through this module: `cargo
//! patina build` wraps them (`--wrap`), so every Rust allocation in the
//! program reaches a `patina_route_*` function, and the real entry points
//! (the guest's `#[global_allocator]`, or the C library's `malloc` behind
//! `System`) stay reachable as `patina_guest_*`. An allocation made while the
//! shim owns the thread ([`crate::panic_boundary::in_shim`]) comes from the
//! arena; every other one goes to the guest's allocator. A block is freed or
//! resized by the allocator whose address range holds it, whichever code frees
//! it, so a block that crosses between shim and guest code in either direction
//! goes back where it came from. The shim's C-level `malloc` calls for blocks
//! it hands the guest (a `getaddrinfo` list, a directory stream, the guest's
//! environment) are the guest's own, as the C library's would be, and stay on
//! its heap.
//!
//! The arena is a power-of-two size-class allocator. Small classes are carved
//! from 64 KiB slabs, so a block is aligned to its size; larger blocks are
//! carved at 64 KiB alignment. A freed block goes on its class's free list, and
//! a freed block of a megabyte or more gives its pages back to the host first.
//! The region is mapped from its fixed start as the carved part grows, a step
//! at a time, each step at the address the last one ended
//! (`MAP_FIXED_NOREPLACE`), so the arena takes only the memory the runtime
//! uses: a guest under an address-space limit keeps the rest of it.
//!
//! The whole region is the runtime's, however much of it is mapped: how much
//! is differs between a seeded run, a recording and its replay. So the guest
//! is answered about any part of it as about addresses past the end of its
//! address space ([`reserved`]), whatever is mapped there, once the kernel's
//! judgments of a malformed request have had their say: a mapping asked for
//! at a fixed address in it is `ENOMEM` (`EEXIST` for `MAP_FIXED_NOREPLACE`,
//! whose answer for a range it may not take is that), a mere hint there is
//! dropped and the host picks, a mapping that grows in place into it moves
//! when it may, and an unmap (`EINVAL`), protection change, advice, residency
//! query, lock or sync of a range in it is refused with the errno the kernel
//! gives for an unmapped range (`crate::mem`). An address is judged as the
//! kernel acts on it, without an aarch64 pointer tag. A host that puts one of
//! the guest's mappings there stops the run by name. A guest stack mapping
//! (`MAP_GROWSDOWN`), which the kernel grows into address space nothing maps,
//! is refused by name wherever it is asked for (`crate::mem`).
//!
//! A known limit: the C library maps memory for itself (malloc's arenas,
//! thread stacks) straight from the kernel, unseen here. The kernel could in
//! principle put such a mapping in the region's unmapped part, and calls the
//! shim mediates would then answer for it as for the region. It places
//! mappings down from below the stack and would have to fill tens of TiB
//! first, and the arena's own growth (`MAP_FIXED_NOREPLACE`) stops by name
//! rather than map over one.
//!
//! The region is placed once, at its fixed place unless the host already
//! mapped something there: a randomized executable can load there, and then
//! the region moves to a free place, while under a fixed layout, whose every
//! run must place it alike, the run stops by name. Reserving the whole region
//! up front would let the kernel answer most of this itself, but a replay
//! holds its trace here: a 19 MB trace takes about half a GiB of the region,
//! so a reservation a long replay fits in would not fit under the
//! address-space limits guests run with.

#![deny(clippy::undocumented_unsafe_blocks)]

use std::cell::{Cell, UnsafeCell};
use std::ffi::c_long;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use patina_dst_syscalls::Syscall;

/// The smallest block: room for the free list's link, at 16-byte alignment.
const MIN_SHIFT: u32 = 4;
/// Classes below this are carved from slabs of this size.
const SLAB_SHIFT: u32 = 16;
const SLAB: usize = 1 << SLAB_SHIFT;
/// Classes up to `1 << 47`, past any region this module places.
const CLASSES: usize = 48;
/// The mapped prefix grows in steps of this size.
const GROW_STEP: usize = 2 << 20;
/// A freed block of this class or larger returns its pages to the host.
const RELEASE_FROM: usize = 1 << 20;
/// The largest region, whatever the address space's size.
const MAX_REGION: usize = 256 << 30;

/// The region's start: 0 until its first use places it ([`region`]), and
/// never changed after.
static BASE: AtomicUsize = AtomicUsize::new(0);
/// The end of the region's mapped prefix, which holds every block: 0 until
/// the first allocation, readable without the lock, and only ever growing.
static MAPPED: AtomicUsize = AtomicUsize::new(0);

/// The arena's bookkeeping, behind [`LOCK`].
struct State {
    /// The next address no block has been carved from.
    frontier: usize,
    /// Each class's free list: the first block, whose first word links the
    /// next, or 0.
    free: [usize; CLASSES],
    /// Each slab class's current slab: its next uncarved block and its end.
    slabs: [(usize, usize); SLAB_SHIFT as usize],
}

struct Shared(UnsafeCell<State>);
// SAFETY: the state is only reached through `Locked`, which holds `LOCK`.
unsafe impl Sync for Shared {}

static STATE: Shared = Shared(UnsafeCell::new(State {
    frontier: 0,
    free: [0; CLASSES],
    slabs: [(0, 0); SLAB_SHIFT as usize],
}));
static LOCK: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// Whether this thread is inside the arena, so a re-entry (a signal
    /// handler that allocates while the lock is held) stops by name instead of
    /// spinning on its own lock.
    static INSIDE: Cell<bool> = const { Cell::new(false) };
}

/// Exclusive access to [`STATE`] while it lives.
struct Locked;

impl Locked {
    fn take() -> Self {
        if INSIDE.with(|inside| inside.replace(true)) {
            fatal(b"the runtime arena was re-entered on one thread");
        }
        let mut spins = 0u32;
        while LOCK
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spins += 1;
            if spins.is_multiple_of(64) {
                // The holder is another host thread the host has descheduled.
                host(Syscall::N_sched_yield, [0; 6]);
            } else {
                std::hint::spin_loop();
            }
        }
        Locked
    }

    fn state(&mut self) -> &mut State {
        // SAFETY: `LOCK` is held for as long as `self` lives, and `self` is
        // borrowed mutably for as long as the reference.
        unsafe { &mut *STATE.0.get() }
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        LOCK.store(false, Ordering::Release);
        INSIDE.with(|inside| inside.set(false));
    }
}

/// A host system call through the private `syscall` alias: never the
/// interposed one, and never trapped.
fn host(row: Syscall, args: [usize; 6]) -> c_long {
    // SAFETY: the callers pass the memory-management calls this module makes
    // on its own region, and a yield.
    unsafe {
        crate::sud_host_syscall(
            c_long::from(row.number()),
            args[0] as c_long,
            args[1] as c_long,
            args[2] as c_long,
            args[3] as c_long,
            args[4] as c_long,
            args[5] as c_long,
        )
    }
}

/// Stop the run: the arena cannot answer, and an allocation failure the
/// runtime saw as its own would be a lie. Allocation-free.
fn fatal(reason: &[u8]) -> ! {
    let _ = crate::host_write_all(2, b"patina native shim fatal: ");
    let _ = crate::host_write_all(2, reason);
    let _ = crate::host_write_all(2, b"\n");
    crate::host_abort();
}

/// [`fatal`] for a host call that failed, naming its errno.
fn host_fatal(reason: &[u8]) -> ! {
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let mut digits = [0u8; 10];
    let mut start = digits.len();
    let mut rest = errno.unsigned_abs();
    loop {
        start -= 1;
        digits[start] = b'0' + (rest % 10) as u8;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    let _ = crate::host_write_all(2, b"patina native shim fatal: ");
    let _ = crate::host_write_all(2, reason);
    let _ = crate::host_write_all(2, b" (errno ");
    let _ = crate::host_write_all(2, &digits[start..]);
    let _ = crate::host_write_all(2, b")\n");
    crate::host_abort();
}

/// Where the region goes in an address space whose top is `top`, and how
/// large it is: three quarters of the way up, past the image and the heap
/// after it (two thirds of the way up, where the kernel loads a position-
/// independent executable) and well below the mappings the kernel places
/// down from the stack.
fn placement(top: usize) -> (usize, usize) {
    let base = top / 4 * 3;
    (base, (top / 64).min(MAX_REGION))
}

/// Room kept free below the region, for a heap that grows up to it.
const MARGIN: usize = 1 << 30;

/// The places the region may go, in order of preference: its fixed place
/// first, then a region's size at a time below and above it, within
/// `[low, high)`; and which of them a mapping the host already made rules
/// out.
struct Candidates {
    bases: [usize; 32],
    clear: [bool; 32],
    count: usize,
    size: usize,
}

impl Candidates {
    fn new(base: usize, size: usize, low: usize, high: usize) -> Self {
        let mut candidates = Candidates {
            bases: [0; 32],
            clear: [true; 32],
            count: 0,
            size,
        };
        let mut push = |at: Option<usize>| {
            if let Some(at) = at.filter(|at| *at >= low && at.saturating_add(size) <= high)
                && candidates.count < candidates.bases.len()
            {
                candidates.bases[candidates.count] = at;
                candidates.count += 1;
            }
        };
        push(Some(base));
        for step in 1..16usize {
            let offset = step.checked_mul(size);
            push(offset.and_then(|offset| base.checked_sub(offset)));
            push(offset.and_then(|offset| base.checked_add(offset)));
        }
        candidates
    }

    /// The host has the mapping `[start, end)`.
    fn see(&mut self, start: usize, end: usize) {
        for index in 0..self.count {
            let base = self.bases[index];
            if start < base + self.size && end > base.saturating_sub(MARGIN) {
                self.clear[index] = false;
            }
        }
    }

    /// Whether the fixed place is clear, and the first clear place.
    fn choice(&self) -> (bool, Option<usize>) {
        let first = (0..self.count)
            .find(|index| self.clear[*index])
            .map(|index| self.bases[index]);
        (self.count > 0 && self.clear[0], first)
    }
}

/// Each mapping the host lists for this process (`/proc/self/maps`), read
/// without allocating; false when the list cannot be read.
pub(crate) fn each_mapping(see: &mut dyn FnMut(usize, usize)) -> bool {
    const PATH: &[u8] = b"/proc/self/maps\0";
    let fd = host(
        Syscall::N_openat,
        [
            libc::AT_FDCWD as usize,
            PATH.as_ptr() as usize,
            (libc::O_RDONLY | libc::O_CLOEXEC) as usize,
            0,
            0,
            0,
        ],
    );
    if fd < 0 {
        return false;
    }
    // Each line starts `start-end ` in hex: parse those two numbers and skip
    // to the line's end.
    let mut buffer = [0u8; 4096];
    let (mut field, mut start, mut end) = (0u8, 0usize, 0usize);
    let complete = loop {
        let read = host(
            Syscall::N_read,
            [
                fd as usize,
                buffer.as_mut_ptr() as usize,
                buffer.len(),
                0,
                0,
                0,
            ],
        );
        if read <= 0 {
            break read == 0;
        }
        for &byte in &buffer[..read as usize] {
            match (field, byte) {
                (_, b'\n') => {
                    if field >= 2 {
                        see(start, end);
                    }
                    (field, start, end) = (0, 0, 0);
                }
                (0, b'-') => field = 1,
                (1, b' ') => field = 2,
                (0 | 1, digit) => {
                    let value = match digit {
                        b'0'..=b'9' => digit - b'0',
                        b'a'..=b'f' => digit - b'a' + 10,
                        _ => 0,
                    } as usize;
                    let slot = if field == 0 { &mut start } else { &mut end };
                    *slot = slot.wrapping_mul(16).wrapping_add(value);
                }
                _ => {}
            }
        }
    };
    host(Syscall::N_close, [fd as usize, 0, 0, 0, 0, 0]);
    complete
}

/// Place the region: at its fixed place, from the address space this
/// thread's stack is in (the stack is at its top, so the power of two above
/// it is its size), unless the host already mapped something there.
fn place() -> (usize, usize) {
    let marker = 0u8;
    let top = (std::hint::black_box(&marker) as *const u8 as usize).next_power_of_two();
    let (base, size) = placement(top);
    let candidates = Candidates::new(base, size, top / 2, top - top / 8);
    match choose(candidates, each_mapping, crate::layout::fixed) {
        Ok(base) => (base, size),
        Err(reason) => fatal(reason),
    }
}

/// The region's start among `candidates`, from the host's mappings as `scan`
/// lists them: its fixed place if that is clear. Under a fixed layout
/// (`fixed`) a taken fixed place stops the run, since the region's place is
/// part of every run's layout; under a randomized one (a randomized
/// executable can load there) the region moves to the first clear place. A
/// list that cannot be read stops the run too: an unverified place could
/// hold the guest's own mappings.
fn choose(
    mut candidates: Candidates,
    scan: impl FnOnce(&mut dyn FnMut(usize, usize)) -> bool,
    fixed: impl FnOnce() -> bool,
) -> Result<usize, &'static [u8]> {
    if !scan(&mut |start, end| candidates.see(start, end)) {
        return Err(b"the runtime arena could not read the host's mappings (/proc/self/maps) to place its region");
    }
    match candidates.choice() {
        (true, Some(base)) => Ok(base),
        (false, _) if fixed() => {
            Err(b"the runtime arena's fixed region is already mapped, under a fixed layout")
        }
        (_, Some(slid)) => Ok(slid),
        (_, None) => Err(b"the address space has no free place for the runtime arena"),
    }
}

/// Whether a thread is placing the region ([`region`]).
static PLACING: AtomicBool = AtomicBool::new(false);
/// The region's end, stored before [`BASE`].
static END: AtomicUsize = AtomicUsize::new(0);

/// The region, `[start, end)`. The first use places it ([`place`]); every
/// later one, on any thread, finds the same.
pub(crate) fn region() -> (usize, usize) {
    let mut spins = 0u32;
    loop {
        let base = BASE.load(Ordering::Acquire);
        if base != 0 {
            return (base, END.load(Ordering::Relaxed));
        }
        if PLACING
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            let (base, size) = place();
            END.store(base + size, Ordering::Relaxed);
            BASE.store(base, Ordering::Release);
            return (base, base + size);
        }
        spins += 1;
        if spins.is_multiple_of(64) {
            host(Syscall::N_sched_yield, [0; 6]);
        } else {
            std::hint::spin_loop();
        }
    }
}

/// The address the kernel's memory rows act on for `addr` (`untagged_addr`):
/// on aarch64 they ignore the pointer tag in the top byte (bits 56 to 63),
/// so a range is judged by the address with bit 55 copied into them. x86_64
/// has no tag the guest can enable (`ARCH_ENABLE_TAGGED_ADDR` is refused).
fn untagged(addr: usize) -> usize {
    if cfg!(target_arch = "aarch64") {
        untag_top_byte(addr)
    } else {
        addr
    }
}

/// aarch64's `untagged_addr`: bit 55 sign-extended over the top byte.
fn untag_top_byte(addr: usize) -> usize {
    (((addr as isize) << 8) >> 8) as usize
}

/// Whether `[addr, addr + len)` reaches into the region: the guest's request
/// about such a range gets the answer this module's doc names, never the
/// host's, whose answer would depend on how much of the region is mapped. An
/// empty range reaches nothing.
pub(crate) fn reserved(addr: usize, len: usize) -> bool {
    let (base, end) = region();
    let addr = untagged(addr);
    len != 0 && addr < end && addr.saturating_add(len) > base
}

/// Stop the run if the host put the guest's mapping `[addr, addr + len)` in
/// the region: a mapping the host places there in one run and elsewhere in
/// another (the arena had mapped less of the region) moves every later one.
pub(crate) fn refuse_placement(addr: usize, len: usize) {
    if reserved(addr, len) {
        fatal(b"the host placed a guest mapping inside the runtime arena's region");
    }
}

/// The class of a block of `size` bytes at `align`, as a shift: the power of
/// two that holds both, if one is a class.
fn class(size: usize, align: usize) -> Option<u32> {
    let bytes = size.max(align).max(1 << MIN_SHIFT);
    let shift = bytes.checked_next_power_of_two()?.trailing_zeros();
    (shift < CLASSES as u32).then_some(shift)
}

/// The class of a block the arena handed out.
fn class_of_block(size: usize, align: usize) -> u32 {
    class(size, align)
        .unwrap_or_else(|| fatal(b"a block freed to the runtime arena is no arena block"))
}

impl State {
    /// `len` bytes at `align` from the frontier, mapped.
    fn take(&mut self, len: usize, align: usize) -> usize {
        let (_, end) = region();
        let start = self.frontier.next_multiple_of(align);
        let Some(stop) = start.checked_add(len).filter(|stop| *stop <= end) else {
            fatal(b"the runtime arena is exhausted");
        };
        let mapped = MAPPED.load(Ordering::Relaxed);
        if stop > mapped {
            let grown = stop.next_multiple_of(GROW_STEP).min(end);
            let protection = libc::PROT_READ | libc::PROT_WRITE;
            let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE;
            let address = host(
                Syscall::N_mmap,
                [
                    mapped,
                    grown - mapped,
                    protection as usize,
                    flags as usize,
                    usize::MAX,
                    0,
                ],
            );
            if address as usize != mapped {
                if address != -1 {
                    // A kernel older than `MAP_FIXED_NOREPLACE` read it as a
                    // hint and put the pages elsewhere.
                    host(
                        Syscall::N_munmap,
                        [address as usize, grown - mapped, 0, 0, 0, 0],
                    );
                }
                host_fatal(
                    b"the runtime arena could not map its next pages at their fixed address (mmap)",
                );
            }
            MAPPED.store(grown, Ordering::Release);
        }
        self.frontier = stop;
        start
    }

    /// A block of class `shift`, never used before (so zero), at `align`.
    fn carve(&mut self, shift: u32, align: usize) -> usize {
        let size = 1usize << shift;
        if shift >= SLAB_SHIFT {
            return self.take(size, align.max(SLAB));
        }
        let slab = &mut self.slabs[shift as usize];
        if slab.0 == slab.1 {
            let start = self.take(SLAB, SLAB);
            self.slabs[shift as usize] = (start, start + SLAB);
        }
        let slab = &mut self.slabs[shift as usize];
        let block = slab.0;
        slab.0 += size;
        block
    }

    /// A free block of class `shift` at `align`, if its list's first is one.
    fn reuse(&mut self, shift: u32, align: usize) -> Option<usize> {
        let block = self.free[shift as usize];
        // A large class's blocks are aligned to the slab size, not their own:
        // a stricter request than that takes a fresh block.
        if block == 0 || !block.is_multiple_of(align) {
            return None;
        }
        // SAFETY: a free block of this class, whose first word is its link.
        self.free[shift as usize] = unsafe { (block as *const usize).read() };
        Some(block)
    }
}

/// A block of `size` bytes at `align` from the arena, and whether it is
/// fresh (and so already zero); null for a block larger than the region, as
/// an allocator answers a request it can never meet.
fn allocate(size: usize, align: usize) -> (*mut u8, bool) {
    let Some(shift) = class(size, align) else {
        return (std::ptr::null_mut(), false);
    };
    let (base, end) = region();
    if 1usize << shift > end - base {
        return (std::ptr::null_mut(), false);
    }
    let mut locked = Locked::take();
    if MAPPED.load(Ordering::Relaxed) == 0 {
        locked.state().frontier = base;
        // A reader that sees the mapped end sees the base ([`contains`]).
        MAPPED.store(base, Ordering::Release);
    }
    let state = locked.state();
    match state.reuse(shift, align) {
        Some(block) => (block as *mut u8, false),
        None => (state.carve(shift, align) as *mut u8, true),
    }
}

/// Whether `ptr` is an arena block.
pub(crate) fn contains(ptr: *const u8) -> bool {
    let address = ptr as usize;
    // The mapped end first: 0 until the first allocation, and once it is
    // not, the base was placed before it.
    let mapped = MAPPED.load(Ordering::Acquire);
    address < mapped && address >= BASE.load(Ordering::Relaxed)
}

pub(crate) fn alloc(size: usize, align: usize) -> *mut u8 {
    allocate(size, align).0
}

pub(crate) fn alloc_zeroed(size: usize, align: usize) -> *mut u8 {
    let (block, fresh) = allocate(size, align);
    if !fresh && !block.is_null() {
        // SAFETY: a block of at least `size` bytes this call owns.
        unsafe { block.write_bytes(0, size) };
    }
    block
}

/// Return the arena block `ptr`, allocated as `size` bytes at `align`.
///
/// # Safety
/// `ptr` is a live arena block of that layout, never used again.
pub(crate) unsafe fn dealloc(ptr: *mut u8, size: usize, align: usize) {
    let shift = class_of_block(size, align);
    let bytes = 1usize << shift;
    if bytes >= RELEASE_FROM {
        // Advice failing only keeps the pages resident.
        host(
            Syscall::N_madvise,
            [ptr as usize, bytes, libc::MADV_DONTNEED as usize, 0, 0, 0],
        );
    }
    let mut locked = Locked::take();
    let state = locked.state();
    // SAFETY: the block is the caller's to give back, at least a word long.
    unsafe { (ptr as *mut usize).write(state.free[shift as usize]) };
    state.free[shift as usize] = ptr as usize;
}

/// Resize the arena block `ptr` from `size` to `new_size` bytes at `align`,
/// in the arena.
///
/// # Safety
/// `ptr` is a live arena block of `size` bytes at `align`.
pub(crate) unsafe fn realloc(ptr: *mut u8, size: usize, align: usize, new_size: usize) -> *mut u8 {
    if class(new_size, align) == Some(class_of_block(size, align)) {
        return ptr;
    }
    let grown = alloc(new_size, align);
    if grown.is_null() {
        return grown;
    }
    // SAFETY: two distinct live blocks, each at least as long as the copy.
    unsafe {
        std::ptr::copy_nonoverlapping(ptr, grown, size.min(new_size));
        dealloc(ptr, size, align);
    }
    grown
}

/// Whether an allocation the shim makes comes from the arena: the link routed
/// Rust's allocator entry points through it. Called where the shim owns the
/// thread.
pub(crate) fn routed() -> bool {
    let probe = std::hint::black_box(Box::new(0u8));
    contains(&*probe)
}

// The real allocator entry points, which the link names `patina_guest_*`
// (`--defsym` of each `__real_` name). Weak, so a link without the routing,
// in which nothing calls the `patina_route_*` functions, needs none of them.
core::arch::global_asm!(
    ".weak patina_guest_alloc",
    ".weak patina_guest_dealloc",
    ".weak patina_guest_realloc",
    ".weak patina_guest_alloc_zeroed",
);
unsafe extern "Rust" {
    fn patina_guest_alloc(size: usize, align: usize) -> *mut u8;
    fn patina_guest_dealloc(ptr: *mut u8, size: usize, align: usize);
    fn patina_guest_realloc(ptr: *mut u8, size: usize, align: usize, new_size: usize) -> *mut u8;
    fn patina_guest_alloc_zeroed(size: usize, align: usize) -> *mut u8;
}

/// Rust's `__rust_alloc`, routed.
///
/// # Safety
/// The `GlobalAlloc::alloc` contract.
#[unsafe(no_mangle)]
pub unsafe extern "Rust" fn patina_route_alloc(size: usize, align: usize) -> *mut u8 {
    if crate::panic_boundary::in_shim() {
        alloc(size, align)
    } else {
        // SAFETY: the real entry point, under the caller's contract.
        unsafe { patina_guest_alloc(size, align) }
    }
}

/// Rust's `__rust_alloc_zeroed`, routed.
///
/// # Safety
/// The `GlobalAlloc::alloc_zeroed` contract.
#[unsafe(no_mangle)]
pub unsafe extern "Rust" fn patina_route_alloc_zeroed(size: usize, align: usize) -> *mut u8 {
    if crate::panic_boundary::in_shim() {
        alloc_zeroed(size, align)
    } else {
        // SAFETY: the real entry point, under the caller's contract.
        unsafe { patina_guest_alloc_zeroed(size, align) }
    }
}

/// Rust's `__rust_dealloc`, routed by the block's address.
///
/// # Safety
/// The `GlobalAlloc::dealloc` contract.
#[unsafe(no_mangle)]
pub unsafe extern "Rust" fn patina_route_dealloc(ptr: *mut u8, size: usize, align: usize) {
    // SAFETY: the caller's block, returned to the allocator that holds it.
    unsafe {
        if contains(ptr) {
            dealloc(ptr, size, align);
        } else {
            patina_guest_dealloc(ptr, size, align);
        }
    }
}

/// Rust's `__rust_realloc`, routed by the block's address: the block stays
/// with the allocator that holds it.
///
/// # Safety
/// The `GlobalAlloc::realloc` contract.
#[unsafe(no_mangle)]
pub unsafe extern "Rust" fn patina_route_realloc(
    ptr: *mut u8,
    size: usize,
    align: usize,
    new_size: usize,
) -> *mut u8 {
    // SAFETY: the caller's block, resized by the allocator that holds it.
    unsafe {
        if contains(ptr) {
            realloc(ptr, size, align, new_size)
        } else {
            patina_guest_realloc(ptr, size, align, new_size)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_region_sits_between_the_heap_and_the_mappings() {
        for top in [1usize << 39, 1 << 47, 1 << 48] {
            let (base, size) = placement(top);
            // A position-independent executable loads two thirds of the way
            // up, and its heap grows from there.
            assert!(base > top / 3 * 2 + top / 64, "{top:#x}");
            assert!(base + size < top - top / 8, "{top:#x}");
        }
    }

    #[test]
    fn blocks_are_aligned_distinct_and_writable() {
        let layouts = [
            (1, 1),
            (24, 8),
            (48, 16),
            (100, 64),
            (4096, 4096),
            (70_000, 8),
            (8, 1 << 17),
        ];
        let blocks: Vec<_> = layouts
            .iter()
            .map(|&(size, align)| {
                let block = alloc(size, align);
                assert!(contains(block));
                assert!((block as usize).is_multiple_of(align), "{size} at {align}");
                // SAFETY: a fresh block of `size` bytes.
                unsafe { block.write_bytes(0xa5, size) };
                (block, size, align)
            })
            .collect();
        for (index, &(block, size, _)) in blocks.iter().enumerate() {
            for &(other, other_size, _) in &blocks[index + 1..] {
                let (a, b) = (block as usize, other as usize);
                assert!(a + size <= b || b + other_size <= a, "overlap");
            }
        }
        for (block, size, align) in blocks {
            // SAFETY: each block's own layout.
            unsafe { dealloc(block, size, align) };
        }
    }

    #[test]
    fn a_freed_block_is_reused_and_zeroed_on_request() {
        // A class no other test uses, so no concurrent test takes the block.
        let (size, align) = (300, 8);
        let block = alloc(size, align);
        // SAFETY: the block's own bytes and layout.
        unsafe {
            block.write_bytes(0xff, size);
            dealloc(block, size, align);
        }
        let again = alloc_zeroed(size, align);
        assert_eq!(again, block);
        // SAFETY: a live block of `size` bytes.
        let bytes = unsafe { std::slice::from_raw_parts(again, size) };
        assert!(bytes.iter().all(|byte| *byte == 0));
        // SAFETY: its own layout.
        unsafe { dealloc(again, size, align) };
    }

    #[test]
    fn realloc_keeps_the_bytes_across_classes() {
        let block = alloc(10, 1);
        // SAFETY: the blocks' own bytes and layouts.
        unsafe {
            block.copy_from_nonoverlapping(b"0123456789".as_ptr(), 10);
            let same = realloc(block, 10, 1, 16);
            assert_eq!(same, block, "one class");
            let grown = realloc(same, 16, 1, 3 << 20);
            assert!(contains(grown));
            assert_eq!(std::slice::from_raw_parts(grown, 10), b"0123456789");
            let shrunk = realloc(grown, 3 << 20, 1, 5);
            assert_eq!(std::slice::from_raw_parts(shrunk, 5), b"01234");
            dealloc(shrunk, 5, 1);
        }
    }

    #[test]
    fn a_block_larger_than_the_region_is_null_zeroed_or_not() {
        let (base, end) = region();
        let size = (end - base) * 2;
        assert!(alloc(size, 8).is_null());
        assert!(alloc_zeroed(size, 8).is_null());
    }

    #[test]
    fn the_whole_region_is_reserved_however_little_is_mapped() {
        let (base, end) = region();
        let page = 4096;
        for (addr, len) in [
            (base, 1),
            (end - page, page),
            (base - page, 2 * page),
            (end - page, usize::MAX),
            (0, usize::MAX),
        ] {
            assert!(reserved(addr, len), "{addr:#x}+{len:#x}");
        }
        for (addr, len) in [(base - page, page), (end, page), (base, 0)] {
            assert!(!reserved(addr, len), "{addr:#x}+{len:#x}");
        }
        // Past anything the arena has mapped, too.
        let block = alloc(8, 8);
        assert!(MAPPED.load(Ordering::Acquire) < end);
        assert!(reserved(end - 1, 1));
        // SAFETY: its own layout.
        unsafe { dealloc(block, 8, 8) };
    }

    #[test]
    fn a_tagged_address_is_judged_by_the_address_the_kernel_acts_on() {
        let (base, _) = region();
        for tag in [1usize, 0x5a, 0xff] {
            assert_eq!(untag_top_byte(base | tag << 56), base, "{tag:#x}");
        }
        // Bit 55 set: the kernel half, whatever the tag.
        assert_eq!(untag_top_byte(0x0080_0000_0000_0000), usize::MAX << 55);
        if cfg!(target_arch = "aarch64") {
            assert!(reserved(base | 1 << 56, 4096));
        }
    }

    #[test]
    fn a_taken_place_moves_the_region_to_the_first_clear_one() {
        let (size, top) = (1usize << 30, 1usize << 47);
        let base = top / 4 * 3;
        let fresh = || Candidates::new(base, size, top / 2, top - top / 8);
        assert_eq!(fresh().choice(), (true, Some(base)));
        // A randomized executable loaded inside the fixed place.
        let mut taken = fresh();
        taken.see(base + 0x0b3c_6000, base + 0x0b3c_6000 + (2 << 20));
        assert_eq!(taken.choice(), (false, Some(base - size)));
        // A mapping inside a place, or just below one (no room for a heap
        // to grow up to it), rules it out.
        taken.see(base - size - 4096, base - size);
        assert_eq!(taken.choice(), (false, Some(base + 2 * size)));
    }

    #[test]
    fn an_unreadable_mapping_list_places_no_region() {
        let (size, top) = (1usize << 30, 1usize << 47);
        let fresh = || Candidates::new(top / 4 * 3, size, top / 2, top - top / 8);
        assert_eq!(choose(fresh(), |_| true, || true), Ok(top / 4 * 3));
        assert!(choose(fresh(), |_| false, || true).is_err());
        assert!(choose(fresh(), |_| false, || false).is_err());
    }

    #[test]
    fn the_hosts_mappings_are_read_without_allocating() {
        let page = 4096usize;
        let flags = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as usize;
        let mapped = host(Syscall::N_mmap, [0, page, 0, flags, usize::MAX, 0]) as usize;
        let mut seen = false;
        assert!(each_mapping(
            &mut |start, end| seen |= start <= mapped && mapped < end
        ));
        host(Syscall::N_munmap, [mapped, page, 0, 0, 0, 0]);
        assert!(seen);
    }

    #[test]
    fn a_guest_heap_block_is_not_the_arenas() {
        let block = Box::new(0u64);
        assert!(!contains(&*block as *const u64 as *const u8));
    }
}
