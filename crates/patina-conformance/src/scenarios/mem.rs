/// The gap of a scenario whose row `$row` the registry leaves
/// `Trap(unmodeled)`: the SUD dispatcher aborts by name at its first call,
/// after `$events` events, on every door in `$vehicles`.
macro_rules! unmodeled_trap {
    ($row:literal, $vehicles:expr, $events:expr) => {
        crate::catalog::Gap {
            status: crate::catalog::Status::Pending(crate::catalog::Arc::MemoryIpc),
            vehicles: $vehicles,
            what: concat!(
                $row,
                " is Trap(unmodeled) in the registry (patina-syscalls linux.rs), so the SUD dispatcher aborts by name on every door"
            ),
            failure: crate::compare::Failure::Stops {
                events: $events,
                ending: crate::compare::Ending::Signal(libc::SIGABRT),
                diagnostic: concat!("patina: SUD trapped unsupported syscall ", $row, " (nr"),
            },
        }
    };
}

pub mod brk;
mod fault;
pub mod membarrier;
pub mod memfd;
pub mod mincore;
pub mod mlock;
pub mod mmap;
pub mod mmap_file;
pub mod mremap;
pub mod msync;
pub mod numa;
pub mod pkeys;
pub mod process_madvise;
pub mod protect;
pub mod remap_file_pages;
pub mod secret;
pub mod shadow_stack;
pub mod userfaultfd;
