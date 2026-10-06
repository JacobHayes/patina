//! Generated syscall dispatch indexing and refusal paths.

use super::*;

/// "No row" / "no binding" sentinel in the dispatch index.
pub(super) const NONE: u16 = u16::MAX;
/// The dispatch index covers numbers below this bound; the vendored tables top
/// out well under it (x86_64 at 472), and a number at or above it is answered
/// as "not in the vendored table" without consulting the index.
pub(super) const INDEX_LEN: usize = 1024;

/// The compile-time dispatch index for this arch: number → row, row → binding.
struct Dispatch {
    row_for_nr: [u16; INDEX_LEN],
    binding_for_row: [u16; SYSCALLS.len()],
}

const DISPATCH: Dispatch = build_dispatch();

/// Build [`DISPATCH`] from the registry rows for the host arch. Every check
/// here is a compile error, which is what makes the registry the single source
/// of dispatch: a row cannot claim `Modeled` without a handler, a `Trap` row
/// cannot carry one, and a binding cannot name a row that does not exist.
const fn build_dispatch() -> Dispatch {
    let mut row_for_nr = [NONE; INDEX_LEN];
    let mut binding_for_row = [NONE; SYSCALLS.len()];
    let mut i = 0;
    while i < SYSCALLS.len() {
        let row = &SYSCALLS[i];
        let mut bound = NONE;
        let mut j = 0;
        while j < BINDINGS.len() {
            if BINDINGS[j].0 as usize == row.id as usize {
                if bound != NONE {
                    panic!("a registry row has two handler bindings in sud::BINDINGS");
                }
                bound = j as u16;
            }
            j += 1;
        }
        if row.disposition.is_routed() && bound == NONE {
            panic!("a Modeled/Passthrough registry row has no handler binding in sud::BINDINGS");
        }
        if !row.disposition.may_bind() && bound != NONE {
            panic!("a Trap/Absent registry row has a handler binding in sud::BINDINGS");
        }
        binding_for_row[i] = bound;
        {
            let nr = row.id.number();
            let nr = nr as usize;
            if nr >= INDEX_LEN {
                panic!("a registry row's syscall number exceeds sud::INDEX_LEN");
            }
            if row_for_nr[nr] != NONE {
                panic!("two registry rows share a syscall number on this arch");
            }
            row_for_nr[nr] = i as u16;
        }
        i += 1;
    }
    let mut j = 0;
    while j < BINDINGS.len() {
        let mut found = false;
        let mut i = 0;
        while i < SYSCALLS.len() {
            if SYSCALLS[i].id as usize == BINDINGS[j].0 as usize {
                found = true;
            }
            i += 1;
        }
        if !found {
            panic!("a sud::BINDINGS entry names a syscall that has no registry row");
        }
        j += 1;
    }
    Dispatch {
        row_for_nr,
        binding_for_row,
    }
}

/// The registry row a number resolves to on this arch, if the vendored table
/// lists it.
pub(super) fn row_for(nr: i64) -> Option<(usize, &'static SyscallRow)> {
    let index = usize::try_from(nr).ok().filter(|nr| *nr < INDEX_LEN)?;
    let row = DISPATCH.row_for_nr[index];
    (row != NONE).then(|| (row as usize, &SYSCALLS[row as usize]))
}

pub(super) fn dispatch(nr: i64, args: [u64; 6]) -> i64 {
    let Some((index, row)) = row_for(nr) else {
        return not_in_table(nr, args);
    };
    let binding = DISPATCH.binding_for_row[index];
    let bound = (binding != NONE).then(|| BINDINGS[binding as usize].1);
    match (row.disposition, bound) {
        (Disposition::Modeled | Disposition::Passthrough, Some(handler)) => handler(nr, args),
        // A routed row always has a binding: `build_dispatch` refused to compile
        // otherwise. Unreachable by construction, and still a loud abort rather
        // than a silent answer if that ever stopped being true.
        (Disposition::Modeled | Disposition::Passthrough, None) => {
            crate::trap_fatal("SUD dispatch: a routed registry row has no handler binding")
        }
        // A bound handler answers a constant/soft-deny row (it may print the
        // shared deny diagnostic first); an unbound one is answered from the row.
        (Disposition::Constant(_) | Disposition::SoftDeny(_), Some(handler)) => handler(nr, args),
        (Disposition::Constant(value), None) => value,
        (Disposition::SoftDeny(errno), None) => -(errno as i64),
        (Disposition::Trap(class), _) => trap_row(row, class, nr, args),
        (Disposition::Absent, _) => -ENOSYS,
    }
}

/// A number the registry dispositions as a named, deterministic abort. The
/// diagnostic carries the row's name, class, and reasoning, so the guest's
/// stderr says exactly why the number is excluded and what closes it.
fn trap_row(row: &SyscallRow, class: &str, nr: i64, args: [u64; 6]) -> i64 {
    let closes = match row.closes_in {
        Some(arc) => format!(" Closes in the {arc} arc."),
        None => String::new(),
    };
    crate::trap_fatal(&format!(
        "SUD trapped unsupported syscall {} (nr {nr}, class {class}; args {:#x} {:#x} {:#x} {:#x} \
         {:#x} {:#x}): {}{closes} Guest raw syscalls must map to a deterministic route; `cargo \
         patina syscalls` lists every row",
        row.name, args[0], args[1], args[2], args[3], args[4], args[5], row.reasoning
    ));
}

/// A number the vendored table for this arch does not list at all: either
/// newer than the vendored snapshot (refresh the tables and add its row) or
/// garbage in the syscall register. Distinct from a trapped row, which is a
/// deliberate disposition.
fn not_in_table(nr: i64, args: [u64; 6]) -> i64 {
    crate::trap_fatal(&format!(
        "SUD trapped syscall number {nr}, which is not in the vendored Linux {} syscall table \
         (args {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}); run scripts/refresh-syscalls.py and \
         add a registry row if the kernel has grown a number, or treat this as a corrupt raw \
         syscall",
        Arch::host().name(),
        args[0],
        args[1],
        args[2],
        args[3],
        args[4],
        args[5]
    ));
}
