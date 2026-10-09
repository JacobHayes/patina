//! Charging guest calls never allocates: an embedder may charge from a signal
//! handler that interrupted the guest's allocator (the native counter trap).

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use patina_dst_abi::{ChargeClass, ChargeCounts, TaskId};
use patina_dst_runtime::{Context, RuntimeConfig};

/// Counts this thread's allocations while armed.
struct Counting;

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.with(Cell::get) {
            ALLOCATIONS.with(|count| count.set(count.get() + 1));
        }
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The allocations `body` makes on this thread.
fn allocations(body: impl FnOnce()) -> u64 {
    ALLOCATIONS.with(|count| count.set(0));
    ARMED.with(|armed| armed.set(true));
    body();
    ARMED.with(|armed| armed.set(false));
    ALLOCATIONS.with(Cell::get)
}

fn calls() -> ChargeCounts {
    let mut calls = ChargeCounts::new();
    calls.count(ChargeClass::Clock);
    calls.count(ChargeClass::Syscall);
    calls
}

#[test]
fn charging_a_spawned_reserved_or_unknown_task_never_allocates() {
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let spawned = context.task_spawn("spawned").unwrap();
    let reserved = Some(TaskId(40));
    context.reserve_charge(reserved);
    for task in [None, Some(spawned), reserved, Some(TaskId(99))] {
        assert_eq!(
            allocations(|| context.charge_calls(task, calls()).unwrap()),
            0,
            "charging {task:?} allocated"
        );
        // Again, now that the first charge has landed.
        assert_eq!(
            allocations(|| context.charge_calls(task, calls()).unwrap()),
            0
        );
    }
    // Many tasks the runtime does not know: a map that grew an entry per
    // task would outgrow its node and allocate.
    for id in 100..140 {
        assert_eq!(
            allocations(|| context.charge_calls(Some(TaskId(id)), calls()).unwrap()),
            0,
            "charging unknown task {id} allocated"
        );
    }
    // The unknown task's charge is kept, not lost, and not given an entry.
    assert_eq!(context.cpu_charge(Some(TaskId(99))), Default::default());
    let facts = context.run_facts();
    assert!(
        facts["cpu_charges"]["unreserved"]["system_ns"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(facts["cpu_charges"].get("task99").is_none());
}

#[test]
fn a_charge_before_its_tasks_reservation_stays_unreserved() {
    // Whether or not another task was charged in between, a reservation
    // does not adopt what was charged before it.
    for between in [false, true] {
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        let early = Some(TaskId(7));
        context.charge_calls(early, calls()).unwrap();
        if between {
            context.charge_calls(None, calls()).unwrap();
        }
        context.reserve_charge(early);
        context.charge_calls(early, calls()).unwrap();
        assert_eq!(
            context.cpu_charge(early),
            calls().charge(),
            "between={between}"
        );
        let facts = context.run_facts();
        assert_eq!(
            facts["cpu_charges"]["unreserved"]["system_ns"].as_u64(),
            Some(calls().charge().system_ns),
            "between={between}: {facts}"
        );
    }
}
