//! Unit tests for this module and its focused submodules.

use super::*;

fn perm() -> Perm {
    Perm::new(IPC_PRIVATE, 0o600)
}

#[test]
fn ids_advance_cyclically_and_a_removed_id_stays_invalid() {
    let mut space: Space<()> = Space::new(3);
    let first = space.add(perm(), ()).unwrap();
    let second = space.add(perm(), ()).unwrap();
    assert_eq!((first, second), (0, 1));
    assert!(space.remove(first).is_some());
    // The next index after the last one handed out, not the freed one.
    assert_eq!(space.add(perm(), ()).unwrap(), 2);
    // Wrapping reuses index 0 under the next sequence number.
    assert_eq!(space.add(perm(), ()).unwrap(), IPCMNI);
    assert_eq!(space.add(perm(), ()), Err(ENOSPC));
    assert_eq!(space.get(first).err(), Some(EINVAL));
    assert!(space.get(IPCMNI).is_ok());
}

#[test]
fn ids_cycle_within_the_window_in_use_sets() {
    let mut space: Space<()> = Space::new(SEMMNI);
    for expected in 0..IPC_MIN_CYCLE {
        let id = space.add(perm(), ()).unwrap();
        assert_eq!(id, expected);
        space.remove(id).unwrap();
    }
    // Few objects in use: the index wraps at 64, not at the limit.
    assert_eq!(space.add(perm(), ()).unwrap(), IPCMNI);
}

fn set(values: &[i32]) -> SemSet {
    SemSet {
        sems: values.iter().map(|value| (*value, 0)).collect(),
        adjust: vec![0; values.len()],
        undo: false,
        otime: 0,
        ctime: 0,
        pending: WaitQueue::new(),
    }
}

fn op(num: u16, op: i16, flg: i16) -> Sembuf {
    Sembuf { num, op, flg }
}

#[test]
fn semaphore_operations_apply_all_or_none_in_order() {
    let mut sems = set(&[1, 0]);
    // The second operation blocks, so the first is not applied.
    assert!(matches!(
        perform(&mut sems, &[op(0, -1, 0), op(1, -1, 0)]),
        Err(Refused::Block(1))
    ));
    assert_eq!(sems.sems[0].0, 1);
    assert!(matches!(
        perform(&mut sems, &[op(1, -1, IPC_NOWAIT as i16)]),
        Err(Refused::Errno(EAGAIN))
    ));
    // Operations on one semaphore apply in sequence.
    assert!(perform(&mut sems, &[op(1, 2, 0), op(1, -1, 0)]).is_ok());
    assert_eq!(sems.sems[1], (1, PID));
    assert!(matches!(
        perform(&mut sems, &[op(0, SEMVMX as i16, 0)]),
        Err(Refused::Errno(ERANGE))
    ));
    assert!(matches!(
        perform(&mut sems, &[op(1, 0, 0)]),
        Err(Refused::Block(0))
    ));
}

#[test]
fn a_blocked_operation_is_completed_by_the_one_that_allows_it() {
    let mut sems = set(&[0]);
    let waiter = SemWaiter {
        task: TaskId(7),
        ops: vec![op(0, -1, 0)],
        blocking: 0,
        alter: true,
    };
    let loc = WaiterLoc::Ipc(IpcWait::Sem(0));
    Wait::new(BlockClass::Ipc, vec![]).enqueue(&mut sems.pending, waiter, loc);
    let mut outcomes = BTreeMap::new();
    assert!(update_queue(&mut sems, &mut outcomes).is_empty());
    sems.sems[0].0 = 1;
    assert_eq!(update_queue(&mut sems, &mut outcomes), vec![TaskId(7)]);
    assert!(matches!(outcomes.get(&TaskId(7)), Some(Outcome::Done(0))));
    assert_eq!(sems.sems[0].0, 0);
    assert!(sems.pending.is_empty());
}

#[test]
fn a_receive_selects_by_type_as_find_msg_does() {
    let mut queue = MsgQueue {
        messages: VecDeque::new(),
        cbytes: 0,
        qbytes: MSGMNB,
        stime: 0,
        rtime: 0,
        ctime: 0,
        lspid: 0,
        lrpid: 0,
        receivers: WaitQueue::new(),
        senders: WaitQueue::new(),
    };
    for mtype in [3, 2, 1, 2] {
        queue.messages.push_back(Message {
            mtype,
            text: Vec::new(),
        });
    }
    assert_eq!(queue.find(0, Search::Any), Some(0));
    assert_eq!(queue.find(2, Search::Equal), Some(1));
    assert_eq!(queue.find(3, Search::NotEqual), Some(1));
    // The first of the lowest type not above 2.
    assert_eq!(queue.find(2, Search::LessEqual), Some(2));
    assert_eq!(queue.find(5, Search::Equal), None);
    assert!(queue.fits(MSGMNB));
    assert!(!queue.fits(MSGMNB + 1));
}
