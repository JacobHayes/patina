//! Everything the runtime (`rt`, no_std, inside every guest process) and the
//! launcher/supervisor (`patina`) must agree on: fixed addresses, hidden
//! descriptor numbers, the control region, the request protocol, the
//! stateless random draw, the boundary record with its hash, and the syscall
//! table as data.
#![no_std]

pub mod abi;
pub mod compute;
pub mod ctl;
pub mod draw;
pub mod faults;
pub mod insn;
pub mod layout;
pub mod nr;
pub mod oplog;
pub mod pmu;
pub mod rec;
pub mod sdk;
pub mod swap;
pub mod table;
pub mod vfs;
pub mod wire;

pub use ctl::{Config, Ctl, Op, Reply, Request, Slot};
pub use draw::{draw, fill, fill_from, Stream};
pub use rec::{Rec, RecKind};
pub use table::{row, Class, Group, Len, Out, Row, Strength};
