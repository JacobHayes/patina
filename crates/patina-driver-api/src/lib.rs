//! Narrow data-plane interfaces implemented by deterministic drivers.
//!
//! Concrete drivers keep rich builders in their own crates. These traits only
//! describe effects required by the runtime boundary.

use patina_dst_abi::{ClockKind, EffectError};

mod address;
mod faults;
mod filesystem;
mod network;
mod scheduler;

pub use address::{
    ANY_FAMILY_HOST, InterfaceIpv4, NetInterface, VIRTUAL_INTERFACES, WILDCARD_HOST,
    WILDCARD_V6_HOST, canonicalize_path, datagram_source, local_ipv4, local_ipv6, source_address,
    wildcard_bind_keys,
};
pub use faults::{
    ClockFaultReport, CustomOpFaultReport, DnsFaultReport, EMPTY_OP_BREAKDOWN, EntropyFaultReport,
    FsFaultOpKind, FsFaultReport, FsOpCounts, NetFaultReport, VACUITY_MIN_EXPECTED_FIRES,
    epoch_jump_vacuity_is_diagnosable, range_vacuity_is_diagnosable, vacuity_is_diagnosable,
};
pub use filesystem::{FsDriver, XattrNamespace, xattr_permission};
pub use network::{NetDriver, NetReadiness};
pub use scheduler::{SchedulePolicyReport, SchedulerDriver};

pub type DriverResult<T> = Result<T, EffectError>;

pub trait ClockDriver: Send {
    fn now(&mut self, clock: ClockKind) -> DriverResult<u64>;
    fn sleep_until(&mut self, clock: ClockKind, deadline_nanos: u64) -> DriverResult<()>;
}

pub trait EntropyDriver: Send {
    fn fill(&mut self, destination: &mut [u8]) -> DriverResult<()>;
}
