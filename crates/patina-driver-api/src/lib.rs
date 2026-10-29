//! Narrow data-plane interfaces implemented by deterministic drivers.
//!
//! Concrete drivers keep rich builders in their own crates. These traits only
//! describe effects required by the runtime boundary.

use patina_dst_abi::EffectError;

mod address;
mod faults;
mod filesystem;
mod network;

pub use address::{
    ANY_FAMILY_HOST, InterfaceIpv4, NetInterface, VIRTUAL_INTERFACES, WILDCARD_HOST,
    WILDCARD_V6_HOST, canonicalize_path, datagram_source, local_ipv4, local_ipv6, source_address,
    wildcard_bind_keys,
};
pub use faults::{
    ClockFaultReport, CustomOpFaultReport, DnsFaultReport, EMPTY_OP_BREAKDOWN, EntropyFaultReport,
    FsErrno, FsErrorTarget, FsFaultOpKind, FsFaultReport, FsOpCounts, NetFaultReport,
    VACUITY_MIN_EXPECTED_FIRES, epoch_jump_vacuity_is_diagnosable, range_vacuity_is_diagnosable,
    vacuity_is_diagnosable,
};
pub use filesystem::{FsDriver, XattrNamespace, xattr_permission};
pub use network::{NetDriver, NetReadiness};

pub type DriverResult<T> = Result<T, EffectError>;
