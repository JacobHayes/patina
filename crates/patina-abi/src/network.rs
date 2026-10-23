//! Datagram delivery, send reports, and TCP connection contracts.

use crate::{SocketId, bytes_base64};
use serde::{Deserialize, Serialize};

/// A datagram delivered by a virtual network.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Datagram {
    pub packet_id: u64,
    pub from: String,
    pub to: String,
    #[serde(with = "bytes_base64")]
    pub bytes: Vec<u8>,
    pub delivery_nanos: u64,
    /// The address the sender dialed: the header's destination, where `to`
    /// is the binding the datagram was queued under (a wildcard binding
    /// takes datagrams dialed at any local address).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub dialed: String,
    /// The type of service (IPv4) or traffic class (IPv6) the sender marked
    /// the datagram with.
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub tos: u8,
}

fn is_zero_u8(value: &u8) -> bool {
    *value == 0
}

/// Why a virtual send did or did not queue packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendDisposition {
    Queued,
    DroppedByFault,
    DroppedByPartition,
    /// Nothing is bound at the destination: the datagram is dropped, and the
    /// network answers the sender as a host's ICMP port-unreachable does.
    Unreachable,
}

/// Observable packet-lifecycle decisions made for one send.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendReport {
    pub written: usize,
    pub copies: usize,
    pub delivery_nanos: Vec<u64>,
    pub disposition: SendDisposition,
}

/// Directions closed by a virtual TCP shutdown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShutdownHow {
    Read,
    Write,
    Both,
}

/// One established connection handed to a virtual TCP accept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpAccepted {
    /// The acceptor-side stream endpoint.
    pub socket: SocketId,
    /// The connecting side's virtual address, e.g. "127.0.0.1:49152".
    pub peer: String,
}
