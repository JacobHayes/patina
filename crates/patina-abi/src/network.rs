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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Operation, Outcome, TaskId};

    #[test]
    fn timer_delivery_and_tcp_operations_round_trip() {
        let operations = [
            Operation::TaskParkTimed {
                task: TaskId(4),
                reason: "cond-timedwait".into(),
                deadline_nanos: 1_000,
            },
            Operation::NetNextDelivery {
                socket: SocketId(2),
                now_nanos: 42,
            },
            Operation::NetTcpListen {
                address: "127.0.0.1:80".into(),
                backlog: 4,
            },
            Operation::NetTcpAccept {
                listener: SocketId(3),
                now_nanos: 43,
            },
            Operation::NetTcpConnect {
                address: "127.0.0.1:49152".into(),
                to: "127.0.0.1:80".into(),
                now_nanos: 44,
            },
            Operation::NetTcpSend {
                socket: SocketId(5),
                bytes: b"ping".to_vec(),
                now_nanos: 45,
            },
            Operation::NetTcpRecv {
                socket: SocketId(6),
                max_len: 16,
                now_nanos: 46,
            },
            Operation::NetTcpShutdown {
                socket: SocketId(5),
                how: ShutdownHow::Write,
            },
        ];
        for operation in operations {
            let json = serde_json::to_string(&operation).unwrap();
            assert!(json.contains("\"kind\""));
            assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), operation);
        }
        let outcomes = [
            Outcome::OptionalU64(Some(7)),
            Outcome::OptionalU64(None),
            Outcome::TcpAccepted(None),
            Outcome::TcpAccepted(Some(TcpAccepted {
                socket: SocketId(6),
                peer: "127.0.0.1:49152".into(),
            })),
            Outcome::OptionalBytes(None),
            Outcome::OptionalBytes(Some(Vec::new())),
            Outcome::OptionalBytes(Some(b"pong".to_vec())),
        ];
        for outcome in outcomes {
            let json = serde_json::to_string(&outcome).unwrap();
            assert_eq!(serde_json::from_str::<Outcome>(&json).unwrap(), outcome);
        }
    }
}
