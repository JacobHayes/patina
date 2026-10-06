//! Async UDP sockets and their simulated-network futures.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use patina_dst_abi::{Datagram, SendReport, SocketId};
use patina_dst_runtime::RuntimeError;

use crate::executor::{NetInterestKind, invalid_state, with_scope};

const REASON_NET_RECV: &str = "net-recv";

/// A deterministic virtual UDP socket.
///
/// Dropping a socket records no boundary operation. Packets already sent remain
/// governed by the virtual network driver.
#[derive(Clone, Debug)]
pub struct UdpSocket {
    socket: SocketId,
    address: String,
}

impl UdpSocket {
    pub fn bind(address: &str) -> UdpBindFuture {
        UdpBindFuture {
            address: address.into(),
            done: false,
        }
    }

    pub fn send_to<'a>(&self, to: &str, bytes: &'a [u8]) -> UdpSendToFuture<'a> {
        UdpSendToFuture {
            socket: self.socket,
            to: to.into(),
            bytes,
            done: false,
        }
    }

    pub fn recv(&self) -> UdpRecvFuture {
        UdpRecvFuture {
            socket: self.socket,
            address: self.address.clone(),
        }
    }
}

pub struct UdpBindFuture {
    address: String,
    done: bool,
}

impl Future for UdpBindFuture {
    type Output = Result<UdpSocket, RuntimeError>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        if self.done {
            return Poll::Ready(Err(invalid_state(
                "UdpSocket::bind polled after completion",
            )));
        }
        self.done = true;
        let result = with_scope(|scope| {
            // SAFETY: the scope is live for this poll on the executor thread.
            let socket = unsafe { scope.context_mut() }.net_bind(&self.address)?;
            Ok(UdpSocket {
                socket,
                address: self.address.clone(),
            })
        });
        Poll::Ready(result)
    }
}

pub struct UdpSendToFuture<'a> {
    socket: SocketId,
    to: String,
    bytes: &'a [u8],
    done: bool,
}

impl Future for UdpSendToFuture<'_> {
    type Output = Result<SendReport, RuntimeError>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        if self.done {
            return Poll::Ready(Err(invalid_state(
                "UdpSocket::send_to polled after completion",
            )));
        }
        self.done = true;
        let result = with_scope(|scope| {
            // SAFETY: the scope is live for this poll on the executor thread.
            let report =
                unsafe { scope.context_mut() }.net_send(self.socket, &self.to, self.bytes)?;
            // SAFETY: the executor pointer is valid for this poll.
            unsafe { scope.executor_mut() }.wake_waiters(NetInterestKind::Recv, &self.to);
            Ok(report)
        });
        Poll::Ready(result)
    }
}

pub struct UdpRecvFuture {
    socket: SocketId,
    address: String,
}

impl Future for UdpRecvFuture {
    type Output = Result<Datagram, RuntimeError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let result = with_scope(|scope| {
            // SAFETY: the scope is live for this poll on the executor thread.
            match unsafe { scope.context_mut() }.net_recv(this.socket)? {
                Some(datagram) => Ok(Some(datagram)),
                None => {
                    scope.register_interest(
                        NetInterestKind::Recv,
                        this.address.clone(),
                        REASON_NET_RECV,
                    );
                    // SAFETY: the scope is live for this poll on the executor thread.
                    if let Some(deadline) =
                        unsafe { scope.context_mut() }.net_next_delivery(this.socket)?
                    {
                        scope.register_deadline(deadline, REASON_NET_RECV);
                    }
                    Ok(None)
                }
            }
        });
        match result {
            Ok(Some(datagram)) => Poll::Ready(Ok(datagram)),
            Ok(None) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

#[cfg(test)]
mod tests;
