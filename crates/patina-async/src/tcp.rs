//! Async TCP listeners, streams, and their simulated-network futures.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use patina_dst_abi::{ShutdownHow, SocketId};
use patina_dst_runtime::RuntimeError;

use crate::executor::{NetInterestKind, invalid_state, with_scope};

const REASON_TCP_ACCEPT: &str = "tcp-accept";
const REASON_TCP_RECV: &str = "tcp-recv";
const REASON_TCP_SEND: &str = "tcp-send";

/// A deterministic virtual TCP listener.
///
/// Dropping a listener records no boundary operation. Use explicit protocol
/// shutdown on accepted streams when close semantics matter.
///
/// ```
/// use patina_dst_async::{block_on, TcpListener, TcpStream};
/// use patina_dst_runtime::{run, RuntimeError};
///
/// run(|ctx| {
///     block_on(ctx, async {
///         let listener = TcpListener::listen("server", 4).await?;
///         let client = TcpStream::connect("client", "server").await?;
///         let peer = listener.accept().await?;
///         client.write_all(b"ping").await?;
///         assert_eq!(peer.read(64).await?, b"ping");
///         Ok::<_, RuntimeError>(())
///     })?
/// })?;
/// # Ok::<(), RuntimeError>(())
/// ```
#[derive(Clone, Debug)]
pub struct TcpListener {
    socket: SocketId,
    address: String,
}

impl TcpListener {
    pub fn listen(address: &str, backlog: usize) -> ListenFuture {
        ListenFuture {
            address: address.into(),
            backlog,
            done: false,
        }
    }

    pub fn accept(&self) -> AcceptFuture {
        AcceptFuture {
            listener: self.socket,
            address: self.address.clone(),
        }
    }
}

pub struct ListenFuture {
    address: String,
    backlog: usize,
    done: bool,
}

impl Future for ListenFuture {
    type Output = Result<TcpListener, RuntimeError>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        if self.done {
            return Poll::Ready(Err(invalid_state(
                "TcpListener::listen polled after completion",
            )));
        }
        self.done = true;
        let result = with_scope(|scope| {
            // SAFETY: the scope is live for this poll on the executor thread.
            let socket =
                unsafe { scope.context_mut() }.net_tcp_listen(&self.address, self.backlog)?;
            Ok(TcpListener {
                socket,
                address: self.address.clone(),
            })
        });
        Poll::Ready(result)
    }
}

pub struct AcceptFuture {
    listener: SocketId,
    address: String,
}

impl Future for AcceptFuture {
    type Output = Result<TcpStream, RuntimeError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let result = with_scope(|scope| {
            // SAFETY: the scope is live for this poll on the executor thread.
            match unsafe { scope.context_mut() }.net_tcp_accept(this.listener)? {
                Some(accepted) => Ok(Some(TcpStream {
                    socket: accepted.socket,
                    local_addr: this.address.clone(),
                    peer_addr: accepted.peer,
                })),
                None => {
                    scope.register_interest(
                        NetInterestKind::Accept,
                        this.address.clone(),
                        REASON_TCP_ACCEPT,
                    );
                    Ok(None)
                }
            }
        });
        match result {
            Ok(Some(stream)) => Poll::Ready(Ok(stream)),
            Ok(None) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

/// A deterministic virtual TCP stream.
///
/// Dropping a stream records no boundary operation; call [`TcpStream::shutdown`]
/// when deterministic close/EOF behavior matters.
#[derive(Clone, Debug)]
pub struct TcpStream {
    socket: SocketId,
    local_addr: String,
    peer_addr: String,
}

impl TcpStream {
    pub fn connect(address: &str, to: &str) -> ConnectFuture {
        ConnectFuture {
            address: address.into(),
            to: to.into(),
            done: false,
        }
    }

    pub fn read(&self, max_len: usize) -> ReadFuture {
        ReadFuture {
            socket: self.socket,
            local_addr: self.local_addr.clone(),
            peer_addr: self.peer_addr.clone(),
            max_len,
        }
    }

    pub fn write_all<'a>(&self, bytes: &'a [u8]) -> WriteAllFuture<'a> {
        WriteAllFuture {
            socket: self.socket,
            local_addr: self.local_addr.clone(),
            peer_addr: self.peer_addr.clone(),
            bytes,
            offset: 0,
        }
    }

    pub fn shutdown(&self, how: ShutdownHow) -> ShutdownFuture {
        ShutdownFuture {
            socket: self.socket,
            peer_addr: self.peer_addr.clone(),
            how,
            done: false,
        }
    }
}

pub struct ConnectFuture {
    address: String,
    to: String,
    done: bool,
}

impl Future for ConnectFuture {
    type Output = Result<TcpStream, RuntimeError>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        if self.done {
            return Poll::Ready(Err(invalid_state(
                "TcpStream::connect polled after completion",
            )));
        }
        self.done = true;
        let result = with_scope(|scope| {
            // SAFETY: the scope is live for this poll on the executor thread.
            let socket = unsafe { scope.context_mut() }.net_tcp_connect(&self.address, &self.to)?;
            // SAFETY: the executor pointer is valid for this poll.
            unsafe { scope.executor_mut() }.wake_waiters(NetInterestKind::Accept, &self.to);
            Ok(TcpStream {
                socket,
                local_addr: self.address.clone(),
                peer_addr: self.to.clone(),
            })
        });
        Poll::Ready(result)
    }
}

pub struct ReadFuture {
    socket: SocketId,
    local_addr: String,
    peer_addr: String,
    max_len: usize,
}

impl Future for ReadFuture {
    type Output = Result<Vec<u8>, RuntimeError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let result = with_scope(|scope| {
            // SAFETY: the scope is live for this poll on the executor thread.
            match unsafe { scope.context_mut() }.net_tcp_recv(this.socket, this.max_len)? {
                Some(bytes) => {
                    if !bytes.is_empty() {
                        // SAFETY: the executor pointer is valid for this poll.
                        unsafe { scope.executor_mut() }
                            .wake_waiters(NetInterestKind::Send, &this.peer_addr);
                    }
                    Ok(Some(bytes))
                }
                None => {
                    scope.register_interest(
                        NetInterestKind::Recv,
                        this.local_addr.clone(),
                        REASON_TCP_RECV,
                    );
                    // SAFETY: the scope is live for this poll on the executor thread.
                    if let Some(deadline) =
                        unsafe { scope.context_mut() }.net_next_delivery(this.socket)?
                    {
                        scope.register_deadline(deadline, REASON_TCP_RECV);
                    }
                    Ok(None)
                }
            }
        });
        match result {
            Ok(Some(bytes)) => Poll::Ready(Ok(bytes)),
            Ok(None) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

pub struct WriteAllFuture<'a> {
    socket: SocketId,
    local_addr: String,
    peer_addr: String,
    bytes: &'a [u8],
    offset: usize,
}

impl Future for WriteAllFuture<'_> {
    type Output = Result<(), RuntimeError>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let result = with_scope(|scope| {
            while self.offset < self.bytes.len() {
                // SAFETY: the scope is live for this poll on the executor thread.
                let accepted = unsafe { scope.context_mut() }
                    .net_tcp_send(self.socket, &self.bytes[self.offset..])?;
                if accepted == 0 {
                    scope.register_interest(
                        NetInterestKind::Send,
                        self.local_addr.clone(),
                        REASON_TCP_SEND,
                    );
                    return Ok(false);
                }
                self.offset += accepted;
                // SAFETY: the executor pointer is valid for this poll.
                unsafe { scope.executor_mut() }
                    .wake_waiters(NetInterestKind::Recv, &self.peer_addr);
            }
            Ok(true)
        });
        match result {
            Ok(true) => Poll::Ready(Ok(())),
            Ok(false) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

pub struct ShutdownFuture {
    socket: SocketId,
    peer_addr: String,
    how: ShutdownHow,
    done: bool,
}

impl Future for ShutdownFuture {
    type Output = Result<(), RuntimeError>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        if self.done {
            return Poll::Ready(Err(invalid_state(
                "TcpStream::shutdown polled after completion",
            )));
        }
        self.done = true;
        let result = with_scope(|scope| {
            // SAFETY: the scope is live for this poll on the executor thread.
            unsafe { scope.context_mut() }.net_tcp_shutdown(self.socket, self.how)?;
            // SAFETY: the executor pointer is valid for this poll.
            let executor = unsafe { scope.executor_mut() };
            executor.wake_waiters(NetInterestKind::Recv, &self.peer_addr);
            executor.wake_waiters(NetInterestKind::Send, &self.peer_addr);
            Ok(())
        });
        Poll::Ready(result)
    }
}

#[cfg(test)]
mod tests;
