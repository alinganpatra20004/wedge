// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! A socket wrapper that fails I/O once no bytes have moved in either
//! direction for the idle timeout. hyper's header timeout starts only when
//! the first byte of a request arrives, so without this a client that
//! connects and sends nothing would hold a connection slot forever
//! (threat model T2.5).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

pub(crate) struct IdleTimeout<S> {
    inner: S,
    timeout: Duration,
    sleep: Pin<Box<Sleep>>,
}

impl<S> IdleTimeout<S> {
    pub(crate) fn new(inner: S, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            sleep: Box::pin(tokio::time::sleep(timeout)),
        }
    }

    fn touch(&mut self) {
        self.sleep.as_mut().reset(Instant::now() + self.timeout);
    }

    /// Returns an error once the idle deadline has passed.
    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        match self.sleep.as_mut().poll(cx) {
            Poll::Ready(()) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connection idle timeout",
            )),
            Poll::Pending => Ok(()),
        }
    }
}

use std::future::Future;

impl<S: AsyncRead + Unpin> AsyncRead for IdleTimeout<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(result) => {
                if buf.filled().len() > before {
                    this.touch();
                }
                Poll::Ready(result)
            }
            Poll::Pending => {
                this.check(cx)?;
                Poll::Pending
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for IdleTimeout<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, data) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    this.touch();
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                this.check(cx)?;
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write_vectored(cx, bufs) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    this.touch();
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                this.check(cx)?;
                Poll::Pending
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn read_fails_after_idle_timeout() {
        let (client, server) = tokio::io::duplex(64);
        let mut wrapped = IdleTimeout::new(server, Duration::from_millis(100));
        let mut buf = [0u8; 8];
        let err = wrapped.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        drop(client);
    }

    #[tokio::test]
    async fn activity_resets_the_deadline() {
        let (mut client, server) = tokio::io::duplex(64);
        let mut wrapped = IdleTimeout::new(server, Duration::from_millis(300));
        let mut buf = [0u8; 1];
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(150)).await;
            client.write_all(b"x").await.unwrap();
            wrapped.read_exact(&mut buf).await.unwrap();
        }
    }
}
