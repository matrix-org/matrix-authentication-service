// Copyright 2022 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::ops::Deref;

use futures_util::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::ProxyProtocolV1Info;

// Max theorical size we need is 108 for proxy protocol v1
const BUF_SIZE: usize = 256;

#[derive(Debug)]
enum ProxyStreamState {
    Handshaking {
        buffer: [u8; BUF_SIZE],
        index: usize,
    },
    Established(ProxyProtocolV1Info),
}

pin_project_lite::pin_project! {
    #[derive(Debug)]
    pub struct ProxyStream<S> {
        state: ProxyStreamState,

        #[pin]
        inner: S,
    }
}

impl<S> ProxyStream<S> {
    pub const fn new(inner: S) -> Self {
        Self {
            state: ProxyStreamState::Handshaking {
                buffer: [0; BUF_SIZE],
                index: 0,
            },
            inner,
        }
    }
}

impl<S> Deref for ProxyStream<S> {
    type Target = S;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<S> ProxyStream<S> {
    pub fn proxy_info(&self) -> Option<&ProxyProtocolV1Info> {
        match &self.state {
            ProxyStreamState::Handshaking { .. } => None,
            ProxyStreamState::Established(info) => Some(info),
        }
    }
}

impl<S> AsyncRead for ProxyStream<S>
where
    S: AsyncRead,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let proj = self.project();
        match proj.state {
            ProxyStreamState::Handshaking { buffer, index } => {
                let mut buffer = ReadBuf::new(&mut buffer[..]);
                buffer.advance(*index);
                ready!(proj.inner.poll_read(cx, &mut buffer))?;
                let filled = buffer.filled();
                *index = filled.len();

                match ProxyProtocolV1Info::parse(filled) {
                    Ok((info, rest)) => {
                        if buf.remaining() < rest.len() {
                            // This is highly unlikely, but is better than panicking later.
                            // If it ever happens, we could introduce a "buffer draining" state
                            // which drains the inner buffer repeatedly until it's empty
                            return std::task::Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "underlying buffer is too small",
                            )));
                        }
                        buf.put_slice(rest);
                        *proj.state = ProxyStreamState::Established(info);
                        std::task::Poll::Ready(Ok(()))
                    }
                    Err(e) if e.not_enough_bytes() => std::task::Poll::Ready(Ok(())),
                    Err(e) => std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e,
                    ))),
                }
            }
            ProxyStreamState::Established(_) => proj.inner.poll_read(cx, buf),
        }
    }
}

impl<S> AsyncWrite for ProxyStream<S>
where
    S: AsyncWrite,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let proj = self.project();
        match proj.state {
            // Hold off writes until the handshake is done
            // XXX: is this the right way to do it?
            ProxyStreamState::Handshaking { .. } => std::task::Poll::Pending,
            ProxyStreamState::Established(_) => proj.inner.poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_shutdown(cx)
    }
}
