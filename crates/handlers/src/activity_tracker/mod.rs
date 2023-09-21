// Copyright 2023 The Matrix.org Foundation C.I.C.
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

mod bound;
mod worker;

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use mas_data_model::{BrowserSession, CompatSession, Session};
use mas_storage::Clock;
use sqlx::PgPool;
use ulid::Ulid;

pub use self::bound::Bound;
use self::worker::Worker;

static MESSAGE_QUEUE_SIZE: usize = 1000;

#[derive(Clone, Copy, Debug, PartialOrd, PartialEq, Eq, Hash)]
enum SessionKind {
    OAuth2,
    Compat,
    Browser,
}

impl SessionKind {
    const fn as_str(self) -> &'static str {
        match self {
            SessionKind::OAuth2 => "oauth2",
            SessionKind::Compat => "compat",
            SessionKind::Browser => "browser",
        }
    }
}

enum Message {
    Record {
        kind: SessionKind,
        id: Ulid,
        date_time: DateTime<Utc>,
        ip: Option<IpAddr>,
    },
    Flush(tokio::sync::oneshot::Sender<()>),
    Shutdown(tokio::sync::oneshot::Sender<()>),
}

#[derive(Clone)]
pub struct ActivityTracker {
    channel: tokio::sync::mpsc::Sender<Message>,
}

impl ActivityTracker {
    /// Create a new activity tracker, spawning the worker.
    #[must_use]
    pub fn new(pool: PgPool, flush_interval: std::time::Duration) -> Self {
        let worker = Worker::new(pool);
        let (sender, receiver) = tokio::sync::mpsc::channel(MESSAGE_QUEUE_SIZE);
        let tracker = ActivityTracker { channel: sender };

        // Spawn the flush loop and the worker
        tokio::spawn(tracker.clone().flush_loop(flush_interval));
        tokio::spawn(worker.run(receiver));

        tracker
    }

    /// Bind the activity tracker to an IP address.
    #[must_use]
    pub fn bind(self, ip: Option<IpAddr>) -> Bound {
        Bound::new(self, ip)
    }

    /// Record activity in an OAuth 2.0 session.
    pub async fn record_oauth2_session(
        &self,
        clock: &dyn Clock,
        session: &Session,
        ip: Option<IpAddr>,
    ) {
        let res = self
            .channel
            .send(Message::Record {
                kind: SessionKind::OAuth2,
                id: session.id,
                date_time: clock.now(),
                ip,
            })
            .await;

        if let Err(e) = res {
            tracing::error!("Failed to record OAuth2 session: {}", e);
        }
    }

    /// Record activity in a compat session.
    pub async fn record_compat_session(
        &self,
        clock: &dyn Clock,
        compat_session: &CompatSession,
        ip: Option<IpAddr>,
    ) {
        let res = self
            .channel
            .send(Message::Record {
                kind: SessionKind::Compat,
                id: compat_session.id,
                date_time: clock.now(),
                ip,
            })
            .await;

        if let Err(e) = res {
            tracing::error!("Failed to record compat session: {}", e);
        }
    }

    /// Record activity in a browser session.
    pub async fn record_browser_session(
        &self,
        clock: &dyn Clock,
        browser_session: &BrowserSession,
        ip: Option<IpAddr>,
    ) {
        let res = self
            .channel
            .send(Message::Record {
                kind: SessionKind::Browser,
                id: browser_session.id,
                date_time: clock.now(),
                ip,
            })
            .await;

        if let Err(e) = res {
            tracing::error!("Failed to record browser session: {}", e);
        }
    }

    /// Manually flush the activity tracker.
    pub async fn flush(&self) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let res = self.channel.send(Message::Flush(tx)).await;

        match res {
            Ok(_) => {
                if let Err(e) = rx.await {
                    tracing::error!("Failed to flush activity tracker: {}", e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to flush activity tracker: {}", e);
            }
        }
    }

    /// Regularly flush the activity tracker.
    async fn flush_loop(self, interval: std::time::Duration) {
        loop {
            tokio::select! {
                biased;

                // First check if the channel is closed, then check if the timer expired
                _ = self.channel.closed() => {
                    // The channel was closed, so we should exit
                    break;
                }

                _ = tokio::time::sleep(interval) => {
                    self.flush().await;
                }
            }
        }
    }

    /// Shutdown the activity tracker.
    ///
    /// This will wait for all pending messages to be processed.
    pub async fn shutdown(&self) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let res = self.channel.send(Message::Shutdown(tx)).await;

        match res {
            Ok(_) => {
                if let Err(e) = rx.await {
                    tracing::error!("Failed to shutdown activity tracker: {}", e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to shutdown activity tracker: {}", e);
            }
        }
    }
}
