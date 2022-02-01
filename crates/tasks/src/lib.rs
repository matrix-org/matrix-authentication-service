// Copyright 2021 The Matrix.org Foundation C.I.C.
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

//! Generic, sequential task scheduler
//!
//! Tasks here are ran one after another to avoid having to unnecesarily lock
//! resources and avoid database conflicts. Tasks are not persisted, which is
//! considered "good enough" for now.

#![forbid(unsafe_code)]
#![deny(clippy::all, missing_docs, rustdoc::broken_intra_doc_links)]
#![warn(clippy::pedantic)]

use std::{collections::VecDeque, sync::Arc, time::Duration};

use futures_util::StreamExt;
use tokio::{
    sync::{Mutex, Notify},
    time::Interval,
};
use tokio_stream::wrappers::IntervalStream;
use tracing::debug;

mod database;

pub use self::database::cleanup_expired;

/// A [`Task`] can be executed by a [`TaskQueue`]
#[async_trait::async_trait]
pub trait Task: std::fmt::Debug + Send + Sync + 'static {
    /// Execute the [`Task`]
    async fn run(&self);
}

#[derive(Default)]
struct TaskQueueInner {
    pending_tasks: Mutex<VecDeque<Box<dyn Task>>>,
    notifier: Notify,
}

impl TaskQueueInner {
    async fn recuring<T: Task + Clone>(&self, interval: Interval, task: T) {
        let mut stream = IntervalStream::new(interval);

        while (stream.next()).await.is_some() {
            self.schedule(task.clone()).await;
        }
    }

    async fn schedule<T: Task>(&self, task: T) {
        let task = Box::new(task);
        self.pending_tasks.lock().await.push_back(task);
        self.notifier.notify_one();
    }

    async fn tick(&self) {
        loop {
            let pending = {
                let mut tasks = self.pending_tasks.lock().await;
                tasks.pop_front()
            };

            if let Some(pending) = pending {
                pending.run().await;
            } else {
                break;
            }
        }
    }

    async fn run_forever(&self) {
        loop {
            self.notifier.notified().await;
            self.tick().await;
        }
    }
}

/// A [`TaskQueue`] executes tasks inserted in it in order
#[derive(Default)]
pub struct TaskQueue {
    inner: Arc<TaskQueueInner>,
}

impl TaskQueue {
    /// Start the task queue to run forever
    pub fn start(&self) {
        let queue = self.inner.clone();
        tokio::task::spawn(async move {
            queue.run_forever().await;
        });
    }

    #[allow(dead_code)]
    async fn schedule<T: Task>(&self, task: T) {
        let queue = self.inner.clone();
        queue.schedule(task).await;
    }

    /// Schedule a task in the queue at regular intervals
    pub fn recuring(&self, every: Duration, task: impl Task + Clone + std::fmt::Debug) {
        debug!(?task, period = every.as_secs(), "Scheduling recuring task");
        let queue = self.inner.clone();
        tokio::task::spawn(async move {
            queue.recuring(tokio::time::interval(every), task).await;
        });
    }
}
