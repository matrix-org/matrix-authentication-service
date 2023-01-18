// Copyright 2021-2023 The Matrix.org Foundation C.I.C.
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

//! Interactions with the database

#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::str_to_string,
    clippy::future_not_send,
    rustdoc::broken_intra_doc_links
)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions
)]

use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Default)]
pub struct Clock {
    _private: (),

    // #[cfg(test)]
    mock: Option<std::sync::Arc<std::sync::atomic::AtomicI64>>,
}

impl Clock {
    #[must_use]
    pub fn now(&self) -> DateTime<Utc> {
        // #[cfg(test)]
        if let Some(timestamp) = &self.mock {
            let timestamp = timestamp.load(std::sync::atomic::Ordering::Relaxed);
            return chrono::TimeZone::timestamp_opt(&Utc, timestamp, 0).unwrap();
        }

        // This is the clock used elsewhere, it's fine to call Utc::now here
        #[allow(clippy::disallowed_methods)]
        Utc::now()
    }

    // #[cfg(test)]
    #[must_use]
    pub fn mock() -> Self {
        use std::sync::{atomic::AtomicI64, Arc};

        use chrono::TimeZone;

        let datetime = Utc.with_ymd_and_hms(2022, 1, 16, 14, 40, 0).unwrap();
        let timestamp = datetime.timestamp();

        Self {
            mock: Some(Arc::new(AtomicI64::new(timestamp))),
            _private: (),
        }
    }

    // #[cfg(test)]
    pub fn advance(&self, duration: chrono::Duration) {
        let timestamp = self
            .mock
            .as_ref()
            .expect("Clock::advance should only be called on mocked clocks in tests");
        timestamp.fetch_add(duration.num_seconds(), std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    #[test]
    fn test_mocked_clock() {
        let clock = Clock::mock();

        // Time should be frozen, and give out the same timestamp on each call
        let first = clock.now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let second = clock.now();

        assert_eq!(first, second);

        // Clock can be advanced by a fixed duration
        clock.advance(Duration::seconds(10));
        let third = clock.now();
        assert_eq!(first + Duration::seconds(10), third);
    }

    #[test]
    fn test_real_clock() {
        let clock = Clock::default();

        // Time should not be frozen
        let first = clock.now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let second = clock.now();

        assert_ne!(first, second);
        assert!(first < second);
    }
}

pub mod compat;
pub mod oauth2;
pub mod pagination;
pub(crate) mod repository;
pub mod upstream_oauth2;
pub mod user;

pub use self::{
    pagination::{Page, Pagination},
    repository::Repository,
};
