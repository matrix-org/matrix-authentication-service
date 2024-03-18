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

//! A [`Clock`] is a way to get the current date and time.
//!
//! This module defines two implemetation of the [`Clock`] trait:
//! [`SystemClock`] which uses the system time, and a [`MockClock`], which can
//! be used and freely manipulated in tests.

use std::sync::{atomic::AtomicI64, Arc};

use chrono::{DateTime, TimeZone, Utc};

/// Represents a clock which can give the current date and time
pub trait Clock: Sync {
    /// Get the current date and time
    fn now(&self) -> DateTime<Utc>;
}

impl<C: Clock + Send + ?Sized> Clock for Arc<C> {
    fn now(&self) -> DateTime<Utc> {
        (**self).now()
    }
}

impl<C: Clock + ?Sized> Clock for Box<C> {
    fn now(&self) -> DateTime<Utc> {
        (**self).now()
    }
}

/// A clock which uses the system time
#[derive(Clone, Default)]
pub struct SystemClock {
    _private: (),
}

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        // This is the clock used elsewhere, it's fine to call Utc::now here
        #[allow(clippy::disallowed_methods)]
        Utc::now()
    }
}

/// A fake clock, which uses a fixed timestamp, and can be advanced with the
/// [`MockClock::advance`] method.
///
/// ```rust
/// use mas_storage::clock::{Clock, MockClock};
/// use chrono::Duration;
///
/// let clock = MockClock::default();
/// let t1 = clock.now();
/// let t2 = clock.now();
/// assert_eq!(t1, t2);
///
/// clock.advance(Duration::microseconds(10 * 1000 * 1000));
/// let t3 = clock.now();
/// assert_eq!(t2 + Duration::microseconds(10 * 1000 * 1000), t3);
/// ```
pub struct MockClock {
    timestamp: AtomicI64,
}

impl Default for MockClock {
    fn default() -> Self {
        let datetime = Utc.with_ymd_and_hms(2022, 1, 16, 14, 40, 0).unwrap();
        Self::new(datetime)
    }
}

impl MockClock {
    /// Create a new clock which starts at the given datetime
    #[must_use]
    pub fn new(datetime: DateTime<Utc>) -> Self {
        let timestamp = AtomicI64::new(datetime.timestamp());
        Self { timestamp }
    }

    /// Move the clock forward by the given amount of time
    pub fn advance(&self, duration: chrono::Duration) {
        self.timestamp
            .fetch_add(duration.num_seconds(), std::sync::atomic::Ordering::Relaxed);
    }
}

impl Clock for MockClock {
    fn now(&self) -> DateTime<Utc> {
        let timestamp = self.timestamp.load(std::sync::atomic::Ordering::Relaxed);
        chrono::TimeZone::timestamp_opt(&Utc, timestamp, 0).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    #[test]
    fn test_mocked_clock() {
        let clock = MockClock::default();

        // Time should be frozen, and give out the same timestamp on each call
        let first = clock.now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let second = clock.now();

        assert_eq!(first, second);

        // Clock can be advanced by a fixed duration
        clock.advance(Duration::microseconds(10 * 1000 * 1000));
        let third = clock.now();
        assert_eq!(first + Duration::microseconds(10 * 1000 * 1000), third);
    }

    #[test]
    fn test_real_clock() {
        let clock = SystemClock::default();

        // Time should not be frozen
        let first = clock.now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let second = clock.now();

        assert_ne!(first, second);
        assert!(first < second);
    }
}
