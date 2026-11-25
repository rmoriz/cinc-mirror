//! Bandwidth pacing.
//!
//! The limiter is a schedule, not a token bucket: each call reserves the next
//! slice of wall-clock time for its bytes and sleeps until that slice begins.
//! The first call of a transfer is therefore immediate and a 1 MiB transfer at
//! 1 MiB/s takes about a second, without accumulating a burst credit that a
//! later run could spend.
//!
//! Pacing happens after a chunk is written, in the transport copy loop, so a
//! cap slows a transfer instead of failing it. An unlimited limiter (the
//! configuration default `0`) never sleeps.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// A shared download bandwidth cap.
///
/// `None` (or a rate of zero) means unlimited. One limiter is shared by every
/// download of a run, so `concurrency` does not multiply the configured rate.
#[derive(Debug)]
pub struct RateLimiter {
    bytes_per_second: Option<u64>,
    next_slot: Mutex<Option<Instant>>,
}

impl RateLimiter {
    /// Build a limiter for `bytes_per_second`; `None` and `Some(0)` are
    /// unlimited.
    #[must_use]
    pub fn new(bytes_per_second: Option<u64>) -> Arc<Self> {
        Arc::new(Self {
            bytes_per_second: bytes_per_second.filter(|rate| *rate > 0),
            next_slot: Mutex::new(None),
        })
    }

    /// The configured cap, when one is set.
    #[must_use]
    pub fn bytes_per_second(&self) -> Option<u64> {
        self.bytes_per_second
    }

    /// Account for `bytes` and wait until this chunk's slot starts.
    ///
    /// The first call for a transfer returns immediately; each later call waits
    /// for the bytes already charged. A zero-byte charge is a no-op, so callers
    /// do not have to special-case empty reads.
    pub async fn consume(&self, bytes: u64) {
        let Some(rate) = self.bytes_per_second else {
            return;
        };
        if bytes == 0 {
            return;
        }

        let now = Instant::now();
        let wait_until = {
            let mut slot = lock(&self.next_slot);
            let start = match *slot {
                Some(next) if next > now => next,
                _ => now,
            };
            *slot = Some(start + transfer_time(bytes, rate));
            start
        };

        let delay = wait_until.saturating_duration_since(now);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
}

/// How long `bytes` take at `rate`, rounded up to whole nanoseconds.
fn transfer_time(bytes: u64, rate: u64) -> Duration {
    let seconds = bytes as f64 / rate as f64;
    Duration::from_secs_f64(seconds)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_and_none_are_unlimited() {
        assert_eq!(RateLimiter::new(None).bytes_per_second(), None);
        assert_eq!(RateLimiter::new(Some(0)).bytes_per_second(), None);
        assert_eq!(
            RateLimiter::new(Some(1_048_576)).bytes_per_second(),
            Some(1_048_576)
        );
    }

    #[test]
    fn transfer_time_is_proportional() {
        assert_eq!(
            transfer_time(1_048_576, 1_048_576),
            Duration::from_millis(1000)
        );
        assert_eq!(transfer_time(65_536, 1_048_576).as_micros(), 62_500);
    }

    #[tokio::test]
    async fn the_first_call_is_immediate() {
        let limiter = RateLimiter::new(Some(1024));
        let started = Instant::now();
        limiter.consume(1024).await;
        assert!(started.elapsed() < Duration::from_millis(200));
        limiter.consume(0).await;
    }
}
