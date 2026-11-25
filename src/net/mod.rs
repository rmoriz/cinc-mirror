//! Network helpers shared by the source and target layers.
//!
//! Only pacing lives here so far: [`ratelimit::RateLimiter`] is used by the
//! payload copy loops and by the runner.

pub mod ratelimit;

pub use ratelimit::RateLimiter;
