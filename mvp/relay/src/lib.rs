//! Reusable pieces of the hardened M5 relay: token-bucket rate limiter
//! and a sled-backed persistent queue for offline recipients.

pub mod rate_limit;
pub mod queue;
