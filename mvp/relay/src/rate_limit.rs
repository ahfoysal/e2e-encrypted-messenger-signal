//! Token-bucket rate limiter for per-connection flood control.
//!
//! A bucket holds up to `capacity` tokens and refills at `refill_per_sec`.
//! Each inbound frame costs one token; if none are available we drop the
//! frame and return a soft error to the client.

use std::time::Instant;

#[derive(Debug, Clone, Copy)]
pub struct TokenBucket {
    capacity: f64,
    refill_per_sec: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(capacity: u32, refill_per_sec: f64) -> Self {
        Self {
            capacity: capacity as f64,
            refill_per_sec,
            tokens: capacity as f64,
            last: Instant::now(),
        }
    }

    /// Try to consume one token; returns `true` if allowed.
    pub fn try_acquire(&mut self) -> bool {
        self.try_acquire_at(Instant::now())
    }

    /// Test hook — same as `try_acquire` but you pass the clock.
    pub fn try_acquire_at(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn tokens(&self) -> f64 {
        self.tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn full_bucket_allows_up_to_capacity() {
        let mut tb = TokenBucket::new(5, 1.0);
        for _ in 0..5 {
            assert!(tb.try_acquire());
        }
        assert!(!tb.try_acquire(), "sixth call must be denied");
    }

    #[test]
    fn bucket_refills_over_time() {
        let t0 = Instant::now();
        let mut tb = TokenBucket::new(2, 10.0);
        assert!(tb.try_acquire_at(t0));
        assert!(tb.try_acquire_at(t0));
        assert!(!tb.try_acquire_at(t0));
        // 0.2s at 10 tokens/sec => +2 tokens.
        let t1 = t0 + Duration::from_millis(200);
        assert!(tb.try_acquire_at(t1));
        assert!(tb.try_acquire_at(t1));
        assert!(!tb.try_acquire_at(t1));
    }

    #[test]
    fn refill_is_capped_at_capacity() {
        let t0 = Instant::now();
        let mut tb = TokenBucket::new(3, 100.0);
        // Drain.
        for _ in 0..3 {
            tb.try_acquire_at(t0);
        }
        // Wait a long time — should NOT overflow past capacity.
        let t1 = t0 + Duration::from_secs(60);
        assert!(tb.try_acquire_at(t1));
        // Tokens after acquire should be at most capacity-1 = 2.
        assert!(tb.tokens() <= 2.0 + 1e-9);
    }
}
