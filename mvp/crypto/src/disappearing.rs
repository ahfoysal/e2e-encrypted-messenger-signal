//! Disappearing messages (TTL) — thin wrapper used by both relay and client.
//!
//! A sender tags each envelope with `expires_at_unix_ms` (absolute wall
//! clock). Two enforcement points:
//!
//!   * The **relay** drops expired envelopes both on ingress (rejecting a
//!     message that is already stale) and on any persistent-queue flush
//!     (so offline recipients reconnecting after a long absence don't
//!     receive messages that have expired).
//!   * The **client** checks expiry after decrypting and refuses to
//!     display expired messages (and schedules local deletion when the
//!     timer fires for already-displayed ones).
//!
//! This is opportunistic — malicious peers can always save plaintext —
//! but it matches the Signal / WhatsApp "disappearing messages" UX for
//! honest participants and shrinks the server-side attack surface.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Monotonically-increasing milliseconds since the Unix epoch.
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A TTL policy for a conversation or a single message.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ttl {
    pub ttl_ms: u64,
}

impl Ttl {
    pub const fn seconds(s: u64) -> Self {
        Self { ttl_ms: s * 1000 }
    }
    pub const fn minutes(m: u64) -> Self {
        Self { ttl_ms: m * 60 * 1000 }
    }
    pub const fn hours(h: u64) -> Self {
        Self { ttl_ms: h * 60 * 60 * 1000 }
    }

    /// Compute an absolute expiry stamp from "now".
    pub fn deadline_from_now(self) -> u64 {
        now_unix_ms().saturating_add(self.ttl_ms)
    }
}

/// Has the given deadline passed?
pub fn is_expired(expires_at_unix_ms: u64) -> bool {
    expires_at_unix_ms != 0 && now_unix_ms() >= expires_at_unix_ms
}

/// Envelope metadata. `expires_at_unix_ms == 0` means "never expires"
/// (compatible with M1..M4 clients that don't send the field).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Expiry {
    #[serde(default)]
    pub expires_at_unix_ms: u64,
}

impl Expiry {
    pub fn never() -> Self {
        Self::default()
    }
    pub fn in_(ttl: Ttl) -> Self {
        Self {
            expires_at_unix_ms: ttl.deadline_from_now(),
        }
    }
    pub fn at(unix_ms: u64) -> Self {
        Self {
            expires_at_unix_ms: unix_ms,
        }
    }
    pub fn is_expired(&self) -> bool {
        is_expired(self.expires_at_unix_ms)
    }
    pub fn is_set(&self) -> bool {
        self.expires_at_unix_ms != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn never_expires_default() {
        let e = Expiry::never();
        assert!(!e.is_expired());
        assert!(!e.is_set());
    }

    #[test]
    fn ttl_deadline_is_in_the_future() {
        let d = Ttl::seconds(10).deadline_from_now();
        assert!(d > now_unix_ms());
    }

    #[test]
    fn expired_after_sleep() {
        let e = Expiry::in_(Ttl { ttl_ms: 30 });
        assert!(!e.is_expired(), "not yet expired");
        sleep(Duration::from_millis(80));
        assert!(e.is_expired(), "should be expired after sleep");
    }

    #[test]
    fn is_expired_zero_stamp_means_no_expiry() {
        assert!(!is_expired(0));
    }
}
