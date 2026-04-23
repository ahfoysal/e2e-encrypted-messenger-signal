//! MVP Signal-style E2E crypto core: X3DH + Double Ratchet.
//!
//! This is a teaching-quality implementation. It implements the core
//! cryptographic state machines but is **not** production-ready — no
//! constant-time signature scheme, no skipped-message cache, no replay
//! protection beyond per-chain counters, no serialization format.

pub mod x3dh;
pub mod ratchet;

pub use x3dh::{IdentityKey, PreKeyBundle, SignedPreKey, OneTimePreKey, x3dh_initiator, x3dh_responder};
pub use ratchet::{RatchetState, RatchetHeader, RatchetMessage};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("aead encryption/decryption failed")]
    Aead,
    #[error("invalid message (truncated or malformed)")]
    InvalidMessage,
    #[error("key derivation failed")]
    Kdf,
}
