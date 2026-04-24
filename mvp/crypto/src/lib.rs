//! MVP Signal-style E2E crypto core: X3DH + Double Ratchet + sender keys +
//! sealed sender + multi-device + safety numbers + disappearing messages.
//!
//! This is a teaching-quality implementation. It implements the core
//! cryptographic state machines but is **not** production-ready — no
//! constant-time signature scheme, no replay window beyond per-chain
//! counters, no auditable wire format.

pub mod x3dh;
pub mod ratchet;
pub mod signed_prekey;
pub mod wire;
pub mod sender_keys;
pub mod group;
pub mod sealed_sender;
pub mod multi_device;
pub mod safety_numbers;
pub mod disappearing;
pub mod mls;

pub use x3dh::{
    IdentityKey, PreKeyBundle, SignedPreKey, OneTimePreKey, X3dhError,
    x3dh_initiator, x3dh_responder,
};
pub use ratchet::{RatchetState, RatchetHeader, RatchetMessage};
pub use signed_prekey::{IdentitySigningKey, SpkSigError, verify_spk_signature};
pub use multi_device::{DeviceEntry, DeviceId, DeviceRoster, FanoutPlan, FanoutTarget, plan_fanout};
pub use safety_numbers::{IdentityProfile, compute as safety_number, compute_digest};
pub use disappearing::{Expiry, Ttl, now_unix_ms, is_expired};

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
