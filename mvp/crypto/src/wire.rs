//! Serde-serializable wire formats for the WebSocket relay + CLI clients.
//!
//! Keys are serialized as standard-base64 strings. Clients never expose
//! secret key material; only public keys, signatures, and ciphertext travel
//! across the wire.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey;

use crate::ratchet::{RatchetHeader, RatchetMessage};
use crate::x3dh::PreKeyBundle;

/// Wire-friendly version of `PreKeyBundle` — base64 strings all the way down.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleWire {
    pub identity: String,
    pub identity_signing: String,
    pub signed_prekey: String,
    pub spk_signature: String,
    pub one_time_prekey: String,
}

impl BundleWire {
    pub fn from_bundle(b: &PreKeyBundle) -> Self {
        Self {
            identity: B64.encode(b.identity.as_bytes()),
            identity_signing: B64.encode(b.identity_signing.as_bytes()),
            signed_prekey: B64.encode(b.signed_prekey.as_bytes()),
            spk_signature: B64.encode(b.spk_signature.to_bytes()),
            one_time_prekey: B64.encode(b.one_time_prekey.as_bytes()),
        }
    }

    pub fn to_bundle(&self) -> anyhow::Result<PreKeyBundle> {
        Ok(PreKeyBundle {
            identity: pk_from_b64(&self.identity)?,
            identity_signing: vk_from_b64(&self.identity_signing)?,
            signed_prekey: pk_from_b64(&self.signed_prekey)?,
            spk_signature: sig_from_b64(&self.spk_signature)?,
            one_time_prekey: pk_from_b64(&self.one_time_prekey)?,
        })
    }
}

/// Wire-friendly ratchet header + ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageWire {
    pub dh: String,
    pub n: u32,
    pub pn: u32,
    pub ciphertext: String,
    /// Attached on the very first message so the responder can run X3DH.
    pub initial: Option<InitialHandshake>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialHandshake {
    /// Alice's long-term X25519 identity public.
    pub alice_ik: String,
    /// Alice's X3DH ephemeral public.
    pub alice_ek: String,
}

impl MessageWire {
    pub fn from_msg(m: &RatchetMessage, initial: Option<InitialHandshake>) -> Self {
        Self {
            dh: B64.encode(m.header.dh.as_bytes()),
            n: m.header.n,
            pn: m.header.pn,
            ciphertext: B64.encode(&m.ciphertext),
            initial,
        }
    }

    pub fn to_msg(&self) -> anyhow::Result<RatchetMessage> {
        Ok(RatchetMessage {
            header: RatchetHeader {
                dh: pk_from_b64(&self.dh)?,
                n: self.n,
                pn: self.pn,
            },
            ciphertext: B64.decode(&self.ciphertext)?,
        })
    }
}

/// Envelope exchanged between client and relay (and between clients via the relay).
///
/// M5: optional `device_id` (sender/recipient device selector for multi-device
/// fan-out) and `expires_at_unix_ms` (disappearing-messages TTL). Both default
/// to zero (= "unspecified" / "never") so pre-M5 clients stay compatible.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayMsg {
    /// Client -> server: announce who I am.
    Hello {
        who: String,
        #[serde(default)]
        device_id: u32,
    },
    /// Client -> server: publish my pre-key bundle for others to fetch.
    PublishBundle {
        who: String,
        bundle: BundleWire,
        #[serde(default)]
        device_id: u32,
    },
    /// Client -> server: fetch `who`'s bundle.
    FetchBundle { who: String },
    /// Server -> client: requested bundle (or `None` if unknown).
    Bundle {
        who: String,
        bundle: Option<BundleWire>,
    },
    /// Client -> server: relay this message to `to`.
    Envelope {
        from: String,
        to: String,
        msg: MessageWire,
        #[serde(default)]
        from_device: u32,
        #[serde(default)]
        to_device: u32,
        /// Absolute unix-ms expiry; 0 = never expires.
        #[serde(default)]
        expires_at_unix_ms: u64,
    },
    /// Server -> client: a message delivered from `from`.
    Deliver {
        from: String,
        msg: MessageWire,
        #[serde(default)]
        from_device: u32,
        #[serde(default)]
        expires_at_unix_ms: u64,
    },
    /// Server -> client: protocol-level error (unknown peer, etc.).
    Error { reason: String },
}

pub fn pk_from_b64(s: &str) -> anyhow::Result<PublicKey> {
    let bytes = B64.decode(s)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("x25519 pub must be 32 bytes"))?;
    Ok(PublicKey::from(arr))
}

pub fn vk_from_b64(s: &str) -> anyhow::Result<VerifyingKey> {
    let bytes = B64.decode(s)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("ed25519 vk must be 32 bytes"))?;
    Ok(VerifyingKey::from_bytes(&arr)?)
}

pub fn sig_from_b64(s: &str) -> anyhow::Result<Signature> {
    let bytes = B64.decode(s)?;
    let arr: [u8; 64] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("ed25519 sig must be 64 bytes"))?;
    Ok(Signature::from_bytes(&arr))
}
