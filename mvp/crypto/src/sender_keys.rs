//! Sender Keys (Signal's group-messaging primitive) — M3.
//!
//! In Signal's group protocol each *group member* owns one **SenderKey** per
//! group, consisting of:
//!   - a symmetric **chain key** (advanced per message, same HMAC-SHA256
//!     construction as the Double Ratchet's sending chain), and
//!   - an Ed25519 **signing keypair** used to sign each ciphertext so other
//!     members can authenticate the origin even though they all share the
//!     (derived) symmetric key.
//!
//! The SenderKey is created locally by a member and then **distributed** to
//! every other group member over the existing pairwise Double Ratchet
//! sessions (see `group.rs`). Each recipient stores the peer's chain key
//! + verifying key under (group_id, sender_id).
//!
//! On send:
//!   1. Advance own chain — `(ck, mk) <- KDF_CK(ck)`.
//!   2. `ct = AEAD_encrypt(mk, nonce(n), plaintext)`.
//!   3. `sig = Sign(sk_sign, dh || n || ct)` (domain-separated).
//!   4. Broadcast `{ sender_id, n, ct, sig }`.
//!
//! On receive:
//!   1. Look up (group_id, sender_id) -> (their_chain_key, their_vk).
//!   2. Verify signature with their_vk. Reject on failure.
//!   3. Advance their_chain_key forward to `n` (caching skipped keys FIFO
//!      like in `ratchet.rs`) and use the derived mk to AEAD-decrypt.
//!
//! This gives forward secrecy (chain key advances) but not post-compromise
//! security within a single chain — that's why Signal rotates SenderKeys
//! on membership change (see `group.rs`).
//!
//! Differences from MLS (RFC 9420): no TreeKEM, no group epochs, no
//! hierarchical welcome messages. Simpler to implement and what Signal
//! actually ships for groups today.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use std::collections::VecDeque;

use crate::CryptoError;

type HmacSha256 = Hmac<Sha256>;

const AD: &[u8] = b"Signal-MVP-GroupAD";
/// Max skipped message keys retained per sender chain.
pub const GROUP_MAX_SKIP: usize = 64;

/// A SenderKey owned by a member for a specific group. Contains both the
/// symmetric chain key (advanced per send) and the Ed25519 signing key.
pub struct SenderKey {
    /// 32-byte chain key — advanced per send.
    chain_key: [u8; 32],
    /// Current counter `n` in this chain (monotonically increasing).
    counter: u32,
    /// Ed25519 signing key used to sign outgoing ciphertexts.
    signing: SigningKey,
    /// Corresponding verifying key (also sent in the distribution message).
    verifying: VerifyingKey,
}

impl SenderKey {
    /// Freshly generate a SenderKey (random chain key + fresh Ed25519 pair).
    pub fn generate() -> Self {
        let mut ck = [0u8; 32];
        use rand_core::RngCore;
        OsRng.fill_bytes(&mut ck);
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        Self {
            chain_key: ck,
            counter: 0,
            signing,
            verifying,
        }
    }

    pub fn verifying(&self) -> VerifyingKey {
        self.verifying
    }

    /// Serialize the *public* parts of this SenderKey so it can be wrapped
    /// in a pairwise-encrypted distribution message. Includes the starting
    /// chain key (secret: only sent inside the Double Ratchet envelope).
    pub fn to_distribution(&self) -> SenderKeyDistribution {
        SenderKeyDistribution {
            chain_key: self.chain_key,
            counter: self.counter,
            verifying: self.verifying,
        }
    }

    /// Encrypt + sign one group message.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<GroupMessage, CryptoError> {
        let (next_ck, mk) = kdf_ck(&self.chain_key);
        let n = self.counter;
        let ciphertext = aead_encrypt(&mk, n, plaintext)?;
        self.chain_key = next_ck;
        self.counter = self.counter.wrapping_add(1);

        // Signature covers counter || ciphertext || verifying_key (stable
        // domain-separated). The verifying key pin prevents key-swapping.
        let sig = self
            .signing
            .sign(&sign_transcript(n, &ciphertext, &self.verifying));

        Ok(GroupMessage {
            n,
            ciphertext,
            signature: sig.to_bytes().to_vec(),
        })
    }
}

/// The data distributed from a SenderKey owner to every other group member
/// over the pairwise Double Ratchet. It is NEVER sent in plaintext.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SenderKeyDistribution {
    pub chain_key: [u8; 32],
    pub counter: u32,
    #[serde(with = "vk_serde")]
    pub verifying: VerifyingKey,
}

/// A group ciphertext broadcast to all members.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMessage {
    pub n: u32,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Receiver-side per-sender chain state. Tracks expected counter + cache of
/// skipped message keys for out-of-order delivery.
pub struct SenderKeyReceiver {
    chain_key: [u8; 32],
    next_n: u32,
    verifying: VerifyingKey,
    skipped: VecDeque<SkippedGroupKey>,
}

#[derive(Clone)]
struct SkippedGroupKey {
    n: u32,
    mk: [u8; 32],
}

impl SenderKeyReceiver {
    pub fn from_distribution(dist: SenderKeyDistribution) -> Self {
        Self {
            chain_key: dist.chain_key,
            next_n: dist.counter,
            verifying: dist.verifying,
            skipped: VecDeque::new(),
        }
    }

    pub fn verifying(&self) -> VerifyingKey {
        self.verifying
    }

    /// Verify + decrypt a group message. Advances the chain; caches keys
    /// for any gap between `next_n` and `msg.n`.
    pub fn decrypt(&mut self, msg: &GroupMessage) -> Result<Vec<u8>, CryptoError> {
        // 1. Verify signature first (authenticates origin before we touch any state).
        let sig_bytes: [u8; 64] = msg
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidMessage)?;
        let sig = Signature::from_bytes(&sig_bytes);
        self.verifying
            .verify(&sign_transcript(msg.n, &msg.ciphertext, &self.verifying), &sig)
            .map_err(|_| CryptoError::InvalidMessage)?;

        // 2. Try skipped cache.
        if let Some(mk) = self.take_skipped(msg.n) {
            return aead_decrypt(&mk, msg.n, &msg.ciphertext);
        }

        // 3. If `n` is behind `next_n` and not cached, it's a replay.
        if msg.n < self.next_n {
            return Err(CryptoError::InvalidMessage);
        }

        // 4. Advance chain up to `msg.n`, caching keys in between.
        if msg.n.saturating_sub(self.next_n) as usize > GROUP_MAX_SKIP {
            return Err(CryptoError::InvalidMessage);
        }
        while self.next_n < msg.n {
            let (next_ck, mk) = kdf_ck(&self.chain_key);
            self.chain_key = next_ck;
            self.store_skipped(self.next_n, mk);
            self.next_n += 1;
        }
        let (next_ck, mk) = kdf_ck(&self.chain_key);
        self.chain_key = next_ck;
        self.next_n += 1;
        aead_decrypt(&mk, msg.n, &msg.ciphertext)
    }

    fn store_skipped(&mut self, n: u32, mk: [u8; 32]) {
        if self.skipped.len() >= GROUP_MAX_SKIP {
            self.skipped.pop_front();
        }
        self.skipped.push_back(SkippedGroupKey { n, mk });
    }

    fn take_skipped(&mut self, n: u32) -> Option<[u8; 32]> {
        let pos = self.skipped.iter().position(|e| e.n == n)?;
        Some(self.skipped.remove(pos).unwrap().mk)
    }
}

fn sign_transcript(n: u32, ct: &[u8], vk: &VerifyingKey) -> Vec<u8> {
    let mut t = Vec::with_capacity(4 + ct.len() + 32 + AD.len());
    t.extend_from_slice(AD);
    t.extend_from_slice(&n.to_be_bytes());
    t.extend_from_slice(vk.as_bytes());
    t.extend_from_slice(ct);
    t
}

fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // Same construction as ratchet.rs — HMAC-SHA256 with constants 0x01/0x02.
    let mut mk_mac = <HmacSha256 as Mac>::new_from_slice(ck).expect("32 bytes");
    mk_mac.update(&[0x01]);
    let mk = mk_mac.finalize().into_bytes();
    let mut ck_mac = <HmacSha256 as Mac>::new_from_slice(ck).expect("32 bytes");
    ck_mac.update(&[0x02]);
    let next = ck_mac.finalize().into_bytes();
    let mut mk_a = [0u8; 32];
    let mut ck_a = [0u8; 32];
    mk_a.copy_from_slice(&mk);
    ck_a.copy_from_slice(&next);
    (ck_a, mk_a)
}

fn nonce_from_counter(n: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[8..].copy_from_slice(&n.to_be_bytes());
    nonce
}

fn aead_encrypt(mk: &[u8; 32], n: u32, pt: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(mk));
    let nonce_bytes = nonce_from_counter(n);
    cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload { msg: pt, aad: AD },
        )
        .map_err(|_| CryptoError::Aead)
}

fn aead_decrypt(mk: &[u8; 32], n: u32, ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(mk));
    let nonce_bytes = nonce_from_counter(n);
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload { msg: ct, aad: AD },
        )
        .map_err(|_| CryptoError::Aead)
}

mod vk_serde {
    use ed25519_dalek::VerifyingKey;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(vk: &VerifyingKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(vk.as_bytes())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<VerifyingKey, D::Error> {
        let bytes: Vec<u8> = Vec::deserialize(d)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("vk must be 32 bytes"))?;
        VerifyingKey::from_bytes(&arr).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_recv_roundtrip() {
        let mut sk = SenderKey::generate();
        let mut rx = SenderKeyReceiver::from_distribution(sk.to_distribution());
        let m = sk.encrypt(b"hello group").unwrap();
        assert_eq!(rx.decrypt(&m).unwrap(), b"hello group");
    }

    #[test]
    fn multiple_in_order_messages() {
        let mut sk = SenderKey::generate();
        let mut rx = SenderKeyReceiver::from_distribution(sk.to_distribution());
        for i in 0..10u32 {
            let pt = format!("msg {i}");
            let m = sk.encrypt(pt.as_bytes()).unwrap();
            assert_eq!(m.n, i);
            assert_eq!(rx.decrypt(&m).unwrap(), pt.as_bytes());
        }
    }

    #[test]
    fn out_of_order_works() {
        let mut sk = SenderKey::generate();
        let mut rx = SenderKeyReceiver::from_distribution(sk.to_distribution());
        let m0 = sk.encrypt(b"zero").unwrap();
        let m1 = sk.encrypt(b"one").unwrap();
        let m2 = sk.encrypt(b"two").unwrap();
        // Deliver 0, 2, 1.
        assert_eq!(rx.decrypt(&m0).unwrap(), b"zero");
        assert_eq!(rx.decrypt(&m2).unwrap(), b"two");
        assert_eq!(rx.decrypt(&m1).unwrap(), b"one");
    }

    #[test]
    fn forged_signature_rejected() {
        let mut sk = SenderKey::generate();
        let mut rx = SenderKeyReceiver::from_distribution(sk.to_distribution());
        let mut m = sk.encrypt(b"bad").unwrap();
        m.signature[0] ^= 0xFF;
        assert!(rx.decrypt(&m).is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let mut sk = SenderKey::generate();
        let mut rx = SenderKeyReceiver::from_distribution(sk.to_distribution());
        let mut m = sk.encrypt(b"data").unwrap();
        m.ciphertext[0] ^= 0x01;
        assert!(rx.decrypt(&m).is_err());
    }

    #[test]
    fn wrong_sender_key_rejected() {
        // Receiver has Alice's SenderKey, but Mallory signs with her own.
        let mut alice = SenderKey::generate();
        let mut mallory = SenderKey::generate();
        let mut rx = SenderKeyReceiver::from_distribution(alice.to_distribution());

        // Mallory encrypts a message with her chain key — rx won't decrypt
        // because chain keys differ AND signature won't match Alice's vk.
        let m = mallory.encrypt(b"forged").unwrap();
        assert!(rx.decrypt(&m).is_err());
        // Sanity: alice's own message still works.
        let ok = alice.encrypt(b"real").unwrap();
        assert_eq!(rx.decrypt(&ok).unwrap(), b"real");
    }
}
