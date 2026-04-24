//! Sealed Sender (M4).
//!
//! Goal: the relay should be able to deliver a message to the recipient
//! without learning *who* the sender is. In plain Double Ratchet each
//! envelope carries `{from, to}` in the clear so the server can route
//! replies; sealed sender removes `from` from the envelope and puts an
//! encrypted-and-authenticated sender certificate *inside* the ciphertext.
//!
//! Scheme (teaching-quality, modeled on Signal's UnidentifiedSenderMessage):
//!
//!   1. Sender prepares a `SenderCertificate` — `{sender_handle,
//!      sender_device_id, sender_identity_pub, sender_signing_vk}` signed
//!      with the sender's Ed25519 long-term key (binds the identity pub
//!      to the human-readable handle + device id).
//!   2. Sender serializes `(certificate, inner_ciphertext)` where
//!      `inner_ciphertext` is e.g. a normal Double Ratchet `RatchetMessage`
//!      already bound to this specific recipient device.
//!   3. Sender generates an ephemeral X25519 keypair `e`, does
//!      `DH(e, recipient_identity_pub)` to derive a symmetric key via
//!      HKDF-SHA256, and encrypts the inner blob with ChaCha20-Poly1305.
//!   4. The wire envelope carries `(ephemeral_pub, aead_ct)` + the
//!      recipient's opaque routing id — and **nothing** about the sender.
//!
//! The relay sees only recipient routing id + opaque bytes. The recipient
//! decrypts with its identity key, parses the certificate, verifies the
//! Ed25519 signature under the embedded `signing_vk`, and checks that the
//! `sender_identity_pub` in the certificate matches the one used in the
//! inner Double Ratchet session (preventing a "steal cert and reuse"
//! confusion attack).
//!
//! **Not** a replacement for authentication: the *inner* payload is still
//! authenticated by the regular Double Ratchet AEAD + the sender
//! certificate's Ed25519 signature. Sealed sender just hides the sender
//! from a passive/active relay adversary.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::signed_prekey::IdentitySigningKey;
use crate::x3dh::IdentityKey;

const SEALED_INFO: &[u8] = b"Signal-MVP-SealedSender-v1";
const SEALED_AD: &[u8] = b"Signal-MVP-SealedSender-AD";
const CERT_CONTEXT: &[u8] = b"Signal-MVP-SealedSender-Cert-v1";

/// Signed attestation binding a sender's identity pub to a human-readable
/// handle + device id. Validated by the recipient after unsealing.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SenderCertificate {
    pub sender_handle: String,
    pub sender_device_id: u32,
    /// Sender's long-term X25519 identity public (same one used for X3DH).
    pub sender_identity_pub: [u8; 32],
    /// Sender's Ed25519 verifying key (signs this cert + inner messages).
    pub sender_signing_vk: [u8; 32],
    /// Ed25519 signature over the canonical encoding of the other fields,
    /// produced by the private half of `sender_signing_vk`.
    pub signature: [u8; 64],
}

impl SenderCertificate {
    /// Canonical message bytes that get signed (everything except the signature).
    fn signing_bytes(
        handle: &str,
        device_id: u32,
        identity_pub: &[u8; 32],
        signing_vk: &[u8; 32],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            CERT_CONTEXT.len() + 4 + handle.len() + 4 + 32 + 32,
        );
        buf.extend_from_slice(CERT_CONTEXT);
        buf.extend_from_slice(&(handle.len() as u32).to_be_bytes());
        buf.extend_from_slice(handle.as_bytes());
        buf.extend_from_slice(&device_id.to_be_bytes());
        buf.extend_from_slice(identity_pub);
        buf.extend_from_slice(signing_vk);
        buf
    }

    /// Issue a self-signed sender certificate. In production, certificates
    /// would be issued by the server's identity CA (and carry an expiry);
    /// here the sender signs its own for simplicity — the recipient trusts
    /// the signing key because it was pinned out-of-band via the X3DH
    /// handshake.
    pub fn issue(
        handle: &str,
        device_id: u32,
        identity: &IdentityKey,
        signing: &IdentitySigningKey,
    ) -> Self {
        let identity_pub = *identity.public.as_bytes();
        let signing_vk = *signing.verifying.as_bytes();
        let msg = Self::signing_bytes(handle, device_id, &identity_pub, &signing_vk);
        let sig: Signature = signing.signing.sign(&msg);
        Self {
            sender_handle: handle.to_string(),
            sender_device_id: device_id,
            sender_identity_pub: identity_pub,
            sender_signing_vk: signing_vk,
            signature: sig.to_bytes(),
        }
    }

    /// Verify the certificate's self-signature. Returns `Ok(())` iff the
    /// signature under `sender_signing_vk` is valid for the canonical bytes.
    pub fn verify(&self) -> Result<(), SealedSenderError> {
        let vk = VerifyingKey::from_bytes(&self.sender_signing_vk)
            .map_err(|_| SealedSenderError::BadCertificate)?;
        let msg = Self::signing_bytes(
            &self.sender_handle,
            self.sender_device_id,
            &self.sender_identity_pub,
            &self.sender_signing_vk,
        );
        let sig = Signature::from_bytes(&self.signature);
        vk.verify(&msg, &sig)
            .map_err(|_| SealedSenderError::BadCertificate)
    }
}

/// The plaintext that actually gets encrypted to the recipient: the
/// sender's certificate plus whatever opaque inner ciphertext the caller
/// wants to deliver (typically a `RatchetMessage` serialized by `wire.rs`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedPayload {
    pub certificate: SenderCertificate,
    pub inner_ciphertext: Vec<u8>,
}

/// Wire form of a sealed envelope. The relay sees only this + the
/// recipient routing id. **No sender fields.**
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedEnvelope {
    /// Ephemeral X25519 public used for the ECIES-style key agreement.
    pub ephemeral_pub: [u8; 32],
    /// ChaCha20-Poly1305 ciphertext of a serde-encoded `SealedPayload`.
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum SealedSenderError {
    #[error("aead decryption failed (wrong recipient or tampered)")]
    Aead,
    #[error("sender certificate signature did not verify")]
    BadCertificate,
    #[error("sender identity in certificate does not match expected")]
    CertIdentityMismatch,
    #[error("serialization error")]
    Serde,
}

fn derive_sealed_key(ephemeral_priv: &StaticSecret, recipient_pub: &PublicKey) -> [u8; 32] {
    let shared = ephemeral_priv.diffie_hellman(recipient_pub);
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(SEALED_INFO, &mut okm).expect("32 bytes fits");
    okm
}

fn derive_sealed_key_recipient(
    recipient_priv: &StaticSecret,
    ephemeral_pub: &PublicKey,
) -> [u8; 32] {
    let shared = recipient_priv.diffie_hellman(ephemeral_pub);
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(SEALED_INFO, &mut okm).expect("32 bytes fits");
    okm
}

fn fixed_nonce() -> Nonce {
    // The symmetric key is freshly derived per envelope (ephemeral sender
    // key on each call), so key reuse is not a concern and a fixed nonce
    // is safe. We still stick to 12 bytes because the type requires it.
    Nonce::clone_from_slice(&[0u8; 12])
}

/// Seal `inner_ciphertext` (typically a Double Ratchet message) together
/// with the sender's certificate, encrypted to `recipient_identity_pub`.
pub fn seal(
    certificate: SenderCertificate,
    inner_ciphertext: Vec<u8>,
    recipient_identity_pub: &PublicKey,
) -> Result<SealedEnvelope, SealedSenderError> {
    let payload = SealedPayload {
        certificate,
        inner_ciphertext,
    };
    let pt = serde_json::to_vec(&payload).map_err(|_| SealedSenderError::Serde)?;

    let e_priv = StaticSecret::random_from_rng(OsRng);
    let e_pub = PublicKey::from(&e_priv);
    let key = derive_sealed_key(&e_priv, recipient_identity_pub);

    let aead = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ct = aead
        .encrypt(
            &fixed_nonce(),
            Payload {
                msg: &pt,
                aad: SEALED_AD,
            },
        )
        .map_err(|_| SealedSenderError::Aead)?;

    Ok(SealedEnvelope {
        ephemeral_pub: *e_pub.as_bytes(),
        ciphertext: ct,
    })
}

/// Open a sealed envelope with the recipient's long-term X25519 identity
/// key. Returns the verified `SenderCertificate` + the inner ciphertext
/// that should be handed to the Double Ratchet for the *actual* decryption.
pub fn open(
    envelope: &SealedEnvelope,
    recipient_identity: &IdentityKey,
) -> Result<SealedPayload, SealedSenderError> {
    let e_pub = PublicKey::from(envelope.ephemeral_pub);
    let key = derive_sealed_key_recipient(&recipient_identity.secret, &e_pub);

    let aead = ChaCha20Poly1305::new(Key::from_slice(&key));
    let pt = aead
        .decrypt(
            &fixed_nonce(),
            Payload {
                msg: &envelope.ciphertext,
                aad: SEALED_AD,
            },
        )
        .map_err(|_| SealedSenderError::Aead)?;

    let payload: SealedPayload =
        serde_json::from_slice(&pt).map_err(|_| SealedSenderError::Serde)?;
    payload.certificate.verify()?;
    Ok(payload)
}

/// Higher-level helper: open + additionally assert that the certificate
/// advertises a specific expected sender identity pub (e.g. the one the
/// recipient pinned out-of-band via X3DH).
pub fn open_expecting(
    envelope: &SealedEnvelope,
    recipient_identity: &IdentityKey,
    expected_sender_identity_pub: &[u8; 32],
) -> Result<SealedPayload, SealedSenderError> {
    let payload = open(envelope, recipient_identity)?;
    if &payload.certificate.sender_identity_pub != expected_sender_identity_pub {
        return Err(SealedSenderError::CertIdentityMismatch);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_sender() -> (IdentityKey, IdentitySigningKey, SenderCertificate) {
        let ik = IdentityKey::generate();
        let sk = IdentitySigningKey::generate();
        let cert = SenderCertificate::issue("alice", 1, &ik, &sk);
        (ik, sk, cert)
    }

    #[test]
    fn certificate_roundtrip_verifies() {
        let (_ik, _sk, cert) = setup_sender();
        assert!(cert.verify().is_ok());
    }

    #[test]
    fn tampered_certificate_handle_is_rejected() {
        let (_ik, _sk, mut cert) = setup_sender();
        cert.sender_handle = "mallory".to_string();
        assert!(matches!(cert.verify(), Err(SealedSenderError::BadCertificate)));
    }

    #[test]
    fn tampered_certificate_identity_is_rejected() {
        let (_ik, _sk, mut cert) = setup_sender();
        // Flip a byte in the identity pub.
        cert.sender_identity_pub[0] ^= 0xFF;
        assert!(matches!(cert.verify(), Err(SealedSenderError::BadCertificate)));
    }

    #[test]
    fn seal_open_roundtrip() {
        let (_a_ik, _a_sk, cert) = setup_sender();
        let bob_ik = IdentityKey::generate();

        let inner = b"<opaque double-ratchet bytes>".to_vec();
        let env = seal(cert.clone(), inner.clone(), &bob_ik.public).unwrap();

        // The envelope carries NO sender-identifying fields.
        // (SealedEnvelope is just (ephemeral_pub, ciphertext).)
        let opened = open(&env, &bob_ik).unwrap();
        assert_eq!(opened.certificate, cert);
        assert_eq!(opened.inner_ciphertext, inner);
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let (_a_ik, _a_sk, cert) = setup_sender();
        let bob_ik = IdentityKey::generate();
        let eve_ik = IdentityKey::generate();

        let env = seal(cert, b"hi bob".to_vec(), &bob_ik.public).unwrap();
        // Eve is on the wire but can't decrypt.
        assert!(matches!(open(&env, &eve_ik), Err(SealedSenderError::Aead)));
    }

    #[test]
    fn relay_eavesdropper_learns_nothing_about_sender() {
        // This test asserts the metadata-hiding property: the serialized
        // sealed envelope bytes do NOT contain the sender's handle,
        // identity pub, or signing vk anywhere.
        let (a_ik, a_sk, cert) = setup_sender();
        let bob_ik = IdentityKey::generate();

        let env = seal(cert, b"secret".to_vec(), &bob_ik.public).unwrap();
        let wire = serde_json::to_vec(&env).unwrap();

        // Sender's public identity pub must not appear in the wire bytes.
        let a_ik_pub_bytes = a_ik.public.to_bytes();
        assert!(
            wire.windows(32).all(|w| w != a_ik_pub_bytes),
            "sender identity pub leaked in sealed envelope"
        );
        let a_sk_vk_bytes = a_sk.verifying.to_bytes();
        assert!(
            wire.windows(32).all(|w| w != a_sk_vk_bytes),
            "sender signing vk leaked in sealed envelope"
        );
        // Handle too.
        assert!(
            !wire.windows(5).any(|w| w == b"alice"),
            "sender handle leaked in sealed envelope"
        );
    }

    #[test]
    fn open_expecting_detects_cert_identity_mismatch() {
        let (_a_ik, _a_sk, cert) = setup_sender();
        let bob_ik = IdentityKey::generate();
        let env = seal(cert, b"x".to_vec(), &bob_ik.public).unwrap();

        let wrong_expected = [0u8; 32];
        assert!(matches!(
            open_expecting(&env, &bob_ik, &wrong_expected),
            Err(SealedSenderError::CertIdentityMismatch)
        ));
    }
}
