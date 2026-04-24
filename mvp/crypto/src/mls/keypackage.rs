//! LeafNode + KeyPackage (RFC 9420 §7.2, §10).
//!
//! A **LeafNode** is the per-member record that lives at a leaf of the
//! ratchet tree. It carries:
//!   - `encryption_key` — the X25519 public used by TreeKEM to wrap path
//!     secrets *to this member* when they're at their leaf.
//!   - `signature_key` — the Ed25519 public used to verify commits /
//!     proposals this member sends.
//!   - `credential` — an opaque identity (we just use a `String`).
//!   - `signature` — Ed25519 self-signature over the node body; binds
//!     the encryption/identity keys together.
//!
//! A **KeyPackage** wraps a LeafNode plus an `init_key` — an X25519
//! public used specifically for Welcome encryption when this member is
//! added. The init_key is distinct from encryption_key so that a member
//! can be added even when they're not online; the server (or any
//! committer) can encrypt Welcome secrets to the init_key.
//!
//! A member generates a `KeyPackageBundle` (public KeyPackage + the
//! matching private keys) locally; publishes the KeyPackage to a
//! directory; and holds onto the bundle until someone adds them.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

/// Public member record — sits at a leaf and is mirrored to every other
/// member's copy of the tree.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeafNode {
    pub credential: String,
    /// X25519 public for TreeKEM direct-path encryption at this leaf.
    pub encryption_key: [u8; 32],
    /// Ed25519 public for signing proposals/commits.
    pub signature_key: [u8; 32],
    /// Ed25519 self-signature over `body_bytes(credential, enc_key, sig_key)`.
    pub signature: Vec<u8>,
}

impl LeafNode {
    pub fn body_bytes(credential: &str, enc: &[u8; 32], sig: &[u8; 32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(credential.len() + 64 + 16);
        v.extend_from_slice(b"MLS-LeafNode-v1");
        v.extend_from_slice(&(credential.len() as u32).to_be_bytes());
        v.extend_from_slice(credential.as_bytes());
        v.extend_from_slice(enc);
        v.extend_from_slice(sig);
        v
    }

    pub fn verify(&self) -> bool {
        let vk = match VerifyingKey::from_bytes(&self.signature_key) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let Ok::<[u8; 64], _>(sb) = self.signature.as_slice().try_into() else {
            return false;
        };
        let sig = Signature::from_bytes(&sb);
        let body = Self::body_bytes(&self.credential, &self.encryption_key, &self.signature_key);
        vk.verify(&body, &sig).is_ok()
    }
}

/// Publishable "calling card": LeafNode + init_key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPackage {
    pub leaf: LeafNode,
    /// X25519 public used for Welcome encryption when this member is added.
    pub init_key: [u8; 32],
    /// Self-signature over `leaf || init_key`.
    pub signature: Vec<u8>,
}

impl KeyPackage {
    pub fn tbs_bytes(leaf: &LeafNode, init_key: &[u8; 32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(256);
        v.extend_from_slice(b"MLS-KeyPackage-v1");
        v.extend_from_slice(&LeafNode::body_bytes(
            &leaf.credential,
            &leaf.encryption_key,
            &leaf.signature_key,
        ));
        v.extend_from_slice(&leaf.signature);
        v.extend_from_slice(init_key);
        v
    }

    pub fn verify(&self) -> bool {
        if !self.leaf.verify() {
            return false;
        }
        let vk = match VerifyingKey::from_bytes(&self.leaf.signature_key) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let Ok::<[u8; 64], _>(sb) = self.signature.as_slice().try_into() else {
            return false;
        };
        let sig = Signature::from_bytes(&sb);
        let body = Self::tbs_bytes(&self.leaf, &self.init_key);
        vk.verify(&body, &sig).is_ok()
    }
}

/// The private counterparts, held locally by the member until they're
/// added to a group (or until the KP expires and is rotated).
pub struct KeyPackageBundle {
    pub kp: KeyPackage,
    pub secrets: LeafSecrets,
}

pub struct LeafSecrets {
    pub encryption_priv: [u8; 32],
    pub init_priv: [u8; 32],
    pub signing: SigningKey,
}

impl LeafSecrets {
    pub fn signing_pub(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }
}

impl KeyPackageBundle {
    /// Generate a fresh KeyPackageBundle for the given credential.
    pub fn generate(credential: &str) -> Self {
        // Encryption key (leaf-level TreeKEM).
        let mut enc_seed = [0u8; 32];
        OsRng.fill_bytes(&mut enc_seed);
        let enc_priv = X25519Secret::from(enc_seed);
        let enc_pub = X25519Public::from(&enc_priv);

        // Init key (Welcome target).
        let mut init_seed = [0u8; 32];
        OsRng.fill_bytes(&mut init_seed);
        let init_priv = X25519Secret::from(init_seed);
        let init_pub = X25519Public::from(&init_priv);

        // Signing key.
        let signing = SigningKey::generate(&mut OsRng);
        let sig_pub = signing.verifying_key().to_bytes();

        // Build + self-sign LeafNode.
        let leaf_body = LeafNode::body_bytes(credential, enc_pub.as_bytes(), &sig_pub);
        let leaf_sig = signing.sign(&leaf_body).to_bytes().to_vec();
        let leaf = LeafNode {
            credential: credential.to_string(),
            encryption_key: *enc_pub.as_bytes(),
            signature_key: sig_pub,
            signature: leaf_sig,
        };

        // Sign the KeyPackage body.
        let kp_body = KeyPackage::tbs_bytes(&leaf, init_pub.as_bytes());
        let kp_sig = signing.sign(&kp_body).to_bytes().to_vec();

        let kp = KeyPackage {
            leaf,
            init_key: *init_pub.as_bytes(),
            signature: kp_sig,
        };

        Self {
            kp,
            secrets: LeafSecrets {
                encryption_priv: enc_priv.to_bytes(),
                init_priv: init_priv.to_bytes(),
                signing,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keypackage_verifies() {
        let b = KeyPackageBundle::generate("alice@ex.com");
        assert!(b.kp.leaf.verify());
        assert!(b.kp.verify());
    }

    #[test]
    fn tampered_leaf_fails() {
        let mut b = KeyPackageBundle::generate("alice@ex.com");
        b.kp.leaf.credential = "eve@ex.com".to_string();
        assert!(!b.kp.leaf.verify());
        assert!(!b.kp.verify());
    }

    #[test]
    fn tampered_init_key_fails() {
        let mut b = KeyPackageBundle::generate("alice@ex.com");
        b.kp.init_key[0] ^= 0xFF;
        assert!(!b.kp.verify());
    }
}
