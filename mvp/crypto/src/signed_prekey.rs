//! Signed pre-key with Ed25519 signature (M2).
//!
//! The real Signal protocol uses XEdDSA so the same X25519 identity key
//! can both do DH and produce signatures. We simplify by giving each
//! participant *two* long-term keys: an X25519 `IdentityKey` (DH) and an
//! Ed25519 `IdentitySigningKey` (signatures). The signing key signs the
//! X25519 public of the signed pre-key; initiators verify this signature
//! *before* running X3DH with the bundle.
//!
//! This matches the security property the spec cares about: "the SPK
//! comes from the legitimate owner of the identity", without the extra
//! complexity of implementing XEdDSA's point-parity trick.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use x25519_dalek::PublicKey as X25519Public;

/// Long-term Ed25519 signing key. Paired with the X25519 `IdentityKey`
/// from `x3dh.rs`. In production these would be combined (XEd25519).
pub struct IdentitySigningKey {
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
}

impl IdentitySigningKey {
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    /// Produce a signature over the encoded X25519 public key of a SPK.
    pub fn sign_spk(&self, spk_public: &X25519Public) -> Signature {
        self.signing.sign(spk_public.as_bytes())
    }
}

/// Verify that `signature` is a valid Ed25519 signature, by
/// `verifying_key`, of `spk_public`'s 32-byte encoding.
///
/// Returns `Err(SpkSigError::BadSignature)` on failure — the initiator
/// MUST treat this as a hard abort and refuse to run X3DH.
pub fn verify_spk_signature(
    verifying_key: &VerifyingKey,
    spk_public: &X25519Public,
    signature: &Signature,
) -> Result<(), SpkSigError> {
    verifying_key
        .verify(spk_public.as_bytes(), signature)
        .map_err(|_| SpkSigError::BadSignature)
}

#[derive(Debug, thiserror::Error)]
pub enum SpkSigError {
    #[error("signed pre-key signature did not verify")]
    BadSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::StaticSecret;

    fn random_x25519_pub() -> X25519Public {
        let s = StaticSecret::random_from_rng(OsRng);
        X25519Public::from(&s)
    }

    #[test]
    fn valid_signature_verifies() {
        let id = IdentitySigningKey::generate();
        let spk = random_x25519_pub();
        let sig = id.sign_spk(&spk);
        assert!(verify_spk_signature(&id.verifying, &spk, &sig).is_ok());
    }

    #[test]
    fn tampered_spk_is_rejected() {
        let id = IdentitySigningKey::generate();
        let spk = random_x25519_pub();
        let sig = id.sign_spk(&spk);
        // Attacker swaps the SPK but keeps the old signature.
        let evil_spk = random_x25519_pub();
        assert!(matches!(
            verify_spk_signature(&id.verifying, &evil_spk, &sig),
            Err(SpkSigError::BadSignature)
        ));
    }

    #[test]
    fn wrong_identity_is_rejected() {
        let victim = IdentitySigningKey::generate();
        let attacker = IdentitySigningKey::generate();
        let spk = random_x25519_pub();
        let attacker_sig = attacker.sign_spk(&spk);
        // Bundle claims victim's identity but carries attacker's signature.
        assert!(matches!(
            verify_spk_signature(&victim.verifying, &spk, &attacker_sig),
            Err(SpkSigError::BadSignature)
        ));
    }
}
