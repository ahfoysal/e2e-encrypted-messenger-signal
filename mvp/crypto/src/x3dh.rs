//! X3DH key agreement (simplified).
//!
//! Parties: Alice (initiator) and Bob (responder).
//!
//! Bob publishes a PreKey bundle: (IK_B, SPK_B, OPK_B).
//! Alice generates an ephemeral key EK_A and computes:
//!
//!   DH1 = DH(IK_A, SPK_B)
//!   DH2 = DH(EK_A, IK_B)
//!   DH3 = DH(EK_A, SPK_B)
//!   DH4 = DH(EK_A, OPK_B)
//!
//!   SK = KDF(DH1 || DH2 || DH3 || DH4)
//!
//! Bob reconstructs the same using his private keys and Alice's public IK_A, EK_A.
//!
//! NOTE: For MVP we skip the XEd25519 signature on SPK. In production the
//! initiator MUST verify Sig(IK_B, Encode(SPK_B)) before proceeding.

use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Long-term identity key (X25519 for MVP; real Signal uses XEd25519).
pub struct IdentityKey {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl IdentityKey {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}

/// Signed pre-key (medium-term). Signature omitted in MVP.
pub struct SignedPreKey {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl SignedPreKey {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}

/// One-time pre-key.
pub struct OneTimePreKey {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl OneTimePreKey {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}

/// Bob's published pre-key bundle (public material only).
#[derive(Clone)]
pub struct PreKeyBundle {
    pub identity: PublicKey,
    pub signed_prekey: PublicKey,
    pub one_time_prekey: PublicKey,
}

/// Output of X3DH: the 32-byte shared secret + the ephemeral public for the responder.
pub struct X3dhInitiatorOutput {
    pub shared_secret: [u8; 32],
    pub ephemeral_public: PublicKey,
}

const X3DH_INFO: &[u8] = b"Signal-MVP-X3DH-v1";

fn kdf(ikm: &[u8]) -> [u8; 32] {
    // Signal's X3DH prepends 32 bytes of 0xFF (F) as domain separation for
    // Curve25519. We follow the same convention.
    let mut salted = Vec::with_capacity(32 + ikm.len());
    salted.extend_from_slice(&[0xFFu8; 32]);
    salted.extend_from_slice(ikm);
    let hk = Hkdf::<Sha256>::new(None, &salted);
    let mut okm = [0u8; 32];
    hk.expand(X3DH_INFO, &mut okm).expect("32 bytes fits");
    okm
}

/// Alice side of X3DH. Given Bob's public bundle + Alice's identity,
/// returns (shared_secret, Alice's ephemeral public key to send to Bob).
pub fn x3dh_initiator(
    alice_ik: &IdentityKey,
    bob_bundle: &PreKeyBundle,
) -> X3dhInitiatorOutput {
    let ek = StaticSecret::random_from_rng(OsRng);
    let ek_pub = PublicKey::from(&ek);

    let dh1 = alice_ik.secret.diffie_hellman(&bob_bundle.signed_prekey);
    let dh2 = ek.diffie_hellman(&bob_bundle.identity);
    let dh3 = ek.diffie_hellman(&bob_bundle.signed_prekey);
    let dh4 = ek.diffie_hellman(&bob_bundle.one_time_prekey);

    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());
    ikm.extend_from_slice(dh4.as_bytes());

    let sk = kdf(&ikm);
    ikm.zeroize();

    X3dhInitiatorOutput { shared_secret: sk, ephemeral_public: ek_pub }
}

/// Bob side of X3DH. Given his private keys and Alice's public IK + EK,
/// returns the shared secret.
pub fn x3dh_responder(
    bob_ik: &IdentityKey,
    bob_spk: &SignedPreKey,
    bob_opk: &OneTimePreKey,
    alice_ik_pub: &PublicKey,
    alice_ek_pub: &PublicKey,
) -> [u8; 32] {
    let dh1 = bob_spk.secret.diffie_hellman(alice_ik_pub);
    let dh2 = bob_ik.secret.diffie_hellman(alice_ek_pub);
    let dh3 = bob_spk.secret.diffie_hellman(alice_ek_pub);
    let dh4 = bob_opk.secret.diffie_hellman(alice_ek_pub);

    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());
    ikm.extend_from_slice(dh4.as_bytes());

    let sk = kdf(&ikm);
    ikm.zeroize();
    sk
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x3dh_produces_same_shared_secret_on_both_sides() {
        let alice_ik = IdentityKey::generate();
        let bob_ik = IdentityKey::generate();
        let bob_spk = SignedPreKey::generate();
        let bob_opk = OneTimePreKey::generate();

        let bundle = PreKeyBundle {
            identity: bob_ik.public,
            signed_prekey: bob_spk.public,
            one_time_prekey: bob_opk.public,
        };

        let out = x3dh_initiator(&alice_ik, &bundle);
        let bob_sk = x3dh_responder(
            &bob_ik,
            &bob_spk,
            &bob_opk,
            &alice_ik.public,
            &out.ephemeral_public,
        );

        assert_eq!(out.shared_secret, bob_sk, "X3DH shared secret must match");
    }

    #[test]
    fn x3dh_different_ephemerals_produce_different_secrets() {
        let alice_ik = IdentityKey::generate();
        let bob_ik = IdentityKey::generate();
        let bob_spk = SignedPreKey::generate();
        let bob_opk = OneTimePreKey::generate();

        let bundle = PreKeyBundle {
            identity: bob_ik.public,
            signed_prekey: bob_spk.public,
            one_time_prekey: bob_opk.public,
        };

        let a = x3dh_initiator(&alice_ik, &bundle);
        let b = x3dh_initiator(&alice_ik, &bundle);
        assert_ne!(a.shared_secret, b.shared_secret);
    }
}
