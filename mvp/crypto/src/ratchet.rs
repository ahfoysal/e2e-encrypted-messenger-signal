//! Double Ratchet (Signal spec, simplified).
//!
//! State machine:
//!   - Root key (RK): 32 bytes.
//!   - Sending chain key (CKs) / receiving chain key (CKr).
//!   - DH ratchet keypair: our current ephemeral DH key + their latest DH pub.
//!
//! On every outbound message we advance the sending chain (symmetric ratchet)
//! to derive a fresh message key. On receipt of a message carrying a new DH
//! public key, we perform a DH ratchet step: new DH -> new RK + new CKr, then
//! generate our own fresh DH key -> new RK + new CKs. This gives per-message
//! forward secrecy and post-compromise security.
//!
//! M2 additions:
//!   - **Skipped-message key cache** (up to `MAX_SKIP = 64` keys per chain).
//!     When a message arrives out of order, we derive and cache the message
//!     keys for the gap so they can decrypt the missing messages when they
//!     finally arrive. Also handles the cross-chain case: when a new DH pub
//!     lands, any remaining keys in the old receiving chain are cached
//!     against the *old* remote DH pub before ratcheting.
//!
//! Still simplified:
//!   - No header encryption.
//!   - AD (associated data) is a fixed constant.
//!   - Cache is a simple FIFO evicting at MAX_SKIP entries.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use std::collections::VecDeque;

use crate::CryptoError;

type HmacSha256 = Hmac<Sha256>;

const KDF_RK_INFO: &[u8] = b"Signal-MVP-Ratchet-RK-v1";
const AD: &[u8] = b"Signal-MVP-AD";
/// Maximum number of skipped message keys retained across all chains.
pub const MAX_SKIP: usize = 64;

/// Header sent alongside every ciphertext. Contains sender's current DH pub
/// and the counter `n` within the current sending chain (used for nonce).
#[derive(Clone, Debug)]
pub struct RatchetHeader {
    pub dh: PublicKey,
    pub n: u32,
    /// Number of messages in the previous sending chain (PN). Unused in MVP
    /// since we assume in-order delivery, but carried for protocol parity.
    pub pn: u32,
}

/// Full wire message: header + ciphertext.
#[derive(Clone, Debug)]
pub struct RatchetMessage {
    pub header: RatchetHeader,
    pub ciphertext: Vec<u8>,
}

/// Per-peer Double Ratchet state.
pub struct RatchetState {
    /// Our current DH keypair.
    dh_self: StaticSecret,
    dh_self_pub: PublicKey,
    /// Their latest DH public key we've seen (None until first received).
    dh_remote: Option<PublicKey>,

    /// Root key.
    rk: [u8; 32],
    /// Sending chain key.
    cks: Option<[u8; 32]>,
    /// Receiving chain key.
    ckr: Option<[u8; 32]>,

    /// Message counter in the current sending chain.
    ns: u32,
    /// Message counter in the current receiving chain.
    nr: u32,
    /// Messages sent in the *previous* sending chain.
    pns: u32,

    /// Cache of skipped message keys, keyed by (sender_dh_pub, counter).
    /// FIFO-evicted once `MAX_SKIP` entries are live.
    skipped: VecDeque<SkippedEntry>,
}

#[derive(Clone)]
struct SkippedEntry {
    dh: [u8; 32],
    n: u32,
    mk: [u8; 32],
}

impl RatchetState {
    /// Initialize Alice's side. Alice knows Bob's SPK public (used as Bob's
    /// initial DH pub). She immediately performs a DH ratchet to derive her
    /// first sending chain.
    pub fn init_alice(shared_secret: [u8; 32], bob_spk_pub: PublicKey) -> Self {
        let dh_self = StaticSecret::random_from_rng(OsRng);
        let dh_self_pub = PublicKey::from(&dh_self);

        // DH(Alice_new, Bob_spk) -> (new RK, new CKs).
        let dh_out = dh_self.diffie_hellman(&bob_spk_pub);
        let (rk, cks) = kdf_rk(&shared_secret, dh_out.as_bytes());

        Self {
            dh_self,
            dh_self_pub,
            dh_remote: Some(bob_spk_pub),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pns: 0,
            skipped: VecDeque::new(),
        }
    }

    /// Initialize Bob's side. Bob's initial DH private is his SPK private.
    pub fn init_bob(shared_secret: [u8; 32], bob_spk_secret: StaticSecret) -> Self {
        let dh_self_pub = PublicKey::from(&bob_spk_secret);
        Self {
            dh_self: bob_spk_secret,
            dh_self_pub,
            dh_remote: None,
            rk: shared_secret,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pns: 0,
            skipped: VecDeque::new(),
        }
    }

    pub fn dh_public(&self) -> PublicKey {
        self.dh_self_pub
    }

    /// Encrypt a plaintext. Advances the sending chain.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage, CryptoError> {
        let cks = self.cks.as_mut().ok_or(CryptoError::Kdf)?;
        let (next_ck, mk) = kdf_ck(cks);
        *cks = next_ck;

        let header = RatchetHeader {
            dh: self.dh_self_pub,
            n: self.ns,
            pn: self.pns,
        };

        let ciphertext = aead_encrypt(&mk, self.ns, plaintext)?;
        self.ns += 1;
        Ok(RatchetMessage { header, ciphertext })
    }

    /// Decrypt a message. Handles three cases:
    ///   1. The message was already "skipped" (its key is cached) -> use it.
    ///   2. The header carries a new DH pub -> advance old chain into the
    ///      skipped cache, DH-ratchet, then decrypt.
    ///   3. Same chain but `n > nr` -> cache keys for the gap, then decrypt.
    pub fn decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>, CryptoError> {
        // 1. Try the skipped cache first.
        if let Some(mk) = self.take_skipped(msg.header.dh.as_bytes(), msg.header.n) {
            return aead_decrypt(&mk, msg.header.n, &msg.ciphertext);
        }

        let need_ratchet = match self.dh_remote {
            Some(ref current) => current.as_bytes() != msg.header.dh.as_bytes(),
            None => true,
        };

        if need_ratchet {
            // 2. Before rotating, drain any remaining messages in the *old*
            //    receiving chain (up to header.pn) into the skipped cache,
            //    keyed by the old remote DH pub.
            if let Some(old_remote) = self.dh_remote {
                self.skip_message_keys(old_remote.to_bytes(), msg.header.pn)?;
            }
            self.dh_ratchet(&msg.header)?;
        }

        // 3. Same chain: cache any keys for counters in [nr, msg.n).
        self.skip_message_keys(msg.header.dh.to_bytes(), msg.header.n)?;

        let ckr = self.ckr.as_mut().ok_or(CryptoError::Kdf)?;
        let (next_ck, mk) = kdf_ck(ckr);
        *ckr = next_ck;

        let pt = aead_decrypt(&mk, msg.header.n, &msg.ciphertext)?;
        self.nr += 1;
        Ok(pt)
    }

    /// Walk the current receiving chain forward until `self.nr == until`,
    /// caching each derived message key under `dh` so the skipped messages
    /// can still be decrypted when they arrive.
    fn skip_message_keys(&mut self, dh: [u8; 32], until: u32) -> Result<(), CryptoError> {
        if self.ckr.is_none() {
            return Ok(());
        }
        if until.saturating_sub(self.nr) as usize > MAX_SKIP {
            // Too big a gap — refuse rather than OOM.
            return Err(CryptoError::InvalidMessage);
        }
        while self.nr < until {
            let ckr = self.ckr.as_mut().ok_or(CryptoError::Kdf)?;
            let (next_ck, mk) = kdf_ck(ckr);
            *ckr = next_ck;
            self.store_skipped(dh, self.nr, mk);
            self.nr += 1;
        }
        Ok(())
    }

    fn store_skipped(&mut self, dh: [u8; 32], n: u32, mk: [u8; 32]) {
        if self.skipped.len() >= MAX_SKIP {
            // FIFO eviction — oldest skipped key drops.
            self.skipped.pop_front();
        }
        self.skipped.push_back(SkippedEntry { dh, n, mk });
    }

    fn take_skipped(&mut self, dh: &[u8; 32], n: u32) -> Option<[u8; 32]> {
        let pos = self
            .skipped
            .iter()
            .position(|e| &e.dh == dh && e.n == n)?;
        Some(self.skipped.remove(pos).unwrap().mk)
    }

    /// DH ratchet step triggered by receiving a new remote DH pub.
    fn dh_ratchet(&mut self, header: &RatchetHeader) -> Result<(), CryptoError> {
        self.pns = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dh_remote = Some(header.dh);

        // First: derive new CKr from (old RK, DH(self_priv, new_remote_pub)).
        let dh_out = self.dh_self.diffie_hellman(&header.dh);
        let (new_rk, new_ckr) = kdf_rk(&self.rk, dh_out.as_bytes());
        self.rk = new_rk;
        self.ckr = Some(new_ckr);

        // Rotate our DH keypair, then derive new CKs from
        // (new RK, DH(new_self_priv, new_remote_pub)).
        let new_secret = StaticSecret::random_from_rng(OsRng);
        let new_pub = PublicKey::from(&new_secret);
        let dh_out2 = new_secret.diffie_hellman(&header.dh);
        let (new_rk2, new_cks) = kdf_rk(&self.rk, dh_out2.as_bytes());
        self.rk = new_rk2;
        self.cks = Some(new_cks);
        self.dh_self = new_secret;
        self.dh_self_pub = new_pub;

        Ok(())
    }

    /// Snapshot current root key — for testing that it actually rotates.
    #[cfg(test)]
    pub(crate) fn root_key(&self) -> [u8; 32] {
        self.rk
    }
}

/// KDF_RK: combine root key + DH output -> (new RK, new CK).
fn kdf_rk(rk: &[u8; 32], dh_out: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(rk), dh_out);
    let mut okm = [0u8; 64];
    hk.expand(KDF_RK_INFO, &mut okm).expect("64 bytes fits");
    let mut new_rk = [0u8; 32];
    let mut new_ck = [0u8; 32];
    new_rk.copy_from_slice(&okm[..32]);
    new_ck.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (new_rk, new_ck)
}

/// KDF_CK: chain-key step. Signal uses HMAC with fixed constants (0x01, 0x02).
fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut mk_mac = <HmacSha256 as Mac>::new_from_slice(ck).expect("32 bytes");
    mk_mac.update(&[0x01]);
    let mk = mk_mac.finalize().into_bytes();

    let mut ck_mac = <HmacSha256 as Mac>::new_from_slice(ck).expect("32 bytes");
    ck_mac.update(&[0x02]);
    let next_ck = ck_mac.finalize().into_bytes();

    let mut mk_arr = [0u8; 32];
    let mut ck_arr = [0u8; 32];
    mk_arr.copy_from_slice(&mk);
    ck_arr.copy_from_slice(&next_ck);
    (ck_arr, mk_arr)
}

fn nonce_from_counter(n: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[8..].copy_from_slice(&n.to_be_bytes());
    nonce
}

fn aead_encrypt(mk: &[u8; 32], n: u32, pt: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(mk));
    let nonce_bytes = nonce_from_counter(n);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .encrypt(nonce, Payload { msg: pt, aad: AD })
        .map_err(|_| CryptoError::Aead)
}

fn aead_decrypt(mk: &[u8; 32], n: u32, ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(mk));
    let nonce_bytes = nonce_from_counter(n);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, Payload { msg: ct, aad: AD })
        .map_err(|_| CryptoError::Aead)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signed_prekey::IdentitySigningKey;
    use crate::x3dh::{
        x3dh_initiator, x3dh_responder, IdentityKey, OneTimePreKey, PreKeyBundle, SignedPreKey,
    };

    fn handshake() -> (RatchetState, RatchetState) {
        let alice_ik = IdentityKey::generate();
        let bob_ik = IdentityKey::generate();
        let bob_id_sign = IdentitySigningKey::generate();
        let bob_spk = SignedPreKey::generate();
        let bob_opk = OneTimePreKey::generate();

        let spk_sig = bob_id_sign.sign_spk(&bob_spk.public);
        let bundle = PreKeyBundle {
            identity: bob_ik.public,
            identity_signing: bob_id_sign.verifying,
            signed_prekey: bob_spk.public,
            spk_signature: spk_sig,
            one_time_prekey: bob_opk.public,
        };

        let out = x3dh_initiator(&alice_ik, &bundle).unwrap();
        let bob_sk = x3dh_responder(
            &bob_ik,
            &bob_spk,
            &bob_opk,
            &alice_ik.public,
            &out.ephemeral_public,
        );
        assert_eq!(out.shared_secret, bob_sk);

        let alice = RatchetState::init_alice(out.shared_secret, bob_spk.public);
        // Bob uses his SPK secret as the initial DH private.
        let bob = RatchetState::init_bob(bob_sk, bob_spk.secret);
        (alice, bob)
    }

    #[test]
    fn round_trip_single_message() {
        let (mut alice, mut bob) = handshake();
        let msg = alice.encrypt(b"hello bob").unwrap();
        let pt = bob.decrypt(&msg).unwrap();
        assert_eq!(pt, b"hello bob");
    }

    #[test]
    fn ping_pong_rotates_keys() {
        let (mut alice, mut bob) = handshake();

        let mut prev_roots: Vec<[u8; 32]> = Vec::new();

        // 5 round-trips, alternating sender.
        for i in 0..5 {
            let a_pt = format!("alice->bob #{i}");
            let m = alice.encrypt(a_pt.as_bytes()).unwrap();
            let got = bob.decrypt(&m).unwrap();
            assert_eq!(got, a_pt.as_bytes());
            prev_roots.push(bob.root_key());

            let b_pt = format!("bob->alice #{i}");
            let m = bob.encrypt(b_pt.as_bytes()).unwrap();
            let got = alice.decrypt(&m).unwrap();
            assert_eq!(got, b_pt.as_bytes());
            prev_roots.push(alice.root_key());
        }

        // All snapshotted root keys must be distinct -> the DH ratchet
        // actually rotated state on every turn.
        for i in 0..prev_roots.len() {
            for j in (i + 1)..prev_roots.len() {
                assert_ne!(prev_roots[i], prev_roots[j], "root key must rotate");
            }
        }
    }

    #[test]
    fn tampering_is_detected() {
        let (mut alice, mut bob) = handshake();
        let mut msg = alice.encrypt(b"secret").unwrap();
        // flip a bit in the ciphertext
        msg.ciphertext[0] ^= 0x01;
        assert!(bob.decrypt(&msg).is_err());
    }

    #[test]
    fn out_of_order_same_chain_decrypts() {
        // Alice sends 4 messages; Bob receives them in order 0, 2, 1, 3.
        let (mut alice, mut bob) = handshake();
        let m0 = alice.encrypt(b"zero").unwrap();
        let m1 = alice.encrypt(b"one").unwrap();
        let m2 = alice.encrypt(b"two").unwrap();
        let m3 = alice.encrypt(b"three").unwrap();

        assert_eq!(bob.decrypt(&m0).unwrap(), b"zero");
        // Skip m1 — decrypt m2 first. Bob should cache m1's key.
        assert_eq!(bob.decrypt(&m2).unwrap(), b"two");
        // Now the late m1 can still be decrypted from the cache.
        assert_eq!(bob.decrypt(&m1).unwrap(), b"one");
        assert_eq!(bob.decrypt(&m3).unwrap(), b"three");
    }

    #[test]
    fn out_of_order_across_dh_ratchet() {
        // Alice sends two, Bob only receives the 2nd; Alice then replies
        // triggering a ratchet on Bob's side; the late 1st message from the
        // old chain still decrypts from the skipped cache.
        let (mut alice, mut bob) = handshake();
        let late = alice.encrypt(b"late-from-old-chain").unwrap();
        let m1 = alice.encrypt(b"second").unwrap();
        // Bob gets m1 first (skips `late` with n=0).
        assert_eq!(bob.decrypt(&m1).unwrap(), b"second");

        // Bob replies -> rotates his DH key.
        let b_reply = bob.encrypt(b"bob-reply").unwrap();
        assert_eq!(alice.decrypt(&b_reply).unwrap(), b"bob-reply");

        // Now the very-late `late` message from Alice's *previous* chain
        // arrives. Its DH pub matches the old remote DH Bob cached against.
        assert_eq!(bob.decrypt(&late).unwrap(), b"late-from-old-chain");
    }

    #[test]
    fn gap_larger_than_max_skip_is_rejected() {
        let (mut alice, mut bob) = handshake();
        // Burn through MAX_SKIP + 2 messages on Alice's side.
        let mut last = None;
        for _ in 0..(MAX_SKIP + 2) {
            last = Some(alice.encrypt(b"x").unwrap());
        }
        // Bob tries to jump to the last one, skipping MAX_SKIP+1 keys.
        let err = bob.decrypt(&last.unwrap()).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidMessage));
    }

    #[test]
    fn multiple_sends_same_chain() {
        // Alice sends three in a row before Bob replies — each uses the
        // same sending chain but a fresh message key (counter increments).
        let (mut alice, mut bob) = handshake();
        for i in 0..3u32 {
            let pt = format!("burst {i}");
            let m = alice.encrypt(pt.as_bytes()).unwrap();
            assert_eq!(m.header.n, i);
            let got = bob.decrypt(&m).unwrap();
            assert_eq!(got, pt.as_bytes());
        }
    }
}
