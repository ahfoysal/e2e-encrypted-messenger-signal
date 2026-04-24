//! Safety numbers (Signal-style identity-key fingerprint).
//!
//! Two users looking at each other's conversation info in Signal see the
//! same 60-digit "safety number" (a.k.a. fingerprint). Its job is to let
//! the humans manually compare (in-person, over a secondary channel) and
//! detect any man-in-the-middle attack on X3DH: the relay or an active
//! adversary that swapped either party's pre-key bundle would produce a
//! different safety number, and the users would see the mismatch.
//!
//! Properties implemented here (following Signal's construction):
//!   * **Symmetric**: `compute(A, B) == compute(B, A)` — both sides see
//!     the same number no matter who computes it. Achieved by sorting
//!     the two identity keys before hashing.
//!   * **Per-pair**: binds to both identity keys so compromise of one
//!     user doesn't let you mint a collision for any other pair.
//!   * **Multi-device aware**: accepts *sets* of identity keys per user,
//!     so adding/removing a linked device rotates the safety number —
//!     which is exactly the signal we want (users should re-verify
//!     after a device change).
//!   * **Stable encoding**: 60 decimal digits, grouped in 12 blocks of
//!     5, matching the Signal UX.

use sha2::{Digest, Sha512};

const VERSION: u16 = 1;
const CONTEXT: &[u8] = b"Signal-MVP-SafetyNumber-v1";
const DIGITS: usize = 60;

/// A user's "identity" for safety-number purposes: a stable handle + the
/// set of X25519 identity public keys across all their devices.
#[derive(Debug, Clone)]
pub struct IdentityProfile<'a> {
    pub handle: &'a str,
    pub identity_keys: Vec<[u8; 32]>,
}

/// Compute the 60-digit safety number for a pair of users. Returns a
/// canonical spaced string like `"12345 67890 ... 12345"` (12 groups of
/// 5 digits). Order-independent: `compute(a, b) == compute(b, a)`.
pub fn compute(a: &IdentityProfile<'_>, b: &IdentityProfile<'_>) -> String {
    // Sort the two inputs canonically by the hash of their identity set —
    // this way the pair is order-independent without forcing the caller
    // to know which side "goes first".
    let (lo, hi) = canonical_pair(a, b);

    let mut hasher = Sha512::new();
    hasher.update(CONTEXT);
    hasher.update(VERSION.to_be_bytes());
    absorb_profile(&mut hasher, lo);
    absorb_profile(&mut hasher, hi);
    let digest = hasher.finalize();

    let digits = digits_from_digest(&digest, DIGITS);
    format_grouped(&digits, 5, ' ')
}

/// Lower-level: just the digest bytes (no decimal encoding). Handy for
/// tests that want to compare raw fingerprints, or for UI that wants a
/// QR-code binary.
pub fn compute_digest(a: &IdentityProfile<'_>, b: &IdentityProfile<'_>) -> [u8; 64] {
    let (lo, hi) = canonical_pair(a, b);
    let mut hasher = Sha512::new();
    hasher.update(CONTEXT);
    hasher.update(VERSION.to_be_bytes());
    absorb_profile(&mut hasher, lo);
    absorb_profile(&mut hasher, hi);
    let out = hasher.finalize();
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&out);
    arr
}

fn canonical_pair<'r, 'a>(
    a: &'r IdentityProfile<'a>,
    b: &'r IdentityProfile<'a>,
) -> (&'r IdentityProfile<'a>, &'r IdentityProfile<'a>) {
    // Hash each side's identity-key set alone (sorted for determinism)
    // and pick the ordering with the smaller hash first.
    let fa = fingerprint(a);
    let fb = fingerprint(b);
    if fa <= fb {
        (a, b)
    } else {
        (b, a)
    }
}

fn fingerprint(p: &IdentityProfile<'_>) -> [u8; 64] {
    let mut keys = p.identity_keys.clone();
    keys.sort();
    keys.dedup();
    let mut hasher = Sha512::new();
    hasher.update(b"Signal-MVP-IDProfile-v1");
    hasher.update((p.handle.len() as u32).to_be_bytes());
    hasher.update(p.handle.as_bytes());
    hasher.update((keys.len() as u32).to_be_bytes());
    for k in &keys {
        hasher.update(k);
    }
    let out = hasher.finalize();
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&out);
    arr
}

fn absorb_profile(hasher: &mut Sha512, p: &IdentityProfile<'_>) {
    let fp = fingerprint(p);
    hasher.update(fp);
}

fn digits_from_digest(digest: &[u8], n_digits: usize) -> Vec<u8> {
    // Signal derives 5-digit "chunks" from consecutive 40-bit slices of
    // the hash. Here we just iterate the digest as big-endian bytes and
    // emit `digit = byte_of_state % 10`, consuming fresh bytes as needed.
    // Not bit-for-bit identical to Signal but meets the documented
    // properties (deterministic, changes on input change, good spread).
    let mut out = Vec::with_capacity(n_digits);
    let mut i = 0usize;
    while out.len() < n_digits {
        let byte = digest[i % digest.len()];
        // Mix in the round counter so we don't alias once we wrap the
        // digest.
        let d = (byte.wrapping_add((i / digest.len()) as u8)) % 10;
        out.push(d);
        i += 1;
    }
    out
}

fn format_grouped(digits: &[u8], group: usize, sep: char) -> String {
    let mut s = String::with_capacity(digits.len() + digits.len() / group);
    for (i, d) in digits.iter().enumerate() {
        if i > 0 && i % group == 0 {
            s.push(sep);
        }
        s.push((b'0' + d) as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(handle: &str, seed: u8) -> IdentityProfile<'_> {
        IdentityProfile {
            handle,
            identity_keys: vec![[seed; 32]],
        }
    }

    #[test]
    fn safety_number_is_deterministic() {
        let a = mk("alice", 1);
        let b = mk("bob", 2);
        let n1 = compute(&a, &b);
        let n2 = compute(&a, &b);
        assert_eq!(n1, n2);
    }

    #[test]
    fn safety_number_is_symmetric() {
        let a = mk("alice", 1);
        let b = mk("bob", 2);
        assert_eq!(compute(&a, &b), compute(&b, &a));
    }

    #[test]
    fn safety_number_format_is_60_digits_in_12_groups() {
        let a = mk("alice", 1);
        let b = mk("bob", 2);
        let s = compute(&a, &b);
        let groups: Vec<&str> = s.split(' ').collect();
        assert_eq!(groups.len(), 12);
        for g in &groups {
            assert_eq!(g.len(), 5);
            assert!(g.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn safety_number_changes_when_any_identity_rotates() {
        let a = mk("alice", 1);
        let b = mk("bob", 2);
        let s_before = compute(&a, &b);
        // Alice rotates her identity key (or adds a new device with a
        // different key).
        let a2 = IdentityProfile {
            handle: "alice",
            identity_keys: vec![[1u8; 32], [9u8; 32]],
        };
        let s_after = compute(&a2, &b);
        assert_ne!(s_before, s_after);
    }

    #[test]
    fn safety_number_differs_per_pair() {
        let a = mk("alice", 1);
        let b = mk("bob", 2);
        let c = mk("carol", 3);
        assert_ne!(compute(&a, &b), compute(&a, &c));
        assert_ne!(compute(&a, &b), compute(&b, &c));
    }

    #[test]
    fn adding_a_device_flips_the_safety_number() {
        // This is the M5 multi-device property: installing a new device
        // under an existing handle MUST change the safety number so the
        // peer has a chance to re-verify.
        let a1 = IdentityProfile {
            handle: "alice",
            identity_keys: vec![[1u8; 32]],
        };
        let a2 = IdentityProfile {
            handle: "alice",
            identity_keys: vec![[1u8; 32], [2u8; 32]],
        };
        let bob = mk("bob", 9);
        assert_ne!(compute(&a1, &bob), compute(&a2, &bob));
    }

    #[test]
    fn device_key_set_order_does_not_matter() {
        // Same identity-key multiset, different insertion order, must
        // still produce the same safety number.
        let a1 = IdentityProfile {
            handle: "alice",
            identity_keys: vec![[1u8; 32], [2u8; 32]],
        };
        let a2 = IdentityProfile {
            handle: "alice",
            identity_keys: vec![[2u8; 32], [1u8; 32]],
        };
        let bob = mk("bob", 9);
        assert_eq!(compute(&a1, &bob), compute(&a2, &bob));
    }
}
