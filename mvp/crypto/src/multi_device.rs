//! Multi-device support (M4 gap, finished in M5).
//!
//! A single user identity (a "handle" like "alice") can own multiple
//! devices (phone, laptop, tablet). Each device holds its *own* long-term
//! identity key and pre-key bundle — devices are never copies of each
//! other. The user identity is modeled as a set of `(device_id,
//! PreKeyBundleWire)` pairs published by the user to the relay; any
//! sender fanning out to that user MUST encrypt a separate pairwise
//! Double Ratchet message to each device.
//!
//! This also solves **self-sync**: when Alice sends from her phone, the
//! relay fans the message out to *every device of the recipient* AND to
//! *all of Alice's other devices* (so her laptop sees what she typed).
//!
//! This module is pure data: it defines the on-wire shape of a device
//! roster and a plaintext fan-out plan. It deliberately does not touch
//! the ratchet — each pairwise session is constructed exactly like in
//! M1/M2, just indexed by `(handle, device_id)` instead of `handle`.
//!
//! Threat model: the roster itself is public (the relay stores it),
//! but the recipient of any message verifies the certificate chain via
//! safety numbers (`safety_numbers.rs`) — a relay that silently injects
//! a ghost device will flip the user's safety number.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::wire::BundleWire;

/// Stable globally-unique address for a single device within a handle.
pub type DeviceId = u32;

/// One device entry in a user's roster.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceEntry {
    pub device_id: DeviceId,
    /// The bundle this device published (its own identity key, SPK, OPK).
    pub bundle: BundleWire,
    /// Optional human label, e.g. "phone" / "laptop" — hint only.
    pub label: Option<String>,
}

/// The full public roster for a user. Relay stores one per handle.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRoster {
    pub handle: String,
    /// Devices keyed by `device_id` for deterministic iteration.
    pub devices: BTreeMap<DeviceId, DeviceEntry>,
}

impl DeviceRoster {
    pub fn new(handle: impl Into<String>) -> Self {
        Self {
            handle: handle.into(),
            devices: BTreeMap::new(),
        }
    }

    pub fn upsert(&mut self, entry: DeviceEntry) {
        self.devices.insert(entry.device_id, entry);
    }

    pub fn remove(&mut self, device_id: DeviceId) -> Option<DeviceEntry> {
        self.devices.remove(&device_id)
    }

    pub fn device_ids(&self) -> Vec<DeviceId> {
        self.devices.keys().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Stable fingerprint over all device identity keys. Used by the
    /// safety-number code to detect silent device injection.
    pub fn identity_key_set(&self) -> Vec<[u8; 32]> {
        // `BTreeMap` iterates in ascending `device_id` order, so the
        // output is canonical without further sorting.
        let mut out = Vec::with_capacity(self.devices.len());
        for entry in self.devices.values() {
            // `identity` in BundleWire is base64 of the 32-byte X25519
            // public key. Decode best-effort — bundles that fail to
            // decode are skipped (they would already be unusable).
            if let Ok(pub_bytes) = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &entry.bundle.identity,
            ) {
                if let Ok(arr) = <[u8; 32]>::try_from(pub_bytes.as_slice()) {
                    out.push(arr);
                }
            }
        }
        out
    }
}

/// A fan-out plan produced by a sender before dispatch. The sender runs
/// a pairwise ratchet encrypt per `(recipient_handle, recipient_device)`
/// AND per `(own_handle, own_other_device)` so every device involved —
/// including the sender's other devices — sees the cleartext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanoutPlan {
    /// Each target to deliver a separately-encrypted envelope to.
    pub targets: Vec<FanoutTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanoutTarget {
    pub handle: String,
    pub device_id: DeviceId,
    /// Marks "this is me on another device" so the UI can render it
    /// in the sender's own thread ("sent from phone") rather than as a
    /// received message.
    pub self_sync: bool,
}

/// Compute the fan-out for a single outgoing message.
///
/// * `sender_handle` / `sender_device`  — who is sending, on which device.
///   Other devices belonging to the same handle will receive self-sync copies.
/// * `sender_roster` — the sender's own device roster (to find its other devices).
/// * `recipient_roster` — the peer's roster (or, for groups, one of several).
///
/// The sender's *own* device is excluded from the fan-out (it already
/// has the plaintext in local storage).
pub fn plan_fanout(
    sender_handle: &str,
    sender_device: DeviceId,
    sender_roster: &DeviceRoster,
    recipient_roster: &DeviceRoster,
) -> FanoutPlan {
    let mut targets = Vec::new();

    // Recipient devices — normal fan-out.
    for &did in recipient_roster.devices.keys() {
        targets.push(FanoutTarget {
            handle: recipient_roster.handle.clone(),
            device_id: did,
            self_sync: false,
        });
    }

    // Sender's OTHER devices — self-sync.
    for &did in sender_roster.devices.keys() {
        if did == sender_device {
            continue;
        }
        targets.push(FanoutTarget {
            handle: sender_handle.to_string(),
            device_id: did,
            self_sync: true,
        });
    }

    FanoutPlan { targets }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signed_prekey::IdentitySigningKey;
    use crate::x3dh::{IdentityKey, OneTimePreKey, PreKeyBundle, SignedPreKey};

    fn mk_entry(device_id: DeviceId, label: &str) -> DeviceEntry {
        let ik = IdentityKey::generate();
        let isk = IdentitySigningKey::generate();
        let spk = SignedPreKey::generate();
        let opk = OneTimePreKey::generate();
        let spk_sig = isk.sign_spk(&spk.public);
        let bundle = PreKeyBundle {
            identity: ik.public,
            identity_signing: isk.verifying,
            signed_prekey: spk.public,
            spk_signature: spk_sig,
            one_time_prekey: opk.public,
        };
        DeviceEntry {
            device_id,
            bundle: BundleWire::from_bundle(&bundle),
            label: Some(label.to_string()),
        }
    }

    #[test]
    fn roster_upsert_and_list() {
        let mut r = DeviceRoster::new("alice");
        r.upsert(mk_entry(1, "phone"));
        r.upsert(mk_entry(2, "laptop"));
        assert_eq!(r.len(), 2);
        assert_eq!(r.device_ids(), vec![1, 2]);
        // Upsert with same id overwrites (re-registration).
        r.upsert(mk_entry(1, "new-phone"));
        assert_eq!(r.len(), 2);
        assert_eq!(r.devices[&1].label.as_deref(), Some("new-phone"));
    }

    #[test]
    fn roster_remove() {
        let mut r = DeviceRoster::new("alice");
        r.upsert(mk_entry(1, "phone"));
        r.upsert(mk_entry(2, "laptop"));
        assert!(r.remove(1).is_some());
        assert_eq!(r.device_ids(), vec![2]);
        assert!(r.remove(99).is_none());
    }

    #[test]
    fn fanout_includes_self_sync_but_not_self() {
        let mut alice = DeviceRoster::new("alice");
        alice.upsert(mk_entry(1, "phone"));
        alice.upsert(mk_entry(2, "laptop"));
        alice.upsert(mk_entry(3, "tablet"));

        let mut bob = DeviceRoster::new("bob");
        bob.upsert(mk_entry(1, "phone"));
        bob.upsert(mk_entry(7, "desktop"));

        let plan = plan_fanout("alice", 1, &alice, &bob);
        // Expect: bob/1, bob/7 (normal) + alice/2, alice/3 (self-sync).
        assert_eq!(plan.targets.len(), 4);
        let bob_targets: Vec<_> = plan.targets.iter().filter(|t| t.handle == "bob").collect();
        assert_eq!(bob_targets.len(), 2);
        assert!(bob_targets.iter().all(|t| !t.self_sync));
        let self_targets: Vec<_> = plan.targets.iter().filter(|t| t.self_sync).collect();
        assert_eq!(self_targets.len(), 2);
        assert!(self_targets.iter().all(|t| t.handle == "alice"));
        assert!(!self_targets.iter().any(|t| t.device_id == 1));
    }

    #[test]
    fn fanout_single_device_sender_has_no_self_sync() {
        let mut alice = DeviceRoster::new("alice");
        alice.upsert(mk_entry(1, "phone"));
        let mut bob = DeviceRoster::new("bob");
        bob.upsert(mk_entry(1, "phone"));

        let plan = plan_fanout("alice", 1, &alice, &bob);
        assert_eq!(plan.targets.len(), 1);
        assert_eq!(plan.targets[0].handle, "bob");
        assert!(!plan.targets[0].self_sync);
    }

    #[test]
    fn identity_key_set_is_stable_and_canonical() {
        let mut r = DeviceRoster::new("alice");
        let e1 = mk_entry(2, "laptop");
        let e2 = mk_entry(1, "phone");
        r.upsert(e1.clone());
        r.upsert(e2.clone());
        let set1 = r.identity_key_set();
        // Reinsert in different order — canonical output must be identical.
        let mut r2 = DeviceRoster::new("alice");
        r2.upsert(e2);
        r2.upsert(e1);
        let set2 = r2.identity_key_set();
        assert_eq!(set1, set2);
        assert_eq!(set1.len(), 2);
    }
}
