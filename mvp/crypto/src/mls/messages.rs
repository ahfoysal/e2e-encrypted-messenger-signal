//! MLS wire messages — Proposals, Commit, Welcome, application messages.
//!
//! RFC 9420 has an elaborate framed-message layer (`MLSMessage`,
//! `PublicMessage`, `PrivateMessage`, `FramedContent`, …). We collapse
//! that into a single `MlsMessage` enum — the distinctions (`encrypted_
//! sender_data`, `content_auth`, etc.) aren't load-bearing for our
//! teaching implementation because we're not trying to hide sender
//! identity within the group (sealed sender operates at the transport
//! layer — see `sealed_sender.rs`).
//!
//! Wire framing uses `bincode`-compatible serde, not the MLS TLS
//! presentation language.

use serde::{Deserialize, Serialize};

use super::keypackage::KeyPackage;
use crate::CryptoError;

#[derive(Debug, thiserror::Error)]
pub enum MlsError {
    #[error("invalid mls message")]
    Invalid,
    #[error("unknown sender leaf {0}")]
    UnknownSender(usize),
    #[error("wrong epoch (expected {expected}, got {got})")]
    WrongEpoch { expected: u64, got: u64 },
    #[error("signature verification failed")]
    BadSignature,
    #[error("decryption failed")]
    Decrypt,
    #[error("group full (max {0} members)")]
    GroupFull(usize),
    #[error("member {0} is not in the group")]
    NotAMember(usize),
    #[error("member with credential {0:?} already in group")]
    AlreadyMember(String),
    #[error("key package failed verification")]
    BadKeyPackage,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// A single proposal. Only Add and Remove are implemented — Update is
/// deferred.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Proposal {
    Add { key_package: KeyPackage },
    Remove { leaf: u32 },
}

/// One encrypted path secret in a commit's update-path.
///
/// `to_node` identifies which co-path node this secret is addressed to.
/// `enc_pub` is an X25519 ephemeral public; `ct` is
/// AEAD(ChaCha20Poly1305) of the raw 32-byte path_secret under a key
/// derived from `DH(eph, co_path_node_pub)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpkeCiphertext {
    /// Which node's public key was used to seal this ciphertext. The
    /// receiver uses this to locate the matching private key.
    pub to_node: u32,
    /// Which direct-path index (0 = deepest) this path_secret seeds.
    /// Multiple HpkeCiphertexts can share the same `path_level` when
    /// a co-path node's resolution contains several sub-publics.
    pub path_level: u32,
    pub enc_pub: [u8; 32],
    pub ct: Vec<u8>,
}

/// Update-path accompanying a commit: the sender's new leaf public,
/// the full sequence of node publics on their direct path, and one
/// HPKE-style ciphertext per co-path node delivering the right path
/// secret to each sibling subtree.
///
/// Additionally, when a Commit contains Add proposals, the joiner_secret
/// is encrypted to each added member's init_key via a `Welcome` — we
/// bundle those Welcomes separately.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdatePath {
    pub sender_leaf: u32,
    /// New leaf public (X25519) for the sender after this commit.
    pub new_leaf_public: [u8; 32],
    /// Node publics for each node on the sender's direct path.
    pub path_publics: Vec<[u8; 32]>,
    /// HPKE-wrapped path secrets, one per co-path node.
    pub path_secrets: Vec<HpkeCiphertext>,
}

/// A signed Commit message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commit {
    pub group_id: String,
    pub epoch: u64,
    pub sender_leaf: u32,
    pub proposals: Vec<Proposal>,
    pub update_path: UpdatePath,
    /// Ed25519 signature by the sender over the TBS-encoded commit.
    pub signature: Vec<u8>,
}

impl Commit {
    pub fn tbs(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(256);
        v.extend_from_slice(b"MLS-Commit-TBS-v1");
        v.extend_from_slice(self.group_id.as_bytes());
        v.extend_from_slice(&self.epoch.to_be_bytes());
        v.extend_from_slice(&self.sender_leaf.to_be_bytes());
        // Proposals: include a stable encoding.
        let prop_bytes = serde_json::to_vec(&self.proposals).expect("ser proposals");
        v.extend_from_slice(&(prop_bytes.len() as u32).to_be_bytes());
        v.extend_from_slice(&prop_bytes);
        let up_bytes = serde_json::to_vec(&self.update_path).expect("ser update_path");
        v.extend_from_slice(&(up_bytes.len() as u32).to_be_bytes());
        v.extend_from_slice(&up_bytes);
        v
    }
}

/// A Welcome delivered to each newly-added member. Contains enough
/// public state for the new member to reconstruct the tree + the
/// joiner_secret encrypted under their KeyPackage.init_key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Welcome {
    pub group_id: String,
    /// Epoch *at which the new member joins* (i.e. the epoch the Commit
    /// transitions to).
    pub epoch: u64,
    pub tree_size: u32,
    /// Public view of the ratchet tree (one entry per node; `None`
    /// means blank). New members rebuild their local tree from this.
    pub tree_publics: Vec<Option<[u8; 32]>>,
    /// LeafNodes for every filled leaf (membership roster).
    pub leaves: Vec<Option<super::keypackage::LeafNode>>,
    /// Identifier of the joiner within `encrypted_joiner_secret`.
    pub init_key_target: [u8; 32],
    /// X25519 ephemeral public + AEAD ciphertext containing the 32-byte
    /// joiner_secret.
    pub enc_pub: [u8; 32],
    pub encrypted_joiner_secret: Vec<u8>,
    /// The leaf index assigned to the new member.
    pub assigned_leaf: u32,
}

/// An encrypted application message.
///
/// `generation` is the per-sender ratchet counter within the current
/// epoch. The receiver derives the matching message key by advancing
/// the sender's "application chain" key schedule.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlsApplicationMessage {
    pub group_id: String,
    pub epoch: u64,
    pub sender_leaf: u32,
    pub generation: u32,
    pub ciphertext: Vec<u8>,
    /// Ed25519 signature by the sender over the body.
    pub signature: Vec<u8>,
}

impl MlsApplicationMessage {
    pub fn tbs(group_id: &str, epoch: u64, sender_leaf: u32, gen: u32, ct: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(ct.len() + 64);
        v.extend_from_slice(b"MLS-App-TBS-v1");
        v.extend_from_slice(group_id.as_bytes());
        v.extend_from_slice(&epoch.to_be_bytes());
        v.extend_from_slice(&sender_leaf.to_be_bytes());
        v.extend_from_slice(&gen.to_be_bytes());
        v.extend_from_slice(ct);
        v
    }
}
