//! MlsGroup — per-member group state machine.
//!
//! Lifecycle:
//!
//! ```text
//!   create ────────────▶ epoch 0 (creator-only)
//!     │
//!     ▼
//!   add(kp)/remove(leaf)            ◀────── process_commit()
//!     │                                        ▲
//!     ▼                                        │
//!   Commit + Welcome ──────────────────────────┘
//!     │
//!     ▼
//!   epoch N+1 (all members reconverge on same epoch_secret)
//! ```
//!
//! Key schedule per epoch:
//!
//! ```text
//!   commit_secret = root path_secret produced by TreeKEM
//!   joiner_secret = HKDF-Extract(salt=0, ikm=commit_secret)
//!   epoch_secret  = HKDF-Expand(joiner_secret, "epoch" || group_id || epoch)
//!   sender_base   = HKDF-Expand(epoch_secret, "app" || leaf_idx)
//!   msg_key[i]    = HKDF-Expand(sender_base advance-chain, "key", i)
//! ```
//!
//! We keep a simple per-sender counter (`generation`) and re-derive
//! message keys from the sender_base each time (so out-of-order within
//! an epoch decodes by counter). This is simpler than a full chain
//! ratchet and fine for teaching — message keys are independent by `i`.

use std::collections::HashMap;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use super::keypackage::{KeyPackage, KeyPackageBundle, LeafNode, LeafSecrets};
use super::messages::{
    Commit, HpkeCiphertext, MlsApplicationMessage, MlsError, Proposal, UpdatePath, Welcome,
};
use super::treekem::{PathSecret, RatchetTree};
use crate::CryptoError;

pub type GroupId = String;
pub type MemberId = u32;

const AD: &[u8] = b"MLS-App-v1";

/// Published-by-the-committer info a new joiner uses to bootstrap.
pub type GroupInfo = Welcome;

pub struct MlsGroup {
    pub group_id: GroupId,
    pub epoch: u64,
    pub own_leaf: u32,
    pub roster: Vec<Option<LeafNode>>,
    pub tree: RatchetTree,
    pub secrets: LeafSecrets,
    /// Current epoch's epoch_secret.
    epoch_secret: [u8; 32],
    /// Send counter for our own leaf in the current epoch.
    send_gen: u32,
    /// Last-seen generation per (sender_leaf) in the current epoch, for
    /// replay protection. (We accept any `gen >= last_seen`.)
    recv_gen: HashMap<u32, u32>,
}

impl MlsGroup {
    // ===================================================================
    // Creation
    // ===================================================================

    /// Create a brand-new group with `creator` as the sole member at leaf 0.
    pub fn create(group_id: &str, creator: KeyPackageBundle) -> Self {
        let mut tree = RatchetTree::new(2);
        let mut roster: Vec<Option<LeafNode>> = vec![None; tree.leaf_capacity];

        // Place the creator as leaf 0 with their encryption_key public.
        tree.set_leaf_public(0, creator.kp.leaf.encryption_key);
        roster[0] = Some(creator.kp.leaf.clone());

        // Seed the initial commit secret from random — single-member tree
        // doesn't need TreeKEM.
        let mut commit_secret = [0u8; 32];
        OsRng.fill_bytes(&mut commit_secret);

        let epoch_secret = derive_epoch_secret(&commit_secret, group_id, 0);

        Self {
            group_id: group_id.to_string(),
            epoch: 0,
            own_leaf: 0,
            roster,
            tree,
            secrets: creator.secrets,
            epoch_secret,
            send_gen: 0,
            recv_gen: HashMap::new(),
        }
    }

    // ===================================================================
    // Propose + Commit: add a new member
    // ===================================================================

    /// Commit an `Add` proposal for the given KeyPackage. Returns the
    /// Commit (broadcast to existing members) and a Welcome (delivered
    /// to the new member).
    pub fn commit_add(
        &mut self,
        kp: KeyPackage,
    ) -> Result<(Commit, Welcome), MlsError> {
        if !kp.verify() {
            return Err(MlsError::BadKeyPackage);
        }
        if self
            .roster
            .iter()
            .flatten()
            .any(|l| l.credential == kp.leaf.credential)
        {
            return Err(MlsError::AlreadyMember(kp.leaf.credential.clone()));
        }

        // 1. Find a free leaf slot — grow the tree if needed.
        let new_leaf = match self.first_blank_leaf() {
            Some(l) => l,
            None => {
                // Double tree size.
                self.grow_tree();
                self.first_blank_leaf().ok_or(MlsError::GroupFull(self.tree.leaf_capacity))?
            }
        };
        // Install the new member's public at the target leaf *before*
        // deriving our own path, so our path derivation includes the
        // correct co-path at the level where the new member sits.
        self.tree.set_leaf_public(new_leaf as usize, kp.leaf.encryption_key);
        self.roster[new_leaf as usize] = Some(kp.leaf.clone());

        // 2. Pick a fresh path secret at our own leaf and derive new
        //    keys up to the root.
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let leaf_secret = PathSecret(seed);
        let (path_publics, commit_secret_ps) =
            self.tree.derive_path(self.own_leaf as usize, leaf_secret);

        // 3. HPKE-wrap the per-level path_secret to each co-path node.
        //    `copath[i]` is the sibling of direct_path[i]; we encrypt
        //    the path_secret at *level i+1* (i.e. the secret that seeds
        //    the parent at direct_path[i]) to the PUBLIC key at the
        //    co-path node. Members in that sibling subtree will decrypt
        //    using whichever private key they hold along that subtree.
        let dp = self.tree.direct_path(self.own_leaf as usize);
        let cp = self.tree.copath(self.own_leaf as usize);

        // Re-derive path_secrets along the direct path so we know ps[i].
        let mut ps_series: Vec<PathSecret> = Vec::with_capacity(dp.len());
        {
            let mut ps = leaf_secret;
            for _ in 0..dp.len() {
                ps = ps.next();
                ps_series.push(ps);
            }
        }

        let path_secrets_enc = build_update_path_ciphertexts(&self.tree, &cp, &ps_series)?;

        // Commit secret = one more advance past the root-level path
        // secret (matches what derive_path returned).
        let commit_secret = commit_secret_ps.0;

        // 4. Build the new leaf public for our leaf (it was overwritten
        //    by derive_path with the fresh encryption key).
        let new_leaf_public = self
            .tree
            .node_public(RatchetTree::leaf_to_node(self.own_leaf as usize))
            .expect("own leaf just set");

        let proposals = vec![Proposal::Add { key_package: kp.clone() }];
        let update_path = UpdatePath {
            sender_leaf: self.own_leaf,
            new_leaf_public,
            path_publics,
            path_secrets: path_secrets_enc,
        };

        // 5. Sign the commit.
        let mut commit = Commit {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            sender_leaf: self.own_leaf,
            proposals,
            update_path,
            signature: Vec::new(),
        };
        commit.signature = self.secrets.signing.sign(&commit.tbs()).to_bytes().to_vec();

        // 6. Advance our own epoch.
        let new_epoch = self.epoch + 1;
        let new_epoch_secret = derive_epoch_secret(&commit_secret, &self.group_id, new_epoch);

        // 7. Build the Welcome. We encrypt the *joiner_secret* (= the
        //    commit_secret for the new epoch; new joiner doesn't know
        //    previous epochs but starts fresh at `new_epoch`) to the
        //    added member's init_key.
        let wc_ct = hpke_seal(&kp.init_key, &commit_secret)?;

        // Update our own tree+roster key material *after* we've captured
        // what we needed for the commit body.
        self.epoch = new_epoch;
        self.epoch_secret = new_epoch_secret;
        self.send_gen = 0;
        self.recv_gen.clear();

        let tree_publics: Vec<Option<[u8; 32]>> =
            self.tree.nodes.iter().map(|n| n.public).collect();

        let welcome = Welcome {
            group_id: self.group_id.clone(),
            epoch: new_epoch,
            tree_size: self.tree.leaf_capacity as u32,
            tree_publics,
            leaves: self.roster.clone(),
            init_key_target: kp.init_key,
            enc_pub: wc_ct.0,
            encrypted_joiner_secret: wc_ct.1,
            assigned_leaf: new_leaf as u32,
        };

        Ok((commit, welcome))
    }

    // ===================================================================
    // Commit: remove a member
    // ===================================================================

    pub fn commit_remove(&mut self, target_leaf: u32) -> Result<Commit, MlsError> {
        if self.roster.get(target_leaf as usize).and_then(|x| x.as_ref()).is_none() {
            return Err(MlsError::NotAMember(target_leaf as usize));
        }
        if target_leaf == self.own_leaf {
            return Err(MlsError::Invalid);
        }

        // 1. Blank the leaf (and ancestors) first so our direct-path
        //    derivation doesn't encrypt to the removed node.
        self.tree.blank_leaf(target_leaf as usize);
        self.roster[target_leaf as usize] = None;

        // 2. Derive a fresh path from our leaf.
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let leaf_secret = PathSecret(seed);
        let (path_publics, commit_secret_ps) =
            self.tree.derive_path(self.own_leaf as usize, leaf_secret);

        let dp = self.tree.direct_path(self.own_leaf as usize);
        let cp = self.tree.copath(self.own_leaf as usize);

        let mut ps_series: Vec<PathSecret> = Vec::with_capacity(dp.len());
        {
            let mut ps = leaf_secret;
            for _ in 0..dp.len() {
                ps = ps.next();
                ps_series.push(ps);
            }
        }

        let path_secrets_enc = build_update_path_ciphertexts(&self.tree, &cp, &ps_series)?;

        let commit_secret = commit_secret_ps.0;
        let new_leaf_public = self
            .tree
            .node_public(RatchetTree::leaf_to_node(self.own_leaf as usize))
            .expect("own leaf");

        let proposals = vec![Proposal::Remove { leaf: target_leaf }];
        let update_path = UpdatePath {
            sender_leaf: self.own_leaf,
            new_leaf_public,
            path_publics,
            path_secrets: path_secrets_enc,
        };

        let mut commit = Commit {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            sender_leaf: self.own_leaf,
            proposals,
            update_path,
            signature: Vec::new(),
        };
        commit.signature = self.secrets.signing.sign(&commit.tbs()).to_bytes().to_vec();

        self.epoch += 1;
        self.epoch_secret = derive_epoch_secret(&commit_secret, &self.group_id, self.epoch);
        self.send_gen = 0;
        self.recv_gen.clear();

        Ok(commit)
    }

    // ===================================================================
    // Receive Commit
    // ===================================================================

    pub fn process_commit(&mut self, commit: &Commit) -> Result<(), MlsError> {
        if commit.group_id != self.group_id {
            return Err(MlsError::Invalid);
        }
        if commit.epoch != self.epoch {
            return Err(MlsError::WrongEpoch {
                expected: self.epoch,
                got: commit.epoch,
            });
        }

        // 1. Verify signature from sender's leaf.
        let sender_leaf = self
            .roster
            .get(commit.sender_leaf as usize)
            .and_then(|x| x.as_ref())
            .ok_or(MlsError::UnknownSender(commit.sender_leaf as usize))?;
        let vk = VerifyingKey::from_bytes(&sender_leaf.signature_key)
            .map_err(|_| MlsError::BadSignature)?;
        let sig_bytes: [u8; 64] = commit
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| MlsError::BadSignature)?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(&commit.tbs(), &sig)
            .map_err(|_| MlsError::BadSignature)?;

        // 2. Apply proposals to local roster+tree (pre-path updates).
        //    We must mirror the committer's pre-path state.
        for prop in &commit.proposals {
            match prop {
                Proposal::Add { key_package } => {
                    if !key_package.verify() {
                        return Err(MlsError::BadKeyPackage);
                    }
                    // Find/grow leaf slot — same rule as committer.
                    let leaf = match self.first_blank_leaf() {
                        Some(l) => l,
                        None => {
                            self.grow_tree();
                            self.first_blank_leaf().ok_or(MlsError::Invalid)?
                        }
                    };
                    self.tree.set_leaf_public(leaf as usize, key_package.leaf.encryption_key);
                    self.roster[leaf as usize] = Some(key_package.leaf.clone());
                }
                Proposal::Remove { leaf } => {
                    if self.roster.get(*leaf as usize).and_then(|x| x.as_ref()).is_none() {
                        return Err(MlsError::NotAMember(*leaf as usize));
                    }
                    self.tree.blank_leaf(*leaf as usize);
                    self.roster[*leaf as usize] = None;
                }
            }
        }

        // 3. Apply the sender's update-path.
        //    We must determine which (if any) HPKE ciphertext in
        //    `update_path.path_secrets` is addressed to a node we hold
        //    a private key for. That tells us the injection level.
        let sender_leaf_idx = commit.sender_leaf as usize;
        let dp = self.tree.direct_path(sender_leaf_idx);
        let _cp = self.tree.copath(sender_leaf_idx);

        // First set the sender's new leaf public.
        self.tree
            .set_leaf_public(sender_leaf_idx, commit.update_path.new_leaf_public);
        // Update roster's encryption_key mirror too (so later adds use it).
        if let Some(l) = self.roster.get_mut(sender_leaf_idx).and_then(|x| x.as_mut()) {
            l.encryption_key = commit.update_path.new_leaf_public;
        }

        // Find injection level.
        let commit_secret = if sender_leaf_idx == self.own_leaf as usize {
            // We issued this commit — shouldn't normally call process_commit
            // on our own commit, but handle it gracefully.
            return Err(MlsError::Invalid);
        } else {
            let mut injected: Option<(usize, PathSecret)> = None;
            for ct in &commit.update_path.path_secrets {
                // Does this ciphertext target a node whose private key
                // we hold? Walk from our own leaf up and check.
                let target_node = ct.to_node as usize;
                if let Some(priv_bytes) = self.private_on_our_path(target_node) {
                    if let Ok(ps_bytes) = hpke_open(&priv_bytes, &ct.enc_pub, &ct.ct) {
                        injected = Some((ct.path_level as usize, PathSecret(ps_bytes)));
                        break;
                    }
                }
            }

            let (inject_level, inject_secret) = match injected {
                Some(x) => x,
                None => {
                    // No ciphertext was addressed to us — either we were
                    // just Removed, or the committer's co-path didn't
                    // include a subtree containing us. For Remove, we
                    // should have already been blanked above and this is
                    // fine (we stop here). Otherwise it's an error.
                    if self.roster.get(self.own_leaf as usize).and_then(|x| x.as_ref()).is_none() {
                        return Ok(());
                    }
                    return Err(MlsError::Decrypt);
                }
            };

            // inject_level is the index in direct_path where we inject;
            // but our `apply_path` expects injection at a given level in
            // the sender's direct path. The index `i` into the co-path
            // corresponds directly to the level in the sender's direct
            // path where we got the secret for the *parent* of cp[i] —
            // which is dp[i]. So we inject at dp's level `i`.
            let commit_secret_ps =
                self.tree
                    .apply_path(sender_leaf_idx, &commit.update_path.path_publics, inject_level, inject_secret);
            commit_secret_ps.0
        };

        self.epoch += 1;
        self.epoch_secret = derive_epoch_secret(&commit_secret, &self.group_id, self.epoch);
        self.send_gen = 0;
        self.recv_gen.clear();
        // Reference dp so it's considered used (silence warning on some
        // compilers even though we use it above).
        let _ = dp;
        Ok(())
    }

    /// Return the private key we hold at `target_node` *if* it lies on
    /// our own path-to-root (including our leaf). Used to decrypt
    /// commit ciphertexts addressed to our own leaf or to an ancestor.
    fn private_on_our_path(&self, target_node: usize) -> Option<[u8; 32]> {
        let mut n = RatchetTree::leaf_to_node(self.own_leaf as usize);
        loop {
            if n == target_node {
                return self.tree.node_private(n);
            }
            match self.tree.parent(n) {
                Some(p) => n = p,
                None => return None,
            }
        }
    }

    /// Look up a private key we hold for some node in the subtree rooted
    /// at `subtree_root`. We walk from our own leaf upward, and return
    /// the first node we find that is inside that subtree. If our leaf
    /// isn't in the subtree at all, returns None.
    #[allow(dead_code)]
    fn find_decrypt_key_for_subtree(&self, subtree_root: usize) -> Option<([u8; 32], usize)> {
        // Walk from our leaf up to the root; for each node on our path
        // check if it *is* the subtree_root or a descendant of it.
        // "Descendant of subtree_root" means: subtree_root is on our
        // node's path-to-root.
        let mut n = RatchetTree::leaf_to_node(self.own_leaf as usize);
        loop {
            // Is `subtree_root` an ancestor of `n` (or equal)?
            if self.is_ancestor_or_self(subtree_root, n) {
                // We need the private key at `n`.
                if let Some(priv_bytes) = self.tree.node_private(n) {
                    return Some((priv_bytes, n));
                }
                // No private key held at this level — shouldn't happen
                // for a well-maintained tree, but bail.
                return None;
            }
            match self.tree.parent(n) {
                Some(p) => n = p,
                None => return None,
            }
        }
    }

    fn is_ancestor_or_self(&self, ancestor: usize, node: usize) -> bool {
        if ancestor == node {
            return true;
        }
        let mut n = node;
        while let Some(p) = self.tree.parent(n) {
            if p == ancestor {
                return true;
            }
            n = p;
        }
        false
    }

    // ===================================================================
    // Process Welcome (new member joining)
    // ===================================================================

    pub fn join_from_welcome(
        welcome: &Welcome,
        bundle: KeyPackageBundle,
    ) -> Result<Self, MlsError> {
        if welcome.init_key_target != bundle.kp.init_key {
            return Err(MlsError::Invalid);
        }
        // Decrypt joiner_secret with init_priv.
        let commit_secret = hpke_open(
            &bundle.secrets.init_priv,
            &welcome.enc_pub,
            &welcome.encrypted_joiner_secret,
        )
        .map_err(|_| MlsError::Decrypt)?;

        let epoch_secret = derive_epoch_secret(&commit_secret, &welcome.group_id, welcome.epoch);

        // Rebuild the tree from the public view.
        let cap = welcome.tree_size as usize;
        let mut tree = RatchetTree::new(cap);
        // tree_publics length might differ if sender grew post-signing —
        // we trust the Welcome.
        for (i, pk) in welcome.tree_publics.iter().enumerate() {
            if i >= tree.nodes.len() {
                tree.nodes.push(Default::default());
            }
            tree.nodes[i] = super::treekem::TreeNode {
                public: *pk,
                private: None,
            };
        }
        // Install our own private encryption key at our leaf.
        let own_leaf = welcome.assigned_leaf as usize;
        let leaf_node_idx = RatchetTree::leaf_to_node(own_leaf);
        tree.nodes[leaf_node_idx].private = Some(bundle.secrets.encryption_priv);

        let mut roster = welcome.leaves.clone();
        // Ensure roster has the right length.
        if roster.len() < cap {
            roster.resize(cap, None);
        }

        Ok(Self {
            group_id: welcome.group_id.clone(),
            epoch: welcome.epoch,
            own_leaf: welcome.assigned_leaf,
            roster,
            tree,
            secrets: bundle.secrets,
            epoch_secret,
            send_gen: 0,
            recv_gen: HashMap::new(),
        })
    }

    // ===================================================================
    // Application messages
    // ===================================================================

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<MlsApplicationMessage, MlsError> {
        let gen = self.send_gen;
        self.send_gen = self.send_gen.wrapping_add(1);
        let msg_key = derive_msg_key(&self.epoch_secret, self.own_leaf, gen);
        let nonce = nonce_for(self.own_leaf, gen);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: AD })
            .map_err(|_| CryptoError::Aead)?;

        let tbs = MlsApplicationMessage::tbs(&self.group_id, self.epoch, self.own_leaf, gen, &ct);
        let sig = self.secrets.signing.sign(&tbs).to_bytes().to_vec();

        Ok(MlsApplicationMessage {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            sender_leaf: self.own_leaf,
            generation: gen,
            ciphertext: ct,
            signature: sig,
        })
    }

    pub fn decrypt(&mut self, msg: &MlsApplicationMessage) -> Result<Vec<u8>, MlsError> {
        if msg.group_id != self.group_id {
            return Err(MlsError::Invalid);
        }
        if msg.epoch != self.epoch {
            return Err(MlsError::WrongEpoch {
                expected: self.epoch,
                got: msg.epoch,
            });
        }
        let sender = self
            .roster
            .get(msg.sender_leaf as usize)
            .and_then(|x| x.as_ref())
            .ok_or(MlsError::UnknownSender(msg.sender_leaf as usize))?;
        // Verify signature.
        let vk = VerifyingKey::from_bytes(&sender.signature_key)
            .map_err(|_| MlsError::BadSignature)?;
        let sb: [u8; 64] = msg
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| MlsError::BadSignature)?;
        let sig = Signature::from_bytes(&sb);
        let tbs = MlsApplicationMessage::tbs(
            &msg.group_id,
            msg.epoch,
            msg.sender_leaf,
            msg.generation,
            &msg.ciphertext,
        );
        vk.verify(&tbs, &sig).map_err(|_| MlsError::BadSignature)?;

        // Replay check — reject generations strictly less than what we've
        // seen (within-epoch monotonicity).
        let last = self.recv_gen.get(&msg.sender_leaf).copied();
        if let Some(l) = last {
            if msg.generation < l {
                return Err(MlsError::Invalid);
            }
        }

        let key = derive_msg_key(&self.epoch_secret, msg.sender_leaf, msg.generation);
        let nonce = nonce_for(msg.sender_leaf, msg.generation);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let pt = cipher
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: &msg.ciphertext, aad: AD })
            .map_err(|_| CryptoError::Aead)?;

        self.recv_gen.insert(msg.sender_leaf, msg.generation);
        Ok(pt)
    }

    // ===================================================================
    // Helpers
    // ===================================================================

    pub fn n_members(&self) -> usize {
        self.roster.iter().filter(|x| x.is_some()).count()
    }

    fn first_blank_leaf(&self) -> Option<u32> {
        self.roster
            .iter()
            .enumerate()
            .find(|(_, x)| x.is_none())
            .map(|(i, _)| i as u32)
    }

    fn grow_tree(&mut self) {
        let old_cap = self.tree.leaf_capacity;
        let new_cap = old_cap * 2;
        let mut new_tree = RatchetTree::new(new_cap);
        // Copy leaves' publics and our leaf's private.
        for leaf in 0..old_cap {
            let old_idx = RatchetTree::leaf_to_node(leaf);
            let new_idx = RatchetTree::leaf_to_node(leaf);
            // new_tree and old tree use the same leaf->node mapping
            // when old_cap <= new_cap (even indices only), but the
            // parent structure above differs. We only preserve leaf
            // publics — interior nodes will be re-derived on the next
            // commit.
            let _ = old_idx; // same index
            new_tree.nodes[new_idx].public = self.tree.nodes[old_idx].public;
            if leaf as u32 == self.own_leaf {
                new_tree.nodes[new_idx].private = self.tree.nodes[old_idx].private;
            }
        }
        self.tree = new_tree;
        self.roster.resize(new_cap, None);
    }
}

fn build_update_path_ciphertexts(
    tree: &RatchetTree,
    copath: &[usize],
    ps_series: &[PathSecret],
) -> Result<Vec<HpkeCiphertext>, CryptoError> {
    let mut out = Vec::with_capacity(copath.len());
    for (i, sib) in copath.iter().enumerate() {
        for target_node in tree.resolution(*sib) {
            let target_pub = tree
                .node_public(target_node)
                .expect("resolution returns only non-blank nodes");
            let ct = hpke_seal(&target_pub, &ps_series[i].0)?;
            out.push(HpkeCiphertext {
                to_node: target_node as u32,
                path_level: i as u32,
                enc_pub: ct.0,
                ct: ct.1,
            });
        }
    }
    Ok(out)
}

// =======================================================================
// Key schedule helpers
// =======================================================================

fn derive_epoch_secret(commit_secret: &[u8; 32], group_id: &str, epoch: u64) -> [u8; 32] {
    let mut info = Vec::with_capacity(group_id.len() + 16);
    info.extend_from_slice(b"mls-epoch");
    info.extend_from_slice(group_id.as_bytes());
    info.extend_from_slice(&epoch.to_be_bytes());
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::from_prk(commit_secret)
        .expect("32")
        .expand(&info, &mut out)
        .expect("32");
    out
}

fn derive_msg_key(epoch_secret: &[u8; 32], leaf: u32, gen: u32) -> [u8; 32] {
    let mut info = Vec::with_capacity(32);
    info.extend_from_slice(b"mls-app-key");
    info.extend_from_slice(&leaf.to_be_bytes());
    info.extend_from_slice(&gen.to_be_bytes());
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::from_prk(epoch_secret)
        .expect("32")
        .expand(&info, &mut out)
        .expect("32");
    out
}

fn nonce_for(leaf: u32, gen: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&leaf.to_be_bytes());
    n[8..].copy_from_slice(&gen.to_be_bytes());
    n
}

// =======================================================================
// Mini-HPKE: X25519 + HKDF-SHA256 + ChaCha20Poly1305
// =======================================================================
//
// Not full RFC 9180; just enough to seal a 32-byte path_secret to an
// X25519 public key. Ephemeral-static DH: sender generates an ephemeral
// X25519 keypair, shared = DH(eph, recipient_pub), key =
// HKDF-Expand(shared, "mls-hpke"), nonce = zero. The ephemeral public
// travels alongside the ciphertext.

fn hpke_seal(recipient_pub: &[u8; 32], plaintext: &[u8]) -> Result<([u8; 32], Vec<u8>), CryptoError> {
    let mut eph_seed = [0u8; 32];
    OsRng.fill_bytes(&mut eph_seed);
    let eph_priv = X25519Secret::from(eph_seed);
    let eph_pub = X25519Public::from(&eph_priv);
    let recip = X25519Public::from(*recipient_pub);
    let shared = eph_priv.diffie_hellman(&recip);
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::from_prk(shared.as_bytes())
        .expect("32")
        .expand(b"mls-hpke-seal", &mut key)
        .expect("32");
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = [0u8; 12];
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: b"mls-hpke" })
        .map_err(|_| CryptoError::Aead)?;
    Ok((*eph_pub.as_bytes(), ct))
}

fn hpke_open(
    recipient_priv: &[u8; 32],
    eph_pub: &[u8; 32],
    ct: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let priv_key = X25519Secret::from(*recipient_priv);
    let eph = X25519Public::from(*eph_pub);
    let shared = priv_key.diffie_hellman(&eph);
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::from_prk(shared.as_bytes())
        .expect("32")
        .expand(b"mls-hpke-seal", &mut key)
        .expect("32");
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = [0u8; 12];
    let pt = cipher
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: ct, aad: b"mls-hpke" })
        .map_err(|_| CryptoError::Aead)?;
    if pt.len() != 32 {
        return Err(CryptoError::InvalidMessage);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&pt);
    Ok(out)
}

// =======================================================================
// Tests
// =======================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(name: &str) -> KeyPackageBundle {
        KeyPackageBundle::generate(name)
    }

    #[test]
    fn two_member_group_roundtrip() {
        let alice_kp = kp("alice");
        let bob_kp = kp("bob");

        let mut alice = MlsGroup::create("grp1", alice_kp);
        assert_eq!(alice.n_members(), 1);
        assert_eq!(alice.epoch, 0);

        // Alice adds Bob.
        let (commit, welcome) = alice.commit_add(bob_kp.kp.clone()).unwrap();
        assert_eq!(alice.epoch, 1);
        assert_eq!(alice.n_members(), 2);

        // Bob processes Welcome -> joins at epoch 1.
        let mut bob = MlsGroup::join_from_welcome(&welcome, bob_kp).unwrap();
        assert_eq!(bob.epoch, 1);
        assert_eq!(bob.n_members(), 2);

        // Bob and Alice share the same epoch_secret.
        assert_eq!(alice.epoch_secret, bob.epoch_secret);

        // commit's sender is alice; nobody else needs to process it
        // here because bob learned everything from Welcome.
        let _ = commit;

        // Application messages: Alice -> Bob.
        let m = alice.encrypt(b"hello mls").unwrap();
        assert_eq!(bob.decrypt(&m).unwrap(), b"hello mls");

        // Bob -> Alice.
        let m = bob.encrypt(b"hi alice").unwrap();
        assert_eq!(alice.decrypt(&m).unwrap(), b"hi alice");
    }

    #[test]
    fn three_member_group_treekem_derives_same_root() {
        let alice_kp = kp("alice");
        let bob_kp = kp("bob");
        let carol_kp = kp("carol");

        let mut alice = MlsGroup::create("grp-abc", alice_kp);

        // Add Bob.
        let (commit_b, welcome_b) = alice.commit_add(bob_kp.kp.clone()).unwrap();
        let mut bob = MlsGroup::join_from_welcome(&welcome_b, bob_kp).unwrap();
        assert_eq!(alice.epoch_secret, bob.epoch_secret);
        let _ = commit_b;

        // Alice adds Carol — now both Alice and Bob must process the
        // commit; Carol joins via Welcome.
        let (commit_c, welcome_c) = alice.commit_add(carol_kp.kp.clone()).unwrap();
        bob.process_commit(&commit_c).unwrap();
        let mut carol = MlsGroup::join_from_welcome(&welcome_c, carol_kp).unwrap();

        assert_eq!(alice.epoch, 2);
        assert_eq!(bob.epoch, 2);
        assert_eq!(carol.epoch, 2);

        // All three derive the same epoch_secret via TreeKEM.
        assert_eq!(alice.epoch_secret, bob.epoch_secret);
        assert_eq!(alice.epoch_secret, carol.epoch_secret);

        // Each can encrypt to all others.
        let m = alice.encrypt(b"to all").unwrap();
        assert_eq!(bob.decrypt(&m).unwrap(), b"to all");
        assert_eq!(carol.decrypt(&m).unwrap(), b"to all");

        let m = bob.encrypt(b"bob says hi").unwrap();
        assert_eq!(alice.decrypt(&m).unwrap(), b"bob says hi");
        assert_eq!(carol.decrypt(&m).unwrap(), b"bob says hi");

        let m = carol.encrypt(b"carol here").unwrap();
        assert_eq!(alice.decrypt(&m).unwrap(), b"carol here");
        assert_eq!(bob.decrypt(&m).unwrap(), b"carol here");
    }

    #[test]
    fn four_member_group_with_remove_evicts() {
        let a = kp("alice");
        let b = kp("bob");
        let c = kp("carol");
        let d = kp("dave");

        let mut alice = MlsGroup::create("g4", a);

        let (_, wb) = alice.commit_add(b.kp.clone()).unwrap();
        let mut bob = MlsGroup::join_from_welcome(&wb, b).unwrap();

        let (cm, wc) = alice.commit_add(c.kp.clone()).unwrap();
        bob.process_commit(&cm).unwrap();
        let mut carol = MlsGroup::join_from_welcome(&wc, c).unwrap();

        let (cm, wd) = alice.commit_add(d.kp.clone()).unwrap();
        bob.process_commit(&cm).unwrap();
        carol.process_commit(&cm).unwrap();
        let mut dave = MlsGroup::join_from_welcome(&wd, d).unwrap();

        assert_eq!(alice.epoch, 3);
        assert_eq!(alice.epoch_secret, bob.epoch_secret);
        assert_eq!(alice.epoch_secret, carol.epoch_secret);
        assert_eq!(alice.epoch_secret, dave.epoch_secret);

        // All four send + receive.
        let m = alice.encrypt(b"four-way").unwrap();
        assert_eq!(bob.decrypt(&m).unwrap(), b"four-way");
        assert_eq!(carol.decrypt(&m).unwrap(), b"four-way");
        assert_eq!(dave.decrypt(&m).unwrap(), b"four-way");

        // Alice removes Carol.
        let remove_commit = alice.commit_remove(carol.own_leaf).unwrap();
        bob.process_commit(&remove_commit).unwrap();
        // Dave processes too.
        dave.process_commit(&remove_commit).unwrap();

        assert_eq!(alice.epoch, 4);
        assert_eq!(alice.epoch_secret, bob.epoch_secret);
        assert_eq!(alice.epoch_secret, dave.epoch_secret);
        // Carol didn't process (she's out of the group) — she's still
        // at epoch 3, and the new epoch_secret differs from her view.
        assert_ne!(carol.epoch_secret, alice.epoch_secret);

        // New message after remove — Carol cannot decrypt.
        let post = alice.encrypt(b"after-remove").unwrap();
        assert_eq!(bob.decrypt(&post).unwrap(), b"after-remove");
        assert_eq!(dave.decrypt(&post).unwrap(), b"after-remove");
        assert!(carol.decrypt(&post).is_err()); // wrong epoch / can't verify
    }

    #[test]
    fn tampered_application_rejected() {
        let a = kp("alice");
        let b = kp("bob");
        let mut alice = MlsGroup::create("x", a);
        let (_, w) = alice.commit_add(b.kp.clone()).unwrap();
        let mut bob = MlsGroup::join_from_welcome(&w, b).unwrap();
        let mut m = alice.encrypt(b"real").unwrap();
        m.ciphertext[0] ^= 0xFF;
        assert!(bob.decrypt(&m).is_err());
    }

    #[test]
    fn forged_signature_rejected() {
        let a = kp("alice");
        let b = kp("bob");
        let mut alice = MlsGroup::create("x", a);
        let (_, w) = alice.commit_add(b.kp.clone()).unwrap();
        let mut bob = MlsGroup::join_from_welcome(&w, b).unwrap();
        let mut m = alice.encrypt(b"real").unwrap();
        m.signature[0] ^= 0xFF;
        assert!(bob.decrypt(&m).is_err());
    }

    #[test]
    fn wrong_epoch_rejected() {
        let a = kp("alice");
        let b = kp("bob");
        let mut alice = MlsGroup::create("x", a);
        let (_, w) = alice.commit_add(b.kp.clone()).unwrap();
        let mut bob = MlsGroup::join_from_welcome(&w, b).unwrap();
        let mut m = alice.encrypt(b"real").unwrap();
        m.epoch = 99;
        // signature won't verify because epoch is part of TBS, but error
        // surfaces as WrongEpoch first.
        assert!(bob.decrypt(&m).is_err());
    }

    #[test]
    fn duplicate_credential_rejected() {
        let a = kp("alice");
        let b1 = kp("bob");
        let b2 = kp("bob"); // same credential
        let mut alice = MlsGroup::create("x", a);
        let (_, _w) = alice.commit_add(b1.kp.clone()).unwrap();
        assert!(matches!(
            alice.commit_add(b2.kp.clone()),
            Err(MlsError::AlreadyMember(_))
        ));
    }
}
