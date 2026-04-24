//! TreeKEM — the heart of MLS (RFC 9420 §7).
//!
//! The ratchet tree is a **left-balanced binary tree** where each leaf
//! corresponds to one group member and each internal node holds an
//! X25519 keypair derived from a *path secret* that only members on that
//! node's subtree can reproduce.
//!
//! Node indexing (RFC 9420 §4.2) — the "array" representation:
//! for a tree of `2n-1` nodes (n leaves), leaves sit at even indices
//! `0, 2, 4, ...` and internal nodes at odd indices. So for 4 leaves:
//!
//! ```text
//!        3 (root)
//!       / \
//!      1   5
//!     / \ / \
//!     0 2 4 6
//! ```
//!
//! ### Direct path derivation
//!
//! When member L commits an update, they pick a fresh **path secret**
//! `ps[0]` and walk up the tree. At each level, the next path secret is
//! derived by `HKDF-Expand(ps[i], "path")`. From each path secret we
//! derive a node secret via `HKDF-Expand(ps[i], "node")` and from that
//! an X25519 keypair. The sibling subtree receives `ps[i]` encrypted
//! under the *public* key sitting at the sibling node (which that
//! subtree's members already know from earlier commits / welcome).
//!
//! At the root, the last path secret becomes the group's
//! **commit secret** — the input to the epoch key schedule.
//!
//! This gives `O(log N)` bandwidth per commit and every member derives
//! the same root secret regardless of their leaf position.

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

/// Raw index into the array-representation of the tree (any node).
pub type NodeIndex = usize;
/// Index restricted to leaves (0-based member slot).
pub type LeafIndex = usize;

/// A path-secret is the 32-byte seed from which a node's keypair is
/// deterministically derived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathSecret(pub [u8; 32]);

impl PathSecret {
    /// Advance along the direct path: `ps_next = HKDF-Expand(ps, "path")`.
    pub fn next(&self) -> PathSecret {
        let mut out = [0u8; 32];
        Hkdf::<Sha256>::from_prk(&self.0)
            .expect("32 bytes")
            .expand(b"mls path", &mut out)
            .expect("32 out");
        PathSecret(out)
    }

    /// Derive the node secret used to seed the X25519 keypair at this level.
    pub fn node_secret(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        Hkdf::<Sha256>::from_prk(&self.0)
            .expect("32 bytes")
            .expand(b"mls node", &mut out)
            .expect("32 out");
        out
    }

    /// Derive the X25519 keypair sitting at the node owning this path secret.
    pub fn derive_keypair(&self) -> (X25519Secret, X25519Public) {
        let seed = self.node_secret();
        let sk = X25519Secret::from(seed);
        let pk = X25519Public::from(&sk);
        (sk, pk)
    }
}

/// A single node in the ratchet tree. We store only what the local member
/// actually needs to know:
///   - the public key (for encrypting to that subtree), and
///   - the private key *if* this member is on the node's subtree.
#[derive(Clone, Debug, Default)]
pub struct TreeNode {
    /// `None` means this slot is "blank" — either a removed leaf or an
    /// internal node whose subtree has no current members.
    pub public: Option<[u8; 32]>,
    /// Only populated if the local member holds the secret for this node.
    pub private: Option<[u8; 32]>,
}

impl TreeNode {
    pub fn blank() -> Self {
        Self { public: None, private: None }
    }
    pub fn is_blank(&self) -> bool {
        self.public.is_none()
    }
}

/// The ratchet tree held by every member. All members maintain the *same*
/// public structure; the `private` slots differ per member (each holds
/// the secrets along their own direct path).
#[derive(Clone, Debug)]
pub struct RatchetTree {
    /// Number of leaves the tree was sized for (power of two >= 2).
    pub leaf_capacity: usize,
    pub nodes: Vec<TreeNode>,
}

impl RatchetTree {
    /// Build a fresh tree with enough capacity for `n_members` members.
    /// `n_members` is rounded up to the next power of two.
    pub fn new(n_members: usize) -> Self {
        let cap = n_members.next_power_of_two().max(2);
        let n_nodes = 2 * cap - 1;
        Self {
            leaf_capacity: cap,
            nodes: vec![TreeNode::blank(); n_nodes],
        }
    }

    pub fn n_leaves(&self) -> usize {
        self.leaf_capacity
    }

    /// Node-index of leaf `leaf`.
    pub fn leaf_to_node(leaf: LeafIndex) -> NodeIndex {
        2 * leaf
    }

    pub fn node_to_leaf(node: NodeIndex) -> Option<LeafIndex> {
        if node % 2 == 0 {
            Some(node / 2)
        } else {
            None
        }
    }

    pub fn root(&self) -> NodeIndex {
        self.nodes.len() / 2
    }

    /// Compute the level of a node (leaf level = 0).
    pub fn level(node: NodeIndex) -> u32 {
        // Number of trailing ones in `node+1` ... we use a simple
        // implementation: count trailing set bits of (node|~(node+1))...
        // Simpler: count how many times we can halve until it's a leaf
        // in the tree of a given size. We do it using the known formula:
        // level = number of trailing 1 bits of node (0-indexed leaves).
        // Wait — easier to iterate.
        let mut n = node;
        let mut lvl = 0;
        // A leaf has even index. An internal node at level k has index
        // ≡ 2^k - 1  (mod 2^{k+1}). We count trailing ones of (n + 1) - 1.
        // Actually simplest:
        while n & 1 == 1 {
            lvl += 1;
            n >>= 1;
        }
        // But leaves are even indexed. For leaves we want level 0.
        // Above loop on an even node gives 0 — correct. On node 1
        // (internal level-1) gives: n=1 odd -> lvl=1, n>>=1=0 even ->
        // stop. Correct.
        lvl
    }

    /// Parent of a node. Returns `None` for the root.
    pub fn parent(&self, node: NodeIndex) -> Option<NodeIndex> {
        if node == self.root() {
            return None;
        }
        // Walk down from the root, recursing left/right until we hit
        // the child. O(log N). Not hot-path; correctness > elegance.
        fn find(n: NodeIndex, lvl: u32, target: NodeIndex) -> Option<NodeIndex> {
            if lvl == 0 {
                return None;
            }
            let span = 1usize << lvl;
            let left = n - span / 2;
            let right = n + span / 2;
            if left == target || right == target {
                return Some(n);
            }
            if target < n {
                find(left, lvl - 1, target)
            } else {
                find(right, lvl - 1, target)
            }
        }
        let root = self.root();
        let root_lvl = self.leaf_capacity.trailing_zeros();
        find(root, root_lvl, node)
    }

    /// Sibling of a node (panics on root).
    pub fn sibling(&self, node: NodeIndex) -> NodeIndex {
        let parent = self.parent(node).expect("root has no sibling");
        if node < parent {
            // right child is parent + (parent - node)
            parent + (parent - node)
        } else {
            parent - (node - parent)
        }
    }

    /// Direct path from leaf `leaf` up to (but not including) the root.
    pub fn direct_path(&self, leaf: LeafIndex) -> Vec<NodeIndex> {
        let mut path = Vec::new();
        let mut n = Self::leaf_to_node(leaf);
        while let Some(p) = self.parent(n) {
            path.push(p);
            n = p;
        }
        path
    }

    /// Co-path = siblings of each node on the direct path. Same length
    /// as `direct_path`.
    pub fn copath(&self, leaf: LeafIndex) -> Vec<NodeIndex> {
        let mut cop = Vec::new();
        let mut n = Self::leaf_to_node(leaf);
        while let Some(p) = self.parent(n) {
            cop.push(self.sibling(n));
            n = p;
        }
        cop
    }

    /// Place a leaf's public key (called on Add and on group creation).
    pub fn set_leaf_public(&mut self, leaf: LeafIndex, pk: [u8; 32]) {
        let idx = Self::leaf_to_node(leaf);
        self.nodes[idx] = TreeNode { public: Some(pk), private: None };
    }

    /// Mark a leaf blank (Remove).
    pub fn blank_leaf(&mut self, leaf: LeafIndex) {
        let idx = Self::leaf_to_node(leaf);
        self.nodes[idx] = TreeNode::blank();
        // Blank the entire path up to the root so stale keys aren't used.
        let mut n = idx;
        while let Some(p) = self.parent(n) {
            self.nodes[p] = TreeNode::blank();
            n = p;
        }
    }

    /// Derive and install a direct path starting from `leaf_secret` at
    /// `leaf`. Returns (path_public_keys, commit_secret).
    ///
    /// `path_public_keys[i]` is the public key of the i-th node on the
    /// direct path (indexed from leaf upward). The final item is the
    /// root public. The `commit_secret` is the path secret at the root —
    /// it's what seeds the new epoch's key schedule.
    pub fn derive_path(
        &mut self,
        leaf: LeafIndex,
        leaf_secret: PathSecret,
    ) -> (Vec<[u8; 32]>, PathSecret) {
        // Place the leaf's own keypair.
        let (leaf_sk, leaf_pk) = leaf_secret.derive_keypair();
        let leaf_node = Self::leaf_to_node(leaf);
        self.nodes[leaf_node] = TreeNode {
            public: Some(*leaf_pk.as_bytes()),
            private: Some(leaf_sk.to_bytes()),
        };

        let mut pubs = Vec::new();
        let mut ps = leaf_secret;
        let path = self.direct_path(leaf);
        for node in path {
            ps = ps.next();
            let (sk, pk) = ps.derive_keypair();
            self.nodes[node] = TreeNode {
                public: Some(*pk.as_bytes()),
                private: Some(sk.to_bytes()),
            };
            pubs.push(*pk.as_bytes());
        }
        // commit_secret = one more advance past the root's path secret,
        // matching what `apply_path` produces.
        let commit_secret = ps.next();
        (pubs, commit_secret)
    }

    /// A receiver applies a commit path: they know the sender's leaf and
    /// one path secret somewhere along the direct path (decrypted from
    /// the commit's HPKE-wrapped secrets — whichever ciphertext was
    /// addressed to a subtree this receiver is on). From that secret we
    /// derive forward to the root, filling in both public and private
    /// slots for the nodes above the injection point. Nodes below the
    /// injection point only get their public keys (from `path_pubs`).
    ///
    /// Returns the commit_secret derived at the root.
    pub fn apply_path(
        &mut self,
        sender_leaf: LeafIndex,
        path_pubs: &[[u8; 32]],
        inject_at_level: usize,
        inject_secret: PathSecret,
    ) -> PathSecret {
        let path = self.direct_path(sender_leaf);
        assert_eq!(path_pubs.len(), path.len(), "path length mismatch");

        // Fill public keys for the full direct path.
        for (i, node) in path.iter().enumerate() {
            self.nodes[*node] = TreeNode {
                public: Some(path_pubs[i]),
                private: None,
            };
        }
        // Sender's leaf public is the first of `path_pubs`? No — it's
        // not included. The sender's leaf public is handled separately
        // (by `LeafNode` update when the commit's path is applied).

        // `inject_secret` is the path-secret AT node `path[inject_at_level]`.
        // We install its keypair, then advance up the path, installing
        // each further node from the successive path-secret. Finally
        // we advance once more past the root to produce commit_secret —
        // same convention as `derive_path`.
        let mut ps = inject_secret;
        for i in inject_at_level..path.len() {
            let (sk, pk) = ps.derive_keypair();
            // Sanity — derived public must match the path_pubs[i] the
            // sender committed.
            debug_assert_eq!(pk.as_bytes(), &path_pubs[i]);
            self.nodes[path[i]] = TreeNode {
                public: Some(*pk.as_bytes()),
                private: Some(sk.to_bytes()),
            };
            ps = ps.next();
        }
        ps
    }

    /// Get node's public key (panics on blank — caller's responsibility).
    pub fn node_public(&self, node: NodeIndex) -> Option<[u8; 32]> {
        self.nodes[node].public
    }

    /// Resolution of a node (RFC 9420 §7.4): if the node itself has a
    /// public key, return `[node]`. Otherwise, return the union of the
    /// resolutions of its children. For a leaf that's blank, returns
    /// `[]`. This gives the set of public keys we need to encrypt to in
    /// order to reach every member in the subtree.
    pub fn resolution(&self, node: NodeIndex) -> Vec<NodeIndex> {
        if self.nodes[node].public.is_some() {
            return vec![node];
        }
        // Leaf & blank → nothing.
        if node % 2 == 0 {
            return Vec::new();
        }
        // Internal & blank → descend.
        let lvl = self.level_of(node);
        let span = 1usize << lvl;
        let left = node - span / 2;
        let right = node + span / 2;
        let mut r = self.resolution(left);
        r.extend(self.resolution(right));
        r
    }

    /// Level of a node using the tree's known height (needed for
    /// resolution's left/right descent).
    fn level_of(&self, node: NodeIndex) -> u32 {
        // Find by walking down from root.
        fn find(n: NodeIndex, lvl: u32, target: NodeIndex) -> Option<u32> {
            if n == target {
                return Some(lvl);
            }
            if lvl == 0 {
                return None;
            }
            let span = 1usize << lvl;
            let left = n - span / 2;
            let right = n + span / 2;
            if target < n {
                find(left, lvl - 1, target)
            } else {
                find(right, lvl - 1, target)
            }
        }
        let root = self.root();
        let root_lvl = self.leaf_capacity.trailing_zeros();
        find(root, root_lvl, node).unwrap_or(0)
    }

    /// Get node's private key if we hold it.
    pub fn node_private(&self, node: NodeIndex) -> Option<[u8; 32]> {
        self.nodes[node].private
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn array_layout_four_leaves() {
        let t = RatchetTree::new(4);
        assert_eq!(t.nodes.len(), 7);
        assert_eq!(t.root(), 3);
        assert_eq!(RatchetTree::leaf_to_node(0), 0);
        assert_eq!(RatchetTree::leaf_to_node(1), 2);
        assert_eq!(RatchetTree::leaf_to_node(2), 4);
        assert_eq!(RatchetTree::leaf_to_node(3), 6);
        assert_eq!(t.parent(0), Some(1));
        assert_eq!(t.parent(2), Some(1));
        assert_eq!(t.parent(1), Some(3));
        assert_eq!(t.parent(5), Some(3));
        assert_eq!(t.sibling(0), 2);
        assert_eq!(t.sibling(1), 5);
        assert_eq!(t.direct_path(0), vec![1, 3]);
        assert_eq!(t.copath(0), vec![2, 5]);
        assert_eq!(t.direct_path(3), vec![5, 3]);
        assert_eq!(t.copath(3), vec![4, 1]);
    }

    #[test]
    fn path_secret_advance_is_deterministic() {
        let p = PathSecret([7u8; 32]);
        let a = p.next();
        let b = p.next();
        assert_eq!(a, b);
        assert_ne!(a, p);
    }

    #[test]
    fn derive_path_populates_tree() {
        let mut t = RatchetTree::new(4);
        let secret = PathSecret([1u8; 32]);
        let (pubs, root_secret) = t.derive_path(0, secret);
        // Leaf 0 direct path = [1, 3], so two public keys.
        assert_eq!(pubs.len(), 2);
        // All nodes on the path now have keys.
        assert!(t.node_public(0).is_some());
        assert!(t.node_public(1).is_some());
        assert!(t.node_public(3).is_some());
        // Root secret is deterministic.
        let (_, root2) = {
            let mut t2 = RatchetTree::new(4);
            t2.derive_path(0, PathSecret([1u8; 32]))
        };
        assert_eq!(root_secret, root2);
    }

    #[test]
    fn both_sides_derive_same_root_when_they_share_subtree_secret() {
        // Alice is leaf 0, Bob is leaf 1. They share parent node 1.
        // If Alice commits a path_secret `ps0` at leaf-level, parent 1's
        // path secret is ps0.next(), which Alice encrypts to Bob's leaf
        // pub. Bob decrypts -> ps1 -> derives keypair for node 1 and
        // continues up -> derives same root secret Alice got.
        let mut alice = RatchetTree::new(2); // 3 nodes: 0, 1, 2
        let mut bob = RatchetTree::new(2);

        let alice_leaf_secret = PathSecret([0xAAu8; 32]);
        let (alice_pubs, alice_commit) = alice.derive_path(0, alice_leaf_secret);
        // In a 2-leaf tree, leaf 0's direct path is [1] (= root). So
        // `alice_pubs` has 1 entry (root's public), and commit_secret
        // is the *next* path secret after ps0 (= ps at the root, then
        // advanced once more to get the commit secret).
        // Wait — in `derive_path`, we produce root_secret as `ps` after
        // deriving the keypair at the root. For a 2-leaf tree path.len()
        // == 1, so the loop runs once, sets root keypair from ps.next(),
        // and does NOT advance further (the inner if's else advances).
        // Let's trace: initial ps=alice_leaf_secret. Loop i=0 (last):
        // ps = ps.next() -> ps_root, derive, and since i+1 == len, we
        // hit the else branch -> ps = ps.next(). So commit_secret is
        // ps_root.next(). OK.

        // Now Bob is leaf 1. Sender is leaf 0. Bob's copath for leaf 1
        // is [0] (Alice's leaf). Bob is not on Alice's subtree at level 0,
        // but *is* on Alice's subtree at level 1 (root). So Alice would
        // encrypt the root-level path_secret to ... the sibling of the
        // root's subtree ... wait, for 2 leaves, root has no sibling
        // below itself other than the two leaves.
        //
        // Proper TreeKEM: Alice's direct path = [root]. Copath = [Bob's
        // leaf]. Alice encrypts the path_secret for node `root` (which
        // is ps_root = alice_leaf_secret.next()) to Bob's leaf public.
        // Bob receives it, and calls apply_path with:
        //   inject_at_level = 0  (index 0 in the direct path)
        //   inject_secret = ps_root
        // and derives the commit_secret.
        let ps_root = alice_leaf_secret.next();

        // Bob also needs the sender's leaf public (Alice's leaf) set.
        bob.set_leaf_public(0, alice.node_public(0).unwrap());

        let bob_commit = bob.apply_path(0, &alice_pubs, 0, ps_root);
        assert_eq!(alice_commit, bob_commit);

        // And both should now hold matching public keys at the root.
        assert_eq!(alice.node_public(1), bob.node_public(1));
    }
}
