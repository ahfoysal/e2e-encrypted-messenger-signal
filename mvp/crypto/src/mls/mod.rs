//! MLS (RFC 9420) — hand-rolled, scoped-down group messaging engine — M6.
//!
//! This module is an alternative to `sender_keys` / `group`. Both engines
//! remain available; clients pick one via a flag. MLS brings:
//!
//!   - **TreeKEM** — hierarchical key agreement over a left-balanced binary
//!     tree of leaves (one per member). A commit path updates only `O(log N)`
//!     nodes and every member derives the same epoch secret.
//!   - **KeyPackages / LeafNodes** — long-lived "calling cards" that let a
//!     new member be added without an interactive handshake.
//!   - **Welcome messages** — the committer encrypts the epoch joiner secret
//!     to each new member's init key so they can reconstruct the tree and
//!     start decrypting at the new epoch.
//!   - **Commits / Proposals** — state transitions are explicit, signed, and
//!     advance the `epoch` counter. We implement **Add** and **Remove**
//!     proposals (Update is deferred — see below).
//!   - **Application messages** — encrypted under an epoch-derived
//!     per-sender key schedule; authenticated by the sender's signing key.
//!
//! ## Scope & deferred items
//!
//! We implement enough MLS to be *recognizable* as RFC 9420 without pulling
//! in an external crate. Scoped-down:
//!
//!   - Cipher suite is fixed: **X25519 + Ed25519 + HKDF-SHA256 +
//!     ChaCha20-Poly1305** (close to MLS `MLS_128_DHKEMX25519_CHACHA20POLY1305_
//!     SHA256_Ed25519` — suite 0x0003) but our HPKE is a simplified
//!     `X25519 + HKDF + ChaCha20Poly1305` construction, not the full RFC 9180
//!     framing.
//!   - 2..=16 member groups.
//!   - Proposals: **Add**, **Remove** only. **Update** (leaf refresh),
//!     **ReInit**, **ExternalInit**, **PSK**, external joiners are deferred.
//!   - No parent-hash chain / tree signatures — we rely on the committer's
//!     signature over the full `Commit` + on LeafNode self-signatures.
//!   - Wire format is `bincode`-style serde, not the MLS TLS presentation
//!     language.
//!   - No epoch authenticators / confirmation-tag chain beyond the commit
//!     signature.
//!
//! Layout:
//!
//! ```text
//!   mls/
//!     treekem.rs     TreeKEM ratchet tree + direct-path derivation.
//!     keypackage.rs  LeafNode + KeyPackage definitions.
//!     messages.rs    Proposal / Commit / Welcome / MlsMessage wire types.
//!     group.rs       MlsGroup state machine (create/add/remove/encrypt/
//!                    decrypt/process_commit/process_welcome).
//! ```

pub mod treekem;
pub mod keypackage;
pub mod messages;
pub mod group;

pub use treekem::{RatchetTree, NodeIndex, LeafIndex, PathSecret};
pub use keypackage::{LeafNode, KeyPackage, KeyPackageBundle, LeafSecrets};
pub use messages::{Proposal, Commit, Welcome, MlsApplicationMessage, MlsError};
pub use group::{MlsGroup, GroupInfo, GroupId, MemberId};
