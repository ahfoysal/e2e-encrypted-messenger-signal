# E2E Encrypted Messenger (Signal Protocol)

**Stack:** Rust (crypto core, shareable) · TypeScript + React Native (clients) · `libsignal-protocol` patterns (self-implemented) · `ring` / `RustCrypto` · Axum (relay server) · WebSocket · SQLite (local) · Postgres (server metadata)

## Full Vision
X3DH + Double Ratchet, sealed sender, multi-device sync, group messaging (MLS), metadata resistance, Tor, mobile+desktop+web clients.

## MVP (1 weekend)
Two CLI clients exchanging E2E messages via Double Ratchet, relayed through a dumb WebSocket server.

## Milestones
- **M1 (Week 2):** X3DH key agreement + Double Ratchet 1:1
- **M2 (Week 5):** Multi-device (linked devices + key sync via encrypted channel)
- **M3 (Week 8):** Group messaging via MLS (RFC 9420)
- **M4 (Week 10):** Sealed sender + metadata-minimizing server
- **M5 (Week 12):** React Native clients + Tor support + hardened relay

## MVP Status — DONE (crypto core + in-process demo)

The `mvp/` cargo workspace ships the M1 crypto core:

- `mvp/crypto/` — library with:
  - **X3DH** (`src/x3dh.rs`): identity key, signed pre-key, one-time pre-key, all X25519. Initiator and responder derive the same 32-byte shared secret via `HKDF-SHA256(DH1 || DH2 || DH3 || DH4)` with the standard 32-byte 0xFF domain-separation prefix.
  - **Double Ratchet** (`src/ratchet.rs`): root key / sending chain / receiving chain; HMAC-SHA256 chain-key KDF (constants 0x01/0x02); per-message DH ratchet step on every received header carrying a new DH pub. AEAD is ChaCha20-Poly1305 with a counter-based nonce and a fixed AD.
- `mvp/demo/` — single binary that runs Alice and Bob in-process, performs X3DH, then exchanges 10 messages. Each turn rotates the sender's DH key and root key (verified by a test).

### Run it

```bash
cd mvp
cargo test          # 14 tests (M1 + M2): X3DH + SPK-sig + round-trip + out-of-order + DH-rotation
cargo run --bin demo
```

Sample output:

```
=== Signal-MVP demo: Alice <-> Bob ===

[X3DH] shared secret agreed:
  SK = b6af95b2b0067c48b8aeb521c4d5dad0b02e6598a28e255d502ef664e4b1f966

#00 Alice -> Bob  dh=a13e2eaa82e95f54.. ct=[41 B] 'Hi Bob — did X3DH work?'
#01 Bob   -> Alice dh=b9833f0db4d794bb.. ct=[46 B] 'Yep, shared secret looks good.'
...
[OK] 10 messages exchanged; DH key rotated on every turn.
```

### MVP simplifications (not production-ready)
- Identity-signing key is a separate Ed25519 keypair (we don't implement XEd25519's
  single-key trick — the security property is the same).
- No header encryption; no replay-window beyond per-chain counters.
- No persistent session state (sessions live only in memory).
- Relay has no auth/TLS — any client can claim any handle.

## M2 Status — DONE (crypto hardening + WebSocket relay + CLI clients)

M2 ships:

- **`mvp/crypto/src/signed_prekey.rs`** — Ed25519 `IdentitySigningKey`.
  The responder signs the X25519 signed-prekey public with its long-term
  Ed25519 key. `PreKeyBundle` now carries `identity_signing` + `spk_signature`,
  and `x3dh_initiator` **verifies the signature before running X3DH**,
  returning `X3dhError::BadSpkSignature` on failure. This blocks the
  "swap the SPK" attack where a MITM substitutes a pre-key bundle.

- **Skipped-message key cache** in `ratchet.rs`. The receiver now tolerates
  out-of-order delivery by deriving and caching the message keys for any
  gap (up to `MAX_SKIP = 64` keys, FIFO-evicted). Handles both in-chain
  gaps and the cross-chain case where a late message from the *previous*
  sending chain arrives after a DH ratchet step (keys are cached against
  the old remote DH pub so they still decrypt).

- **`mvp/relay/`** — dumb WebSocket relay (`tokio` + `tokio-tungstenite`).
  Caches per-handle pre-key bundles, routes opaque `Envelope`s between
  two connected clients. Sees only base64 ciphertext + public keys.

- **`mvp/client/`** — interactive CLI. Publishes its own bundle, fetches
  the peer's bundle, runs X3DH, then reads stdin line-by-line — each line
  is encrypted through the Double Ratchet and sent as an `Envelope`.
  Incoming `Deliver` messages are decrypted and printed.

- **`mvp/crypto/src/wire.rs`** — serde-serializable wire types
  (`BundleWire`, `MessageWire`, `RelayMsg`) with base64 key/ciphertext encoding.

### Tests (M2)

14 tests total, all passing:

- `signed_prekey::valid_signature_verifies` / `tampered_spk_is_rejected` /
  `wrong_identity_is_rejected`
- `x3dh::x3dh_rejects_invalid_spk_signature` — attacker's signature on a
  real SPK is rejected
- `x3dh::x3dh_rejects_tampered_spk` — honest signature + swapped SPK rejected
- `ratchet::out_of_order_same_chain_decrypts` — receive 0, 2, 1, 3
- `ratchet::out_of_order_across_dh_ratchet` — late message from the
  *old* chain still decrypts after peer ratchets
- `ratchet::gap_larger_than_max_skip_is_rejected` — safety bound
- Plus the five M1 tests (round-trip, tampering, ping-pong DH rotation,
  multi-send, dual-direction X3DH).

### Run M2

Terminal 1 — relay:

```bash
cd mvp
cargo run --bin relay -- 127.0.0.1:9000
```

Terminal 2 — Bob (waits for Alice):

```bash
cargo run --bin client -- --name bob --peer alice --relay ws://127.0.0.1:9000
```

Terminal 3 — Alice (initiates):

```bash
cargo run --bin client -- --name alice --peer bob --relay ws://127.0.0.1:9000
```

Type lines in either terminal — they appear decrypted as `<sender> text`
in the peer's terminal. The relay only ever sees base64 ciphertext.

## M3 Status — DONE (group messaging via Sender Keys)

M3 ships group messaging using the **Sender Keys** scheme — what Signal
actually ships for groups today. (Full MLS/RFC 9420 is deferred; Sender
Keys gives the same E2E security with a smaller implementation.)

- **`mvp/crypto/src/sender_keys.rs`** — each group member owns a
  `SenderKey = (chain_key, Ed25519 signing keypair)` per group. The chain
  key advances per message using the same `HMAC-SHA256(ck, 0x01/0x02)`
  construction as the Double Ratchet's sending chain. Every group
  ciphertext is signed with the member's Ed25519 key so other members
  authenticate the origin even though they all hold the symmetric chain
  state. A receiver-side `SenderKeyReceiver` verifies signatures first,
  caches out-of-order message keys (up to `GROUP_MAX_SKIP = 64`), and
  rejects replays / forged signatures / tampered ciphertexts.

- **`mvp/crypto/src/group.rs`** — `GroupSession` composes one
  `SenderKey` (self) + one `SenderKeyReceiver` per peer. API:
  `create`, `join`, `encrypt`, `decrypt`, `add_member`, `remove_member`.
  **Add** sends the adder's current SenderKey to the new member (no
  rotation — historical ciphertexts aren't leaked). **Remove** rotates
  the remover's SenderKey so the evicted member can't decrypt future
  broadcasts (post-compromise security at membership-change granularity).
  Transport assumption: `SenderKeyDistribution` blobs travel over the
  already-established pairwise Double Ratchet sessions from M1/M2.

- **`mvp/client/src/group_demo.rs`** — `cargo run --bin group_demo`
  runs an in-process 3-member group (Alice, Bob, Carol), exchanges
  round-robin messages, adds a 4th member (Dave), then removes one and
  shows post-removal messages still decrypt for the remaining members.

### Tests (M3)

11 new tests, 25 total, all passing:

- `sender_keys::send_recv_roundtrip`, `multiple_in_order_messages`,
  `out_of_order_works`, `forged_signature_rejected`,
  `tampered_ciphertext_rejected`, `wrong_sender_key_rejected`.
- `group::three_member_group_exchanges_messages` — Alice/Bob/Carol all
  send and converge on the same plaintext.
- `group::adding_fourth_member_works` — Dave joins, all 4 exchange.
- `group::removed_member_cannot_decrypt_new_messages` — Carol is
  removed; her stale receiver state cannot decrypt Alice's post-rotation
  broadcast (signature + chain key both change).
- `group::member_not_in_group_cannot_be_removed`,
  `group::duplicate_add_is_rejected` — membership invariants.

### Run M3

```bash
cd mvp
cargo test                    # 25 tests (M1 + M2 + M3)
cargo run --bin group_demo    # in-process 3-member group demo
cargo run --bin group_demo -- --members alice,bob,carol,eve
```

### M3 simplifications (vs. Signal's production Sender Keys)
- Group transport is modeled in-process — a real deployment wraps each
  `SenderKeyDistribution` in a 1:1 Double Ratchet envelope before the
  relay forwards it.
- No epoch/version numbers on distribution messages; the latest install
  for a (group, sender) simply overwrites prior state.
- Remove rotates only the caller's own key; every remaining member must
  independently call `remove_member` to rotate theirs.
- Relay still treats group broadcasts as N separate envelopes — no
  fan-out optimization.

### Next (M4 and beyond)
- Multi-device (linked devices + key sync via encrypted channel).
- Persistent session state (SQLite).
- Full MLS (RFC 9420) with TreeKEM for larger groups.
- Sealed sender + metadata-minimizing server.

## M6 Status — DONE (full MLS / RFC 9420 group engine)

M6 ships a hand-rolled **MLS (RFC 9420)** implementation as an alternative
to Sender Keys for group messaging. Both engines coexist — a client
picks one per-group via a flag. MLS brings asynchronous joins
(Welcome messages), `O(log N)` commits via TreeKEM, and explicit
epoch-based state transitions.

New module tree:

```
mvp/crypto/src/mls/
  mod.rs          // public surface: re-exports everything below
  treekem.rs      // ratchet tree + path_secret derivation + resolution
  keypackage.rs   // LeafNode + KeyPackage + self-signatures
  messages.rs     // Proposal / Commit / Welcome / MlsApplicationMessage
  group.rs        // MlsGroup state machine + mini-HPKE + key schedule
```

### What's implemented

- **TreeKEM** (`treekem.rs`): left-balanced binary tree with MLS's array
  indexing (leaves at even indices, internals at odd). `direct_path`,
  `copath`, `resolution` (RFC 9420 §7.4 — descends into blank internal
  nodes until it finds real public keys), and `derive_path` /
  `apply_path` that produce **the same `commit_secret` on both sides**
  of a commit (verified by `both_sides_derive_same_root_when_they_
  share_subtree_secret`).
- **LeafNode + KeyPackage** (`keypackage.rs`): Ed25519-signed member
  "calling cards" carrying separate **encryption_key** (X25519, used
  for TreeKEM direct-path at the leaf) and **init_key** (X25519, used
  only for Welcome encryption). Self-signature prevents swapping.
- **Proposals** (`messages.rs`): **Add { KeyPackage }** and
  **Remove { leaf }**. (Update / ReInit / PSK / ExternalInit deferred.)
- **Commit** (`messages.rs`, `group.rs::commit_add`, `commit_remove`):
  signed by the committer, contains proposals + `UpdatePath`
  (sender's new leaf public, `path_publics[i]`, and HPKE-wrapped
  `path_secrets` addressed to the resolution of each co-path node).
  `path_level` on each `HpkeCiphertext` tells the receiver which
  direct-path index the secret seeds — so one commit can cover a
  sibling subtree with multiple blank-descended targets.
- **Welcome** (`messages.rs`, `group.rs::join_from_welcome`): the
  committer encrypts the new epoch's `joiner_secret` to the added
  member's `init_key`. The Welcome also carries the full public view of
  the ratchet tree + roster so the joiner rebuilds local state
  without knowing prior epochs' plaintexts.
- **Epoch key schedule**: `commit_secret → HKDF-Expand("epoch" || gid
  || epoch) → epoch_secret → HKDF-Expand("app" || leaf || gen) →
  msg_key`. Every member re-derives the same `epoch_secret` after a
  commit → direct equality test in the tests.
- **Application messages** (`MlsApplicationMessage`): AEAD
  (ChaCha20-Poly1305) under a per-(sender, generation) message key,
  nonce = `leaf || 0..0 || gen`, and an Ed25519 signature under the
  sender's signing key over the full TBS. Replay protection via
  monotonic per-sender generations within the epoch.
- **Mini-HPKE** for TreeKEM wrapping: X25519 ephemeral-static
  + HKDF-SHA256 + ChaCha20-Poly1305. Not the full RFC 9180 framing —
  close enough for the crypto core and documented as such.

### Tests (M6)

14 new tests, 62 in `crypto` total, all passing:

- `mls::treekem::array_layout_four_leaves` — parent / sibling /
  direct_path / copath match the RFC 9420 §4.2 array layout.
- `mls::treekem::path_secret_advance_is_deterministic`.
- `mls::treekem::derive_path_populates_tree`.
- `mls::treekem::both_sides_derive_same_root_when_they_share_
  subtree_secret` — **the core TreeKEM invariant**: given the right
  injection secret, a receiver lands on the exact same
  `commit_secret` the sender produced.
- `mls::keypackage::generated_keypackage_verifies` /
  `tampered_leaf_fails` / `tampered_init_key_fails`.
- `mls::group::two_member_group_roundtrip` — Commit + Welcome end-to-
  end; Bob encrypts back to Alice.
- `mls::group::three_member_group_treekem_derives_same_root` —
  Alice + Bob + Carol all converge on the same `epoch_secret` after
  two Adds; each can broadcast and the other two decrypt.
- `mls::group::four_member_group_with_remove_evicts` — grows the
  tree cap from 2 to 4, adds Dave, then removes Carol. After the
  Remove commit, Alice/Bob/Dave all converge on a new
  `epoch_secret`; Carol is stuck at the prior epoch and **cannot
  decrypt** new broadcasts.
- `mls::group::tampered_application_rejected` /
  `forged_signature_rejected` / `wrong_epoch_rejected` /
  `duplicate_credential_rejected` — negative paths.

### M6 simplifications / deferred items

- **Scope**: 2..=16 member groups. Only **Add** and **Remove**
  proposals. No **Update** (leaf refresh), **ReInit**,
  **ExternalInit**, **PSK**, or external joiners. No commit batching
  of multiple proposals from different senders.
- **HPKE** is our own X25519 + HKDF + ChaCha20Poly1305 construction,
  not the full RFC 9180 framing with KEM/KDF/AEAD ids + info contexts.
- **Cipher suite is fixed** — corresponds loosely to MLS 0x0003
  (`MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`).
- **No parent-hash chain / tree signatures** — we rely on the
  committer's signature + each LeafNode's self-signature. RFC 9420's
  `tree_hash` + `parent_hash` invariants are not enforced.
- **No confirmation-tag / interim-transcript-hash chain** beyond the
  commit signature.
- **No on-wire MLS TLS-presentation framing** — we use
  `serde_json` / `bincode` compatible serde.
- **grow_tree** only copies leaf publics; interior nodes are
  re-derived on the next commit. Works because every commit touches
  the full direct path anyway.

### Run M6

```bash
cd mvp
cargo test           # 62 crypto + 6 relay tests, all passing
cargo test mls       # just the MLS module (14 tests)
```

## Key References
- Signal Protocol docs (X3DH, Double Ratchet specs)
- MLS RFC 9420
- "The Messaging Layer Security (MLS) Protocol"
