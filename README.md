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

## Key References
- Signal Protocol docs (X3DH, Double Ratchet specs)
- MLS RFC 9420
- "The Messaging Layer Security (MLS) Protocol"
