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
cargo test          # 6 tests: X3DH agreement, round-trip, tampering, key rotation, burst send
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
- SPK signature omitted (real X3DH requires `XEdDSA(IK_B, SPK_B)` verified before use).
- No skipped-message cache → strict in-order delivery between DH ratchet steps.
- No header encryption; no serialization format; no replay-window beyond per-chain counters.
- Identity key is plain X25519; Signal uses XEd25519 so the same key does both DH and signatures.

### Next (M1 remainder → M2)
- WebSocket relay (`mvp/relay/`) + two-process CLI clients.
- Out-of-order / skipped-key handling.
- Persistent session state (SQLite).
- XEdDSA signatures on SPK.

## Key References
- Signal Protocol docs (X3DH, Double Ratchet specs)
- MLS RFC 9420
- "The Messaging Layer Security (MLS) Protocol"
