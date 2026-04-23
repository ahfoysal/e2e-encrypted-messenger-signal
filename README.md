# 10 — E2E Encrypted Messenger (Signal Protocol)

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

## Key References
- Signal Protocol docs (X3DH, Double Ratchet specs)
- MLS RFC 9420
- "The Messaging Layer Security (MLS) Protocol"
