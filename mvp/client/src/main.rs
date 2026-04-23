//! Interactive CLI client for the Signal-MVP messenger.
//!
//! Each invocation represents one user (identified by `--name`). The
//! client:
//!   1. Connects to the relay over WebSocket and announces its handle.
//!   2. Publishes a pre-key bundle (identity, signed-prekey with Ed25519
//!      signature, one-time-prekey) for the other party to fetch.
//!   3. Tries to fetch the peer's bundle. If present -> act as X3DH
//!      initiator (Alice). If absent -> wait; on the first incoming
//!      message that carries an `initial` handshake, run X3DH as
//!      responder (Bob).
//!   4. Reads plaintext lines from stdin, encrypts each through the
//!      Double Ratchet, and sends as `Envelope { from, to, msg }`.
//!   5. Decrypts incoming `Deliver` messages and prints them.
//!
//! Usage:
//!     cargo run --bin client -- --name alice --peer bob --relay ws://127.0.0.1:9000
//!     cargo run --bin client -- --name bob   --peer alice --relay ws://127.0.0.1:9000

use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crypto::{
    ratchet::RatchetState,
    signed_prekey::IdentitySigningKey,
    wire::{pk_from_b64, BundleWire, InitialHandshake, MessageWire, RelayMsg},
    x3dh::{
        x3dh_initiator, x3dh_responder, IdentityKey, OneTimePreKey, PreKeyBundle, SignedPreKey,
    },
};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::{connect_async, tungstenite::Message};

struct Args {
    name: String,
    peer: String,
    relay: String,
}

fn parse_args() -> Result<Args> {
    let mut name = None;
    let mut peer = None;
    let mut relay = "ws://127.0.0.1:9000".to_string();
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--name" => name = it.next(),
            "--peer" => peer = it.next(),
            "--relay" => relay = it.next().ok_or_else(|| anyhow!("--relay needs value"))?,
            "-h" | "--help" => {
                eprintln!("client --name <me> --peer <them> [--relay ws://host:port]");
                std::process::exit(0);
            }
            other => bail!("unknown arg: {other}"),
        }
    }
    Ok(Args {
        name: name.ok_or_else(|| anyhow!("--name required"))?,
        peer: peer.ok_or_else(|| anyhow!("--peer required"))?,
        relay,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;

    // --- Generate this user's key material.
    let ik = IdentityKey::generate();
    let id_sign = IdentitySigningKey::generate();
    let spk = SignedPreKey::generate();
    let opk = OneTimePreKey::generate();
    let spk_sig = id_sign.sign_spk(&spk.public);

    let bundle = PreKeyBundle {
        identity: ik.public,
        identity_signing: id_sign.verifying,
        signed_prekey: spk.public,
        spk_signature: spk_sig,
        one_time_prekey: opk.public,
    };
    let bundle_wire = BundleWire::from_bundle(&bundle);

    // --- Connect to relay.
    let (ws, _) = connect_async(&args.relay)
        .await
        .with_context(|| format!("connecting to {}", args.relay))?;
    let (mut ws_tx, mut ws_rx) = ws.split();

    // Outbound channel so multiple tasks (stdin reader + main loop) can
    // push frames onto the single WS writer.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Message>();

    let ws_writer = tokio::spawn(async move {
        while let Some(m) = out_rx.recv().await {
            if ws_tx.send(m).await.is_err() {
                break;
            }
        }
    });

    // Hello + publish bundle.
    send(&out_tx, &RelayMsg::Hello { who: args.name.clone() })?;
    send(
        &out_tx,
        &RelayMsg::PublishBundle {
            who: args.name.clone(),
            bundle: bundle_wire.clone(),
        },
    )?;
    // Request peer's bundle.
    send(
        &out_tx,
        &RelayMsg::FetchBundle { who: args.peer.clone() },
    )?;

    // Ratchet state appears only after handshake completes on either side.
    let state: Arc<Mutex<Option<RatchetState>>> = Arc::new(Mutex::new(None));
    // Initial-handshake payload to attach to Alice's first ciphertext.
    let pending_initial: Arc<Mutex<Option<InitialHandshake>>> = Arc::new(Mutex::new(None));

    // --- Spawn stdin reader: each line -> encrypt -> Envelope.
    {
        let state = state.clone();
        let pending_initial = pending_initial.clone();
        let out_tx = out_tx.clone();
        let me = args.name.clone();
        let peer = args.peer.clone();
        tokio::spawn(async move {
            let stdin = tokio::io::stdin();
            let mut lines = BufReader::new(stdin).lines();
            eprintln!("[client] type messages and press enter (Ctrl-D to quit)");
            while let Ok(Some(line)) = lines.next_line().await {
                let mut guard = state.lock().await;
                let Some(rs) = guard.as_mut() else {
                    eprintln!("[client] handshake not ready yet — buffering disabled, dropping: {line:?}");
                    continue;
                };
                let msg = match rs.encrypt(line.as_bytes()) {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("[client] encrypt error: {e}");
                        continue;
                    }
                };
                // Attach handshake info on Alice's first send only.
                let initial = pending_initial.lock().await.take();
                let envelope = RelayMsg::Envelope {
                    from: me.clone(),
                    to: peer.clone(),
                    msg: MessageWire::from_msg(&msg, initial),
                };
                let _ = out_tx.send(Message::Text(serde_json::to_string(&envelope).unwrap()));
            }
            eprintln!("[client] stdin closed");
        });
    }

    // --- Main loop: process incoming relay messages.
    while let Some(frame) = ws_rx.next().await {
        let frame = frame?;
        let text = match frame {
            Message::Text(t) => t,
            Message::Close(_) => break,
            _ => continue,
        };
        let msg: RelayMsg = serde_json::from_str(&text)?;
        match msg {
            RelayMsg::Bundle { who, bundle } => {
                if who != args.peer {
                    continue;
                }
                let Some(bw) = bundle else {
                    eprintln!(
                        "[client] peer '{}' has no bundle yet — waiting for them to connect",
                        who
                    );
                    continue;
                };
                let peer_bundle = bw.to_bundle()?;
                // We are Alice. Run X3DH, init ratchet, stash handshake data
                // for the first outgoing ciphertext.
                let out = x3dh_initiator(&ik, &peer_bundle)
                    .map_err(|e| anyhow!("X3DH initiator failed: {e}"))?;
                eprintln!(
                    "[client] X3DH (initiator) OK — SK={}",
                    short_hex(&out.shared_secret)
                );
                let rs = RatchetState::init_alice(out.shared_secret, peer_bundle.signed_prekey);
                *state.lock().await = Some(rs);
                *pending_initial.lock().await = Some(InitialHandshake {
                    alice_ik: B64.encode(ik.public.as_bytes()),
                    alice_ek: B64.encode(out.ephemeral_public.as_bytes()),
                });
            }
            RelayMsg::Deliver { from, msg } => {
                // Lazy responder-side X3DH on the very first delivery.
                {
                    let mut guard = state.lock().await;
                    if guard.is_none() {
                        let initial = msg.initial.as_ref().ok_or_else(|| {
                            anyhow!("first message missing initial handshake payload")
                        })?;
                        let alice_ik_pub = pk_from_b64(&initial.alice_ik)?;
                        let alice_ek_pub = pk_from_b64(&initial.alice_ek)?;
                        // Bob reconstructs the shared secret.
                        // NOTE: we clone SPK/OPK secrets here. In M2 MVP the
                        // one-time-prekey is used once then would be deleted.
                        let spk_secret_for_x3dh = spk.secret.clone();
                        let spk_secret_for_ratchet = spk.secret.clone();
                        let opk_ref = OneTimePreKey {
                            secret: opk.secret.clone(),
                            public: opk.public,
                        };
                        let sk = x3dh_responder(
                            &ik,
                            &SignedPreKey {
                                secret: spk_secret_for_x3dh,
                                public: spk.public,
                            },
                            &opk_ref,
                            &alice_ik_pub,
                            &alice_ek_pub,
                        );
                        eprintln!(
                            "[client] X3DH (responder) OK — SK={}",
                            short_hex(&sk)
                        );
                        *guard = Some(RatchetState::init_bob(sk, spk_secret_for_ratchet));
                    }
                }

                let wire_msg = msg.to_msg()?;
                let mut guard = state.lock().await;
                let rs = guard.as_mut().unwrap();
                match rs.decrypt(&wire_msg) {
                    Ok(pt) => {
                        println!("<{}> {}", from, String::from_utf8_lossy(&pt));
                    }
                    Err(e) => eprintln!("[client] decrypt failed: {e}"),
                }
            }
            RelayMsg::Error { reason } => eprintln!("[relay] error: {reason}"),
            _ => {}
        }
    }

    drop(out_tx);
    let _ = ws_writer.await;
    Ok(())
}

fn send(tx: &mpsc::UnboundedSender<Message>, m: &RelayMsg) -> Result<()> {
    tx.send(Message::Text(serde_json::to_string(m)?))?;
    Ok(())
}

fn short_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(16);
    for byte in &b[..8.min(b.len())] {
        s.push_str(&format!("{:02x}", byte));
    }
    s.push_str("..");
    s
}
