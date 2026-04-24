//! Interactive CLI client for the Signal-MVP messenger.
//!
//! M5 additions:
//!   * `--device <u32>` — each run advertises a specific device id. Multiple
//!     processes can register the same `--name` with different device ids and
//!     all receive messages sent to that handle.
//!   * `--socks5 <host:port>` — dial the relay through a SOCKS5 proxy
//!     (Tor: `--socks5 127.0.0.1:9050`, with a `wss://<onion>.onion:443` relay).
//!   * `--ttl-secs <N>` — attach an absolute `expires_at_unix_ms` to every
//!     outgoing envelope; the relay drops expired messages and the peer
//!     refuses to display them.
//!   * Prints the computed 60-digit safety number after the handshake —
//!     humans compare it to detect MITM / unexpected identity rotations.

use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crypto::disappearing::{is_expired, Ttl};
use crypto::safety_numbers::{compute as safety_number, IdentityProfile};
use crypto::{
    ratchet::RatchetState,
    signed_prekey::IdentitySigningKey,
    wire::{pk_from_b64, BundleWire, InitialHandshake, MessageWire, RelayMsg},
    x3dh::{
        x3dh_initiator, IdentityKey, OneTimePreKey, PreKeyBundle, SignedPreKey,
    },
};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::{client_async, connect_async, tungstenite::Message};

struct Args {
    name: String,
    peer: String,
    relay: String,
    device: u32,
    socks5: Option<String>,
    ttl_secs: Option<u64>,
}

fn parse_args() -> Result<Args> {
    let mut name = None;
    let mut peer = None;
    let mut relay = "ws://127.0.0.1:9000".to_string();
    let mut device: u32 = 1;
    let mut socks5: Option<String> = None;
    let mut ttl_secs: Option<u64> = None;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--name" => name = it.next(),
            "--peer" => peer = it.next(),
            "--relay" => relay = it.next().ok_or_else(|| anyhow!("--relay needs value"))?,
            "--device" => {
                device = it
                    .next()
                    .ok_or_else(|| anyhow!("--device needs value"))?
                    .parse()?;
            }
            "--socks5" => socks5 = it.next(),
            "--ttl-secs" => {
                ttl_secs = Some(
                    it.next()
                        .ok_or_else(|| anyhow!("--ttl-secs needs value"))?
                        .parse()?,
                );
            }
            "-h" | "--help" => {
                eprintln!(
                    "client --name <me> --peer <them> [--relay ws://host:port] \
                     [--device N] [--socks5 host:port] [--ttl-secs N]"
                );
                std::process::exit(0);
            }
            other => bail!("unknown arg: {other}"),
        }
    }
    Ok(Args {
        name: name.ok_or_else(|| anyhow!("--name required"))?,
        peer: peer.ok_or_else(|| anyhow!("--peer required"))?,
        relay,
        device,
        socks5,
        ttl_secs,
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

    // --- Connect to relay (optionally via SOCKS5 for Tor).
    let (mut ws_tx, mut ws_rx): (BoxSink, BoxStream) = if let Some(proxy) = args.socks5.as_deref() {
        connect_via_socks5(&args.relay, proxy).await?
    } else {
        let (ws, _) = connect_async(&args.relay)
            .await
            .with_context(|| format!("connecting to {}", args.relay))?;
        let (tx, rx) = ws.split();
        (Box::new(tx), Box::new(rx))
    };

    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Message>();

    let ws_writer = tokio::spawn(async move {
        while let Some(m) = out_rx.recv().await {
            if ws_tx.send(m).await.is_err() {
                break;
            }
        }
    });

    send(
        &out_tx,
        &RelayMsg::Hello {
            who: args.name.clone(),
            device_id: args.device,
        },
    )?;
    send(
        &out_tx,
        &RelayMsg::PublishBundle {
            who: args.name.clone(),
            bundle: bundle_wire.clone(),
            device_id: args.device,
        },
    )?;
    send(
        &out_tx,
        &RelayMsg::FetchBundle {
            who: args.peer.clone(),
        },
    )?;

    let state: Arc<Mutex<Option<RatchetState>>> = Arc::new(Mutex::new(None));
    let pending_initial: Arc<Mutex<Option<InitialHandshake>>> = Arc::new(Mutex::new(None));

    // --- Stdin reader.
    {
        let state = state.clone();
        let pending_initial = pending_initial.clone();
        let out_tx = out_tx.clone();
        let me = args.name.clone();
        let peer = args.peer.clone();
        let my_device = args.device;
        let ttl = args.ttl_secs;
        tokio::spawn(async move {
            let stdin = tokio::io::stdin();
            let mut lines = BufReader::new(stdin).lines();
            eprintln!("[client] type messages and press enter (Ctrl-D to quit)");
            while let Ok(Some(line)) = lines.next_line().await {
                let mut guard = state.lock().await;
                let Some(rs) = guard.as_mut() else {
                    eprintln!("[client] handshake not ready yet — dropping: {line:?}");
                    continue;
                };
                let msg = match rs.encrypt(line.as_bytes()) {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("[client] encrypt error: {e}");
                        continue;
                    }
                };
                let initial = pending_initial.lock().await.take();
                let expires_at_unix_ms = ttl.map(|s| Ttl::seconds(s).deadline_from_now()).unwrap_or(0);
                let envelope = RelayMsg::Envelope {
                    from: me.clone(),
                    to: peer.clone(),
                    msg: MessageWire::from_msg(&msg, initial),
                    from_device: my_device,
                    to_device: 0, // fan out to every device of the peer
                    expires_at_unix_ms,
                };
                let _ = out_tx.send(Message::Text(serde_json::to_string(&envelope).unwrap()));
            }
            eprintln!("[client] stdin closed");
        });
    }

    // --- Main loop.
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
                let out = x3dh_initiator(&ik, &peer_bundle)
                    .map_err(|e| anyhow!("X3DH initiator failed: {e}"))?;
                eprintln!(
                    "[client] X3DH (initiator) OK — SK={}",
                    short_hex(&out.shared_secret)
                );
                print_safety_number(
                    &args.name,
                    ik.public.as_bytes(),
                    &args.peer,
                    peer_bundle.identity.as_bytes(),
                );
                let rs = RatchetState::init_alice(out.shared_secret, peer_bundle.signed_prekey);
                *state.lock().await = Some(rs);
                *pending_initial.lock().await = Some(InitialHandshake {
                    alice_ik: B64.encode(ik.public.as_bytes()),
                    alice_ek: B64.encode(out.ephemeral_public.as_bytes()),
                });
            }
            RelayMsg::Deliver {
                from,
                msg,
                from_device: _,
                expires_at_unix_ms,
            } => {
                if is_expired(expires_at_unix_ms) {
                    eprintln!("[client] dropping expired message from '{from}'");
                    continue;
                }
                {
                    let mut guard = state.lock().await;
                    if guard.is_none() {
                        let initial = msg.initial.as_ref().ok_or_else(|| {
                            anyhow!("first message missing initial handshake payload")
                        })?;
                        let alice_ik_pub = pk_from_b64(&initial.alice_ik)?;
                        let alice_ek_pub = pk_from_b64(&initial.alice_ek)?;
                        let spk_secret_for_x3dh = spk.secret.clone();
                        let spk_secret_for_ratchet = spk.secret.clone();
                        let opk_ref = OneTimePreKey {
                            secret: opk.secret.clone(),
                            public: opk.public,
                        };
                        let sk = crypto::x3dh::x3dh_responder(
                            &ik,
                            &SignedPreKey {
                                secret: spk_secret_for_x3dh,
                                public: spk.public,
                            },
                            &opk_ref,
                            &alice_ik_pub,
                            &alice_ek_pub,
                        );
                        eprintln!("[client] X3DH (responder) OK — SK={}", short_hex(&sk));
                        print_safety_number(
                            &args.name,
                            ik.public.as_bytes(),
                            &from,
                            alice_ik_pub.as_bytes(),
                        );
                        *guard = Some(RatchetState::init_bob(sk, spk_secret_for_ratchet));
                    }
                }

                let wire_msg = msg.to_msg()?;
                let mut guard = state.lock().await;
                let rs = guard.as_mut().unwrap();
                match rs.decrypt(&wire_msg) {
                    Ok(pt) => {
                        let suffix = if expires_at_unix_ms != 0 {
                            " [disappearing]"
                        } else {
                            ""
                        };
                        println!("<{}>{} {}", from, suffix, String::from_utf8_lossy(&pt));
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

fn print_safety_number(me: &str, my_ik: &[u8; 32], them: &str, their_ik: &[u8; 32]) {
    let mine = IdentityProfile {
        handle: me,
        identity_keys: vec![*my_ik],
    };
    let theirs = IdentityProfile {
        handle: them,
        identity_keys: vec![*their_ik],
    };
    eprintln!("[client] safety number with '{}': {}", them, safety_number(&mine, &theirs));
    eprintln!("[client]   (compare out-of-band; mismatch => possible MITM)");
}

// ---- SOCKS5 connection path ----

type BoxSink = Box<
    dyn futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Send + Unpin,
>;
type BoxStream = Box<
    dyn futures_util::Stream<
            Item = Result<Message, tokio_tungstenite::tungstenite::Error>,
        > + Send
        + Unpin,
>;

async fn connect_via_socks5(relay_url: &str, proxy: &str) -> Result<(BoxSink, BoxStream)> {
    use tokio_socks::tcp::Socks5Stream;

    let url = url::Url::parse(relay_url).context("parsing relay url")?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("relay url missing host"))?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("relay url missing port"))?;

    eprintln!("[client] dialing {host}:{port} via SOCKS5 {proxy}");
    let target = format!("{}:{}", host, port);
    let socks = Socks5Stream::connect(proxy, target.as_str())
        .await
        .context("SOCKS5 connect")?;
    let tcp: TcpStream = socks.into_inner();

    // Use `client_async` with the constructed TCP stream so the WS
    // handshake runs over the SOCKS5-tunneled connection.
    let (ws, _resp) = client_async(relay_url, tcp).await.context("ws handshake over SOCKS5")?;
    let (tx, rx) = ws.split();
    Ok((Box::new(tx), Box::new(rx)))
}
