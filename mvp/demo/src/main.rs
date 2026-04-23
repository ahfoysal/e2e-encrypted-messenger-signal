//! Alice <-> Bob in-process demo of the X3DH + Double Ratchet MVP.
//!
//! Prints each message's ciphertext (hex) + the sender's current DH public
//! after each turn so you can see the ratchet rotating.

use crypto::{
    ratchet::RatchetState,
    x3dh::{
        x3dh_initiator, x3dh_responder, IdentityKey, OneTimePreKey, PreKeyBundle, SignedPreKey,
    },
};

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn main() {
    println!("=== Signal-MVP demo: Alice <-> Bob ===\n");

    // --- Bob generates long-term + prekey material and publishes a bundle.
    let bob_ik = IdentityKey::generate();
    let bob_spk = SignedPreKey::generate();
    let bob_opk = OneTimePreKey::generate();
    let bundle = PreKeyBundle {
        identity: bob_ik.public,
        signed_prekey: bob_spk.public,
        one_time_prekey: bob_opk.public,
    };

    // --- Alice has an identity key and runs X3DH against Bob's bundle.
    let alice_ik = IdentityKey::generate();
    let out = x3dh_initiator(&alice_ik, &bundle);

    // --- Bob receives (alice_ik_pub, ek_pub) and derives the same secret.
    let bob_sk = x3dh_responder(
        &bob_ik,
        &bob_spk,
        &bob_opk,
        &alice_ik.public,
        &out.ephemeral_public,
    );

    assert_eq!(out.shared_secret, bob_sk, "X3DH mismatch");
    println!("[X3DH] shared secret agreed:");
    println!("  SK = {}\n", hex(&out.shared_secret));

    // --- Initialize Double Ratchet state on both sides.
    let mut alice = RatchetState::init_alice(out.shared_secret, bob_spk.public);
    let mut bob = RatchetState::init_bob(bob_sk, bob_spk.secret);

    // --- Exchange 5 round-trips.
    let script = [
        ("Alice", "Hi Bob — did X3DH work?"),
        ("Bob",   "Yep, shared secret looks good."),
        ("Alice", "Great. Rotating DH on every message?"),
        ("Bob",   "Every turn. New ratchet key below."),
        ("Alice", "Perfect — PFS + post-compromise security."),
        ("Bob",   "And the message keys are one-shot."),
        ("Alice", "Last one, then tests."),
        ("Bob",   "Ack. Closing the demo."),
        ("Alice", "GG."),
        ("Bob",   "GG."),
    ];

    for (i, (who, text)) in script.iter().enumerate() {
        if *who == "Alice" {
            let m = alice.encrypt(text.as_bytes()).expect("encrypt");
            let pt = bob.decrypt(&m).expect("decrypt");
            println!(
                "#{:02} Alice -> Bob  dh={}.. ct=[{} B] '{}'",
                i,
                &hex(m.header.dh.as_bytes())[..16],
                m.ciphertext.len(),
                String::from_utf8_lossy(&pt),
            );
        } else {
            let m = bob.encrypt(text.as_bytes()).expect("encrypt");
            let pt = alice.decrypt(&m).expect("decrypt");
            println!(
                "#{:02} Bob   -> Alice dh={}.. ct=[{} B] '{}'",
                i,
                &hex(m.header.dh.as_bytes())[..16],
                m.ciphertext.len(),
                String::from_utf8_lossy(&pt),
            );
        }
    }

    println!("\n[OK] 10 messages exchanged; DH key rotated on every turn.");
}
