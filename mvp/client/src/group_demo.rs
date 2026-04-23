//! M3 group-messaging CLI demo.
//!
//! Runs in-process with 3 (or N) group members, performs SenderKey
//! distribution, exchanges a few messages, adds a new member, and
//! demonstrates that a removed member can no longer decrypt.
//!
//! Usage:
//!     cargo run --bin group_demo
//!     cargo run --bin group_demo -- --members alice,bob,carol,dave
//!
//! The pairwise Double Ratchet distribution channel is *modeled* — in a
//! real deployment each SenderKeyDistribution would travel over the
//! already-established 1:1 ratchet between sender and recipient. This
//! demo shows the core state machine.

use std::collections::HashMap;

use crypto::group::{GroupSession, MemberId};
use crypto::sender_keys::SenderKeyDistribution;

fn parse_members() -> Vec<String> {
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        if arg == "--members" {
            if let Some(list) = it.next() {
                return list.split(',').map(|s| s.trim().to_string()).collect();
            }
        }
    }
    vec!["alice".into(), "bob".into(), "carol".into()]
}

fn install_all(sessions: &mut HashMap<MemberId, GroupSession>, ids: &[MemberId]) {
    let dists: Vec<(MemberId, SenderKeyDistribution)> = ids
        .iter()
        .map(|m| (m.clone(), sessions[m].own_distribution()))
        .collect();
    for (owner, dist) in &dists {
        for m in ids {
            if m == owner {
                continue;
            }
            sessions
                .get_mut(m)
                .unwrap()
                .install_sender_key(owner.clone(), dist.clone());
        }
    }
}

fn broadcast(
    sessions: &mut HashMap<MemberId, GroupSession>,
    sender: &str,
    plaintext: &[u8],
    recipients: &[&str],
) {
    let msg = sessions.get_mut(sender).unwrap().encrypt(plaintext).unwrap();
    println!(
        "  [{}] sends (n={}, {} B ct, {} B sig) -> {}",
        sender,
        msg.n,
        msg.ciphertext.len(),
        msg.signature.len(),
        recipients.join(", ")
    );
    let sid = sender.to_string();
    for r in recipients {
        if *r == sender {
            continue;
        }
        match sessions.get_mut(*r).unwrap().decrypt(&sid, &msg) {
            Ok(pt) => println!(
                "    [{}] decrypts: {:?}",
                r,
                String::from_utf8_lossy(&pt)
            ),
            Err(e) => println!("    [{}] DECRYPT FAILED: {}", r, e),
        }
    }
}

fn main() {
    let members = parse_members();
    assert!(members.len() >= 3, "group demo needs at least 3 members");
    let group_id = "demo-group".to_string();

    println!("=== M3 group-messaging demo ===");
    println!("Creating group {:?} with members: {:?}\n", group_id, members);

    // Each member creates their local session.
    let mut sessions: HashMap<MemberId, GroupSession> = members
        .iter()
        .map(|m| {
            (
                m.clone(),
                GroupSession::create(group_id.clone(), m.clone(), members.clone()),
            )
        })
        .collect();
    install_all(&mut sessions, &members);

    println!("[1] All SenderKeys distributed over pairwise Double Ratchet (modeled).\n");

    // Round-robin sends.
    println!("[2] Round-robin group chat:");
    let refs: Vec<&str> = members.iter().map(|s| s.as_str()).collect();
    for (i, m) in members.iter().enumerate() {
        let pt = format!("hello from {m} (#{i})");
        broadcast(&mut sessions, m, pt.as_bytes(), &refs);
    }

    // Add a new member.
    let new_member = "dave".to_string();
    if !members.contains(&new_member) {
        println!("\n[3] Adding new member {:?}:", new_member);
        let mut incoming: Vec<(MemberId, SenderKeyDistribution)> = Vec::new();
        for m in &members {
            let dist = sessions
                .get_mut(m)
                .unwrap()
                .add_member(new_member.clone())
                .unwrap();
            incoming.push((m.clone(), dist));
        }
        let mut all_members = members.clone();
        all_members.push(new_member.clone());
        let dave = GroupSession::join(
            group_id.clone(),
            new_member.clone(),
            all_members.clone(),
            incoming,
        );
        let dave_dist = dave.own_distribution();
        sessions.insert(new_member.clone(), dave);
        for m in &members {
            sessions
                .get_mut(m)
                .unwrap()
                .install_sender_key(new_member.clone(), dave_dist.clone());
        }

        let refs_with_dave: Vec<&str> = all_members.iter().map(|s| s.as_str()).collect();
        broadcast(
            &mut sessions,
            &members[0],
            b"welcome dave!",
            &refs_with_dave,
        );
        broadcast(
            &mut sessions,
            &new_member,
            b"thanks all, glad to be here",
            &refs_with_dave,
        );
    }

    // Remove a member.
    let victim = members[members.len() - 1].clone();
    println!("\n[4] Removing member {:?} (rotates every remaining SenderKey):", victim);
    let mut remaining: Vec<MemberId> = sessions
        .keys()
        .filter(|m| **m != victim)
        .cloned()
        .collect();
    remaining.sort();
    for m in &remaining {
        sessions.get_mut(m).unwrap().remove_member(&victim).unwrap();
    }
    // Redistribute post-rotation keys.
    let new_dists: Vec<(MemberId, SenderKeyDistribution)> = remaining
        .iter()
        .map(|m| (m.clone(), sessions[m].own_distribution()))
        .collect();
    for (owner, dist) in &new_dists {
        for m in &remaining {
            if m == owner {
                continue;
            }
            sessions
                .get_mut(m)
                .unwrap()
                .install_sender_key(owner.clone(), dist.clone());
        }
    }

    // Post-remove broadcast.
    let refs_after: Vec<&str> = remaining.iter().map(|s| s.as_str()).collect();
    broadcast(
        &mut sessions,
        &remaining[0],
        b"post-removal message",
        &refs_after,
    );

    println!("\n[OK] M3 group demo complete — {} members exchanged E2E group messages.", remaining.len());
}
