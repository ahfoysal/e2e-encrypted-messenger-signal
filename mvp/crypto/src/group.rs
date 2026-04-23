//! Group messaging state machine built on top of `sender_keys.rs`.
//!
//! Each member maintains a `GroupSession` per group they're in:
//!   - own `SenderKey` (their sending chain + signing key), and
//!   - a table of `SenderKeyReceiver`s keyed by peer member id.
//!
//! When a new member joins or is removed, we **rotate** the owner's
//! SenderKey (generate a fresh one) and re-distribute to every current
//! member. This gives *post-compromise security* at membership-change
//! granularity — the same model Signal ships for groups.
//!
//! **Transport assumption:** the SenderKey distribution blob is delivered
//! to each recipient over an already-established pairwise Double Ratchet
//! session (see `ratchet.rs`). In this module we model that as opaque
//! bytes: the caller is responsible for encrypting `SenderKeyDistribution`
//! with the pairwise ratchet before sending, and decrypting before handing
//! it to `install_sender_key`.

use std::collections::HashMap;

use crate::sender_keys::{GroupMessage, SenderKey, SenderKeyDistribution, SenderKeyReceiver};
use crate::CryptoError;

/// An identifier for a group member in the local view. Could be a username,
/// UUID, device id — the protocol is agnostic.
pub type MemberId = String;

/// Unique group identifier.
pub type GroupId = String;

#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    #[error("no sender key installed for member {0:?}")]
    UnknownSender(MemberId),
    #[error("member {0:?} is not in this group")]
    NotAMember(MemberId),
    #[error("member {0:?} is already in this group")]
    AlreadyMember(MemberId),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// Per-member, per-group state.
pub struct GroupSession {
    group_id: GroupId,
    me: MemberId,
    /// Currently-known member ids (including self).
    members: Vec<MemberId>,
    /// Our own SenderKey for this group.
    own: SenderKey,
    /// Per-peer receiving state.
    peers: HashMap<MemberId, SenderKeyReceiver>,
}

impl GroupSession {
    /// Bootstrap a new group as its founder. Caller will then use
    /// `distribution_for_new_member` to produce blobs for each invitee.
    pub fn create(group_id: GroupId, me: MemberId, initial_members: Vec<MemberId>) -> Self {
        let mut members = initial_members;
        if !members.contains(&me) {
            members.push(me.clone());
        }
        Self {
            group_id,
            me,
            members,
            own: SenderKey::generate(),
            peers: HashMap::new(),
        }
    }

    /// Join an existing group — caller has received the group_id and its
    /// current member roster out-of-band (e.g. in the invite message),
    /// plus one `SenderKeyDistribution` per existing member delivered
    /// over the pairwise Double Ratchet sessions.
    pub fn join(
        group_id: GroupId,
        me: MemberId,
        members: Vec<MemberId>,
        incoming: Vec<(MemberId, SenderKeyDistribution)>,
    ) -> Self {
        let mut session = Self {
            group_id,
            me: me.clone(),
            members,
            own: SenderKey::generate(),
            peers: HashMap::new(),
        };
        if !session.members.contains(&me) {
            session.members.push(me);
        }
        for (sender, dist) in incoming {
            session.install_sender_key(sender, dist);
        }
        session
    }

    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    pub fn me(&self) -> &MemberId {
        &self.me
    }

    pub fn members(&self) -> &[MemberId] {
        &self.members
    }

    /// Produce the distribution blob the caller must deliver (over the
    /// pairwise Double Ratchet) to every other member so they can decrypt
    /// our future sends.
    pub fn own_distribution(&self) -> SenderKeyDistribution {
        self.own.to_distribution()
    }

    /// Receive + install a peer's SenderKey distribution. Overwrites any
    /// existing entry (which is what we want on rotation).
    pub fn install_sender_key(&mut self, sender: MemberId, dist: SenderKeyDistribution) {
        if !self.members.contains(&sender) {
            self.members.push(sender.clone());
        }
        self.peers
            .insert(sender, SenderKeyReceiver::from_distribution(dist));
    }

    /// Encrypt a plaintext for broadcast to the whole group.
    pub fn encrypt(&mut self, pt: &[u8]) -> Result<GroupMessage, GroupError> {
        Ok(self.own.encrypt(pt)?)
    }

    /// Decrypt a group message broadcast by `from`.
    pub fn decrypt(&mut self, from: &MemberId, msg: &GroupMessage) -> Result<Vec<u8>, GroupError> {
        let rx = self
            .peers
            .get_mut(from)
            .ok_or_else(|| GroupError::UnknownSender(from.clone()))?;
        Ok(rx.decrypt(msg)?)
    }

    /// Add a new member. Protocol-level effects the caller must perform:
    ///   1. Send our **current** SenderKey distribution to the new member
    ///      (so they can decrypt our future sends without forcing a rotate).
    ///   2. Each existing member (including us) does NOT rotate on add —
    ///      only the new member needs our key; historical ciphertexts are
    ///      not forwarded. (Signal's choice: adds are cheap; removes are
    ///      where rotation is mandatory.)
    ///
    /// Returns the distribution the caller should deliver to the new member
    /// over their pairwise ratchet.
    pub fn add_member(
        &mut self,
        new_member: MemberId,
    ) -> Result<SenderKeyDistribution, GroupError> {
        if self.members.contains(&new_member) {
            return Err(GroupError::AlreadyMember(new_member));
        }
        self.members.push(new_member);
        Ok(self.own.to_distribution())
    }

    /// Remove a member. Mandatory rotation: we generate a fresh SenderKey
    /// so the removed member can't decrypt anything we send from now on.
    /// Caller must redistribute `own_distribution()` to every remaining
    /// member over their pairwise ratchet.
    pub fn remove_member(&mut self, victim: &MemberId) -> Result<(), GroupError> {
        let pos = self
            .members
            .iter()
            .position(|m| m == victim)
            .ok_or_else(|| GroupError::NotAMember(victim.clone()))?;
        self.members.remove(pos);
        self.peers.remove(victim);
        // Rotate.
        self.own = SenderKey::generate();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a fresh group of `n` members. Each gets a GroupSession
    /// and has installed every other member's initial SenderKey. Returns
    /// them keyed by member id.
    fn make_group(name: &str, members: &[&str]) -> HashMap<MemberId, GroupSession> {
        let ids: Vec<MemberId> = members.iter().map(|s| s.to_string()).collect();

        // Each member first creates their session.
        let mut sessions: HashMap<MemberId, GroupSession> = ids
            .iter()
            .map(|m| {
                (
                    m.clone(),
                    GroupSession::create(name.to_string(), m.clone(), ids.clone()),
                )
            })
            .collect();

        // Collect each member's initial distribution.
        let dists: Vec<(MemberId, SenderKeyDistribution)> = ids
            .iter()
            .map(|m| (m.clone(), sessions[m].own_distribution()))
            .collect();

        // Install: everyone learns everyone else's SenderKey.
        for (owner, dist) in &dists {
            for m in &ids {
                if m == owner {
                    continue;
                }
                sessions
                    .get_mut(m)
                    .unwrap()
                    .install_sender_key(owner.clone(), dist.clone());
            }
        }
        sessions
    }

    #[test]
    fn three_member_group_exchanges_messages() {
        let mut g = make_group("grp1", &["alice", "bob", "carol"]);

        // Alice sends. Bob and Carol both decrypt to the same plaintext.
        let m_a = g.get_mut("alice").unwrap().encrypt(b"hi from alice").unwrap();
        let sender = "alice".to_string();
        assert_eq!(
            g.get_mut("bob").unwrap().decrypt(&sender, &m_a).unwrap(),
            b"hi from alice"
        );
        assert_eq!(
            g.get_mut("carol").unwrap().decrypt(&sender, &m_a).unwrap(),
            b"hi from alice"
        );

        // Bob replies.
        let m_b = g.get_mut("bob").unwrap().encrypt(b"hey alice").unwrap();
        let sender = "bob".to_string();
        assert_eq!(
            g.get_mut("alice").unwrap().decrypt(&sender, &m_b).unwrap(),
            b"hey alice"
        );
        assert_eq!(
            g.get_mut("carol").unwrap().decrypt(&sender, &m_b).unwrap(),
            b"hey alice"
        );

        // Carol also sends; all three chains are independent.
        let m_c = g.get_mut("carol").unwrap().encrypt(b"carol here").unwrap();
        let sender = "carol".to_string();
        assert_eq!(
            g.get_mut("alice").unwrap().decrypt(&sender, &m_c).unwrap(),
            b"carol here"
        );
        assert_eq!(
            g.get_mut("bob").unwrap().decrypt(&sender, &m_c).unwrap(),
            b"carol here"
        );
    }

    #[test]
    fn adding_fourth_member_works() {
        let mut g = make_group("grp2", &["alice", "bob", "carol"]);

        // Dave joins. Each existing member runs add_member and produces
        // their distribution for Dave; Dave joins with the union.
        let mut incoming_for_dave: Vec<(MemberId, SenderKeyDistribution)> = Vec::new();
        for m in ["alice", "bob", "carol"] {
            let dist = g.get_mut(m).unwrap().add_member("dave".to_string()).unwrap();
            incoming_for_dave.push((m.to_string(), dist));
        }
        let members = vec![
            "alice".into(),
            "bob".into(),
            "carol".into(),
            "dave".into(),
        ];
        let dave = GroupSession::join(
            "grp2".to_string(),
            "dave".to_string(),
            members,
            incoming_for_dave,
        );
        // Existing members install Dave's distribution.
        let dave_dist = dave.own_distribution();
        for m in ["alice", "bob", "carol"] {
            g.get_mut(m)
                .unwrap()
                .install_sender_key("dave".to_string(), dave_dist.clone());
        }
        g.insert("dave".to_string(), dave);

        // Alice sends a post-join message; Dave can decrypt.
        let m_a = g.get_mut("alice").unwrap().encrypt(b"welcome dave").unwrap();
        let a = "alice".to_string();
        assert_eq!(
            g.get_mut("dave").unwrap().decrypt(&a, &m_a).unwrap(),
            b"welcome dave"
        );
        // Bob and Carol can also still decrypt (no rotation on add).
        assert_eq!(
            g.get_mut("bob").unwrap().decrypt(&a, &m_a).unwrap(),
            b"welcome dave"
        );
        assert_eq!(
            g.get_mut("carol").unwrap().decrypt(&a, &m_a).unwrap(),
            b"welcome dave"
        );

        // Dave sends.
        let m_d = g.get_mut("dave").unwrap().encrypt(b"hi all").unwrap();
        let d = "dave".to_string();
        for m in ["alice", "bob", "carol"] {
            assert_eq!(g.get_mut(m).unwrap().decrypt(&d, &m_d).unwrap(), b"hi all");
        }
    }

    #[test]
    fn removed_member_cannot_decrypt_new_messages() {
        // 4-member group; remove Carol. Alice's post-remove messages must
        // not be decryptable with Carol's stale copy of Alice's SenderKey.
        let mut g = make_group("grp3", &["alice", "bob", "carol", "dave"]);

        // Snapshot Carol *before* removal — we'll re-use this frozen session
        // to simulate the attacker-who-kept-the-state scenario.
        let carol_stale_alice = {
            // We can't clone GroupSession, so instead we fabricate a peer
            // session holding Alice's pre-rotation SenderKey.
            let alice_pre_dist = g["alice"].own_distribution();
            SenderKeyReceiver::from_distribution(alice_pre_dist)
        };

        // Every remaining member removes Carol (which rotates their own key).
        for m in ["alice", "bob", "dave"] {
            g.get_mut(m)
                .unwrap()
                .remove_member(&"carol".to_string())
                .unwrap();
        }
        // Redistribute the post-rotation keys.
        let new_dists: Vec<(MemberId, SenderKeyDistribution)> = ["alice", "bob", "dave"]
            .iter()
            .map(|m| (m.to_string(), g[*m].own_distribution()))
            .collect();
        for (owner, dist) in &new_dists {
            for m in ["alice", "bob", "dave"] {
                if m == owner {
                    continue;
                }
                g.get_mut(m)
                    .unwrap()
                    .install_sender_key(owner.clone(), dist.clone());
            }
        }

        // Alice sends a post-removal message.
        let m = g.get_mut("alice").unwrap().encrypt(b"carol is gone").unwrap();
        let a = "alice".to_string();

        // Bob + Dave (remaining members) decrypt fine.
        assert_eq!(
            g.get_mut("bob").unwrap().decrypt(&a, &m).unwrap(),
            b"carol is gone"
        );
        assert_eq!(
            g.get_mut("dave").unwrap().decrypt(&a, &m).unwrap(),
            b"carol is gone"
        );

        // Carol's stale receiver cannot decrypt — wrong chain key AND
        // wrong signing key mean both signature verification and AEAD
        // would fail.
        let mut stale = carol_stale_alice;
        assert!(stale.decrypt(&m).is_err());
    }

    #[test]
    fn member_not_in_group_cannot_be_removed() {
        let mut g = make_group("grp4", &["alice", "bob"]);
        let err = g
            .get_mut("alice")
            .unwrap()
            .remove_member(&"eve".to_string())
            .unwrap_err();
        assert!(matches!(err, GroupError::NotAMember(_)));
    }

    #[test]
    fn duplicate_add_is_rejected() {
        let mut g = make_group("grp5", &["alice", "bob"]);
        let err = g
            .get_mut("alice")
            .unwrap()
            .add_member("bob".to_string())
            .unwrap_err();
        assert!(matches!(err, GroupError::AlreadyMember(_)));
    }
}
