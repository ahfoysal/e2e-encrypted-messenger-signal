//! Persistent offline-message queue, backed by `sled`.
//!
//! Entries are keyed by `(to_handle, to_device, seq)` with `seq` an atomic
//! monotonic counter per tree — so on flush we get FIFO delivery per
//! `(handle, device)`. The value is the full serialized `RelayMsg::Deliver`
//! JSON (ready to send to the reconnecting client).
//!
//! Each entry also carries an `expires_at_unix_ms` — on every dequeue we
//! skip (and drop) expired entries, so disappearing-message TTL is honored
//! even for offline recipients.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crypto::disappearing::is_expired;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueuedMessage {
    pub payload_json: String,
    pub expires_at_unix_ms: u64,
    pub enqueued_at_unix_ms: u64,
}

pub struct PersistentQueue {
    db: sled::Db,
    tree: sled::Tree,
    counter: sled::Tree,
}

impl PersistentQueue {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = sled::open(path).context("opening sled db")?;
        let tree = db.open_tree("queue").context("opening queue tree")?;
        let counter = db.open_tree("seq").context("opening seq tree")?;
        Ok(Self { db, tree, counter })
    }

    /// Open an ephemeral in-memory-like DB (via a temp dir) — for tests.
    #[cfg(test)]
    pub fn open_temp() -> Result<(Self, tempdir_like::TempDir)> {
        let tmp = tempdir_like::TempDir::new()?;
        let q = Self::open(tmp.path())?;
        Ok((q, tmp))
    }

    pub fn flush_sync(&self) -> Result<()> {
        self.db.flush().context("sled flush")?;
        Ok(())
    }

    fn next_seq(&self, handle: &str, device: u32) -> Result<u64> {
        let key = format!("{}:{}", handle, device);
        let seq = self
            .counter
            .fetch_and_update(key.as_bytes(), |cur| {
                let n = match cur {
                    Some(b) => {
                        let mut arr = [0u8; 8];
                        if b.len() == 8 {
                            arr.copy_from_slice(b);
                            u64::from_be_bytes(arr)
                        } else {
                            0
                        }
                    }
                    None => 0,
                };
                Some((n + 1).to_be_bytes().to_vec())
            })
            .context("sled seq update")?
            .map(|b| {
                let mut arr = [0u8; 8];
                if b.len() == 8 {
                    arr.copy_from_slice(&b);
                    u64::from_be_bytes(arr)
                } else {
                    0
                }
            })
            .unwrap_or(0);
        Ok(seq + 1)
    }

    fn key(handle: &str, device: u32, seq: u64) -> Vec<u8> {
        // Layout: `<handle_len u16><handle bytes><device u32><seq u64>` —
        // sled's default ord over bytes gives FIFO per `(handle, device)`.
        let mut k = Vec::with_capacity(2 + handle.len() + 4 + 8);
        k.extend_from_slice(&(handle.len() as u16).to_be_bytes());
        k.extend_from_slice(handle.as_bytes());
        k.extend_from_slice(&device.to_be_bytes());
        k.extend_from_slice(&seq.to_be_bytes());
        k
    }

    fn prefix(handle: &str, device: u32) -> Vec<u8> {
        let mut k = Vec::with_capacity(2 + handle.len() + 4);
        k.extend_from_slice(&(handle.len() as u16).to_be_bytes());
        k.extend_from_slice(handle.as_bytes());
        k.extend_from_slice(&device.to_be_bytes());
        k
    }

    pub fn enqueue(
        &self,
        to_handle: &str,
        to_device: u32,
        payload_json: String,
        expires_at_unix_ms: u64,
    ) -> Result<()> {
        let seq = self.next_seq(to_handle, to_device)?;
        let key = Self::key(to_handle, to_device, seq);
        let qm = QueuedMessage {
            payload_json,
            expires_at_unix_ms,
            enqueued_at_unix_ms: crypto::disappearing::now_unix_ms(),
        };
        let bytes = serde_json::to_vec(&qm)?;
        self.tree.insert(key, bytes)?;
        Ok(())
    }

    /// Drain all queued messages for `(handle, device)` that have not expired.
    /// Expired ones are removed without being returned.
    pub fn drain(&self, to_handle: &str, to_device: u32) -> Result<Vec<QueuedMessage>> {
        let mut out = Vec::new();
        let prefix = Self::prefix(to_handle, to_device);
        let mut to_remove: Vec<sled::IVec> = Vec::new();
        for item in self.tree.scan_prefix(&prefix) {
            let (k, v) = item?;
            let qm: QueuedMessage = match serde_json::from_slice(&v) {
                Ok(q) => q,
                Err(_) => {
                    to_remove.push(k);
                    continue;
                }
            };
            to_remove.push(k);
            if qm.expires_at_unix_ms != 0 && is_expired(qm.expires_at_unix_ms) {
                continue; // drop expired, don't deliver
            }
            out.push(qm);
        }
        for k in to_remove {
            let _ = self.tree.remove(k);
        }
        Ok(out)
    }

    pub fn len_for(&self, to_handle: &str, to_device: u32) -> usize {
        let prefix = Self::prefix(to_handle, to_device);
        self.tree.scan_prefix(&prefix).count()
    }

    /// Scan the whole DB and drop entries whose TTL has elapsed. Cheap
    /// maintenance sweep; safe to call periodically.
    pub fn gc_expired(&self) -> Result<usize> {
        let mut dropped = 0usize;
        let mut to_remove: Vec<sled::IVec> = Vec::new();
        for item in self.tree.iter() {
            let (k, v) = item?;
            if let Ok(qm) = serde_json::from_slice::<QueuedMessage>(&v) {
                if qm.expires_at_unix_ms != 0 && is_expired(qm.expires_at_unix_ms) {
                    to_remove.push(k);
                }
            }
        }
        for k in to_remove {
            if self.tree.remove(k)?.is_some() {
                dropped += 1;
            }
        }
        Ok(dropped)
    }
}

// Minimal local tempdir helper so we don't need the `tempfile` crate.
#[cfg(test)]
mod tempdir_like {
    use anyhow::Result;
    use std::path::{Path, PathBuf};

    pub struct TempDir {
        path: PathBuf,
    }
    impl TempDir {
        pub fn new() -> Result<Self> {
            let base = std::env::temp_dir();
            let pid = std::process::id();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = base.join(format!("petzy-relay-queue-{}-{}", pid, nanos));
            std::fs::create_dir_all(&path)?;
            Ok(Self { path })
        }
        pub fn path(&self) -> &Path {
            &self.path
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::disappearing::{now_unix_ms, Ttl};

    #[test]
    fn enqueue_and_drain_fifo() {
        let (q, _t) = PersistentQueue::open_temp().unwrap();
        q.enqueue("alice", 1, "m1".to_string(), 0).unwrap();
        q.enqueue("alice", 1, "m2".to_string(), 0).unwrap();
        q.enqueue("alice", 1, "m3".to_string(), 0).unwrap();
        // A different device should not be affected.
        q.enqueue("alice", 2, "other".to_string(), 0).unwrap();

        let got = q.drain("alice", 1).unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].payload_json, "m1");
        assert_eq!(got[1].payload_json, "m2");
        assert_eq!(got[2].payload_json, "m3");
        // Draining twice returns nothing.
        assert!(q.drain("alice", 1).unwrap().is_empty());
        // Device 2 untouched.
        assert_eq!(q.drain("alice", 2).unwrap().len(), 1);
    }

    #[test]
    fn expired_entries_are_dropped_on_drain() {
        let (q, _t) = PersistentQueue::open_temp().unwrap();
        let past = 1u64; // way in the past
        let future = now_unix_ms() + Ttl::hours(1).ttl_ms;
        q.enqueue("bob", 1, "stale".to_string(), past).unwrap();
        q.enqueue("bob", 1, "fresh".to_string(), future).unwrap();

        let got = q.drain("bob", 1).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].payload_json, "fresh");
    }

    #[test]
    fn gc_expired_removes_stale_entries() {
        let (q, _t) = PersistentQueue::open_temp().unwrap();
        q.enqueue("x", 1, "stale".to_string(), 1).unwrap();
        q.enqueue("x", 1, "fresh".to_string(), now_unix_ms() + 60_000)
            .unwrap();
        let dropped = q.gc_expired().unwrap();
        assert_eq!(dropped, 1);
        assert_eq!(q.len_for("x", 1), 1);
    }
}
