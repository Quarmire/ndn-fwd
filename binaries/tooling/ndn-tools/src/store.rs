//! The host's store with `--store <dir>`: what the device keeps, in memory
//! for reads, and each entry also a file of `<dir>` (named by the SHA-256 of
//! its name; holding the name's TLV length as 4 octets big-endian, the
//! name's TLV, then the stored wire), written atomically and owner-only, so
//! a host started again on `<dir>` resumes what it held — its own logs, and
//! with them its key's sequence reservations.
//!
//! Durability: an entry is written to a temporary file, fsynced, and renamed
//! into place (`secure_fs::write_private`), so a returned insert survives
//! `kill -9` and its data survives a power loss; what a power loss can still
//! take is the rename or a removal, until the directory is fsynced — which
//! [`sync`](DataStore::sync) does, once for every write since the last one
//! (group commit). A failed write or removal fails every later `sync`.
//!
//! A batch ([`apply`](DataStore::apply)) is the trait's default here: the
//! writes one by one, in order, which the data layer accepts of a store that
//! cannot apply a batch atomically (heap.md, "The store": a state left by a
//! prefix of a batch is one a restart accepts).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

use anyhow::{Result, anyhow};
use bytes::Bytes;
use sha2::{Digest, Sha256};

use ndn_packet::Name;
use ndn_sync::{DataStore, MemoryStore};

use crate::hex;

pub struct DirStore {
    memory: MemoryStore,
    dir: PathBuf,
    /// Writes and removals that returned.
    accepted: AtomicU64,
    /// Every accepted one up to this count is known durable.
    durable: AtomicU64,
    /// Held by the one `sync` fsyncing the directory.
    leader: Mutex<()>,
    /// The first write or removal that failed.
    failed: OnceLock<String>,
}

/// The extension of a `--store` entry's file.
const STORE_EXT: &str = "entry";

impl DirStore {
    /// Open `dir` (made if missing) and read back every entry stored there.
    pub fn open(dir: &Path) -> Result<Self> {
        ndn_security::secure_fs::create_private_dir_all(dir)
            .map_err(|e| anyhow!("--store {}: {e}", dir.display()))?;
        // A directory made here must keep its name in its parent across a
        // power loss, or every entry later synced into it goes with it.
        if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::File::open(parent)
                .and_then(|p| p.sync_all())
                .map_err(|e| {
                    anyhow!(
                        "--store {}: fsync of its parent directory failed ({e}); check the \
                         disk, or start with another --store",
                        dir.display()
                    )
                })?;
        }
        let memory = MemoryStore::new();
        let entries =
            std::fs::read_dir(dir).map_err(|e| anyhow!("--store {}: {e}", dir.display()))?;
        for entry in entries {
            let path = entry
                .map_err(|e| anyhow!("--store {}: {e}", dir.display()))?
                .path();
            // Skipped: a write's temporary file, cut short by a stop.
            if path.extension().is_none_or(|x| x != STORE_EXT) {
                continue;
            }
            let bytes = std::fs::read(&path).map_err(|e| anyhow!("{}: {e}", path.display()))?;
            let (name, wire) = Self::decode(Bytes::from(bytes)).ok_or_else(|| {
                anyhow!(
                    "{} is not an entry of this store; remove it, or start with another --store",
                    path.display()
                )
            })?;
            memory.insert(name, wire);
        }
        Ok(Self {
            memory,
            dir: dir.to_path_buf(),
            accepted: AtomicU64::new(0),
            durable: AtomicU64::new(0),
            leader: Mutex::new(()),
            failed: OnceLock::new(),
        })
    }

    fn decode(bytes: Bytes) -> Option<(Name, Bytes)> {
        let len = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
        let end = 4usize.checked_add(len).filter(|&end| end <= bytes.len())?;
        let name = Name::decode_from_tlv(bytes.slice(4..end)).ok()?;
        Some((name, bytes.slice(end..)))
    }

    fn path(&self, name_tlv: &[u8]) -> PathBuf {
        self.dir
            .join(format!("{}.{STORE_EXT}", hex(&Sha256::digest(name_tlv))))
    }

    /// Count a write or removal that returned.
    fn accept(&self) {
        self.accepted.fetch_add(1, Ordering::Release);
    }

    /// `Err` once any write or removal failed.
    fn check(&self) -> std::io::Result<()> {
        match self.failed.get() {
            None => Ok(()),
            Some(what) => Err(std::io::Error::other(format!(
                "--store {}: {what}, so a change this store accepted may not be kept and none \
                 can be promised durable any more; fix the cause (free space, the directory's \
                 permissions), then start the host again",
                self.dir.display()
            ))),
        }
    }
}

impl DataStore for DirStore {
    fn insert(&self, name: Name, wire: Bytes) {
        let tlv = name.encode_to_tlv();
        let mut file = Vec::with_capacity(4 + tlv.len() + wire.len());
        file.extend_from_slice(&(tlv.len() as u32).to_be_bytes());
        file.extend_from_slice(&tlv);
        file.extend_from_slice(&wire);
        let path = self.path(&tlv);
        match ndn_security::secure_fs::write_private(&path, &file) {
            Ok(()) => self.accept(),
            Err(e) => {
                tracing::error!(
                    %name,
                    path = %path.display(),
                    "not written to the store: {e}; held in memory, but a host started again \
                     on this --store loses it: free space or fix the directory's permissions"
                );
                let _ = self.failed.set(format!(
                    "{name} was not written to {} ({e})",
                    path.display()
                ));
            }
        }
        self.memory.insert(name, wire);
    }

    fn get(&self, name: &Name) -> Option<Bytes> {
        self.memory.get(name)
    }

    fn contains(&self, name: &Name) -> bool {
        self.memory.contains(name)
    }

    fn find_under(&self, prefix: &Name) -> Option<Bytes> {
        self.memory.find_under(prefix)
    }

    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        self.memory.scan_under(prefix, limit)
    }

    fn remove(&self, name: &Name) {
        self.memory.remove(name);
        let path = self.path(&name.encode_to_tlv());
        match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                tracing::error!(
                    %name,
                    path = %path.display(),
                    "not removed from the store: {e}; a host started again on this --store \
                     holds it again: fix the directory's permissions"
                );
                let _ = self.failed.set(format!(
                    "{name} was not removed from {} ({e})",
                    path.display()
                ));
            }
            _ => self.accept(),
        }
    }

    /// Group commit: returns at once when every write and removal before the
    /// call is already durable; otherwise the leader fsyncs the directory
    /// (each entry's data was fsynced before its rename) for everything
    /// accepted so far, and callers that waited on it re-check.
    fn sync(&self) -> std::io::Result<()> {
        self.check()?;
        let target = self.accepted.load(Ordering::Acquire);
        if self.durable.load(Ordering::Acquire) >= target {
            return Ok(());
        }
        let _leader = self.leader.lock().unwrap_or_else(PoisonError::into_inner);
        if self.durable.load(Ordering::Acquire) < target {
            let upto = self.accepted.load(Ordering::Acquire);
            match std::fs::File::open(&self.dir).and_then(|d| d.sync_all()) {
                Ok(()) => {
                    self.durable.fetch_max(upto, Ordering::Release);
                }
                Err(e) => {
                    let _ = self
                        .failed
                        .set(format!("fsync of the directory failed ({e})"));
                }
            }
        }
        self.check()
    }
}
