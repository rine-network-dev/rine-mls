use std::fs;
use std::path::PathBuf;

use mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs_core::key_package::{KeyPackageData, KeyPackageStorage};

use super::{read_optional, remove_if_present, write_private, MlsStoreRoot, Result, StoreError};

/// [`KeyPackageStorage`] holding the private half of every KeyPackage this
/// agent has minted, keyed by its KeyPackage ref.
///
/// Only the public half is ever published to the rine server; mls-rs deletes
/// the private half here automatically once its KeyPackage has been used to
/// join a group, which is what makes rine's one-shot destructive claim
/// (`GET /agents/{id}/mls/key-packages` consumes) safe on the client side too.
#[derive(Debug, Clone)]
pub struct FileKeyPackageStorage {
    root: MlsStoreRoot,
}

impl FileKeyPackageStorage {
    pub fn new(root: MlsStoreRoot) -> Self {
        Self { root }
    }

    fn path(&self, id: &[u8]) -> PathBuf {
        self.root
            .key_packages_dir()
            .join(format!("{}.bin", hex::encode(id)))
    }

    /// Every KeyPackage ref whose private half is still held locally.
    ///
    /// This is the only non-destructive inventory reading rine has: the
    /// server's `GET /agents/{id}/mls/key-packages` is a *claim* that consumes
    /// what it returns, and there is no count endpoint. The local mirror
    /// follows the server as claims turn into processed Welcomes, and can only
    /// ever over-count — a KeyPackage published but never claimed, or one
    /// claimed for a Welcome that never arrived — which delays a top-up rather
    /// than pushing the pool past the server's inventory cap.
    pub fn stored_refs(&self) -> Result<Vec<Vec<u8>>> {
        let dir = self.root.key_packages_dir();

        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(StoreError::io(&dir, e)),
        };

        let mut refs = Vec::new();

        for entry in entries {
            let path = entry.map_err(|e| StoreError::io(&dir, e))?.path();

            // A `.tmp` is a write that never landed, not a KeyPackage.
            if path.extension().and_then(|e| e.to_str()) != Some("bin") {
                continue;
            }

            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| StoreError::Corrupt { path: path.clone() })?;

            refs.push(hex::decode(name).map_err(|_| StoreError::Corrupt { path: path.clone() })?);
        }

        Ok(refs)
    }

    /// How many unconsumed KeyPackages this agent still holds the private half
    /// of. See [`Self::stored_refs`] for why this is read locally.
    pub fn count(&self) -> Result<usize> {
        Ok(self.stored_refs()?.len())
    }

    /// Drop one private half. Deleting an entry the store never had is not an
    /// error: MLS KeyPackages are single-use, so "already gone" is the outcome
    /// the caller wanted.
    pub fn remove(&self, id: &[u8]) -> Result<()> {
        remove_if_present(&self.path(id))
    }
}

impl KeyPackageStorage for FileKeyPackageStorage {
    type Error = StoreError;

    fn delete(&mut self, id: &[u8]) -> Result<()> {
        self.remove(id)
    }

    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<()> {
        let path = self.path(&id);

        let encoded = pkg
            .mls_encode_to_vec()
            .map_err(|_| StoreError::Corrupt { path: path.clone() })?;

        write_private(&path, &encoded)
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>> {
        let path = self.path(id);

        let Some(bytes) = read_optional(&path)? else {
            return Ok(None);
        };

        KeyPackageData::mls_decode(&mut bytes.as_slice())
            .map(Some)
            .map_err(|_| StoreError::Corrupt { path })
    }
}
