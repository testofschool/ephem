//! Closed-world, public-input root identity policy, not semantic secret detection.
//! Provisioning and concurrent mutation by the trusted root administrator remain
//! outside the adversary model. No request chooses this manifest or a mount path.
use anyhow::{ensure, Context, Result};
use nix::libc;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const MAX_MANIFEST: u64 = 4 * 1024 * 1024;
const MAX_ENTRIES: usize = 8192;
const MAX_ROOT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    entries: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    kind: String,
    mode: u32,
    bytes: u64,
    // Required even for directories, where the only valid value is null.
    sha256: serde_json::Value,
}

#[derive(Debug)]
pub struct RootManifest {
    path: PathBuf,
    original: Vec<u8>,
    entries: BTreeMap<String, Entry>,
}

fn canonical_name(name: &str, allow_root: bool) -> bool {
    name.starts_with('/')
        && (allow_root || name != "/")
        && (name == "/"
            || (!name.ends_with('/')
                && name.split('/').skip(1).all(|part| {
                    !part.is_empty()
                        && part != "."
                        && part != ".."
                        && part
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"_.+-".contains(&c))
                })))
}

fn trusted_ancestry(path: &Path, directory: bool) -> Result<()> {
    let name = path.to_str().context("manifest paths must be UTF-8")?;
    ensure!(
        canonical_name(name, false),
        "noncanonical manifest host path"
    );
    let mut current = Some(path);
    let mut first = true;
    while let Some(part) = current {
        let meta = fs::symlink_metadata(part).context("cannot inspect policy ancestry")?;
        ensure!(
            !meta.file_type().is_symlink() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
            "policy ancestry must be root-owned, without symlinks or group/world write"
        );
        ensure!(
            if first && !directory {
                meta.is_file() && meta.nlink() == 1
            } else {
                meta.is_dir()
            },
            "invalid policy ancestry type or hardlink"
        );
        first = false;
        current = part.parent();
    }
    Ok(())
}

fn open_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .context("cannot open manifest-controlled file without following links")?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.uid() == 0 && meta.nlink() == 1,
        "invalid manifest-controlled file"
    );
    Ok(file)
}

fn policy_bytes(path: &Path) -> Result<Vec<u8>> {
    trusted_ancestry(path, false)?;
    let file = open_file(path)?;
    ensure!(file.metadata()?.len() <= MAX_MANIFEST, "manifest too large");
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_MANIFEST, "manifest too large");
    Ok(bytes)
}

impl RootManifest {
    pub fn digest(&self) -> String {
        format!("{:x}", Sha256::digest(&self.original))
    }

    pub fn load(path: &Path, root: &Path, worker: &str) -> Result<Self> {
        trusted_ancestry(root, true)?;
        ensure!(
            !path.starts_with(root),
            "manifest must be outside the worker root"
        );
        let original = policy_bytes(path)?;
        let parsed: Manifest =
            serde_json::from_slice(&original).context("invalid root manifest schema")?;
        ensure!(parsed.version == 1, "unsupported root manifest version");
        ensure!(
            !parsed.entries.is_empty() && parsed.entries.len() <= MAX_ENTRIES,
            "invalid manifest entry count"
        );
        let mut entries = BTreeMap::new();
        let mut total = 0u64;
        for entry in parsed.entries {
            ensure!(
                canonical_name(&entry.path, true),
                "noncanonical in-root manifest path"
            );
            ensure!(
                !entry.path.starts_with("/tmp/"),
                "scratch directory must have no manifest children"
            );
            ensure!(
                entry.mode <= 0o7777 && entry.mode & 0o6000 == 0,
                "unsupported manifest mode"
            );
            match entry.kind.as_str() {
                "directory" => {
                    ensure!(
                        entry.bytes == 0 && entry.sha256.is_null(),
                        "directory payload must be zero/null"
                    );
                    ensure!(
                        if entry.path == "/tmp" {
                            entry.mode == 0o1777
                        } else {
                            entry.mode & 0o022 == 0
                        },
                        "writable manifest directory"
                    );
                }
                "file" => {
                    ensure!(
                        entry.path != "/" && entry.mode & 0o222 == 0 && entry.mode & 0o1000 == 0,
                        "writable or special-mode manifest file"
                    );
                    let digest = entry
                        .sha256
                        .as_str()
                        .context("file sha256 must be a string")?;
                    ensure!(
                        digest.len() == 64
                            && digest
                                .bytes()
                                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
                        "invalid file sha256"
                    );
                    total = total
                        .checked_add(entry.bytes)
                        .context("root size overflow")?;
                    ensure!(total <= MAX_ROOT_BYTES, "manifest root too large");
                }
                _ => anyhow::bail!("unsupported manifest entry kind"),
            }
            ensure!(
                entries.insert(entry.path.clone(), entry).is_none(),
                "duplicate manifest path"
            );
        }
        ensure!(
            entries.get("/").is_some_and(|e| e.kind == "directory"),
            "manifest root directory missing"
        );
        ensure!(
            entries.get("/tmp").is_some_and(|e| e.kind == "directory"),
            "manifest tmp directory missing"
        );
        ensure!(
            canonical_name(worker, false)
                && entries
                    .get(worker)
                    .is_some_and(|e| e.kind == "file" && e.mode & 0o111 != 0),
            "worker not an approved executable"
        );
        for name in entries.keys().filter(|name| name.as_str() != "/") {
            let parent = Path::new(name)
                .parent()
                .and_then(Path::to_str)
                .context("entry parent missing")?;
            ensure!(
                entries.get(parent).is_some_and(|e| e.kind == "directory"),
                "manifest parent directory missing"
            );
        }
        let policy = Self {
            path: path.to_owned(),
            original,
            entries,
        };
        policy.validate(root)?;
        Ok(policy)
    }

    pub fn validate(&self, root: &Path) -> Result<()> {
        trusted_ancestry(root, true)?;
        ensure!(
            policy_bytes(&self.path)? == self.original,
            "root manifest changed after startup"
        );
        // mountinfo encodes special characters with octal escapes. Host policy
        // paths use the restricted canonical alphabet above, so no unescaping
        // is necessary for equality or descendant matching against those paths.
        let prefix = format!("{}/", root.display());
        for line in fs::read_to_string("/proc/self/mountinfo")
            .context("mountinfo required for root policy")?
            .lines()
        {
            let mounted = line
                .split_whitespace()
                .nth(4)
                .context("invalid mountinfo")?;
            ensure!(
                !mounted.starts_with(&prefix),
                "nested root mount is not supported"
            );
        }
        let mut found = BTreeSet::new();
        let mut pending = vec![(root.to_path_buf(), "/".to_owned())];
        while let Some((host, name)) = pending.pop() {
            ensure!(found.insert(name.clone()), "duplicate root entry");
            let expected = self.entries.get(&name).context("unapproved root entry")?;
            let meta = fs::symlink_metadata(&host).context("cannot inspect root entry")?;
            ensure!(
                meta.uid() == 0 && meta.mode() & 0o7777 == expected.mode,
                "root entry owner or mode mismatch"
            );
            if expected.kind == "directory" {
                ensure!(
                    meta.is_dir() && !meta.file_type().is_symlink(),
                    "root entry is not an approved directory"
                );
                for child in fs::read_dir(&host).context("cannot enumerate root directory")? {
                    let child = child?;
                    let part = child
                        .file_name()
                        .into_string()
                        .map_err(|_| anyhow::anyhow!("non-UTF8 root filename"))?;
                    let child_name = if name == "/" {
                        format!("/{part}")
                    } else {
                        format!("{name}/{part}")
                    };
                    ensure!(
                        canonical_name(&child_name, false),
                        "noncanonical root filename"
                    );
                    ensure!(
                        self.entries.contains_key(&child_name),
                        "unapproved root entry"
                    );
                    pending.push((child.path(), child_name));
                }
            } else {
                ensure!(
                    meta.is_file() && !meta.file_type().is_symlink() && meta.nlink() == 1,
                    "root file is a link or special file"
                );
                let mut file = open_file(&host)?;
                let opened = file.metadata()?;
                ensure!(
                    opened.dev() == meta.dev()
                        && opened.ino() == meta.ino()
                        && opened.mode() == meta.mode()
                        && opened.len() == expected.bytes,
                    "root file changed while opening"
                );
                let mut hash = Sha256::new();
                let mut count = 0u64;
                let mut block = [0u8; 65536];
                loop {
                    let n = file.read(&mut block)?;
                    if n == 0 {
                        break;
                    }
                    count = count
                        .checked_add(n as u64)
                        .context("root file size overflow")?;
                    ensure!(count <= expected.bytes, "root file grew while hashing");
                    hash.update(&block[..n]);
                }
                let after = file.metadata()?;
                ensure!(
                    count == expected.bytes
                        && after.len() == opened.len()
                        && after.mtime() == opened.mtime()
                        && after.mtime_nsec() == opened.mtime_nsec()
                        && after.ctime() == opened.ctime()
                        && after.ctime_nsec() == opened.ctime_nsec(),
                    "root file changed while hashing"
                );
                let digest = format!("{:x}", hash.finalize());
                ensure!(
                    expected.sha256.as_str() == Some(digest.as_str()),
                    "root file digest mismatch"
                );
            }
        }
        ensure!(
            found.len() == self.entries.len(),
            "approved root entries missing"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_names_reject_ambiguous_and_hidden_path_components() {
        for name in [
            "",
            "relative",
            "//worker",
            "/app//worker",
            "/app/../worker",
            "/app/./worker",
            "/worker/",
            "/worker\n",
            "/é",
        ] {
            assert!(!canonical_name(name, false), "accepted {name:?}");
        }
        assert!(canonical_name("/", true));
        assert!(!canonical_name("/", false));
        assert!(canonical_name("/app/.public-worker_1+2", false));
    }

    #[test]
    fn manifest_schema_rejects_unknown_duplicate_and_missing_fields() {
        for value in [
            r#"{"version":1,"entries":[],"approved":true}"#,
            r#"{"version":1,"version":1,"entries":[]}"#,
            r#"{"version":1,"entries":[{"path":"/","kind":"directory","mode":493,"bytes":0}]}"#,
            r#"{"version":1,"entries":[{"path":"/","kind":"directory","mode":493,"bytes":0,"sha256":null,"secret":false}]}"#,
        ] {
            assert!(
                serde_json::from_str::<Manifest>(value).is_err(),
                "accepted {value}"
            );
        }
        let document: Manifest = serde_json::from_str(r#"{"version":1,"entries":[{"path":"/","kind":"directory","mode":493,"bytes":0,"sha256":null}]}"#).unwrap();
        assert_eq!(document.version, 1);
        assert_eq!(document.entries.len(), 1);
    }
}
