//! Reader for the signed-release SDK index shape used by arismoko/horizon.
//!
//! This module reads only an SDK directory installed by the signed-release installer. It checks
//! the install receipt, index identity, raw selected-asset hashes and the extracted tree before
//! a native build may use the SDK.
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};

#[derive(Clone, Debug, Deserialize)]
pub struct SdkIndex {
    pub schema: u32,
    pub build: Build,
    pub package_format: u32,
    pub toolchain: Toolchain,
    pub content_api: String,
    pub surface: Surface,
    pub inputs: serde_json::Value,
    pub mixins: Mixins,
    pub assets: BTreeMap<String, Asset>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Build {
    pub commit: String,
    pub game: String,
    pub date: String,
    #[serde(default)]
    pub nightly: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Surface {
    pub hash: String,
    #[serde(default)]
    pub previous: Option<String>,
    #[serde(default)]
    pub changes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Toolchain {
    pub rust: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Mixins {
    pub rev: String,
    pub patch: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Asset {
    pub sha256: String,
    pub size: u64,
    pub kind: String,
    pub codec: String,
    pub target: Option<String>,
    pub side: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct InstallReceipt {
    signature_verified: bool,
    tag: String,
    index_sha256: String,
    target: String,
    game_commit: String,
    mixins_rev: String,
    files: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct VerifiedIdentity {
    pub index: SdkIndex,
    pub index_sha256: String,
}



fn hash_file(path: &Path) -> Result<(u64, String), String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let size = file.metadata().map_err(|e| e.to_string())?.len();
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 { break; }
        digest.update(&buffer[..count]);
    }
    Ok((size, format!("{:x}", digest.finalize())))
}

fn hash_tree(root: &Path, current: &Path, output: &mut BTreeMap<String, String>) -> Result<(), String> {
    let entries = std::fs::read_dir(current).map_err(|e| format!("{}: {e}", current.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        if kind.is_symlink() {
            return Err(format!("SDK cache contains a symlink: {}", path.display()));
        }
        if kind.is_dir() {
            hash_tree(root, &path, output)?;
        } else if kind.is_file() {
            use std::io::Read;
            let mut file = std::fs::File::open(&path).map_err(|e| e.to_string())?;
            let mut digest = Sha256::new();
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
                if count == 0 { break; }
                digest.update(&buffer[..count]);
            }
            let relative = path.strip_prefix(root).map_err(|e| e.to_string())?;
            let key = relative.to_str().ok_or_else(|| "SDK cache path is not UTF-8".to_owned())?.to_owned();
            output.insert(key, format!("{:x}", digest.finalize()));
        } else {
            return Err(format!("SDK cache contains a special file: {}", path.display()));
        }
    }
    Ok(())
}

const RELEASE_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAIql+MN7pjxis0Xm+fRhjoW0aIwO1tV/gQLonX1tK35o=\n-----END PUBLIC KEY-----\n";

/// Re-check the upstream Ed25519 signature at use time. The install receipt is writable
/// app data and is not, by itself, cryptographic proof of a trusted SDK.
fn verify_signed_inventory(directory: &Path) -> Result<BTreeMap<String, String>, String> {
    use std::{io::Write, process::Command};
    static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sums = std::fs::read(directory.join("SHA256SUMS"))
        .map_err(|e| format!("SDK signed checksum inventory is missing: {e}"))?;
    let signatures = std::fs::read_to_string(directory.join("SHA256SUMS.sig"))
        .map_err(|e| format!("SDK signature list is missing: {e}"))?;
    let mut entries = BTreeMap::new();
    for line in std::str::from_utf8(&sums).map_err(|_| "SDK checksum inventory is not ASCII")?.lines() {
        let (hash, name) = line.split_once("  ").ok_or("invalid SDK checksum row")?;
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || entries.insert(name.to_owned(), hash.to_owned()).is_some() {
            return Err(format!("invalid or duplicate SDK checksum row: {line:?}"));
        }
    }
    if !entries.contains_key("sdk.json") {
        return Err("signed SDK checksum inventory does not include sdk.json".into());
    }
    let temp = std::env::temp_dir().join(format!(
        "horizon-sdk-verify-{}-{}", std::process::id(),
        NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir(&temp).map_err(|e| format!("cannot create SDK verification directory: {e}"))?;
    let result = (|| {
        let key = temp.join("release-key.pem");
        let message = temp.join("signed-message");
        std::fs::write(&key, RELEASE_PUBLIC_KEY_PEM).map_err(|e| e.to_string())?;
        // The signed payload is the literal release tag followed by the complete SHA256SUMS file.
        let mut signed = Vec::new();
        let index: SdkIndex = serde_json::from_slice(&std::fs::read(directory.join("sdk.json")).map_err(|e| e.to_string())?)
            .map_err(|e| format!("invalid sdk.json: {e}"))?;
        signed.clear();
        signed.extend_from_slice(format!("horizon release sdk-{}\n", index.build.commit).as_bytes());
        signed.extend_from_slice(&sums);
        std::fs::write(&message, signed).map_err(|e| e.to_string())?;
        let sig_path = temp.join("signature");
        let mut verified = false;
        for encoded in signatures.lines().filter(|line| !line.trim().is_empty()) {
            // Decode through stdin so signature records are not interpolated into a shell command.
            use std::process::Stdio;
            let mut child = Command::new("base64").arg("-d").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()
                .map_err(|e| format!("cannot start base64 verifier: {e}"))?;
            child.stdin.take().ok_or("base64 stdin unavailable")?.write_all(encoded.as_bytes())
                .map_err(|e| e.to_string())?;
            let decoded = child.wait_with_output().map_err(|e| e.to_string())?;
            if !decoded.status.success() { continue; }
            std::fs::write(&sig_path, decoded.stdout).map_err(|e| e.to_string())?;
            let check = Command::new("openssl").args([
                "pkeyutl", "-verify", "-pubin", "-inkey", key.to_str().ok_or("temporary key path is not UTF-8")?,
                "-rawin", "-in", message.to_str().ok_or("temporary message path is not UTF-8")?,
                "-sigfile", sig_path.to_str().ok_or("temporary signature path is not UTF-8")?,
            ]).output().map_err(|e| format!("OpenSSL SDK signature verifier unavailable: {e}"))?;
            if check.status.success() { verified = true; break; }
        }
        if !verified { return Err("SDK Ed25519 release signature is invalid".into()); }
        Ok(entries)
    })();
    let _ = std::fs::remove_dir_all(&temp);
    result
}


impl VerifiedIdentity {
    /// Read an SDK only after independently verifying its signed release inventory and assets.
    /// The install receipt is an additional consistency check, never the source of trust.
    pub fn read(directory: &Path) -> Result<Self, String> {
        if !directory.is_dir() {
            return Err(format!("{} is not an installed SDK directory", directory.display()));
        }
        let index_path = directory.join("sdk.json");
        let bytes = std::fs::read(&index_path).map_err(|e| format!("{}: {e}", index_path.display()))?;
        let index: SdkIndex = serde_json::from_slice(&bytes)
            .map_err(|e| format!("{}: invalid sdk.json: {e}", index_path.display()))?;
        let index_sha256 = format!("{:x}", Sha256::digest(&bytes));
        // Re-verify the release signature here; never trust the mutable install receipt's
        // signature_verified boolean as proof that this SDK is still authentic.
        let signed_assets = verify_signed_inventory(directory)?;

        // The release signer covers every indexed SDK asset, not only the Android subset
        // copied into this installation. Enforce the complete inventory shape so an index
        // cannot silently omit or add release assets while retaining a valid signature.
        let mut expected_inventory = std::collections::BTreeSet::new();
        expected_inventory.insert("sdk.json".to_owned());
        expected_inventory.extend(index.assets.keys().cloned());
        let actual_inventory: std::collections::BTreeSet<_> = signed_assets.keys().cloned().collect();
        if actual_inventory != expected_inventory {
            return Err("signed SDK checksum inventory does not exactly match sdk.json assets".into());
        }
        if signed_assets.get("sdk.json") != Some(&index_sha256) {
            return Err("sdk.json does not match its signed checksum inventory entry".into());
        }

        let receipt_path = directory.join(".install-manifest.json");
        let receipt: InstallReceipt = serde_json::from_slice(
            &std::fs::read(&receipt_path).map_err(|e| format!("{}: {e}", receipt_path.display()))?
        ).map_err(|e| format!("{}: invalid install receipt: {e}", receipt_path.display()))?;
        if !receipt.signature_verified
            || receipt.tag != format!("sdk-{}", index.build.commit)
            || receipt.index_sha256 != index_sha256
            || receipt.game_commit != index.build.commit
            || receipt.mixins_rev != index.mixins.rev
            || receipt.target != "aarch64-linux-android"
        {
            return Err("SDK install receipt is missing, unsigned or does not match sdk.json".into());
        }
        let identity = Self { index, index_sha256 };
        identity.validate()?;
        for name in [
            "sdk.json", "SHA256SUMS", "SHA256SUMS.sig",
            "surface.json", "build-data.tar.xz", "api-source.tar.xz",
            "runtime-aarch64-linux-android.tar.xz",
            "api-aarch64-linux-android.tar.xz",
            "engine-aarch64-linux-android.tar.xz",
        ] {
            if name != "SHA256SUMS" && name != "SHA256SUMS.sig" {
                let expected = signed_assets.get(name)
                    .ok_or_else(|| format!("signed SDK inventory omits {name}"))?;
                let (_, actual) = hash_file(&directory.join(name))?;
                if &actual != expected {
                    return Err(format!("SDK asset {name} does not match the signed checksum inventory"));
                }
            }
        }
        for name in [
            "surface.json", "build-data.tar.xz", "api-source.tar.xz",
            "runtime-aarch64-linux-android.tar.xz",
            "api-aarch64-linux-android.tar.xz",
            "engine-aarch64-linux-android.tar.xz",
        ] {
            let asset = identity.index.assets.get(name)
                .ok_or_else(|| format!("SDK index is missing required asset {name}"))?;
            let path = directory.join(name);
            let (size, digest) = hash_file(&path)?;
            if size != asset.size || digest != asset.sha256 {
                return Err(format!("installed SDK asset {name} does not match sdk.json"));
            }
        }
        let slices = directory.join("slices");
        let mut files = BTreeMap::new();
        hash_tree(&slices, &slices, &mut files)?;
        if files != receipt.files {
            return Err("SDK extracted files do not match the signed installation receipt".into());
        }
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), String> {
        let index = &self.index;
        if index.schema != 1 {
            return Err(format!("unsupported SDK schema {}; expected 1", index.schema));
        }
        if !revision(&index.build.commit) || !revision(&index.mixins.rev) {
            return Err("SDK game and mixins revisions must be full lowercase commit IDs".into());
        }
        if index.build.game.trim().is_empty() || index.toolchain.rust.trim().is_empty()
            || index.content_api.trim().is_empty() || !hex(&index.surface.hash, 64)
            || index.package_format == 0 {
            return Err("SDK game version and Rust toolchain identity are required".into());
        }
        if !hex(&index.mixins.patch, 64) {
            return Err("SDK mixins patch identity must be a 64-character SHA-256".into());
        }
        for (name, asset) in &index.assets {
            if name.contains('/') || name.contains('\\') || name.is_empty() {
                return Err(format!("SDK asset name is not a plain file name: {name:?}"));
            }
            if !hex(&asset.sha256, 64) || asset.size == 0 {
                return Err(format!("SDK asset {name} has an invalid SHA-256 or size"));
            }
        }
        for (name, kind, codec) in [
            ("surface.json", "surface", "none"),
            ("build-data.tar.xz", "build-data", "xz"),
            ("api-source.tar.xz", "api-source", "xz"),
        ] {
            let asset = index.assets.get(name)
                .ok_or_else(|| format!("SDK index is missing required asset {name}"))?;
            if asset.kind != kind || asset.codec != codec || asset.target.is_some() || asset.side.is_some() {
                return Err(format!("SDK asset {name} has inconsistent kind/codec metadata"));
            }
        }
        Ok(())
    }

    /// Check that this SDK really describes the selected HMOD pins and contains the slices
    /// required for this target. Android must be explicitly published; host SDKs are not reused.
    pub fn require_target(&self, target: &str, game: &str, horizon: &str, mixins: &str) -> Result<(), String> {
        self.validate()?;
        let index = &self.index;
        if index.build.game != game || index.build.commit != horizon || index.mixins.rev != mixins {
            return Err(format!(
                "HMOD pins game/Horizon/mixins {game}/{horizon}/{mixins} do not match SDK {}/{}/{}",
                index.build.game, index.build.commit, index.mixins.rev
            ));
        }
        for kind in ["runtime", "api", "engine"] {
            let name = format!("{kind}-{target}.tar.xz");
            let asset = index.assets.get(&name)
                .ok_or_else(|| format!("SDK has no {target} {kind} slice; this target is not published"))?;
            if asset.target.as_deref() != Some(target) || asset.codec != "xz" || asset.kind != kind || asset.side.as_deref() != Some("client") {
                return Err(format!("SDK asset {name} has inconsistent target or codec metadata"));
            }
        }
        Ok(())
    }
}

fn revision(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn index(target: &str) -> serde_json::Value {
        let mut assets = serde_json::Map::new();
        for name in ["surface.json", "build-data.tar.xz", "api-source.tar.xz"] {
            let kind = if name == "surface.json" { "surface" } else if name == "build-data.tar.xz" { "build-data" } else { "api-source" };
            let codec = if name == "surface.json" { "none" } else { "xz" };
            assets.insert(name.into(), json!({"sha256":"a".repeat(64),"size":1,"kind":kind,"codec":codec}));
        }
        for kind in ["runtime", "api", "engine"] {
            assets.insert(format!("{kind}-{target}.tar.xz"), json!({
                "sha256":"b".repeat(64), "size":1, "kind":kind, "codec":"xz",
                "target":target, "side":"client"
            }));
        }
        json!({
            "schema":1,
            "build":{"commit":"a".repeat(40),"game":"26.3","date":"2026-11-14"},
            "package_format":1,
            "toolchain":{"rust":"1.95.0"},
            "content_api":"0.2",
            "surface":{"hash":"e".repeat(64)},
            "mixins":{"rev":"b".repeat(40),"patch":"c".repeat(64)},
            "assets":assets,
            "inputs":{}
        })
    }

    #[test]
    fn refuses_a_forged_install_receipt_without_a_signed_inventory() {
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let temp = std::env::temp_dir().join(format!("hnmod-sdk-test-{}-{nonce}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let value = index("aarch64-linux-android");
        let bytes = serde_json::to_vec(&value).unwrap();
        std::fs::write(temp.join("sdk.json"), &bytes).unwrap();
        let parsed: SdkIndex = serde_json::from_slice(&bytes).unwrap();
        let receipt = serde_json::json!({
            "files": {},
            "signature_verified": true,
            "tag": format!("sdk-{}", parsed.build.commit),
            "index_sha256": format!("{:x}", Sha256::digest(&bytes)),
            "target": "aarch64-linux-android",
            "game_commit": parsed.build.commit,
            "mixins_rev": parsed.mixins.rev
        });
        std::fs::write(temp.join(".install-manifest.json"), serde_json::to_vec(&receipt).unwrap()).unwrap();
        let error = VerifiedIdentity::read(&temp).unwrap_err();
        assert!(error.contains("signed checksum inventory is missing"), "{error}");
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn reads_sdk_index_and_checks_android_slices_and_pins() {
        let value = index("aarch64-linux-android");
        let parsed: SdkIndex = serde_json::from_value(value).unwrap();
        let identity = VerifiedIdentity { index: parsed, index_sha256: "d".repeat(64) };
        identity.require_target("aarch64-linux-android", "26.3", &"a".repeat(40), &"b".repeat(40)).unwrap();
    }

    #[test]
    fn refuses_desktop_sdk_for_android() {
        let value = index("x86_64-unknown-linux-gnu");
        let parsed: SdkIndex = serde_json::from_value(value).unwrap();
        let identity = VerifiedIdentity { index: parsed, index_sha256: "d".repeat(64) };
        let error = identity.require_target("aarch64-linux-android", "26.3", &"a".repeat(40), &"b".repeat(40)).unwrap_err();
        assert!(error.contains("this target is not published"));
    }

    #[test]
    fn refuses_wrong_game_or_mixins_pin() {
        let parsed: SdkIndex = serde_json::from_value(index("aarch64-linux-android")).unwrap();
        let identity = VerifiedIdentity { index: parsed, index_sha256: "d".repeat(64) };
        assert!(identity.require_target("aarch64-linux-android", "26.3", &"e".repeat(40), &"b".repeat(40)).is_err());
        assert!(identity.require_target("aarch64-linux-android", "26.3", &"a".repeat(40), &"f".repeat(40)).is_err());
    }
}
