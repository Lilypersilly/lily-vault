//! Core `.lilar` encrypted vault engine (100% compatible with `lily-dashboard`).
//!
//! Uses Argon2id KDF + HKDF-SHA256 per-file subkeys + streaming AES-256-GCM (1 MB chunks)
//! packed into `block_XXX.lilar` files (up to 10 GB each) with an encrypted `vault.lilar`
//! index and rolling `.bak1..bak5` backups.

use aead::stream::{DecryptorBE32, EncryptorBE32};
use aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use gtk4::gio;
use gtk4::glib;
use gtk4::prelude::*;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;

pub const KEYFILE_NAME: &str = ".lily_master.key";
pub const INDEX_FILENAME: &str = "vault.lilar";
pub const RAM_EXTRACT_DIR: &str = "/dev/shm/lily-vault";
pub const VAULT_PASSWORDS_FILENAME: &str = "passwords.txt";

pub const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB plaintext chunks
pub const TAG_SIZE: usize = 16;
pub const CIPHER_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_SIZE;
pub const MAX_BLOCK_SIZE: u64 = 10 * 1024 * 1024 * 1024; // 10 GB per .lilar block

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct VaultAppConfig {
    pub last_vault_dir: String,
    #[serde(default)]
    pub recent_vaults: Vec<String>,
    #[serde(default)]
    pub key_mode: String, // "usb" or "file"
    #[serde(default)]
    pub last_keyfile: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ChunkSegment {
    pub block_id: u32,
    pub offset: u64,
    pub cipher_len: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VaultFileEntry {
    pub name: String,
    pub original_size: u64,
    pub file_salt: [u8; 16],
    pub stream_nonce: [u8; 7],
    pub segments: Vec<ChunkSegment>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VaultIndex {
    pub next_block_id: u32,
    pub max_size_gb: u64,
    pub files: Vec<VaultFileEntry>,
    pub dead_bytes_per_block: HashMap<u32, u64>,
}

impl Default for VaultIndex {
    fn default() -> Self {
        Self {
            next_block_id: 1,
            max_size_gb: 50,
            files: Vec::new(),
            dead_bytes_per_block: HashMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct VaultHeader {
    pub kek_salt: [u8; 16],
    pub dek_wrap_nonce: [u8; 12],
    pub wrapped_dek: Vec<u8>,
    pub requires_pin: bool,
    pub index_nonce: [u8; 12],
    pub encrypted_index: Vec<u8>,
}

pub struct UnlockedSession {
    pub vault_dir: PathBuf,
    pub unlocked_via_usb: bool,
    pub dek: [u8; 32],
    pub kek_salt: [u8; 16],
    pub dek_wrap_nonce: [u8; 12],
    pub wrapped_dek: Vec<u8>,
    pub requires_pin: bool,
    pub index: VaultIndex,
}

impl Drop for UnlockedSession {
    fn drop(&mut self) {
        // Zeroize DEK in memory using write_volatile + compiler_fence so LLVM
        // dead-store elimination cannot strip the wipe in release builds.
        for b in &mut self.dek {
            unsafe {
                std::ptr::write_volatile(b, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

pub enum WorkerEvent {
    Progress(f64, String),
    AddDone(Result<VaultFileEntry, String>),
    ReplaceDone(Result<(usize, VaultFileEntry), String>),
    ExtractDone(Result<(PathBuf, bool), String>),
    VacuumDone(Result<VaultIndex, String>),
}

pub fn app_config_path() -> PathBuf {
    let mut path = glib::user_config_dir();
    path.push("lily-vault");
    let _ = fs::create_dir_all(&path);
    path.push("config.json");
    path
}

pub fn load_app_config() -> VaultAppConfig {
    if let Ok(data) = fs::read_to_string(app_config_path()) {
        if let Ok(cfg) = serde_json::from_str::<VaultAppConfig>(&data) {
            return cfg;
        }
    }
    // Convenience: if lily-dashboard's locker.json exists, pre-fill its vault folder
    let mut dash_locker = glib::user_config_dir();
    dash_locker.push("lily-dashboard");
    dash_locker.push("locker.json");
    if let Ok(data) = fs::read_to_string(dash_locker) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&data) {
            if let Some(v) = json.get("vault_dir").and_then(|s| s.as_str()) {
                if !v.is_empty() {
                    return VaultAppConfig {
                        last_vault_dir: v.to_string(),
                        recent_vaults: vec![v.to_string()],
                        key_mode: "usb".to_string(),
                        last_keyfile: String::new(),
                    };
                }
            }
        }
    }
    VaultAppConfig {
        key_mode: "usb".to_string(),
        ..Default::default()
    }
}

pub fn save_app_config(cfg: &VaultAppConfig) {
    if let Ok(json) = serde_json::to_string_pretty(cfg) {
        let _ = fs::write(app_config_path(), json);
    }
}

pub fn record_recent_vault(cfg: &mut VaultAppConfig, dir: &str) {
    if dir.trim().is_empty() {
        return;
    }
    cfg.last_vault_dir = dir.to_string();
    cfg.recent_vaults.retain(|d| d != dir);
    cfg.recent_vaults.insert(0, dir.to_string());
    cfg.recent_vaults.truncate(6);
    save_app_config(cfg);
}

pub fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf {
        unsafe {
            std::ptr::write_volatile(b, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Generates cryptographically secure bytes modulated with Quantum entropy (XOR pool).
pub fn generate_quantum_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    if let Ok(mut f) = File::open("/dev/urandom") {
        let _ = f.read_exact(&mut bytes);
    }

    let url = "https://lizaonair.com/qrng/?min=100000000&max=999999999";
    if let Ok(output) = Command::new("curl")
        .args(["-sL", "-H", "Accept: application/json", "--max-time", "2", url])
        .output()
    {
        if output.status.success() {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                if let Some(num) = json.get("value").and_then(|v| v.as_u64()) {
                    let q_bytes = num.to_string().into_bytes();
                    if !q_bytes.is_empty() {
                        for (i, b) in bytes.iter_mut().enumerate() {
                            *b ^= q_bytes[i % q_bytes.len()];
                        }
                    }
                }
            }
        }
    }
    bytes
}

pub fn random_fixed<const N: usize>() -> [u8; N] {
    let mut arr = [0u8; N];
    if let Ok(mut f) = File::open("/dev/urandom") {
        let _ = f.read_exact(&mut arr);
    }
    arr
}

/// Scans mounted GIO volumes & standard Linux media directories for `.lily_master.key`.
pub fn find_usb_keyfile() -> Option<PathBuf> {
    let monitor = gio::VolumeMonitor::get();
    for mount in monitor.mounts() {
        if let Some(root_path) = mount.root().path() {
            let candidate = root_path.join(KEYFILE_NAME);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    let user = std::env::var("USER")
        .ok()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| glib::user_name().to_string_lossy().to_string());
    for base_str in [format!("/run/media/{}", user), format!("/media/{}", user)] {
        let base = PathBuf::from(base_str);
        if let Ok(entries) = fs::read_dir(base) {
            for entry in entries.flatten() {
                let candidate = entry.path().join(KEYFILE_NAME);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

/// Returns mounted removable/media folders where a new `.lily_master.key` can be written.
pub fn find_first_usb_mount_dir() -> Option<PathBuf> {
    let monitor = gio::VolumeMonitor::get();
    for mount in monitor.mounts() {
        if let Some(root_path) = mount.root().path() {
            if root_path.is_dir() {
                return Some(root_path);
            }
        }
    }
    let user = std::env::var("USER")
        .ok()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| glib::user_name().to_string_lossy().to_string());
    for base_str in [format!("/run/media/{}", user), format!("/media/{}", user)] {
        let base = PathBuf::from(base_str);
        if let Ok(entries) = fs::read_dir(base) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    return Some(entry.path());
                }
            }
        }
    }
    None
}

/// Derives the 32-byte KEK from `(Keyfile Bytes || PIN)` using Argon2id.
pub fn derive_kek(key_bytes: &[u8], pin: &str, salt: &[u8; 16]) -> Result<[u8; 32], String> {
    let mut combined = Vec::with_capacity(key_bytes.len() + pin.len());
    combined.extend_from_slice(key_bytes);
    combined.extend_from_slice(pin.as_bytes());

    let params = Params::new(64 * 1024, 3, 1, Some(32)).map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut kek = [0u8; 32];
    let res = argon2
        .hash_password_into(&combined, salt, &mut kek)
        .map_err(|e| format!("Argon2 error: {}", e));
    zeroize_bytes(&mut combined);
    res?;
    Ok(kek)
}

pub fn derive_file_subkey(master_dek: &[u8; 32], file_salt: &[u8; 16]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(file_salt), master_dek);
    let mut subkey = [0u8; 32];
    hk.expand(b"lily-quantum-locker-file-key", &mut subkey)
        .expect("HKDF expand failed");
    subkey
}

pub fn block_path(vault_dir: &Path, block_id: u32) -> PathBuf {
    vault_dir.join(format!("block_{:03}.lilar", block_id))
}

pub fn read_vault_header(vault_dir: &Path) -> Result<VaultHeader, String> {
    let idx_path = vault_dir.join(INDEX_FILENAME);
    let data = fs::read(&idx_path)
        .map_err(|e| format!("Could not read {}: {}", idx_path.display(), e))?;
    serde_json::from_slice::<VaultHeader>(&data)
        .map_err(|e| format!("Corrupted vault header: {}", e))
}

/// Creates a brand-new `.lilar` vault in `vault_dir` and writes a 64-byte quantum-modulated
/// keyfile to `keyfile_path` (unless `keyfile_path` already exists and `reuse_existing_key` is true).
pub fn create_new_vault(
    vault_dir: &Path,
    keyfile_path: &Path,
    pin: &str,
    max_size_gb: u64,
    unlocked_via_usb: bool,
) -> Result<UnlockedSession, String> {
    fs::create_dir_all(vault_dir).map_err(|e| format!("Cannot create vault folder: {}", e))?;

    let mut key_bytes = if keyfile_path.is_file() {
        fs::read(keyfile_path).map_err(|e| format!("Cannot read existing keyfile: {}", e))?
    } else {
        if let Some(parent) = keyfile_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let generated = generate_quantum_bytes(64);
        fs::write(keyfile_path, &generated)
            .map_err(|e| format!("Failed to write keyfile: {}", e))?;
        if let Ok(meta) = fs::metadata(keyfile_path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = fs::set_permissions(keyfile_path, perms);
        }
        generated
    };

    let requires_pin = !pin.is_empty();
    let kek_salt = random_fixed::<16>();
    let mut kek = derive_kek(&key_bytes, pin, &kek_salt)?;
    zeroize_bytes(&mut key_bytes);

    let dek_vec = generate_quantum_bytes(32);
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_vec[..32]);

    let dek_wrap_nonce = random_fixed::<12>();
    let kek_cipher = Aes256Gcm::new((&kek).into());
    let wrapped_dek = kek_cipher
        .encrypt(Nonce::from_slice(&dek_wrap_nonce), dek.as_ref())
        .map_err(|_| "Failed to wrap DEK".to_string())?;
    zeroize_bytes(&mut kek);

    let index = VaultIndex {
        next_block_id: 1,
        max_size_gb: max_size_gb.max(1),
        files: Vec::new(),
        dead_bytes_per_block: HashMap::new(),
    };

    let session = UnlockedSession {
        vault_dir: vault_dir.to_path_buf(),
        unlocked_via_usb,
        dek,
        kek_salt,
        dek_wrap_nonce,
        wrapped_dek,
        requires_pin,
        index,
    };

    save_vault_index(&session)?;
    Ok(session)
}

/// Unlocks an existing `.lilar` vault using `keyfile_path` and `pin`.
pub fn unlock_vault(
    vault_dir: &Path,
    keyfile_path: &Path,
    pin: &str,
    unlocked_via_usb: bool,
) -> Result<UnlockedSession, String> {
    let header = read_vault_header(vault_dir)?;
    let mut key_bytes = fs::read(keyfile_path)
        .map_err(|e| format!("Cannot read keyfile ({}): {}", keyfile_path.display(), e))?;

    let pin_used = if header.requires_pin { pin } else { "" };
    let mut kek = derive_kek(&key_bytes, pin_used, &header.kek_salt)?;
    zeroize_bytes(&mut key_bytes);

    let kek_cipher = Aes256Gcm::new((&kek).into());
    let dek_res = kek_cipher.decrypt(
        Nonce::from_slice(&header.dek_wrap_nonce),
        header.wrapped_dek.as_ref(),
    );
    zeroize_bytes(&mut kek);

    let mut dek_bytes = dek_res.map_err(|_| "Wrong keyfile or wrong PIN!".to_string())?;
    if dek_bytes.len() != 32 {
        zeroize_bytes(&mut dek_bytes);
        return Err("Invalid DEK length!".to_string());
    }

    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_bytes);
    zeroize_bytes(&mut dek_bytes);

    let dek_cipher = Aes256Gcm::new((&dek).into());
    let index_json = dek_cipher
        .decrypt(
            Nonce::from_slice(&header.index_nonce),
            header.encrypted_index.as_ref(),
        )
        .map_err(|_| "Index authentication failed!".to_string())?;

    let index = serde_json::from_slice::<VaultIndex>(&index_json)
        .map_err(|e| format!("Failed to parse VaultIndex: {}", e))?;

    Ok(UnlockedSession {
        vault_dir: vault_dir.to_path_buf(),
        unlocked_via_usb,
        dek,
        kek_salt: header.kek_salt,
        dek_wrap_nonce: header.dek_wrap_nonce,
        wrapped_dek: header.wrapped_dek,
        requires_pin: header.requires_pin,
        index,
    })
}

pub fn calculate_vault_physical_bytes(vault_dir: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = fs::read_dir(vault_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                if name.starts_with("block_") && name.ends_with(".lilar") {
                    if let Ok(meta) = p.metadata() {
                        total += meta.len();
                    }
                }
            }
        }
    }
    total
}

/// Rotates `vault.lilar` -> `.bak1`..`.bak5` and atomically writes the updated index.
pub fn save_vault_index(session: &UnlockedSession) -> Result<(), String> {
    let index_json =
        serde_json::to_vec(&session.index).map_err(|e| format!("Serialize error: {}", e))?;

    let cipher = Aes256Gcm::new((&session.dek).into());
    let index_nonce = random_fixed::<12>();
    let encrypted_index = cipher
        .encrypt(Nonce::from_slice(&index_nonce), index_json.as_ref())
        .map_err(|_| "Failed to encrypt index".to_string())?;

    let header = VaultHeader {
        kek_salt: session.kek_salt,
        dek_wrap_nonce: session.dek_wrap_nonce,
        wrapped_dek: session.wrapped_dek.clone(),
        requires_pin: session.requires_pin,
        index_nonce,
        encrypted_index,
    };

    let serialized_header =
        serde_json::to_vec_pretty(&header).map_err(|e| format!("Header error: {}", e))?;

    let main_path = session.vault_dir.join(INDEX_FILENAME);
    let tmp_path = session.vault_dir.join("vault.lilar.tmp");

    fs::write(&tmp_path, &serialized_header).map_err(|e| format!("Write error: {}", e))?;

    if main_path.exists() {
        for i in (1..=4).rev() {
            let src = session.vault_dir.join(format!("vault.lilar.bak{}", i));
            let dst = session.vault_dir.join(format!("vault.lilar.bak{}", i + 1));
            if src.exists() {
                let _ = fs::rename(&src, &dst);
            }
        }
        let bak1 = session.vault_dir.join("vault.lilar.bak1");
        let _ = fs::copy(&main_path, &bak1);
    }

    fs::rename(&tmp_path, &main_path).map_err(|e| format!("Atomic rename failed: {}", e))?;
    Ok(())
}

/// Stream-encrypts a file from `src_path` in 1 MB chunks into `block_XXX.lilar`.
pub fn stream_encrypt_file_to_blocks(
    vault_dir: &Path,
    master_dek: &[u8; 32],
    active_block_id: &mut u32,
    src_path: &Path,
    display_name: String,
    tx: &mpsc::Sender<WorkerEvent>,
) -> Result<VaultFileEntry, String> {
    let mut src_file = File::open(src_path).map_err(|e| format!("Open error: {}", e))?;
    let orig_size = src_file.metadata().map(|m| m.len()).unwrap_or(0);

    let file_salt = random_fixed::<16>();
    let stream_nonce = random_fixed::<7>();
    let mut subkey = derive_file_subkey(master_dek, &file_salt);

    let aead = Aes256Gcm::new((&subkey).into());
    zeroize_bytes(&mut subkey);
    let mut encryptor_opt = Some(EncryptorBE32::from_aead(aead, (&stream_nonce).into()));

    let mut segments: Vec<ChunkSegment> = Vec::new();
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut bytes_processed = 0u64;

    if *active_block_id == 0 {
        *active_block_id = 1;
    }

    loop {
        let mut read_len = 0;
        while read_len < CHUNK_SIZE {
            match src_file.read(&mut buf[read_len..]) {
                Ok(0) => break,
                Ok(n) => read_len += n,
                Err(e) => return Err(format!("Read error: {}", e)),
            }
        }

        let is_eof = read_len < CHUNK_SIZE || {
            let pos = src_file.stream_position().unwrap_or(orig_size);
            pos >= orig_size
        };

        let chunk_slice = &buf[..read_len];
        let ciphertext = if is_eof {
            encryptor_opt
                .take()
                .ok_or_else(|| "Encryptor already consumed".to_string())?
                .encrypt_last(Payload {
                    msg: chunk_slice,
                    aad: b"",
                })
                .map_err(|_| "Stream encrypt_last failed".to_string())?
        } else {
            encryptor_opt
                .as_mut()
                .ok_or_else(|| "Encryptor already consumed".to_string())?
                .encrypt_next(Payload {
                    msg: chunk_slice,
                    aad: b"",
                })
                .map_err(|_| "Stream encrypt_next failed".to_string())?
        };

        let b_path = block_path(vault_dir, *active_block_id);
        let cur_block_len = b_path.metadata().map(|m| m.len()).unwrap_or(0);
        if cur_block_len > 0 && cur_block_len + (ciphertext.len() as u64) > MAX_BLOCK_SIZE {
            *active_block_id += 1;
        }

        let target_block_id = *active_block_id;
        let target_path = block_path(vault_dir, target_block_id);
        let mut block_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&target_path)
            .map_err(|e| format!("Block open error: {}", e))?;

        let write_offset = block_file.metadata().map(|m| m.len()).unwrap_or(0);
        block_file
            .write_all(&ciphertext)
            .map_err(|e| format!("Block write error: {}", e))?;

        let c_len = ciphertext.len() as u64;
        if let Some(last_seg) = segments.last_mut() {
            if last_seg.block_id == target_block_id
                && last_seg.offset + last_seg.cipher_len == write_offset
            {
                last_seg.cipher_len += c_len;
            } else {
                segments.push(ChunkSegment {
                    block_id: target_block_id,
                    offset: write_offset,
                    cipher_len: c_len,
                });
            }
        } else {
            segments.push(ChunkSegment {
                block_id: target_block_id,
                offset: write_offset,
                cipher_len: c_len,
            });
        }

        bytes_processed += read_len as u64;
        if orig_size > 0 {
            let pct = (bytes_processed as f64 / orig_size as f64).clamp(0.0, 1.0);
            let _ = tx.send(WorkerEvent::Progress(
                pct,
                format!("Encrypting {} ({:.0}%)...", display_name, pct * 100.0),
            ));
        }

        if is_eof {
            break;
        }
    }

    Ok(VaultFileEntry {
        name: display_name,
        original_size: orig_size,
        file_salt,
        stream_nonce,
        segments,
    })
}

/// Stream-decrypts a `VaultFileEntry` from its `.lilar` blocks into `dest_path`.
pub fn stream_decrypt_file_from_blocks(
    vault_dir: &Path,
    master_dek: &[u8; 32],
    entry: &VaultFileEntry,
    dest_path: &Path,
    tx: &mpsc::Sender<WorkerEvent>,
) -> Result<(), String> {
    if let Some(parent) = dest_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let mut out_file = File::create(dest_path).map_err(|e| format!("Create error: {}", e))?;
    if dest_path.starts_with(RAM_EXTRACT_DIR) {
        if let Ok(meta) = out_file.metadata() {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = fs::set_permissions(dest_path, perms);
        }
    }

    let mut subkey = derive_file_subkey(master_dek, &entry.file_salt);
    let aead = Aes256Gcm::new((&subkey).into());
    zeroize_bytes(&mut subkey);
    let mut decryptor_opt = Some(DecryptorBE32::from_aead(aead, (&entry.stream_nonce).into()));

    let total_cipher: u64 = entry.segments.iter().map(|s| s.cipher_len).sum();
    let mut cipher_processed = 0u64;

    for (seg_idx, seg) in entry.segments.iter().enumerate() {
        let is_last_seg = seg_idx + 1 == entry.segments.len();
        let b_path = block_path(vault_dir, seg.block_id);
        let mut block_file =
            File::open(&b_path).map_err(|e| format!("Missing block {:03}: {}", seg.block_id, e))?;

        block_file
            .seek(SeekFrom::Start(seg.offset))
            .map_err(|e| format!("Seek error: {}", e))?;

        let mut remaining_in_seg = seg.cipher_len as usize;
        while remaining_in_seg > 0 {
            let to_read = remaining_in_seg.min(CIPHER_CHUNK_SIZE);
            let mut c_buf = vec![0u8; to_read];
            block_file
                .read_exact(&mut c_buf)
                .map_err(|e| format!("Block read error: {}", e))?;

            remaining_in_seg -= to_read;
            cipher_processed += to_read as u64;

            let is_eof = is_last_seg && remaining_in_seg == 0;
            let plaintext = if is_eof {
                decryptor_opt
                    .take()
                    .ok_or_else(|| "Decryptor already consumed".to_string())?
                    .decrypt_last(Payload {
                        msg: &c_buf,
                        aad: b"",
                    })
                    .map_err(|_| "Corrupted block or authentication tag mismatch!".to_string())?
            } else {
                decryptor_opt
                    .as_mut()
                    .ok_or_else(|| "Decryptor already consumed".to_string())?
                    .decrypt_next(Payload {
                        msg: &c_buf,
                        aad: b"",
                    })
                    .map_err(|_| "Corrupted chunk authentication tag!".to_string())?
            };

            out_file
                .write_all(&plaintext)
                .map_err(|e| format!("Write error: {}", e))?;

            if total_cipher > 0 {
                let pct = (cipher_processed as f64 / total_cipher as f64).clamp(0.0, 1.0);
                let _ = tx.send(WorkerEvent::Progress(
                    pct,
                    format!("Decrypting {} ({:.0}%)...", entry.name, pct * 100.0),
                ));
            }

            if is_eof {
                return Ok(());
            }
        }
    }

    Ok(())
}

/// Encrypts an in-memory byte slice directly into `.lilar` blocks (never touches disk in plaintext).
pub fn encrypt_bytes_to_blocks(
    vault_dir: &Path,
    master_dek: &[u8; 32],
    active_block_id: &mut u32,
    data: &[u8],
    display_name: String,
) -> Result<VaultFileEntry, String> {
    let orig_size = data.len() as u64;
    let file_salt = random_fixed::<16>();
    let stream_nonce = random_fixed::<7>();
    let mut subkey = derive_file_subkey(master_dek, &file_salt);

    let aead = Aes256Gcm::new((&subkey).into());
    zeroize_bytes(&mut subkey);
    let mut encryptor_opt = Some(EncryptorBE32::from_aead(aead, (&stream_nonce).into()));

    let mut segments: Vec<ChunkSegment> = Vec::new();
    if *active_block_id == 0 {
        *active_block_id = 1;
    }

    let mut offset = 0usize;
    loop {
        let end = (offset + CHUNK_SIZE).min(data.len());
        let chunk_slice = &data[offset..end];
        let is_eof = end >= data.len();

        let ciphertext = if is_eof {
            encryptor_opt
                .take()
                .ok_or_else(|| "Encryptor already consumed".to_string())?
                .encrypt_last(Payload {
                    msg: chunk_slice,
                    aad: b"",
                })
                .map_err(|_| "Stream encrypt_last failed".to_string())?
        } else {
            encryptor_opt
                .as_mut()
                .ok_or_else(|| "Encryptor already consumed".to_string())?
                .encrypt_next(Payload {
                    msg: chunk_slice,
                    aad: b"",
                })
                .map_err(|_| "Stream encrypt_next failed".to_string())?
        };

        let b_path = block_path(vault_dir, *active_block_id);
        let cur_block_len = b_path.metadata().map(|m| m.len()).unwrap_or(0);
        if cur_block_len > 0 && cur_block_len + (ciphertext.len() as u64) > MAX_BLOCK_SIZE {
            *active_block_id += 1;
        }

        let target_block_id = *active_block_id;
        let target_path = block_path(vault_dir, target_block_id);
        let mut block_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&target_path)
            .map_err(|e| format!("Block open error: {}", e))?;

        let write_offset = block_file.metadata().map(|m| m.len()).unwrap_or(0);
        block_file
            .write_all(&ciphertext)
            .map_err(|e| format!("Block write error: {}", e))?;

        let c_len = ciphertext.len() as u64;
        if let Some(last_seg) = segments.last_mut() {
            if last_seg.block_id == target_block_id
                && last_seg.offset + last_seg.cipher_len == write_offset
            {
                last_seg.cipher_len += c_len;
            } else {
                segments.push(ChunkSegment {
                    block_id: target_block_id,
                    offset: write_offset,
                    cipher_len: c_len,
                });
            }
        } else {
            segments.push(ChunkSegment {
                block_id: target_block_id,
                offset: write_offset,
                cipher_len: c_len,
            });
        }

        offset = end;
        if is_eof {
            break;
        }
    }

    Ok(VaultFileEntry {
        name: display_name,
        original_size: orig_size,
        file_salt,
        stream_nonce,
        segments,
    })
}

/// Decrypts a `VaultFileEntry` directly into an in-memory `Vec<u8>`.
pub fn decrypt_entry_to_bytes(
    vault_dir: &Path,
    master_dek: &[u8; 32],
    entry: &VaultFileEntry,
) -> Result<Vec<u8>, String> {
    let mut subkey = derive_file_subkey(master_dek, &entry.file_salt);
    let aead = Aes256Gcm::new((&subkey).into());
    zeroize_bytes(&mut subkey);
    let mut decryptor_opt = Some(DecryptorBE32::from_aead(aead, (&entry.stream_nonce).into()));
    let mut out = Vec::with_capacity(entry.original_size as usize);

    for (seg_idx, seg) in entry.segments.iter().enumerate() {
        let is_last_seg = seg_idx + 1 == entry.segments.len();
        let b_path = block_path(vault_dir, seg.block_id);
        let mut block_file =
            File::open(&b_path).map_err(|e| format!("Missing block {:03}: {}", seg.block_id, e))?;
        block_file
            .seek(SeekFrom::Start(seg.offset))
            .map_err(|e| format!("Seek error: {}", e))?;

        let mut remaining_in_seg = seg.cipher_len as usize;
        while remaining_in_seg > 0 {
            let to_read = remaining_in_seg.min(CIPHER_CHUNK_SIZE);
            let mut c_buf = vec![0u8; to_read];
            block_file
                .read_exact(&mut c_buf)
                .map_err(|e| format!("Block read error: {}", e))?;

            remaining_in_seg -= to_read;
            let is_eof = is_last_seg && remaining_in_seg == 0;
            let plaintext = if is_eof {
                decryptor_opt
                    .take()
                    .ok_or_else(|| "Decryptor already consumed".to_string())?
                    .decrypt_last(Payload {
                        msg: &c_buf,
                        aad: b"",
                    })
                    .map_err(|_| "Corrupted block or authentication tag mismatch!".to_string())?
            } else {
                decryptor_opt
                    .as_mut()
                    .ok_or_else(|| "Decryptor already consumed".to_string())?
                    .decrypt_next(Payload {
                        msg: &c_buf,
                        aad: b"",
                    })
                    .map_err(|_| "Corrupted chunk authentication tag!".to_string())?
            };

            out.extend_from_slice(&plaintext);
            if is_eof {
                return Ok(out);
            }
        }
    }

    Ok(out)
}

/// Loads `passwords.txt` from `session` into RAM, creating an empty encrypted one if missing.
pub fn load_or_create_passwords_file(session: &mut UnlockedSession) -> Result<String, String> {
    if let Some(entry) = session
        .index
        .files
        .iter()
        .find(|f| f.name == VAULT_PASSWORDS_FILENAME)
        .cloned()
    {
        let mut bytes = decrypt_entry_to_bytes(&session.vault_dir, &session.dek, &entry)?;
        let text = String::from_utf8_lossy(&bytes).to_string();
        zeroize_bytes(&mut bytes);
        return Ok(text);
    }

    save_passwords_file(session, "")?;
    Ok(String::new())
}

/// Encrypts `content` directly from RAM into `session`'s `passwords.txt`.
pub fn save_passwords_file(session: &mut UnlockedSession, content: &str) -> Result<(), String> {
    let mut next_blk = session.index.next_block_id;
    let new_entry = encrypt_bytes_to_blocks(
        &session.vault_dir,
        &session.dek,
        &mut next_blk,
        content.as_bytes(),
        VAULT_PASSWORDS_FILENAME.to_string(),
    )?;

    if let Some(last_seg) = new_entry.segments.last() {
        session.index.next_block_id = session.index.next_block_id.max(last_seg.block_id);
    }

    if let Some(pos) = session
        .index
        .files
        .iter()
        .position(|f| f.name == VAULT_PASSWORDS_FILENAME)
    {
        let old = std::mem::replace(&mut session.index.files[pos], new_entry);
        for seg in old.segments {
            *session
                .index
                .dead_bytes_per_block
                .entry(seg.block_id)
                .or_insert(0) += seg.cipher_len;
        }
    } else {
        session.index.files.push(new_entry);
    }

    save_vault_index(session)
}

/// Atomic Vacuum: compacts any block with dead space into a fresh block ID.
pub fn run_atomic_vacuum(
    vault_dir: &Path,
    mut index: VaultIndex,
    tx: &mpsc::Sender<WorkerEvent>,
) -> Result<(VaultIndex, Vec<u32>), String> {
    let fragmented_blocks: Vec<u32> = index
        .dead_bytes_per_block
        .iter()
        .filter(|&(_, &dead)| dead > 0)
        .map(|(&b_id, _)| b_id)
        .collect();

    if fragmented_blocks.is_empty() {
        return Ok((index, Vec::new()));
    }

    let mut old_blocks_to_remove = Vec::new();

    for (b_idx, old_block_id) in fragmented_blocks.iter().copied().enumerate() {
        let old_path = block_path(vault_dir, old_block_id);
        if !old_path.exists() {
            index.dead_bytes_per_block.remove(&old_block_id);
            continue;
        }

        index.next_block_id += 1;
        let new_block_id = index.next_block_id;
        let new_path = block_path(vault_dir, new_block_id);

        let mut old_file =
            File::open(&old_path).map_err(|e| format!("Vacuum open error: {}", e))?;
        let mut new_file: Option<File> = None;
        let mut new_offset = 0u64;
        let mut copy_buf = vec![0u8; 1024 * 1024];

        for file_entry in &mut index.files {
            for seg in &mut file_entry.segments {
                if seg.block_id == old_block_id {
                    let out_f = match new_file.as_mut() {
                        Some(f) => f,
                        None => {
                            let f = File::create(&new_path)
                                .map_err(|e| format!("Vacuum create error: {}", e))?;
                            new_file = Some(f);
                            new_file.as_mut().unwrap()
                        }
                    };

                    old_file
                        .seek(SeekFrom::Start(seg.offset))
                        .map_err(|e| e.to_string())?;

                    let mut rem = seg.cipher_len as usize;
                    let start_offset = new_offset;
                    while rem > 0 {
                        let step = rem.min(copy_buf.len());
                        old_file
                            .read_exact(&mut copy_buf[..step])
                            .map_err(|e| e.to_string())?;
                        out_f
                            .write_all(&copy_buf[..step])
                            .map_err(|e| e.to_string())?;
                        rem -= step;
                        new_offset += step as u64;
                    }

                    seg.block_id = new_block_id;
                    seg.offset = start_offset;
                }
            }
        }

        index.dead_bytes_per_block.remove(&old_block_id);
        old_blocks_to_remove.push(old_block_id);

        let pct = (b_idx + 1) as f64 / fragmented_blocks.len() as f64;
        let _ = tx.send(WorkerEvent::Progress(
            pct,
            format!("Vacuumed block {:03} -> {:03}...", old_block_id, new_block_id),
        ));
    }

    Ok((index, old_blocks_to_remove))
}

pub fn format_bytes(bytes: u64) -> String {
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const KB: f64 = 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.1} MB", b / MB)
    } else if b >= KB {
        format!("{:.0} KB", b / KB)
    } else {
        format!("{} B", bytes)
    }
}
