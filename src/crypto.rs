//! Compile-time cryptography for bytecode encryption
//!
//! Uses the same algorithms as anticheat-vm/crypto.rs

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

// Domain separation strings (same as runtime)
const KEY_DOMAIN: &[u8] = b"anticheat-vm-key-v1";
const NONCE_DOMAIN: &[u8] = b"anticheat-vm-nonce-v1";
const BUILDID_DOMAIN: &[u8] = b"anticheat-vm-build-id-v1";
const OPCODE_SHUFFLE_DOMAIN: &[u8] = b"opcode-shuffle-v1";

/// Get build seed from shared file
/// This is called at proc-macro expansion time (compile time)
pub fn get_build_seed() -> [u8; 32] {
    // ALWAYS read shared seed file written by vm build.rs
    // We do NOT calculate seed from env var here because HMAC implementation
    // might differ from build.rs (different crates/versions), leading to opcode mismatch.
    if let Some(seed) = read_shared_seed() {
        return seed;
    }

    // PANIC if seed not found - do NOT silently generate different seed!
    // This would cause opcode mismatch between vm-macro and vm runtime.
    panic!(
        "vm-macro: Could not find shared build seed file (.anticheat_build_seed). \
         Make sure anticheat-vm is built before using vm_protect macro. \
         Or set ANTICHEAT_BUILD_KEY environment variable for reproducible builds."
    );
}

/// Read shared seed from target directory
fn read_shared_seed() -> Option<[u8; 32]> {
    use std::fs;
    use std::path::PathBuf;

    let mut all_candidates: Vec<PathBuf> = Vec::new();

    // Try CARGO_TARGET_DIR if set (highest priority)
    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        all_candidates.push(PathBuf::from(&target_dir).join(".anticheat_build_seed"));
    }

    // Try OUT_DIR based path (works during build)
    if let Ok(out_dir) = std::env::var("OUT_DIR") {
        let path = PathBuf::from(&out_dir);
        // Walk up to find target directory
        for ancestor in path.ancestors() {
            if ancestor.file_name().is_some_and(|n| n == "target") {
                all_candidates.push(ancestor.join(".anticheat_build_seed"));
                break;
            }
        }
    }

    // Try CARGO_MANIFEST_DIR based path (works for proc-macros)
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let path = PathBuf::from(&manifest_dir);
        // Walk up to find project root with target directory
        for ancestor in path.ancestors() {
            let target_path = ancestor.join("target/.anticheat_build_seed");
            if target_path.exists() {
                all_candidates.push(target_path);
                break;
            }
        }
    }

    // Common relative paths as fallback
    all_candidates.extend([
        PathBuf::from("target/.anticheat_build_seed"),
        PathBuf::from("../target/.anticheat_build_seed"),
        PathBuf::from("../../target/.anticheat_build_seed"),
        PathBuf::from("../../../target/.anticheat_build_seed"),
        PathBuf::from("../../../../target/.anticheat_build_seed"),
    ]);

    for path in all_candidates {
        if let Ok(hex_str) = fs::read_to_string(&path) {
            if let Ok(bytes) = hex::decode(hex_str.trim()) {
                if bytes.len() == 32 {
                    let mut seed = [0u8; 32];
                    seed.copy_from_slice(&bytes);
                    return Some(seed);
                }
            }
        }
    }

    None
}

/// Generate cryptographically random seed (for testing only)
#[allow(dead_code)]
fn generate_random_seed() -> [u8; 32] {
    use std::fs::File;
    use std::io::Read;
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut seed = [0u8; 32];

    // Try /dev/urandom first (Unix)
    if let Ok(mut file) = File::open("/dev/urandom") {
        if file.read_exact(&mut seed).is_ok() {
            return seed;
        }
    }

    // Fallback: combine multiple entropy sources
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let mut entropy = Vec::new();
    entropy.extend_from_slice(&timestamp.as_nanos().to_le_bytes());
    entropy.extend_from_slice(&std::process::id().to_le_bytes());

    // Add some environment entropy
    if let Ok(pwd) = std::env::var("PWD") {
        entropy.extend_from_slice(pwd.as_bytes());
    }
    if let Ok(user) = std::env::var("USER") {
        entropy.extend_from_slice(user.as_bytes());
    }

    // Hash for uniform distribution using HMAC
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&entropy)
        .expect("HMAC can take any size key");
    mac.update(b"random-seed-derive");
    let result = mac.finalize();
    let mut final_seed = [0u8; 32];
    final_seed.copy_from_slice(&result.into_bytes());
    final_seed
}

/// Derive encryption key from build seed
pub fn derive_key(build_seed: &[u8; 32], context: &[u8]) -> [u8; KEY_SIZE] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(build_seed)
        .expect("HMAC can take any size key");
    mac.update(context);
    mac.update(KEY_DOMAIN);

    let result = mac.finalize();
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&result.into_bytes()[..KEY_SIZE]);
    key
}

/// Derive nonce from build seed and counter
pub fn derive_nonce(build_seed: &[u8; 32], counter: u64) -> [u8; NONCE_SIZE] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(build_seed)
        .expect("HMAC can take any size key");
    mac.update(&counter.to_le_bytes());
    mac.update(NONCE_DOMAIN);

    let result = mac.finalize();
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&result.into_bytes()[..NONCE_SIZE]);
    nonce
}

/// Derive build ID from seed
pub fn derive_build_id(build_seed: &[u8; 32]) -> u64 {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(build_seed)
        .expect("HMAC can take any size key");
    mac.update(BUILDID_DOMAIN);

    let result = mac.finalize();
    let bytes = result.into_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Encrypt bytecode using AES-256-GCM
pub fn encrypt_bytecode(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_SIZE]), String> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead, Nonce};

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;

    let nonce_obj = Nonce::from_slice(nonce);

    let ciphertext = cipher
        .encrypt(nonce_obj, plaintext)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Extract tag from the end
    if ciphertext.len() < TAG_SIZE {
        return Err("Ciphertext too short".to_string());
    }

    let tag_start = ciphertext.len() - TAG_SIZE;
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&ciphertext[tag_start..]);

    let encrypted_data = ciphertext[..tag_start].to_vec();

    Ok((encrypted_data, tag))
}

/// Encrypted bytecode package for embedding
pub struct EncryptedPackage {
    pub build_id: u64,
    pub nonce: [u8; NONCE_SIZE],
    pub tag: [u8; TAG_SIZE],
    pub ciphertext: Vec<u8>,
}

/// Encrypt bytecode with build seed
/// Uses WBC-derived key for maximum key-hiding protection
pub fn encrypt_with_seed(bytecode: &[u8], function_id: u64) -> Result<EncryptedPackage, String> {
    let seed = get_build_seed();

    // Use WBC to derive the encryption key (key-hiding)
    let key = crate::whitebox::derive_bytecode_key(&seed);

    // Nonce is still HMAC-derived (no need to hide nonce)
    let nonce = derive_nonce(&seed, function_id);
    let build_id = derive_build_id(&seed);

    let (ciphertext, tag) = encrypt_bytecode(&key, &nonce, bytecode)?;

    Ok(EncryptedPackage {
        build_id,
        nonce,
        tag,
        ciphertext,
    })
}

/// Base opcode definitions (canonical values)
/// Must match the definitions in vm/build.rs EXACTLY (same order!)
const BASE_OPCODES: &[u8] = &[
    // Stack operations
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    // Register operations
    0x10, 0x11, 0x12, 0x13,
    // Arithmetic operations
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x46, 0x47, 0x48, 0x49,
    // Control flow
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
    // Special operations
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
    // Type conversion
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
    // Memory operations
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    // Heap operations (must match vm/build.rs)
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A,
    // Vector operations (must match vm/build.rs)
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    // String operations (must match vm/build.rs)
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
    // Native calls
    0xF0, 0xF1, 0xF2, 0xF3,
    // Execution control (HALT/HALT_ERR are kept fixed)
];

/// Opcode encoding table (base -> shuffled)
/// Generated at compile time from build seed
#[derive(Clone)]
pub struct OpcodeTable {
    pub encode: [u8; 256],
    seed: u64, // For MBA determinism
}

impl OpcodeTable {
    /// Generate opcode table from build seed
    /// This must produce identical results to vm/build.rs
    pub fn generate(seed: &[u8; 32]) -> Self {
        // Derive shuffle key from seed
        let mut mac = <HmacSha256 as Mac>::new_from_slice(seed)
            .expect("HMAC can take any size key");
        mac.update(OPCODE_SHUFFLE_DOMAIN);
        let shuffle_key: [u8; 32] = mac.finalize().into_bytes().into();

        // Create list of available byte values (0x00-0xFD, excluding 0xFE and 0xFF for HALT)
        let mut available: Vec<u8> = (0x00..0xFE).collect();

        // Fisher-Yates shuffle using HMAC-derived randomness
        let mut rng_state = shuffle_key;
        for i in (1..available.len()).rev() {
            // Get next random index using HMAC
            let mut mac = <HmacSha256 as Mac>::new_from_slice(&rng_state)
                .expect("HMAC can take any size key");
            mac.update(&(i as u32).to_le_bytes());
            let rand_bytes: [u8; 32] = mac.finalize().into_bytes().into();
            rng_state = rand_bytes;

            let j = (u64::from_le_bytes([
                rand_bytes[0], rand_bytes[1], rand_bytes[2], rand_bytes[3],
                rand_bytes[4], rand_bytes[5], rand_bytes[6], rand_bytes[7],
            ]) as usize) % (i + 1);
            available.swap(i, j);
        }

        // Build the encoding table
        let mut encode = [0u8; 256];

        // Initialize as identity mapping
        for (i, val) in encode.iter_mut().enumerate() {
            *val = i as u8;
        }

        // Assign shuffled values to each base opcode (except HALT/HALT_ERR)
        let mut available_idx = 0;
        for &base_val in BASE_OPCODES {
            if base_val == 0xFF || base_val == 0xFE {
                continue;
            }
            let shuffled_val = available[available_idx];
            available_idx += 1;
            encode[base_val as usize] = shuffled_val;
        }

        // Derive seed for MBA from shuffle key
        let mba_seed = u64::from_le_bytes([
            rng_state[0], rng_state[1], rng_state[2], rng_state[3],
            rng_state[4], rng_state[5], rng_state[6], rng_state[7],
        ]);

        OpcodeTable { encode, seed: mba_seed }
    }

    /// Encode a base opcode to its shuffled value
    #[inline]
    pub fn encode(&self, base_opcode: u8) -> u8 {
        self.encode[base_opcode as usize]
    }

    /// Get seed for MBA transformations
    #[inline]
    pub fn get_seed(&self) -> u64 {
        self.seed
    }
}

/// Get the opcode table for current build
pub fn get_opcode_table() -> OpcodeTable {
    let seed = get_build_seed();
    OpcodeTable::generate(&seed)
}
