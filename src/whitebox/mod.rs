// White-Box AES Implementation for Proc-Macro
// Compile-time table generation and key derivation

mod sbox;
mod tables;
mod generator;
mod cipher;

pub use tables::WhiteboxTables;
pub use cipher::whitebox_encrypt;
pub use generator::generate_tables;

/// AES block size in bytes
pub const AES_BLOCK_SIZE: usize = 16;

/// Number of AES-128 rounds
pub const AES_ROUNDS: usize = 10;

/// Derive WBC key and table seed from build seed
/// Returns (wbc_key, table_seed)
pub fn derive_wbc_params(build_seed: &[u8; 32]) -> ([u8; 16], [u8; 32]) {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    // Derive WBC key (16 bytes for AES-128)
    let mut mac = <HmacSha256 as Mac>::new_from_slice(build_seed)
        .expect("HMAC can take any size key");
    mac.update(b"whitebox-aes-key-v1");
    let result = mac.finalize();
    let mut wbc_key = [0u8; 16];
    wbc_key.copy_from_slice(&result.into_bytes()[..16]);

    // Derive table seed (32 bytes)
    let mut mac = <HmacSha256 as Mac>::new_from_slice(build_seed)
        .expect("HMAC can take any size key");
    mac.update(b"whitebox-table-seed-v1");
    let result = mac.finalize();
    let table_seed: [u8; 32] = result.into_bytes().into();

    (wbc_key, table_seed)
}

/// Initialize whitebox tables from build seed
pub fn init_tables_from_seed(build_seed: &[u8; 32]) -> WhiteboxTables {
    let (wbc_key, table_seed) = derive_wbc_params(build_seed);
    generate_tables(&wbc_key, &table_seed)
}

/// Derive a 32-byte key using WBC (for bytecode encryption)
pub fn derive_key(build_seed: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    let tables = init_tables_from_seed(build_seed);
    derive_key_with_tables(domain, &tables)
}

/// Derive key using pre-initialized tables
pub fn derive_key_with_tables(domain: &[u8], tables: &WhiteboxTables) -> [u8; 32] {
    // Create two 16-byte blocks from domain
    let mut block1 = [0u8; AES_BLOCK_SIZE];
    let mut block2 = [0u8; AES_BLOCK_SIZE];

    // Simple domain hashing (FNV-1a style, split into two blocks)
    let mut hash1 = 0xcbf29ce484222325u64;
    let mut hash2 = 0x84222325cbf29ce4u64;

    for &byte in domain {
        hash1 ^= byte as u64;
        hash1 = hash1.wrapping_mul(0x100000001b3);
        hash2 = hash2.wrapping_mul(0x100000001b3);
        hash2 ^= byte as u64;
    }

    // Fill blocks with hash values
    block1[0..8].copy_from_slice(&hash1.to_le_bytes());
    block1[8..16].copy_from_slice(&hash2.to_le_bytes());

    // Second block uses rotated/modified hash
    let hash3 = hash1.rotate_left(13) ^ hash2;
    let hash4 = hash2.rotate_right(17) ^ hash1;
    block2[0..8].copy_from_slice(&hash3.to_le_bytes());
    block2[8..16].copy_from_slice(&hash4.to_le_bytes());

    // Encrypt both blocks through WBC
    whitebox_encrypt(&mut block1, tables);
    whitebox_encrypt(&mut block2, tables);

    // Combine into 32-byte key
    let mut key = [0u8; 32];
    key[0..16].copy_from_slice(&block1);
    key[16..32].copy_from_slice(&block2);

    key
}

/// Derive the bytecode encryption key using WBC
pub fn derive_bytecode_key(build_seed: &[u8; 32]) -> [u8; 32] {
    derive_key(build_seed, b"aegis-bytecode-encryption-v1")
}
