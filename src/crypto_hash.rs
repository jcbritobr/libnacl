pub const CRYPTO_HASH_SHA256_BYTES: usize = 32;
pub const CRYPTO_HASH_SHA512_BYTES: usize = 64;

pub fn crypto_hash_sha256(message: Vec<u8>) -> Option<Vec<u8>> {
    unsafe {
        let mut hash = [0u8; CRYPTO_HASH_SHA256_BYTES];
        let _res = crypto_hash_sha256_ref(hash.as_mut_ptr(), message.as_ptr(), message.len());
        if _res == -1 {
            None
        } else {
            Some(hash.to_vec())
        }
    }
}

pub fn crypto_hash_sha512(message: Vec<u8>) -> Option<Vec<u8>> {
    unsafe {
        let mut hash = [0u8; CRYPTO_HASH_SHA512_BYTES];
        let _res = crypto_hash_sha512_ref(hash.as_mut_ptr(), message.as_ptr(), message.len());
        if _res == -1 {
            None
        } else {
            Some(hash.to_vec())
        }
    }
}

extern "C" {
    fn crypto_hash_sha256_ref(hash: *mut u8, message: *const u8, message_len: usize) -> i32;
    fn crypto_hash_sha512_ref(hash: *mut u8, message: *const u8, message_len: usize) -> i32;
}

#[cfg(test)]
mod tests {
    use crate::crypto_hash::{
        crypto_hash_sha256, crypto_hash_sha512, CRYPTO_HASH_SHA256_BYTES, CRYPTO_HASH_SHA512_BYTES,
    };

    #[test]
    fn test_crypto_hash_sha256_ref() {
        let message = "The quick brown fox jumps over the lazy dog";
        let hash_256 = crypto_hash_sha256(message.as_bytes().to_vec()).unwrap();
        assert_eq!(CRYPTO_HASH_SHA256_BYTES, hash_256.len());
    }

    #[test]
    fn test_crypto_hash_sha512_ref() {
        let message = "The quick brown fox jumps over the lazy dog";
        let hash_512 = crypto_hash_sha512(message.as_bytes().to_vec()).unwrap();
        assert_eq!(CRYPTO_HASH_SHA512_BYTES, hash_512.len());
    }
}
