pub const CRYPTO_HASH_SHA256_BYTES: usize = 32;
pub const CRYPTO_HASH_SHA512_BYTES: usize = 64;
pub const CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_PUBLIC_KEY_BYTES: usize = 32;
pub const CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_SECRET_KEY_BYTES: usize = 32;
pub const CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_NONCEBYTES: usize = 24;
pub const CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_ZEROBYTES: usize = 32;
pub const CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_BOXZEROBYTES: usize = 16;

pub fn crypto_hash_sha256(message: &String) -> Option<String> {
    unsafe {
        let hash = [0u8; CRYPTO_HASH_SHA256_BYTES].as_mut_ptr();
        let _res = crypto_hash_sha256_ref(hash, message.as_ptr(), message.len());
        if _res == -1 {
            return None;
        } else {
            let data = std::slice::from_raw_parts(hash, CRYPTO_HASH_SHA256_BYTES);
            let encoded_hash = hex::encode(data);
            Some(encoded_hash)
        }
    }
}

pub fn crypto_hash_sha512(message: &String) -> Option<String> {
    unsafe {
        let hash = [0u8; CRYPTO_HASH_SHA512_BYTES].as_mut_ptr();
        let _res = crypto_hash_sha512_ref(hash, message.as_ptr(), message.len());
        if _res == -1 {
            return None;
        } else {
            let data = std::slice::from_raw_parts(hash, CRYPTO_HASH_SHA512_BYTES);
            let encoded_hash = hex::encode(data);
            Some(encoded_hash)
        }
    }
}

pub fn crypto_box_keypair() -> Option<(String, String)> {
    let public_key = [0u8; CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_PUBLIC_KEY_BYTES].as_mut_ptr();
    let secret_key = [0u8; CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_SECRET_KEY_BYTES].as_mut_ptr();
    unsafe {
        let res = crypto_box_curve25519xsalsa20poly1305_ref_keypair(public_key, secret_key);
        if res == -1 {
            return None;
        } else {
            let hash_pk = std::slice::from_raw_parts(
                public_key,
                CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_PUBLIC_KEY_BYTES,
            );
            let hash_sk = std::slice::from_raw_parts(
                secret_key,
                CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_SECRET_KEY_BYTES,
            );
            let encoded_hash_pk = hex::encode(hash_pk);
            let encoded_hash_sk = hex::encode(hash_sk);
            Some((encoded_hash_pk, encoded_hash_sk))
        }
    }
}

extern "C" {
    fn crypto_hash_sha256_ref(hash: *mut u8, message: *const u8, message_len: usize) -> i32;
    fn crypto_hash_sha512_ref(hash: *mut u8, message: *const u8, message_len: usize) -> i32;
    fn crypto_box_curve25519xsalsa20poly1305_ref_keypair(
        public_key: *mut u8,
        secret_key: *mut u8,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto_box_keypair, crypto_hash_sha256, crypto_hash_sha512,
        CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_PUBLIC_KEY_BYTES,
        CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_SECRET_KEY_BYTES, CRYPTO_HASH_SHA256_BYTES,
        CRYPTO_HASH_SHA512_BYTES,
    };

    #[test]
    fn test_crypto_hash_sha256_ref() {
        let mut message = "The quick brown fox jumped over the lazy dog".to_string();
        let hex_encoded_hash = crypto_hash_sha256(&mut message).unwrap();
        assert_eq!(CRYPTO_HASH_SHA256_BYTES * 2, hex_encoded_hash.len());
    }

    #[test]
    fn test_crypto_hash_sha512_ref() {
        let mut message_2 = "The quick brown fox jumped over the lazy dog".to_string();
        let _hex_encoded_hash = crypto_hash_sha512(&mut message_2).unwrap();
        assert_eq!(CRYPTO_HASH_SHA512_BYTES * 2, _hex_encoded_hash.len());
    }

    #[test]
    fn test_crypto_box_keypair() {
        let keys = crypto_box_keypair().unwrap();
        assert_eq!(
            CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_PUBLIC_KEY_BYTES * 2,
            keys.0.len()
        );
        assert_eq!(
            CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_SECRET_KEY_BYTES * 2,
            keys.1.len()
        );
    }
}
