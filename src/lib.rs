pub const CRYPTO_HASH_SHA256_BYTES: usize = 32;
pub const CRYPTO_HASH_SHA512_BYTES: usize = 64;
pub const CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_PUBLIC_KEY_BYTES: usize = 32;
pub const CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_SECRET_KEY_BYTES: usize = 32;
pub const CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_NONCEBYTES: usize = 24;
pub const CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_ZEROBYTES: usize = 32;
pub const CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_BOXZEROBYTES: usize = 16;

pub fn crypto_hash_sha256(message: &str) -> Option<Vec<u8>> {
    unsafe {
        let hash = [0u8; CRYPTO_HASH_SHA256_BYTES].as_mut_ptr();
        let _res = crypto_hash_sha256_ref(hash, message.as_ptr(), message.len());
        if _res == -1 {
            return None;
        } else {
            let data = std::slice::from_raw_parts(hash, CRYPTO_HASH_SHA256_BYTES);
            let owned_hash = data.to_owned();
            Some(owned_hash)
        }
    }
}

pub fn crypto_hash_sha512(message: &str) -> Option<Vec<u8>> {
    unsafe {
        let hash = [0u8; CRYPTO_HASH_SHA512_BYTES].as_mut_ptr();
        let _res = crypto_hash_sha512_ref(hash, message.as_ptr(), message.len());
        if _res == -1 {
            return None;
        } else {
            let data = std::slice::from_raw_parts(hash, CRYPTO_HASH_SHA512_BYTES);
            let owned_hash = data.to_owned();
            Some(owned_hash)
        }
    }
}

pub fn crypto_box_keypair() -> Option<(Vec<u8>, Vec<u8>)> {
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
            let owned_hash_pk = hash_pk.to_owned();
            let owned_hash_sk = hash_sk.to_owned();
            Some((owned_hash_pk, owned_hash_sk))
        }
    }
}

pub fn crypto_box(message: &str, nonce: Vec<u8>, pk: Vec<u8>, sk: Vec<u8>) -> Option<Vec<u8>> {
    let mut owned_message_zeros = vec![0u8; CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_ZEROBYTES];
    owned_message_zeros.extend_from_slice(message.as_bytes());
    let mut cypher_text =
        vec![0u8; CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_ZEROBYTES + message.len()];

    unsafe {
        let ret = crypto_box_curve25519xsalsa20poly1305_ref(
            cypher_text.as_mut_ptr(),
            owned_message_zeros.as_ptr(),
            owned_message_zeros.len(),
            nonce.as_ptr(),
            pk.as_ptr(),
            sk.as_ptr(),
        );
        if ret == -1 {
            return None;
        }
    }
    Some(cypher_text)
}

extern "C" {
    fn crypto_hash_sha256_ref(hash: *mut u8, message: *const u8, message_len: usize) -> i32;
    fn crypto_hash_sha512_ref(hash: *mut u8, message: *const u8, message_len: usize) -> i32;
    fn crypto_box_curve25519xsalsa20poly1305_ref(
        cypher_text: *mut u8,
        message: *const u8,
        message_length: usize,
        nonce: *const u8,
        public_key: *const u8,
        secret_key: *const u8,
    ) -> i32;
    fn crypto_box_curve25519xsalsa20poly1305_ref_keypair(
        public_key: *mut u8,
        secret_key: *mut u8,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto_box, crypto_box_keypair, crypto_hash_sha256, crypto_hash_sha512,
        CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_NONCEBYTES,
        CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_PUBLIC_KEY_BYTES,
        CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_SECRET_KEY_BYTES, CRYPTO_HASH_SHA256_BYTES,
        CRYPTO_HASH_SHA512_BYTES,
    };

    #[test]
    fn test_crypto_hash_sha256_ref() {
        let mut message = "The quick brown fox jumped over the lazy dog".to_string();
        let hex_encoded_hash = crypto_hash_sha256(&mut message).unwrap();
        assert_eq!(CRYPTO_HASH_SHA256_BYTES, hex_encoded_hash.len());
    }

    #[test]
    fn test_crypto_hash_sha512_ref() {
        let mut message = "The quick brown fox jumped over the lazy dog".to_string();
        let hex_encoded_hash = crypto_hash_sha512(&mut message).unwrap();
        assert_eq!(CRYPTO_HASH_SHA512_BYTES, hex_encoded_hash.len());
    }

    #[test]
    fn test_crypto_box_keypair() {
        let (pk, sk) = crypto_box_keypair().unwrap();
        assert_eq!(
            CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_PUBLIC_KEY_BYTES,
            pk.len()
        );
        assert_eq!(
            CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_SECRET_KEY_BYTES,
            sk.len()
        );
    }

    #[test]
    fn test_crypto_box() {
        let (pk, sk) = crypto_box_keypair().unwrap();
        let message = "The quick brown fox jumped over the lazy dog";
        let nonce = Vec::<u8>::with_capacity(CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_NONCEBYTES);
        let cypher_text = crypto_box(message, nonce, pk, sk);
        assert_ne!(None, cypher_text);
        assert_eq!(
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &cypher_text.unwrap()[..16]
        );
    }
}
