pub const CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_PUBLIC_KEY_BYTES: usize = 32;
pub const CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_SECRET_KEY_BYTES: usize = 32;
pub const CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_NONCEBYTES: usize = 24;
pub const CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_ZEROBYTES: usize = 32;
pub const CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_BOXZEROBYTES: usize = 16;

pub fn crypto_box_keypair() -> Option<(Vec<u8>, Vec<u8>)> {
    let mut public_key = [0u8; CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_PUBLIC_KEY_BYTES];
    let mut secret_key = [0u8; CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_SECRET_KEY_BYTES];
    unsafe {
        let res = crypto_box_curve25519xsalsa20poly1305_ref_keypair(
            public_key.as_mut_ptr(),
            secret_key.as_mut_ptr(),
        );
        if res == -1 {
            None
        } else {
            Some((public_key.to_vec(), secret_key.to_vec()))
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
            None
        } else {
            Some(cypher_text)
        }
    }
}

pub fn crypto_box_open(
    cipher_text: Vec<u8>,
    nonce: Vec<u8>,
    pk: Vec<u8>,
    sk: Vec<u8>,
) -> Option<Vec<u8>> {
    let mut plain_message = vec![0u8; cipher_text.len()];
    unsafe {
        let res = crypto_box_curve25519xsalsa20poly1305_ref_open(
            plain_message.as_mut_ptr(),
            cipher_text.as_ptr(),
            cipher_text.len(),
            nonce.as_ptr(),
            pk.as_ptr(),
            sk.as_ptr(),
        );
        if res == -1 {
            None
        } else {
            Some(plain_message)
        }
    }
}

extern "C" {
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
    fn crypto_box_curve25519xsalsa20poly1305_ref_open(
        message: *mut u8,
        cipher_text: *const u8,
        cipher_length: usize,
        nonce: *const u8,
        public_key: *const u8,
        secret_key: *const u8,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use crate::crypto_box::{
        crypto_box, crypto_box_keypair, crypto_box_open,
        CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_NONCEBYTES,
        CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_PUBLIC_KEY_BYTES,
        CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_SECRET_KEY_BYTES,
        CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_ZEROBYTES,
    };

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
        let result = crypto_box(message, nonce, pk, sk).unwrap();
        assert_eq!(
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &result[..16]
        );
        assert_eq!(
            CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_ZEROBYTES + message.len(),
            result.len()
        );
    }

    #[test]
    fn test_crypto_box_open() {
        let (alice_pk, alice_sk) = crypto_box_keypair().unwrap();
        let (bob_pk, bob_sk) = crypto_box_keypair().unwrap();

        let message = "The quick brown fox jumped over the lazy dog";
        let nonce = vec![0u8; CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_NONCEBYTES];
        let nonce_to_open = nonce.clone();
        let crypto_text = crypto_box(message, nonce, bob_pk, alice_sk).unwrap();

        let decrypted_message =
            crypto_box_open(crypto_text, nonce_to_open, alice_pk, bob_sk).unwrap();
        assert_eq!(
            message,
            std::str::from_utf8(
                &decrypted_message[CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_ZEROBYTES..]
            )
            .unwrap()
        );
        assert_eq!(
            message.as_bytes().to_vec(),
            decrypted_message[CRYPTO_BOX_CURVE_25519XSALSA20POLY1305_ZEROBYTES..]
        );
    }
}
