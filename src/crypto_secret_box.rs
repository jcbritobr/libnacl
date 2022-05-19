use crate::{
    crypto_constants::*,
    errors::{self, check_crypto_error, Result},
};

pub fn crypto_secret_box(message: Vec<u8>, nonce: Vec<u8>, sk: Vec<u8>) -> Result<Vec<u8>> {
    check_crypto_error(&sk, &nonce)?;

    let mut owned_message_zeros = vec![0u8; CURVE_25519XSALSA20POLY1305_ZEROBYTES];
    owned_message_zeros.extend_from_slice(&message);
    let mut cypher_text = vec![0u8; CURVE_25519XSALSA20POLY1305_ZEROBYTES + message.len()];

    unsafe {
        let ret = crypto_secretbox_xsalsa20poly1305_ref(
            cypher_text.as_mut_ptr(),
            owned_message_zeros.as_ptr(),
            owned_message_zeros.len(),
            nonce.as_ptr(),
            sk.as_ptr(),
        );
        if ret == -1 {
            Err(errors::CryptoError::UnknownError)
        } else {
            Ok(cypher_text)
        }
    }
}

pub fn crypto_secret_box_open(
    cipher_text: Vec<u8>,
    nonce: Vec<u8>,
    sk: Vec<u8>,
) -> Result<Vec<u8>> {
    check_crypto_error(&sk, &nonce)?;

    let mut plain_message = vec![0u8; cipher_text.len()];
    unsafe {
        let res = crypto_secretbox_xsalsa20poly1305_ref_open(
            plain_message.as_mut_ptr(),
            cipher_text.as_ptr(),
            cipher_text.len(),
            nonce.as_ptr(),
            sk.as_ptr(),
        );
        if res == -1 {
            Err(errors::CryptoError::UnknownError)
        } else {
            Ok(plain_message)
        }
    }
}

extern "C" {
    fn crypto_secretbox_xsalsa20poly1305_ref(
        cypher_text: *mut u8,
        message: *const u8,
        message_length: usize,
        nonce: *const u8,
        secret_key: *const u8,
    ) -> i32;

    fn crypto_secretbox_xsalsa20poly1305_ref_open(
        message: *mut u8,
        cipher_text: *const u8,
        cipher_length: usize,
        nonce: *const u8,
        secret_key: *const u8,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use crate::errors::CryptoError;

    use super::*;

    #[test]
    fn test_crypto_secret_box() {
        let sk: Vec<u8> = (0..CURVE_25519XSALSA20POLY1305_KEY_BYTES)
            .map(|b| b as u8)
            .collect();
        let message = "The quick brown fox jumps over the lazy dog";
        let nonce = vec![0u8; CURVE_25519XSALSA20POLY1305_NONCEBYTES];
        let result = crypto_secret_box(message.as_bytes().to_vec(), nonce, sk).unwrap();

        assert_eq!(
            &[0u8; CURVE_25519XSALSA20POLY1305_BOXZEROBYTES],
            &result[..16]
        );

        assert_eq!(
            CURVE_25519XSALSA20POLY1305_ZEROBYTES + message.len(),
            result.len()
        );
    }

    #[test]
    fn test_crypto_secret_box_fail_with_wrong_key_size() {
        let sk: Vec<u8> = (0..CURVE_25519XSALSA20POLY1305_KEY_BYTES - 8)
            .map(|d| d as u8)
            .collect();

        let message = "The quick brown fox jumps over the lazy dog";
        let nonce = vec![0u8; CURVE_25519XSALSA20POLY1305_NONCEBYTES];
        let result = crypto_secret_box(message.as_bytes().to_vec(), nonce, sk);
        assert_eq!(
            Err(CryptoError::KeySizeError(String::from("Wrong key size"))),
            result
        )
    }

    #[test]
    fn test_crypto_secret_box_fail_with_wrong_nonce_size() {
        let sk: Vec<u8> = (0..CURVE_25519XSALSA20POLY1305_KEY_BYTES)
            .map(|d| d as u8)
            .collect();

        let message = "The quick brown fox jumps over the lazy dog";
        let nonce = vec![0u8; CURVE_25519XSALSA20POLY1305_NONCEBYTES - 3];
        let result = crypto_secret_box(message.as_bytes().to_vec(), nonce, sk);
        assert_eq!(
            Err(CryptoError::NonceSizeError(String::from("Wrong nonce size"))),
            result
        )
    }

    #[test]
    fn test_crypto_secret_box_open() {
        let sk: Vec<u8> = (0..CURVE_25519XSALSA20POLY1305_KEY_BYTES)
            .map(|b| b as u8)
            .collect();
        let message = "The quick brown fox jumps over the lazy dog";
        let nonce = vec![0u8; CURVE_25519XSALSA20POLY1305_NONCEBYTES];
        let nonce_to_open = nonce.clone();
        let crypto_text =
            crypto_secret_box(message.as_bytes().to_vec(), nonce, sk.clone()).unwrap();

        assert_eq!(
            &[0u8; CURVE_25519XSALSA20POLY1305_BOXZEROBYTES],
            &crypto_text[..16]
        );

        let decrypted_message = crypto_secret_box_open(crypto_text, nonce_to_open, sk).unwrap();

        assert_eq!(
            message,
            std::str::from_utf8(&decrypted_message[CURVE_25519XSALSA20POLY1305_ZEROBYTES..])
                .unwrap()
        );
    }
}
