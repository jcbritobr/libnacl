use std::fmt::Display;

use crate::crypto_constants::*;

pub type Result<T> = std::result::Result<T, CryptoError>;
#[derive(Debug, Clone, PartialEq)]
pub enum CryptoError {
    KeySizeError(String),
    NonceSizeError(String),
    UnknownError
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::NonceSizeError(e) => write!(f, "{}", e),
            CryptoError::KeySizeError(e) => write!(f, "{}", e),
            CryptoError::UnknownError => write!(f, "{}", "Unknown crypto error")
        }
    }
}

pub fn check_crypto_error(sk: &Vec<u8>, nonce: &Vec<u8>) -> Result<()> {
    if sk.len() != CURVE_25519XSALSA20POLY1305_KEY_BYTES {
        return Err(CryptoError::KeySizeError(String::from(
            "Wrong key size",
        )));
    }
    if nonce.len() != CURVE_25519XSALSA20POLY1305_NONCEBYTES {
        return Err(CryptoError::NonceSizeError(String::from(
            "Wrong nonce size",
        )));
    }
    Ok(())
}