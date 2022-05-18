use std::fmt::Display;

pub type Result<T> = std::result::Result<T, CryptoError>;
#[derive(Debug, Clone)]
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