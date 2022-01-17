pub const CRYPTO_SIGN_EDWARDS25519SHA512BATCH_SECRETKEYBYTES: usize = 64;
pub const CRYPTO_SIGN_EDWARDS25519SHA512BATCH_PUBLICKEYBYTES: usize = 32;
pub const CRYPTO_SIGN_EDWARDS25519SHA512BATCH_BYTES: usize = 64;

pub fn crypto_sign_keypair() -> Option<(Vec<u8>, Vec<u8>)> {
    let mut pk = vec![0u8; CRYPTO_SIGN_EDWARDS25519SHA512BATCH_PUBLICKEYBYTES];
    let mut sk = vec![0u8; CRYPTO_SIGN_EDWARDS25519SHA512BATCH_SECRETKEYBYTES];
    unsafe {
        let res = crypto_sign_edwards25519sha512batch_ref_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        if res == -1 {
            None
        } else {
            Some((pk, sk))
        }
    }
}

extern "C" {
    fn crypto_sign_edwards25519sha512batch_ref_keypair(
        public_key: *mut u8,
        private_key: *mut u8,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use crate::crypto_sign::{
        CRYPTO_SIGN_EDWARDS25519SHA512BATCH_PUBLICKEYBYTES,
        CRYPTO_SIGN_EDWARDS25519SHA512BATCH_SECRETKEYBYTES,
    };

    use super::crypto_sign_keypair;

    #[test]
    fn test_crypto_sign() {
        let (pk, sk) = crypto_sign_keypair().unwrap();
        assert_eq!(CRYPTO_SIGN_EDWARDS25519SHA512BATCH_PUBLICKEYBYTES, pk.len());
        assert_eq!(CRYPTO_SIGN_EDWARDS25519SHA512BATCH_SECRETKEYBYTES, sk.len());
    }
}
