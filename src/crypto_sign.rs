pub const CRYPTO_SIGN_EDWARDS25519SHA512BATCH_SECRETKEYBYTES: usize = 64;
pub const CRYPTO_SIGN_EDWARDS25519SHA512BATCH_PUBLICKEYBYTES: usize = 32;
pub const CRYPTO_SIGN_EDWARDS25519SHA512BATCH_BYTES: usize = 64;

/// The function crypto_sign_keypair returns a tuple with the public key and secret key respectivelly.
/// The keys have sizes **CRYPTO_SIGN_EDWARDS25519SHA512BATCH_PUBLICKEYBYTES** for public key and
/// **CRYPTO_SIGN_EDWARDS25519SHA512BATCH_SECRETKEYBYTES** for private key.
/// 
/// ## Examples
/// 
/// ```
/// use libnacl::crypto_sign::*;
/// 
/// let (pk, sk) = crypto_sign_keypair().unwrap();
/// assert_eq!(CRYPTO_SIGN_EDWARDS25519SHA512BATCH_PUBLICKEYBYTES, pk.len());
/// assert_eq!(CRYPTO_SIGN_EDWARDS25519SHA512BATCH_SECRETKEYBYTES, sk.len());
/// ```
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

pub fn crypto_sign(message: Vec<u8>, sk: Vec<u8>) -> Option<Vec<u8>> {
    let mut smlen: usize = 0;
    let mut signed_message = vec![0u8; message.len() + CRYPTO_SIGN_EDWARDS25519SHA512BATCH_BYTES];
    unsafe {
        let res = crypto_sign_edwards25519sha512batch_ref(
            signed_message.as_mut_ptr(),
            &mut smlen,
            message.as_ptr(),
            message.len(),
            sk.as_ptr(),
        );

        if res == -1 {
            None
        } else {
            Some(signed_message)
        }
    }
}

pub fn crypto_sign_open(signed_message: Vec<u8>, public_key: Vec<u8>) -> Option<Vec<u8>> {
    let mut plain_message = vec![0u8; signed_message.len()];
    let mut _plain_message_len: usize = 0;
    unsafe {
        let res = crypto_sign_edwards25519sha512batch_ref_open(
            plain_message.as_mut_ptr(),
            &mut _plain_message_len,
            signed_message.as_ptr(),
            signed_message.len(),
            public_key.as_ptr(),
        );

        if res == -1 {
            None
        } else {
            Some(plain_message)
        }
    }
}

extern "C" {
    fn crypto_sign_edwards25519sha512batch_ref_keypair(
        public_key: *mut u8,
        private_key: *mut u8,
    ) -> i32;
    fn crypto_sign_edwards25519sha512batch_ref(
        signed_message: *mut u8,
        signed_message_len: *mut usize,
        message: *const u8,
        message_len: usize,
        pk: *const u8,
    ) -> i32;
    fn crypto_sign_edwards25519sha512batch_ref_open(
        message: *mut u8,
        message_len: *mut usize,
        signed_message: *const u8,
        signed_message_len: usize,
        public_key: *const u8,
    ) -> i32;
}

#[cfg(test)]
mod tests {

    use crate::crypto_sign::{
        CRYPTO_SIGN_EDWARDS25519SHA512BATCH_BYTES,
        CRYPTO_SIGN_EDWARDS25519SHA512BATCH_PUBLICKEYBYTES,
        CRYPTO_SIGN_EDWARDS25519SHA512BATCH_SECRETKEYBYTES,
    };

    use super::{crypto_sign, crypto_sign_keypair, crypto_sign_open};

    #[test]
    fn test_crypto_sign_keypair() {
        let (pk, sk) = crypto_sign_keypair().unwrap();
        assert_eq!(CRYPTO_SIGN_EDWARDS25519SHA512BATCH_PUBLICKEYBYTES, pk.len());
        assert_eq!(CRYPTO_SIGN_EDWARDS25519SHA512BATCH_SECRETKEYBYTES, sk.len());
    }

    #[test]
    fn test_crypto_sign() {
        let (_, sk) = crypto_sign_keypair().unwrap();
        let message = "The quick brownfox jumps over the lazy dog";
        let signed_message = crypto_sign(message.as_bytes().to_vec(), sk).unwrap();
        let data_from_signed = std::str::from_utf8(&signed_message[32..][..message.len()]).unwrap();
        assert_eq!(message, data_from_signed);
        assert_eq!(
            message.len() + CRYPTO_SIGN_EDWARDS25519SHA512BATCH_BYTES,
            signed_message.len()
        );
    }

    #[test]
    fn test_crypto_sign_open() {
        let (pk, sk) = crypto_sign_keypair().unwrap();
        let message = "The quick brownfox jumps over the lazy dog";
        let signed_message = crypto_sign(message.as_bytes().to_vec(), sk).unwrap();
        let validated_message = crypto_sign_open(signed_message, pk).unwrap();
        let validated_message = std::str::from_utf8(&validated_message)
            .unwrap()
            .trim_matches(char::from(0));
        assert_eq!(message, validated_message);
    }
}
