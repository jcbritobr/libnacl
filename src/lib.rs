//! # Nacl Wrapper API for Rust
//!
//! NaCl (pronounced "salt") is a new easy-to-use high-speed software library for network
//! communication, encryption, decryption, signatures, etc. NaCl's goal is to provide all of the core
//! operations needed to build higher-level cryptographic tools.
//! 
//! Of course, other libraries already exist for these core operations. NaCl advances the state of
//! the art by improving security, by improving usability, and by improving speed.
//!
//! The following report contrasts NaCl with other libraries from a security perspective: [PDF](https://cr.yp.to/highspeed/coolnacl-20120725.pdf)
//! Daniel J. Bernstein, Tanja Lange, Peter Schwabe, "The security impact of a new cryptographic library". Pages 159–176 in Proceedings of 
//! LatinCrypt 2012, edited by Alejandro Hevia and Gregory Neven, Lecture Notes in Computer Science 7533, Springer, 
//! 2012. ISBN 978-3-642-33480-1.
//!
//! The following report was created for Research Plaza and gives an introduction to NaCl for a wider audience: [PDF](https://nacl.cr.yp.to/securing-communication.pdf)

/// # Public Key Encryption
/// 
/// Imagine Alice wants something valuable shipped to her. Because it’s valuable, she wants to make
/// sure it arrives securely (i.e. hasn’t been opened or tampered with) and that it’s not a forgery
/// (i.e. it’s actually from the sender she’s expecting it to be from and nobody’s pulling the old switcheroo).
/// 
/// One way she can do this is by providing the sender (let’s call him Bob) with a high-security box of her choosing.
/// She provides Bob with this box, and something else: a padlock, but a padlock without a key.
/// Alice is keeping that key all to herself. Bob can put items in the box then put the padlock onto it. But once the padlock snaps shut,
/// the box cannot be opened by anyone who doesn’t have Alice’s private key.
/// 
/// Here’s the twist though: Bob also puts a padlock onto the box. This padlock uses a key Bob has published to the world,
/// such that if you have one of Bob’s keys, you know a box came from him because Bob’s keys will open Bob’s padlocks
/// (let’s imagine a world where padlocks cannot be forged even if you know the key). Bob then sends the box to Alice.
/// 
/// In order for Alice to open the box, she needs two keys: her private key that opens her own padlock, and Bob’s well-known key.
/// If Bob’s key doesn’t open the second padlock, then Alice knows that this is not the box she was expecting from Bob, it’s a forgery.
/// This bidirectional guarantee around identity is known as mutual authentication.
pub mod crypto_box;
/// # Hashing
/// 
/// Cryptographic secure hash functions are irreversible transforms of input data to a fixed length digest.
/// The standard properties of a cryptographic hash make these functions useful both for standalone usage as data integrity checkers,
/// as well as black-box building blocks of other kind of algorithms and data structures.
/// 
/// The standard properties of a cryptographic hash make these functions useful both for standalone usage as data integrity checkers,
/// as well as black-box building blocks of other kind of algorithms and data structures.
pub mod crypto_hash;
/// # Digital Signatures
/// 
/// You can use a digital signature for many of the same reasons that you might sign a paper document. A valid digital signature gives a
/// recipient reason to believe that the message was created by a known sender such that they cannot deny sending it
/// (authentication and non-repudiation) and that the message was not altered in transit (integrity).
/// 
/// Digital signatures allow you to publish a public key, and then you can use your private signing key to sign messages. Others who have your
/// public key can then use it to validate that your messages are actually authentic.
pub mod crypto_sign;

#[cfg(test)]
mod tests {
    
}
