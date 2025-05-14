//! Implementation of Sequoia crypto API using the OpenSSL cryptographic library.

use crate::types::*;

pub mod aead;
pub mod asymmetric;
pub mod ecdh;
pub mod hash;
pub mod kdf;
pub mod symmetric;

pub struct Backend(());

impl super::interface::Backend for Backend {
    fn backend() -> String {
        openssl::version::version().into()
    }

    fn random(buf: &mut [u8]) -> crate::Result<()> {
        openssl::rand::rand_bytes(buf)?;
        Ok(())
    }
}

impl AEADAlgorithm {
    pub(crate) fn is_supported_by_backend(&self) -> bool {
        // First, check whether support is compiled in or not.
        (match self {
            AEADAlgorithm::EAX => false,
            AEADAlgorithm::OCB => cfg!(not(osslconf = "OPENSSL_NO_OCB")),
            AEADAlgorithm::GCM => true,
            AEADAlgorithm::Private(_) |
            AEADAlgorithm::Unknown(_) => false,
        }) && {
            // Then, check whether it has been disabled at runtime,
            // for example by putting OpenSSL into FIPS mode.
            use std::sync::OnceLock;

            static MODES: [OnceLock<bool>; 3] = [const { OnceLock::new() }; 3];
            MODES.get(u8::from(*self) as usize - 1)
                .map(|cell| cell.get_or_init(|| {
                    let algo = SymmetricAlgorithm::AES128;
                    let key = [0; 16];
                    let nonce = &key[..self.nonce_size().unwrap_or(16)];
                    self.context(algo, &key, &[], nonce,
                                 crate::crypto::aead::CipherOp::Encrypt)
                        .is_ok()
                }))
                .cloned()
                .unwrap_or(false)
        }
    }

    #[cfg(test)]
    pub(crate) fn supports_symmetric_algo(&self, algo: &SymmetricAlgorithm) -> bool {
        match &self {
            AEADAlgorithm::EAX => false,
            AEADAlgorithm::OCB =>
                match algo {
                    // OpenSSL supports OCB only with AES
                    // see: https://wiki.openssl.org/index.php/OCB
                    SymmetricAlgorithm::AES128 |
                    SymmetricAlgorithm::AES192 |
                    SymmetricAlgorithm::AES256 => true,
                    _ => false,
                },
            AEADAlgorithm::GCM =>
                match algo {
                    // OpenSSL supports GCM only with AES
                    // see: https://wiki.openssl.org/index.php/GCM
                    SymmetricAlgorithm::AES128 |
                    SymmetricAlgorithm::AES192 |
                    SymmetricAlgorithm::AES256 => true,
                    _ => false,
                },
            AEADAlgorithm::Private(_) |
            AEADAlgorithm::Unknown(_) => false,
        }
    }
}
