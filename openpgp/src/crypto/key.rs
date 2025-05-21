//! Common secret key related operations.

use std::time::SystemTime;

use crate::{
    Result,
    crypto::{
        PublicKeyAlgorithm,
        backend::{Backend, interface::Asymmetric},
        mpi,
    },
    packet::key::{self, Key4, Key6, SecretParts},
    types::Curve,
};

impl<R> Key6<SecretParts, R>
    where R: key::KeyRole,
{
    /// Generates a new X25519 key.
    pub fn generate_x25519() -> Result<Self> {
        Key4::generate_x25519().map(Key6::from_common)
    }

    /// Generates a new X448 key.
    pub fn generate_x448() -> Result<Self> {
        Key4::generate_x448().map(Key6::from_common)
    }

    /// Generates a new Ed25519 key.
    pub fn generate_ed25519() -> Result<Self> {
        Key4::generate_ed25519().map(Key6::from_common)
    }

    /// Generates a new Ed448 key.
    pub fn generate_ed448() -> Result<Self> {
        Key4::generate_ed448().map(Key6::from_common)
    }

    /// Generates a new MLDSA65+Ed25519 key.
    pub fn generate_mldsa65_ed25519() -> Result<Self> {
        let (eddsa_secret, eddsa_public) = Backend::ed25519_generate_key()?;
        let (mldsa_secret, mldsa_public) = Backend::mldsa65_generate_key()?;

        Self::with_secret(
            crate::now(),
            PublicKeyAlgorithm::MLDSA65_Ed25519,
            mpi::PublicKey::MLDSA65_Ed25519 {
                eddsa: Box::new(eddsa_public),
                mldsa: mldsa_public,
            },
            mpi::SecretKeyMaterial::MLDSA65_Ed25519 {
                eddsa: eddsa_secret,
                mldsa: mldsa_secret,
            }.into())
    }

    /// Generates a new MLDSA87+Ed448 key.
    pub fn generate_mldsa87_ed448() -> Result<Self> {
        let (eddsa_secret, eddsa_public) = Backend::ed448_generate_key()?;
        let (mldsa_secret, mldsa_public) = Backend::mldsa87_generate_key()?;

        Self::with_secret(
            crate::now(),
            PublicKeyAlgorithm::MLDSA87_Ed448,
            mpi::PublicKey::MLDSA87_Ed448 {
                eddsa: Box::new(eddsa_public),
                mldsa: mldsa_public,
            },
            mpi::SecretKeyMaterial::MLDSA87_Ed448 {
                eddsa: eddsa_secret,
                mldsa: mldsa_secret,
            }.into())
    }

    /// Generates a new SLHDSA128s key.
    pub fn generate_slhdsa128s() -> Result<Self> {
        let (secret, public) = Backend::slhdsa128s_generate_key()?;

        Self::with_secret(
            crate::now(),
            PublicKeyAlgorithm::SLHDSA128s,
            mpi::PublicKey::SLHDSA128s { public },
            mpi::SecretKeyMaterial::SLHDSA128s { secret }.into())
    }

    /// Generates a new SLHDSA128f key.
    pub fn generate_slhdsa128f() -> Result<Self> {
        let (secret, public) = Backend::slhdsa128f_generate_key()?;

        Self::with_secret(
            crate::now(),
            PublicKeyAlgorithm::SLHDSA128f,
            mpi::PublicKey::SLHDSA128f { public },
            mpi::SecretKeyMaterial::SLHDSA128f { secret }.into())
    }

    /// Generates a new SLHDSA256s key.
    pub fn generate_slhdsa256s() -> Result<Self> {
        let (secret, public) = Backend::slhdsa256s_generate_key()?;

        Self::with_secret(
            crate::now(),
            PublicKeyAlgorithm::SLHDSA256s,
            mpi::PublicKey::SLHDSA256s { public },
            mpi::SecretKeyMaterial::SLHDSA256s { secret }.into())
    }

    /// Generates a new MLKEM768+X25519 key.
    pub fn generate_mlkem768_x25519() -> Result<Self> {
        let (ecdh_secret, ecdh_public) = Backend::x25519_generate_key()?;
        let (mlkem_secret, mlkem_public) = Backend::mlkem768_generate_key()?;

        Self::with_secret(
            crate::now(),
            PublicKeyAlgorithm::MLKEM768_X25519,
            mpi::PublicKey::MLKEM768_X25519 {
                ecdh: Box::new(ecdh_public),
                mlkem: mlkem_public,
            },
            mpi::SecretKeyMaterial::MLKEM768_X25519 {
                ecdh: ecdh_secret,
                mlkem: mlkem_secret,
            }.into())
    }

    /// Generates a new MLKEM1024+X448 key.
    pub fn generate_mlkem1024_x448() -> Result<Self> {
        let (ecdh_secret, ecdh_public) = Backend::x448_generate_key()?;
        let (mlkem_secret, mlkem_public) = Backend::mlkem1024_generate_key()?;

        Self::with_secret(
            crate::now(),
            PublicKeyAlgorithm::MLKEM1024_X448,
            mpi::PublicKey::MLKEM1024_X448 {
                ecdh: Box::new(ecdh_public),
                mlkem: mlkem_public,
            },
            mpi::SecretKeyMaterial::MLKEM1024_X448 {
                ecdh: ecdh_secret,
                mlkem: mlkem_secret,
            }.into())
    }

    /// Generates a new RSA key with a public modulos of size `bits`.
    pub fn generate_rsa(bits: usize) -> Result<Self> {
        Key4::generate_rsa(bits)
            .map(Key6::from_common)
    }

    /// Creates a new OpenPGP public key packet for an existing RSA key.
    ///
    /// The RSA key will use public exponent `e` and modulo `n`. The key will
    /// have its creation date set to `ctime` or the current time if `None`
    /// is given.
    #[allow(clippy::many_single_char_names)]
    pub fn import_secret_rsa<T>(d: &[u8], p: &[u8], q: &[u8], ctime: T)
        -> Result<Self> where T: Into<Option<SystemTime>>
    {
        Key4::import_secret_rsa(d, p, q, ctime)
            .map(Key6::from_common)
    }

    /// Generates a new ECC key over `curve`.
    ///
    /// If `for_signing` is false a ECDH key, if it's true either a
    /// EdDSA or ECDSA key is generated.  Giving `for_signing == true` and
    /// `curve == Cv25519` will produce an error. Likewise
    /// `for_signing == false` and `curve == Ed25519` will produce an error.
    pub fn generate_ecc(for_signing: bool, curve: Curve) -> Result<Self> {
        match (for_signing, curve) {
            (true, Curve::Ed25519) => Self::generate_ed25519(),
            (false, Curve::Cv25519) => Self::generate_x25519(),
            (s, c) => Key4::generate_ecc(s, c).map(Key6::from_common),
        }
    }
}
