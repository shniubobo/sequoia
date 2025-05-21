//! Public-key cryptography interface.

use crate::{
    Error,
    Result,
    crypto::{
        mem::Protected,
        mpi::{MPI, ProtectedMPI},
    },
    types::{Curve, PublicKeyAlgorithm},
};

/// Public-key cryptography interface.
pub trait Asymmetric {
    /// Returns whether the given public key cryptography algorithm is
    /// supported by this backend.
    ///
    /// Note: when implementing this function, match exhaustively on
    /// `algo`, do not use a catch-all.  This way, when new algorithms
    /// are introduced, we will see where we may need to add support.
    fn supports_algo(algo: PublicKeyAlgorithm) -> bool;

    /// Returns whether the given elliptic curve is supported by this
    /// backend.
    ///
    /// Note: when implementing this function, match exhaustively on
    /// `curve`, do not use a catch-all.  This way, when new algorithms
    /// are introduced, we will see where we may need to add support.
    fn supports_curve(curve: &Curve) -> bool;

    /// Generates an X25519 key pair.
    ///
    /// Returns a tuple containing the secret and public key.
    fn x25519_generate_key() -> Result<(Protected, [u8; 32])>;

    /// Clamp the X25519 secret key scalar.
    ///
    /// X25519 does the clamping implicitly, but OpenPGP's ECDH over
    /// Curve25519 requires the secret to be clamped.  To increase
    /// compatibility with OpenPGP implementations that do not
    /// implicitly clamp the secrets before use, we do that before we
    /// store the secrets in OpenPGP data structures.
    ///
    /// Note: like every function in this trait, this function expects
    /// `secret` to be in native byte order.
    fn x25519_clamp_secret(secret: &mut Protected) {
        secret[0] &= 0b1111_1000;
        secret[31] &= !0b1000_0000;
        secret[31] |= 0b0100_0000;
    }

    /// Computes the public key for a given secret key.
    fn x25519_derive_public(secret: &Protected) -> Result<[u8; 32]>;

    /// Computes the shared point.
    fn x25519_shared_point(secret: &Protected, public: &[u8; 32])
                           -> Result<Protected>;

    /// Generates an X448 key pair.
    ///
    /// Returns a tuple containing the secret and public key.
    fn x448_generate_key() -> Result<(Protected, [u8; 56])> {
        Err(Error::UnsupportedPublicKeyAlgorithm(PublicKeyAlgorithm::X448).into())
    }

    /// Computes the public key for a given secret key.
    fn x448_derive_public(_secret: &Protected) -> Result<[u8; 56]> {
        Err(Error::UnsupportedPublicKeyAlgorithm(PublicKeyAlgorithm::X448).into())
    }

    /// Computes the shared point.
    fn x448_shared_point(_secret: &Protected, _public: &[u8; 56])
                           -> Result<Protected> {
        Err(Error::UnsupportedPublicKeyAlgorithm(PublicKeyAlgorithm::X448).into())
    }

    /// Generates an Ed25519 key pair.
    ///
    /// Returns a tuple containing the secret and public key.
    fn ed25519_generate_key() -> Result<(Protected, [u8; 32])>;

    /// Computes the public key for a given secret key.
    fn ed25519_derive_public(secret: &Protected) -> Result<[u8; 32]>;

    /// Creates an Ed25519 signature.
    fn ed25519_sign(secret: &Protected, public: &[u8; 32], digest: &[u8])
                    -> Result<[u8; 64]>;

    /// Verifies an Ed25519 signature.
    fn ed25519_verify(public: &[u8; 32], digest: &[u8], signature: &[u8; 64])
                      -> Result<bool>;

    /// Generates an Ed448 key pair.
    ///
    /// Returns a tuple containing the secret and public key.
    fn ed448_generate_key() -> Result<(Protected, [u8; 57])> {
        Err(Error::UnsupportedPublicKeyAlgorithm(PublicKeyAlgorithm::Ed448).into())
    }

    /// Computes the public key for a given secret key.
    fn ed448_derive_public(_secret: &Protected) -> Result<[u8; 57]> {
        Err(Error::UnsupportedPublicKeyAlgorithm(PublicKeyAlgorithm::Ed448).into())
    }

    /// Creates an Ed448 signature.
    fn ed448_sign(_secret: &Protected, _public: &[u8; 57], _digest: &[u8])
                    -> Result<[u8; 114]> {
        Err(Error::UnsupportedPublicKeyAlgorithm(PublicKeyAlgorithm::Ed448).into())
    }

    /// Verifies an Ed448 signature.
    fn ed448_verify(_public: &[u8; 57], _digest: &[u8], _signature: &[u8; 114])
                      -> Result<bool> {
        Err(Error::UnsupportedPublicKeyAlgorithm(PublicKeyAlgorithm::Ed448).into())
    }

    /// Generates an ML-DSA-65 key pair.
    ///
    /// Returns a tuple containing the secret and public key.
    fn mldsa65_generate_key() -> Result<(Protected, Box<[u8; 1952]>)> {
        // XXX: This is not quite the right error, because we can only
        // use the composite algorithm name in the error message.
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::MLDSA65_Ed25519).into())
    }

    /// Creates an ML-DSA-65 signature.
    fn mldsa65_sign(_secret: &Protected, _digest: &[u8])
                    -> Result<Box<[u8; 3309]>>
    {
        // XXX: This is not quite the right error, because we can only
        // use the composite algorithm name in the error message.
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::MLDSA65_Ed25519).into())
    }

    /// Verifies an ML-DSA-65 signature.
    fn mldsa65_verify(_public: &[u8; 1952], _digest: &[u8], _signature: &[u8; 3309])
                      -> Result<bool>
    {
        // XXX: This is not quite the right error, because we can only
        // use the composite algorithm name in the error message.
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::MLDSA65_Ed25519).into())
    }

    /// Generates an ML-DSA-87 key pair.
    ///
    /// Returns a tuple containing the secret and public key.
    fn mldsa87_generate_key() -> Result<(Protected, Box<[u8; 2592]>)> {
        // XXX: This is not quite the right error, because we can only
        // use the composite algorithm name in the error message.
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::MLDSA87_Ed448).into())
    }

    /// Creates an ML-DSA-87 signature.
    fn mldsa87_sign(_secret: &Protected, _digest: &[u8])
                    -> Result<Box<[u8; 4627]>>
    {
        // XXX: This is not quite the right error, because we can only
        // use the composite algorithm name in the error message.
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::MLDSA87_Ed448).into())
    }

    /// Verifies an ML-DSA-87 signature.
    fn mldsa87_verify(_public: &[u8; 2592], _digest: &[u8], _signature: &[u8; 4627])
                      -> Result<bool>
    {
        // XXX: This is not quite the right error, because we can only
        // use the composite algorithm name in the error message.
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::MLDSA87_Ed448).into())
    }

    /// Generates an SLHDSA128s key pair.
    ///
    /// Returns a tuple containing the secret and public key.
    fn slhdsa128s_generate_key() -> Result<(Protected, [u8; 32])> {
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::SLHDSA128s).into())
    }

    /// Creates an SLHDSA128s signature.
    fn slhdsa128s_sign(_secret: &Protected, _digest: &[u8])
                       -> Result<Box<[u8; 7856]>>
    {
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::SLHDSA128s).into())
    }

    /// Verifies an SLHDSA128s signature.
    fn slhdsa128s_verify(_public: &[u8; 32], _digest: &[u8], _signature: &[u8; 7856])
                         -> Result<bool>
    {
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::SLHDSA128s).into())
    }

    /// Generates an SLHDSA128f key pair.
    ///
    /// Returns a tuple containing the secret and public key.
    fn slhdsa128f_generate_key() -> Result<(Protected, [u8; 32])> {
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::SLHDSA128f).into())
    }

    /// Creates an SLHDSA128f signature.
    fn slhdsa128f_sign(_secret: &Protected, _digest: &[u8])
                       -> Result<Box<[u8; 17088]>>
    {
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::SLHDSA128f).into())
    }

    /// Verifies an SLHDSA128f signature.
    fn slhdsa128f_verify(_public: &[u8; 32], _digest: &[u8], _signature: &[u8; 17088])
                         -> Result<bool>
    {
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::SLHDSA128f).into())
    }

    /// Generates an SLHDSA256s key pair.
    ///
    /// Returns a tuple containing the secret and public key.
    fn slhdsa256s_generate_key() -> Result<(Protected, Box<[u8; 64]>)> {
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::SLHDSA256s).into())
    }

    /// Creates an SLHDSA256s signature.
    fn slhdsa256s_sign(_secret: &Protected, _digest: &[u8])
                       -> Result<Box<[u8; 29792]>>
    {
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::SLHDSA256s).into())
    }

    /// Verifies an SLHDSA256s signature.
    fn slhdsa256s_verify(_public: &[u8; 64], _digest: &[u8], _signature: &[u8; 29792])
                         -> Result<bool>
    {
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::SLHDSA256s).into())
    }

    /// Generates a ML-KEM-768 key pair.
    fn mlkem768_generate_key() -> Result<(Protected, Box<[u8; 1184]>)> {
        // XXX: This is not quite the right error, because we can only
        // use the composite algorithm name in the error message.
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::MLKEM768_X25519).into())
    }

    /// Generates and encapsulates a secret using ML-KEM-768.
    fn mlkem768_encapsulate(_public: &[u8; 1184])
                            -> Result<(Box<[u8; 1088]>, Protected)>
    {
        // XXX: This is not quite the right error, because we can only
        // use the composite algorithm name in the error message.
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::MLKEM768_X25519).into())
    }

    /// Decapsulates a secret using ML-KEM-768.
    fn mlkem768_decapsulate(_secret: &Protected,
                            _ciphertext: &[u8; 1088])
                            -> Result<Protected>
    {
        // XXX: This is not quite the right error, because we can only
        // use the composite algorithm name in the error message.
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::MLKEM768_X25519).into())
    }

    /// Generates a ML-KEM-1024 key pair.
    fn mlkem1024_generate_key() -> Result<(Protected, Box<[u8; 1568]>)> {
        // XXX: This is not quite the right error, because we can only
        // use the composite algorithm name in the error message.
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::MLKEM1024_X448).into())
    }

    /// Generates and encapsulates a secret using ML-KEM-1024.
    fn mlkem1024_encapsulate(_public: &[u8; 1568])
                            -> Result<(Box<[u8; 1568]>, Protected)>
    {
        // XXX: This is not quite the right error, because we can only
        // use the composite algorithm name in the error message.
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::MLKEM1024_X448).into())
    }

    /// Decapsulates a secret using ML-KEM-1024.
    fn mlkem1024_decapsulate(_secret: &Protected,
                            _ciphertext: &[u8; 1568])
                            -> Result<Protected>
    {
        // XXX: This is not quite the right error, because we can only
        // use the composite algorithm name in the error message.
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::MLKEM1024_X448).into())
    }

    /// Generates a DSA key pair.
    ///
    /// `p_bits` denotes the desired size of the parameter `p`.
    /// Returns a tuple containing the parameters `p`, `q`, `g`, the
    /// public key `y`, and the secret key `x`.
    fn dsa_generate_key(p_bits: usize)
                        -> Result<(MPI, MPI, MPI, MPI, ProtectedMPI)>;

    /// Creates a DSA signature.
    fn dsa_sign(x: &ProtectedMPI,
                p: &MPI, q: &MPI, g: &MPI, y: &MPI,
                digest: &[u8])
                -> Result<(MPI, MPI)>;

    /// Verifies a DSA signature.
    fn dsa_verify(p: &MPI, q: &MPI, g: &MPI, y: &MPI,
                  digest: &[u8],
                  r: &MPI, s: &MPI)
                  -> Result<bool>;

    /// Generates an ElGamal key pair.
    ///
    /// `p_bits` denotes the desired size of the parameter `p`.
    /// Returns a tuple containing the parameters `p`, `g`, the public
    /// key `y`, and the secret key `x`.
    fn elgamal_generate_key(p_bits: usize)
                            -> Result<(MPI, MPI, MPI, ProtectedMPI)> {
        let _ = p_bits;
        #[allow(deprecated)]
        Err(Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::ElGamalEncrypt).into())
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::backend::{Backend, interface::Asymmetric};

    #[test]
    pub fn ed25519_generate_key_private_and_public_not_equal() {
        let (secret, public) = Backend::ed25519_generate_key().unwrap();
        assert_ne!(secret.as_ref(), public);
    }
}
