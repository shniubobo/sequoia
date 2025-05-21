//! Asymmetric crypto operations.

use crate::packet::{self, key, Key};
use crate::crypto::SessionKey;
use crate::crypto::mpi;
use crate::types::{
    Curve,
    HashAlgorithm,
    PublicKeyAlgorithm,
    SymmetricAlgorithm,
};

use crate::{Error, Result};

/// Creates a signature.
///
/// Used in the streaming [`Signer`], the methods binding components
/// to certificates (e.g. [`UserID::bind`]), [`SignatureBuilder`]'s
/// signing functions (e.g. [`SignatureBuilder::sign_standalone`]),
/// and likely many more places.
///
///   [`Signer`]: crate::serialize::stream::Signer
///   [`UserID::bind`]: crate::packet::UserID::bind()
///   [`SignatureBuilder`]: crate::packet::signature::SignatureBuilder
///   [`SignatureBuilder::sign_standalone`]: crate::packet::signature::SignatureBuilder::sign_standalone()
///
/// This is a low-level mechanism to produce an arbitrary OpenPGP
/// signature.  Using this trait allows Sequoia to perform all
/// operations involving signing to use a variety of secret key
/// storage mechanisms (e.g. smart cards).
///
/// A signer consists of the public key and a way of creating a
/// signature.  This crate implements `Signer` for [`KeyPair`], which
/// is a tuple containing the public and unencrypted secret key in
/// memory.  Other crates may provide their own implementations of
/// `Signer` to utilize keys stored in various places.  Currently, the
/// following implementations exist:
///
///   - [`KeyPair`]: In-memory keys.
///   - [`sequoia_rpc::gnupg::KeyPair`]: Connects to the `gpg-agent`.
///
///   [`sequoia_rpc::gnupg::KeyPair`]: https://docs.sequoia-pgp.org/sequoia_ipc/gnupg/struct.KeyPair.html
pub trait Signer {
    /// Returns a reference to the public key.
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole>;

    /// Returns a list of hashes that this signer accepts.
    ///
    /// Some cryptographic libraries or hardware modules support signing digests
    /// produced with only a limited set of hashing algorithms. This function
    /// indicates to callers which algorithm digests are supported by this signer.
    ///
    /// The default implementation of this function allows all hash algorithms to
    /// be used. Provide an explicit implementation only when a smaller subset
    /// of hashing algorithms is valid for this `Signer` implementation.
    fn acceptable_hashes(&self) -> &[HashAlgorithm] {
        crate::crypto::hash::default_hashes_sorted()
    }

    /// Creates a signature over the `digest` produced by `hash_algo`.
    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8])
            -> Result<mpi::Signature>;
}

impl Signer for Box<dyn Signer> {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        self.as_ref().public()
    }

    fn acceptable_hashes(&self) -> &[HashAlgorithm] {
        self.as_ref().acceptable_hashes()
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8])
            -> Result<mpi::Signature> {
        self.as_mut().sign(hash_algo, digest)
    }
}

impl Signer for Box<dyn Signer + Send + Sync> {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        self.as_ref().public()
    }

    fn acceptable_hashes(&self) -> &[HashAlgorithm] {
        self.as_ref().acceptable_hashes()
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8])
            -> Result<mpi::Signature> {
        self.as_mut().sign(hash_algo, digest)
    }
}

/// Decrypts a message.
///
/// Used by [`PKESK::decrypt`] to decrypt session keys.
///
///   [`PKESK::decrypt`]: crate::packet::PKESK#method.decrypt
///
/// This is a low-level mechanism to decrypt an arbitrary OpenPGP
/// ciphertext.  Using this trait allows Sequoia to perform all
/// operations involving decryption to use a variety of secret key
/// storage mechanisms (e.g. smart cards).
///
/// A decryptor consists of the public key and a way of decrypting a
/// session key.  This crate implements `Decryptor` for [`KeyPair`],
/// which is a tuple containing the public and unencrypted secret key
/// in memory.  Other crates may provide their own implementations of
/// `Decryptor` to utilize keys stored in various places.  Currently, the
/// following implementations exist:
///
///   - [`KeyPair`]: In-memory keys.
///   - [`sequoia_rpc::gnupg::KeyPair`]: Connects to the `gpg-agent`.
///
///   [`sequoia_rpc::gnupg::KeyPair`]: https://docs.sequoia-pgp.org/sequoia_ipc/gnupg/struct.KeyPair.html
pub trait Decryptor {
    /// Returns a reference to the public key.
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole>;

    /// Decrypts `ciphertext`, returning the plain session key.
    fn decrypt(&mut self, ciphertext: &mpi::Ciphertext,
               plaintext_len: Option<usize>)
               -> Result<SessionKey>;
}

impl Decryptor for Box<dyn Decryptor> {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        self.as_ref().public()
    }

    fn decrypt(&mut self, ciphertext: &mpi::Ciphertext,
               plaintext_len: Option<usize>)
               -> Result<SessionKey> {
        self.as_mut().decrypt(ciphertext, plaintext_len)
    }
}

impl Decryptor for Box<dyn Decryptor + Send + Sync> {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        self.as_ref().public()
    }

    fn decrypt(&mut self, ciphertext: &mpi::Ciphertext,
               plaintext_len: Option<usize>)
               -> Result<SessionKey> {
        self.as_mut().decrypt(ciphertext, plaintext_len)
    }
}

/// A cryptographic key pair.
///
/// A `KeyPair` is a combination of public and secret key.  If both
/// are available in memory, a `KeyPair` is a convenient
/// implementation of [`Signer`] and [`Decryptor`].
///
///
/// # Examples
///
/// ```
/// # fn main() -> sequoia_openpgp::Result<()> {
/// use sequoia_openpgp as openpgp;
/// use openpgp::types::Curve;
/// use openpgp::cert::prelude::*;
/// use openpgp::packet::prelude::*;
///
/// // Conveniently create a KeyPair from a bare key:
/// let keypair =
///     Key4::<_, key::UnspecifiedRole>::generate_ecc(false, Curve::Cv25519)?
///         .into_keypair()?;
///
/// // Or from a query over a certificate:
/// let (cert, _) =
///     CertBuilder::general_purpose(Some("alice@example.org"))
///         .generate()?;
/// let keypair =
///     cert.keys().unencrypted_secret().nth(0).unwrap().key().clone()
///         .into_keypair()?;
/// # Ok(()) }
/// ```
#[derive(Clone)]
pub struct KeyPair {
    public: Key<key::PublicParts, key::UnspecifiedRole>,
    secret: packet::key::Unencrypted,
}
assert_send_and_sync!(KeyPair);

impl KeyPair {
    /// Creates a new key pair.
    pub fn new(public: Key<key::PublicParts, key::UnspecifiedRole>,
               secret: packet::key::Unencrypted)
        -> Result<Self>
    {
        Ok(Self {
            public,
            secret,
        })
    }

    /// Returns a reference to the public key.
    pub fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        &self.public
    }

    /// Returns a reference to the secret key.
    pub fn secret(&self) -> &packet::key::Unencrypted {
        &self.secret
    }
}

impl From<KeyPair> for Key<key::SecretParts, key::UnspecifiedRole> {
    fn from(p: KeyPair) -> Self {
        let (key, secret) = (p.public, p.secret);
        key.add_secret(secret.into()).0
    }
}

impl Signer for KeyPair {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        KeyPair::public(self)
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8])
            -> Result<mpi::Signature>
    {
        use crate::crypto::backend::{Backend, interface::Asymmetric};

        self.secret().map(|secret| {
            #[allow(deprecated)]
            match (self.public().pk_algo(), self.public().mpis(), secret) {
                (PublicKeyAlgorithm::Ed25519,
                 mpi::PublicKey::Ed25519 { a },
                 mpi::SecretKeyMaterial::Ed25519 { x }) => {
                    Ok(mpi::Signature::Ed25519 {
                        s: Box::new(Backend::ed25519_sign(x, a, digest)?),
                    })
                },

                (PublicKeyAlgorithm::Ed448,
                 mpi::PublicKey::Ed448 { a },
                 mpi::SecretKeyMaterial::Ed448 { x }) => {
                    Ok(mpi::Signature::Ed448 {
                        s: Box::new(Backend::ed448_sign(x, a, digest)?),
                    })
                },

                (PublicKeyAlgorithm::MLDSA65_Ed25519,
                 mpi::PublicKey::MLDSA65_Ed25519 {
                     eddsa: eddsa_pub, ..
                 },
                 mpi::SecretKeyMaterial::MLDSA65_Ed25519 {
                     eddsa: eddsa_sec, mldsa: mldsa_sec,
                 }) => Ok(mpi::Signature::MLDSA65_Ed25519 {
                     eddsa: Box::new(Backend::ed25519_sign(
                         eddsa_sec, eddsa_pub, digest)?),
                     mldsa: Backend::mldsa65_sign(
                         mldsa_sec, digest)?,
                 }),

                (PublicKeyAlgorithm::MLDSA87_Ed448,
                 mpi::PublicKey::MLDSA87_Ed448 {
                     eddsa: eddsa_pub, ..
                 },
                 mpi::SecretKeyMaterial::MLDSA87_Ed448 {
                     eddsa: eddsa_sec, mldsa: mldsa_sec,
                 }) => Ok(mpi::Signature::MLDSA87_Ed448 {
                     eddsa: Box::new(Backend::ed448_sign(
                         eddsa_sec, eddsa_pub, digest)?),
                     mldsa: Backend::mldsa87_sign(
                         mldsa_sec, digest)?,
                 }),

                (PublicKeyAlgorithm::SLHDSA128s,
                 mpi::PublicKey::SLHDSA128s { .. },
                 mpi::SecretKeyMaterial::SLHDSA128s { secret }) =>
                    Ok(mpi::Signature::SLHDSA128s {
                        sig: Backend::slhdsa128s_sign(secret, digest)?,
                    }),

                (PublicKeyAlgorithm::SLHDSA128f,
                 mpi::PublicKey::SLHDSA128f { .. },
                 mpi::SecretKeyMaterial::SLHDSA128f { secret }) =>
                    Ok(mpi::Signature::SLHDSA128f {
                        sig: Backend::slhdsa128f_sign(secret, digest)?,
                    }),

                (PublicKeyAlgorithm::SLHDSA256s,
                 mpi::PublicKey::SLHDSA256s { .. },
                 mpi::SecretKeyMaterial::SLHDSA256s { secret }) =>
                    Ok(mpi::Signature::SLHDSA256s {
                        sig: Backend::slhdsa256s_sign(secret, digest)?,
                    }),

                (PublicKeyAlgorithm::EdDSA,
                 mpi::PublicKey::EdDSA { curve, q },
                 mpi::SecretKeyMaterial::EdDSA { scalar }) => match curve {
                    Curve::Ed25519 => {
                        let public = q.decode_point(&Curve::Ed25519)?.0
                            .try_into()?;
                        let secret = scalar.value_padded(32);
                        let sig =
                            Backend::ed25519_sign(&secret, &public, digest)?;
                        Ok(mpi::Signature::EdDSA {
                            r: mpi::MPI::new(&sig[..32]),
                            s: mpi::MPI::new(&sig[32..]),
                        })
                    },
                    _ => Err(
                        Error::UnsupportedEllipticCurve(curve.clone()).into()),
                },

                (PublicKeyAlgorithm::DSA,
                 mpi::PublicKey::DSA { p, q, g, y },
                 mpi::SecretKeyMaterial::DSA { x }) => {
                    let (r, s) = Backend::dsa_sign(x, p, q, g, y, digest)?;
                    Ok(mpi::Signature::DSA { r, s })
                },

                (_algo, _public, secret) =>
                    self.sign_backend(secret, hash_algo, digest),
            }
        })
    }
}

impl Decryptor for KeyPair {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        KeyPair::public(self)
    }

    fn decrypt(&mut self,
               ciphertext: &mpi::Ciphertext,
               plaintext_len: Option<usize>)
               -> Result<SessionKey>
    {
        use crate::crypto::ecdh::aes_key_unwrap;
        use crate::crypto::backend::{Backend, interface::{Asymmetric, Kdf}};

        self.secret().map(|secret| {
            #[allow(non_snake_case)]
            match (self.public().mpis(), secret, ciphertext) {
                (mpi::PublicKey::X25519 { u: U },
                 mpi::SecretKeyMaterial::X25519 { x },
                 mpi::Ciphertext::X25519 { e: E, key }) => {
                    // Compute the shared point S = xE;
                    let S = Backend::x25519_shared_point(x, E)?;

                    // Compute the wrap key.
                    let wrap_algo = SymmetricAlgorithm::AES128;
                    let mut ikm: SessionKey = vec![0; 32 + 32 + 32].into();

                    // Yes clippy, this operation will always return
                    // zero.  This is the intended outcome.  Chill.
                    #[allow(clippy::erasing_op)]
                    ikm[0 * 32..1 * 32].copy_from_slice(&E[..]);
                    ikm[1 * 32..2 * 32].copy_from_slice(&U[..]);
                    ikm[2 * 32..3 * 32].copy_from_slice(&S[..]);
                    let mut kek = vec![0; wrap_algo.key_size()?].into();
                    Backend::hkdf_sha256(&ikm, None, b"OpenPGP X25519",
                                         &mut kek)?;

                    Ok(aes_key_unwrap(wrap_algo, kek.as_protected(),
                                      key)?.into())
                },

                (mpi::PublicKey::X448 { u: U },
                 mpi::SecretKeyMaterial::X448 { x },
                 mpi::Ciphertext::X448 { e: E, key }) => {
                    // Compute the shared point S = xE;
                    let S = Backend::x448_shared_point(x, E)?;

                    // Compute the wrap key.
                    let wrap_algo = SymmetricAlgorithm::AES256;
                    let mut ikm: SessionKey = vec![0; 56 + 56 + 56].into();

                    // Yes clippy, this operation will always return
                    // zero.  This is the intended outcome.  Chill.
                    #[allow(clippy::erasing_op)]
                    ikm[0 * 56..1 * 56].copy_from_slice(&E[..]);
                    ikm[1 * 56..2 * 56].copy_from_slice(&U[..]);
                    ikm[2 * 56..3 * 56].copy_from_slice(&S[..]);
                    let mut kek = vec![0; wrap_algo.key_size()?].into();
                    Backend::hkdf_sha512(&ikm, None, b"OpenPGP X448",
                                         &mut kek)?;

                    Ok(aes_key_unwrap(wrap_algo, kek.as_protected(),
                                      key)?.into())
                },

                (mpi::PublicKey::ECDH { curve: Curve::Cv25519, .. },
                 mpi::SecretKeyMaterial::ECDH { scalar, },
                 mpi::Ciphertext::ECDH { e, .. }) =>
                {
                    // Get the public part V of the ephemeral key.
                    let V = e.decode_point(&Curve::Cv25519)?.0;

                    // X25519 expects the private key to be exactly 32
                    // bytes long but OpenPGP allows leading zeros to
                    // be stripped.  Padding has to be unconditional;
                    // otherwise we have a secret-dependent branch.
                    let mut r = scalar.value_padded(32);

                    // Reverse the scalar.  See
                    // https://lists.gnupg.org/pipermail/gnupg-devel/2018-February/033437.html
                    r.reverse();

                    // Compute the shared point S = rV = rvG, where
                    // (r, R) is the recipient's key pair.
                    let S = Backend::x25519_shared_point(&r, &V.try_into()?)?;

                    crate::crypto::ecdh::decrypt_unwrap(
                        self.public(), &S, ciphertext, plaintext_len)
                },

                (
                    mpi::PublicKey::MLKEM768_X25519 {
                        ecdh: ecdh_public, ..
                    },
                    mpi::SecretKeyMaterial::MLKEM768_X25519 {
                        ecdh: ecdh_secret, mlkem: mlkem_secret,
                    },
                    mpi::Ciphertext::MLKEM768_X25519 {
                        ecdh: ecdh_ciphertext, mlkem: mlkem_ciphertext, esk,
                    },
                ) => {
                    let ecdh_keyshare = Backend::x25519_shared_point(
                        ecdh_secret, ecdh_ciphertext)?;

                    let mlkem_keyshare = Backend::mlkem768_decapsulate(
                        mlkem_secret, mlkem_ciphertext)?;

                    let kek = multi_key_combine(
                        &mlkem_keyshare,
                        &ecdh_keyshare,
                        ecdh_ciphertext.as_ref(),
                        ecdh_public.as_ref(),
                        PublicKeyAlgorithm::MLKEM768_X25519)?;

                    Ok(aes_key_unwrap(SymmetricAlgorithm::AES256,
                                      kek.as_protected(),
                                      esk)?.into())
                },

                (
                    mpi::PublicKey::MLKEM1024_X448 {
                        ecdh: ecdh_public, ..
                    },
                    mpi::SecretKeyMaterial::MLKEM1024_X448 {
                        ecdh: ecdh_secret, mlkem: mlkem_secret,
                    },
                    mpi::Ciphertext::MLKEM1024_X448 {
                        ecdh: ecdh_ciphertext, mlkem: mlkem_ciphertext, esk,
                    },
                ) => {
                    let ecdh_keyshare = Backend::x448_shared_point(
                        ecdh_secret, ecdh_ciphertext)?;

                    let mlkem_keyshare = Backend::mlkem1024_decapsulate(
                        mlkem_secret, mlkem_ciphertext)?;

                    let kek = multi_key_combine(
                        &mlkem_keyshare,
                        &ecdh_keyshare,
                        ecdh_ciphertext.as_ref(),
                        ecdh_public.as_ref(),
                        PublicKeyAlgorithm::MLKEM1024_X448)?;

                    Ok(aes_key_unwrap(SymmetricAlgorithm::AES256,
                                      kek.as_protected(),
                                      esk)?.into())
                },

                (_public, secret, _ciphertext) =>
                    self.decrypt_backend(secret, ciphertext, plaintext_len),
            }
        })
    }
}

/// Combines PQC and classical algorithms.
///
/// See [Section 4.2.1 of draft-ietf-openpgp-pqc-08].
///
/// [Section 4.2.1 of draft-ietf-openpgp-pqc-08]: https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-08.html#kem-key-combiner
pub(crate) fn multi_key_combine(mlkem_key: &[u8],
                                ecdh_key: &[u8],
                                ecdh_ciphertext: &[u8],
                                ecdh_public: &[u8],
                                pk_algo: PublicKeyAlgorithm)
                                -> Result<SessionKey>
{
    //   multiKeyCombine(
    //       mlkemKeyShare, ecdhKeyShare,
    //       ecdhCipherText, ecdhPublicKey,
    //       algId
    //   )
    //
    //   Input:
    //   mlkemKeyShare   - the ML-KEM key share encoded as an octet string
    //   ecdhKeyShare    - the ECDH key share encoded as an octet string
    //   ecdhCipherText  - the ECDH ciphertext encoded as an octet string
    //   ecdhPublicKey   - the ECDH public key of the recipient as an octet string
    //   algId           - the OpenPGP algorithm ID of the public-key encryption algorithm
    //
    // KEK = SHA3-256(
    //           mlkemKeyShare || ecdhKeyShare ||
    //           ecdhCipherText || ecdhPublicKey ||
    //           algId || domSep || len(domSep)
    //       )

    let mut hash = HashAlgorithm::SHA3_256.context()?.for_digest();
    hash.update(mlkem_key);
    hash.update(ecdh_key);
    hash.update(ecdh_ciphertext);
    hash.update(ecdh_public);
    hash.update(&[pk_algo.into()]);
    // Domain separation and length octet.
    hash.update(b"OpenPGPCompositeKDFv1\x15");

    let mut kek = SessionKey::from(vec![0; 32]);
    hash.digest(&mut kek)?;
    Ok(kek)
}
