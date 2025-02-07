//! OpenPGP v6 key packet.

use std::fmt;
use std::cmp::Ordering;
use std::hash::Hasher;
use std::time;

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::crypto::{mpi, hash::Hash, mem::Protected};
use crate::packet::key::{
    KeyParts,
    KeyRole,
    KeyRoleRT,
    PublicParts,
    SecretParts,
    UnspecifiedParts,
};
use crate::packet::prelude::*;
use crate::PublicKeyAlgorithm;
use crate::HashAlgorithm;
use crate::types::Timestamp;
use crate::Result;
use crate::crypto::Password;
use crate::KeyID;
use crate::Fingerprint;
use crate::KeyHandle;
use crate::policy::HashAlgoSecurity;

/// Holds a public key, public subkey, private key or private subkey
/// packet.
///
/// Use [`Key6::generate_rsa`] or [`Key6::generate_ecc`] to create a
/// new key.
///
/// Existing key material can be turned into an OpenPGP key using
/// [`Key6::new`], [`Key6::with_secret`], [`Key6::import_public_x25519`],
/// [`Key6::import_public_ed25519`], [`Key6::import_public_rsa`],
/// [`Key6::import_secret_x25519`], [`Key6::import_secret_ed25519`],
/// and [`Key6::import_secret_rsa`].
///
/// Whether you create a new key or import existing key material, you
/// still need to create a binding signature, and, for signing keys, a
/// back signature before integrating the key into a certificate.
///
/// Normally, you won't directly use `Key6`, but [`Key`], which is a
/// relatively thin wrapper around `Key6`.
///
/// See [Section 5.5 of RFC 4880] and [the documentation for `Key`]
/// for more details.
///
/// [Section 5.5 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.5
/// [the documentation for `Key`]: super::Key
/// [`Key`]: super::Key
#[derive(PartialEq, Eq, Hash)]
pub struct Key6<P: KeyParts, R: KeyRole> {
    pub(crate) common: Key4<P, R>,
}

// derive(Clone) doesn't work as expected with generic type parameters
// that don't implement clone: it adds a trait bound on Clone to P and
// R in the Clone implementation.  Happily, we don't need P or R to
// implement Clone: they are just marker traits, which we can clone
// manually.
//
// See: https://github.com/rust-lang/rust/issues/26925
impl<P, R> Clone for Key6<P, R>
    where P: KeyParts, R: KeyRole
{
    fn clone(&self) -> Self {
        Key6 {
            common: self.common.clone(),
        }
    }
}

impl<P, R> fmt::Debug for Key6<P, R>
where P: KeyParts,
      R: KeyRole,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Key6")
            .field("fingerprint", &self.fingerprint())
            .field("creation_time", &self.creation_time())
            .field("pk_algo", &self.pk_algo())
            .field("mpis", &self.mpis())
            .field("secret", &self.optional_secret())
            .finish()
    }
}

impl<P, R> fmt::Display for Key6<P, R>
where P: KeyParts,
      R: KeyRole,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.fingerprint())
    }
}

impl<P, R> Key6<P, R>
where P: KeyParts,
      R: KeyRole,
{
    /// The security requirements of the hash algorithm for
    /// self-signatures.
    ///
    /// A cryptographic hash algorithm usually has [three security
    /// properties]: pre-image resistance, second pre-image
    /// resistance, and collision resistance.  If an attacker can
    /// influence the signed data, then the hash algorithm needs to
    /// have both second pre-image resistance, and collision
    /// resistance.  If not, second pre-image resistance is
    /// sufficient.
    ///
    ///   [three security properties]: https://en.wikipedia.org/wiki/Cryptographic_hash_function#Properties
    ///
    /// In general, an attacker may be able to influence third-party
    /// signatures.  But direct key signatures, and binding signatures
    /// are only over data fully determined by signer.  And, an
    /// attacker's control over self signatures over User IDs is
    /// limited due to their structure.
    ///
    /// These observations can be used to extend the life of a hash
    /// algorithm after its collision resistance has been partially
    /// compromised, but not completely broken.  For more details,
    /// please refer to the documentation for [HashAlgoSecurity].
    ///
    ///   [HashAlgoSecurity]: crate::policy::HashAlgoSecurity
    pub fn hash_algo_security(&self) -> HashAlgoSecurity {
        HashAlgoSecurity::SecondPreImageResistance
    }

    /// Compares the public bits of two keys.
    ///
    /// This returns `Ordering::Equal` if the public MPIs, creation
    /// time, and algorithm of the two `Key6`s match.  This does not
    /// consider the packets' encodings, packets' tags or their secret
    /// key material.
    pub fn public_cmp<PB, RB>(&self, b: &Key6<PB, RB>) -> Ordering
    where PB: KeyParts,
          RB: KeyRole,
    {
        self.mpis().cmp(b.mpis())
            .then_with(|| self.creation_time().cmp(&b.creation_time()))
            .then_with(|| self.pk_algo().cmp(&b.pk_algo()))
    }

    /// Tests whether two keys are equal modulo their secret key
    /// material.
    ///
    /// This returns true if the public MPIs, creation time and
    /// algorithm of the two `Key6`s match.  This does not consider
    /// the packets' encodings, packets' tags or their secret key
    /// material.
    pub fn public_eq<PB, RB>(&self, b: &Key6<PB, RB>) -> bool
    where PB: KeyParts,
          RB: KeyRole,
    {
        self.public_cmp(b) == Ordering::Equal
    }

    /// Hashes everything but any secret key material into state.
    ///
    /// This is an alternate implementation of [`Hash`], which never
    /// hashes the secret key material.
    ///
    ///   [`Hash`]: std::hash::Hash
    pub fn public_hash<H>(&self, state: &mut H)
    where H: Hasher
    {
        self.common.public_hash(state);
    }
}

impl<P, R> Key6<P, R>
where
    P: KeyParts,
    R: KeyRole,
{
    /// Creates a v6 key from a v4 key.  Used internally in
    /// constructors.
    pub(crate) fn from_common(common: Key4<P, R>) -> Self {
        Key6 { common }
    }

    /// Creates an OpenPGP public key from the specified key material.
    ///
    /// This is an internal version for parse.rs that avoids going
    /// through SystemTime.
    pub(crate) fn make<T>(creation_time: T,
                          pk_algo: PublicKeyAlgorithm,
                          mpis: mpi::PublicKey,
                          secret: Option<SecretKeyMaterial>)
                          -> Result<Self>
    where
        T: Into<Timestamp>,
    {
        Ok(Key6 {
            common: Key4::make(creation_time, pk_algo, mpis, secret)?,
        })
    }

    pub(crate) fn role(&self) -> KeyRoleRT {
        self.common.role()
    }

    pub(crate) fn set_role(&mut self, role: KeyRoleRT) {
        self.common.set_role(role);
    }
}

impl<R> Key6<key::PublicParts, R>
where R: KeyRole,
{
    /// Creates an OpenPGP public key from the specified key material.
    pub fn new<T>(creation_time: T, pk_algo: PublicKeyAlgorithm,
                  mpis: mpi::PublicKey)
                  -> Result<Self>
    where T: Into<time::SystemTime>
    {
        Ok(Key6 {
            common: Key4::new(creation_time, pk_algo, mpis)?,
        })
    }

    /// Creates an OpenPGP public key packet from existing X25519 key
    /// material.
    ///
    /// The key will have its creation date set to `ctime` or the
    /// current time if `None` is given.
    pub fn import_public_x25519<T>(public_key: &[u8], ctime: T)
                                   -> Result<Self>
    where
        T: Into<Option<time::SystemTime>>,
    {
        Ok(Key6 {
            common: Key4::new(ctime.into().unwrap_or_else(crate::now),
                              PublicKeyAlgorithm::X25519,
                              mpi::PublicKey::X25519 {
                                  u: public_key.try_into()?,
                              })?,
        })
    }

    /// Creates an OpenPGP public key packet from existing X448 key
    /// material.
    ///
    /// The key will have its creation date set to `ctime` or the
    /// current time if `None` is given.
    pub fn import_public_x448<T>(public_key: &[u8], ctime: T)
                                 -> Result<Self>
    where
        T: Into<Option<time::SystemTime>>,
    {
        Ok(Key6 {
            common: Key4::new(ctime.into().unwrap_or_else(crate::now),
                              PublicKeyAlgorithm::X448,
                              mpi::PublicKey::X448 {
                                  u: Box::new(public_key.try_into()?),
                              })?,
        })
    }

    /// Creates an OpenPGP public key packet from existing Ed25519 key
    /// material.
    ///
    /// The key will have its creation date set to `ctime` or the
    /// current time if `None` is given.
    pub fn import_public_ed25519<T>(public_key: &[u8], ctime: T) -> Result<Self>
    where
        T: Into<Option<time::SystemTime>>,
    {
        Ok(Key6 {
            common: Key4::new(ctime.into().unwrap_or_else(crate::now),
                              PublicKeyAlgorithm::Ed25519,
                              mpi::PublicKey::Ed25519 {
                                  a: public_key.try_into()?,
                              })?,
        })
    }

    /// Creates an OpenPGP public key packet from existing Ed448 key
    /// material.
    ///
    /// The key will have its creation date set to `ctime` or the
    /// current time if `None` is given.
    pub fn import_public_ed448<T>(public_key: &[u8], ctime: T) -> Result<Self>
    where
        T: Into<Option<time::SystemTime>>,
    {
        Ok(Key6 {
            common: Key4::new(ctime.into().unwrap_or_else(crate::now),
                              PublicKeyAlgorithm::Ed448,
                              mpi::PublicKey::Ed448 {
                                  a: Box::new(public_key.try_into()?),
                              })?,
        })
    }

    /// Creates an OpenPGP public key packet from existing RSA key
    /// material.
    ///
    /// The RSA key will use the public exponent `e` and the modulo
    /// `n`. The key will have its creation date set to `ctime` or the
    /// current time if `None` is given.
    pub fn import_public_rsa<T>(e: &[u8], n: &[u8], ctime: T)
                                -> Result<Self> where T: Into<Option<time::SystemTime>>
    {
        Ok(Key6 {
            common: Key4::import_public_rsa(e, n, ctime)?,
        })
    }
}

impl<R> Key6<SecretParts, R>
where R: KeyRole,
{
    /// Creates an OpenPGP key packet from the specified secret key
    /// material.
    pub fn with_secret<T>(creation_time: T, pk_algo: PublicKeyAlgorithm,
                          mpis: mpi::PublicKey,
                          secret: SecretKeyMaterial)
                          -> Result<Self>
    where T: Into<time::SystemTime>
    {
        Ok(Key6 {
            common: Key4::with_secret(creation_time, pk_algo, mpis, secret)?,
        })
    }

    /// Creates a new OpenPGP secret key packet for an existing X25519
    /// key.
    ///
    /// The given `private_key` is expected to be in the native X25519
    /// representation, i.e. as opaque byte string of length 32.
    ///
    /// The key will have its creation date set to `ctime` or the
    /// current time if `None` is given.
    pub fn import_secret_x25519<T>(private_key: &[u8],
                                   ctime: T)
                                   -> Result<Self>
    where
        T: Into<Option<std::time::SystemTime>>,
    {
        use crate::crypto::backend::{Backend, interface::Asymmetric};

        let private_key = Protected::from(private_key);
        let public_key = Backend::x25519_derive_public(&private_key)?;

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::X25519,
            mpi::PublicKey::X25519 {
                u: public_key,
            },
            mpi::SecretKeyMaterial::X25519 {
                x: private_key.into(),
            }.into())
    }

    /// Creates a new OpenPGP secret key packet for an existing X448
    /// key.
    ///
    /// The given `private_key` is expected to be in the native X448
    /// representation, i.e. as opaque byte string of length 32.
    ///
    /// The key will have its creation date set to `ctime` or the
    /// current time if `None` is given.
    pub fn import_secret_x448<T>(private_key: &[u8],
                                 ctime: T)
                                 -> Result<Self>
    where
        T: Into<Option<std::time::SystemTime>>,
    {
        use crate::crypto::backend::{Backend, interface::Asymmetric};

        let private_key = Protected::from(private_key);
        let public_key = Backend::x448_derive_public(&private_key)?;

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::X448,
            mpi::PublicKey::X448 {
                u: Box::new(public_key),
            },
            mpi::SecretKeyMaterial::X448 {
                x: private_key.into(),
            }.into())
    }

    /// Creates a new OpenPGP secret key packet for an existing
    /// Ed25519 key.
    ///
    /// The key will have its creation date set to `ctime` or the
    /// current time if `None` is given.
    pub fn import_secret_ed25519<T>(private_key: &[u8], ctime: T)
                                    -> Result<Self>
    where
        T: Into<Option<time::SystemTime>>,
    {
        use crate::crypto::backend::{Backend, interface::Asymmetric};

        let private_key = Protected::from(private_key);
        let public_key = Backend::ed25519_derive_public(&private_key)?;

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::Ed25519,
            mpi::PublicKey::Ed25519 {
                a: public_key,
            },
            mpi::SecretKeyMaterial::Ed25519 {
                x: private_key.into(),
            }.into())
    }

    /// Creates a new OpenPGP secret key packet for an existing
    /// Ed448 key.
    ///
    /// The key will have its creation date set to `ctime` or the
    /// current time if `None` is given.
    pub fn import_secret_ed448<T>(private_key: &[u8], ctime: T)
                                  -> Result<Self>
    where
        T: Into<Option<time::SystemTime>>,
    {
        use crate::crypto::backend::{Backend, interface::Asymmetric};

        let private_key = Protected::from(private_key);
        let public_key = Backend::ed448_derive_public(&private_key)?;

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::Ed448,
            mpi::PublicKey::Ed448 {
                a: Box::new(public_key),
            },
            mpi::SecretKeyMaterial::Ed448 {
                x: private_key.into(),
            }.into())
    }
}

impl<P, R> Key6<P, R>
where P: KeyParts,
      R: KeyRole,
{
    /// Gets the `Key`'s creation time.
    pub fn creation_time(&self) -> time::SystemTime {
        self.common.creation_time()
    }

    /// Gets the `Key`'s creation time without converting it to a
    /// system time.
    ///
    /// This conversion may truncate the time to signed 32-bit time_t.
    pub(crate) fn creation_time_raw(&self) -> Timestamp {
        self.common.creation_time_raw()
    }

    /// Sets the `Key`'s creation time.
    ///
    /// `timestamp` is converted to OpenPGP's internal format,
    /// [`Timestamp`]: a 32-bit quantity containing the number of
    /// seconds since the Unix epoch.
    ///
    /// `timestamp` is silently rounded to match the internal
    /// resolution.  An error is returned if `timestamp` is out of
    /// range.
    ///
    /// [`Timestamp`]: crate::types::Timestamp
    pub fn set_creation_time<T>(&mut self, timestamp: T)
                                -> Result<time::SystemTime>
    where T: Into<time::SystemTime>
    {
        self.common.set_creation_time(timestamp)
    }

    /// Gets the public key algorithm.
    pub fn pk_algo(&self) -> PublicKeyAlgorithm {
        self.common.pk_algo()
    }

    /// Sets the public key algorithm.
    ///
    /// Returns the old public key algorithm.
    pub fn set_pk_algo(&mut self, pk_algo: PublicKeyAlgorithm)
                       -> PublicKeyAlgorithm
    {
        self.common.set_pk_algo(pk_algo)
    }

    /// Returns a reference to the `Key`'s MPIs.
    pub fn mpis(&self) -> &mpi::PublicKey {
        self.common.mpis()
    }

    /// Returns a mutable reference to the `Key`'s MPIs.
    pub fn mpis_mut(&mut self) -> &mut mpi::PublicKey {
        self.common.mpis_mut()
    }

    /// Sets the `Key`'s MPIs.
    ///
    /// This function returns the old MPIs, if any.
    pub fn set_mpis(&mut self, mpis: mpi::PublicKey) -> mpi::PublicKey {
        self.common.set_mpis(mpis)
    }

    /// Returns whether the `Key` contains secret key material.
    pub fn has_secret(&self) -> bool {
        self.common.has_secret()
    }

    /// Returns whether the `Key` contains unencrypted secret key
    /// material.
    ///
    /// This returns false if the `Key` doesn't contain any secret key
    /// material.
    pub fn has_unencrypted_secret(&self) -> bool {
        self.common.has_unencrypted_secret()
    }

    /// Returns `Key`'s secret key material, if any.
    pub fn optional_secret(&self) -> Option<&SecretKeyMaterial> {
        self.common.optional_secret()
    }

    /// Computes and returns the `Key`'s `Fingerprint` and returns it as
    /// a `KeyHandle`.
    ///
    /// See [Section 12.2 of RFC 4880].
    ///
    /// [Section 12.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-12.2
    pub fn key_handle(&self) -> KeyHandle {
        self.fingerprint().into()
    }

    /// Computes and returns the `Key`'s `Fingerprint`.
    ///
    /// See [Key IDs and Fingerprints].
    ///
    /// [Key IDs and Fingerprints]: https://www.rfc-editor.org/rfc/rfc9580.html#key-ids-fingerprints
    pub fn fingerprint(&self) -> Fingerprint {
        let fp = self.common.fingerprint.get_or_init(|| {
            let mut h = HashAlgorithm::SHA256.context()
                .expect("SHA256 is MTI for RFC9580")
            // v6 fingerprints are computed the same way a key is
            // hashed for v6 signatures.
                .for_signature(6);

            self.hash(&mut h).expect("v6 key hashing is infallible");

            let mut digest = [0u8; 32];
            let _ = h.digest(&mut digest);
            Fingerprint::V6(digest)
        });

        // Currently, it could happen that a Key4 has its fingerprint
        // computed, and is then converted to a Key6.  That is only
        // possible within this crate, and should not happen.  Assert
        // that.  The better way to handle this is to have a CommonKey
        // struct which both Key4 and Key6 use, so that a Key6 does
        // not start out as a Key4, preventing this issue.
        debug_assert!(matches!(fp, Fingerprint::V6(_)));

        fp.clone()
    }

    /// Computes and returns the `Key`'s `Key ID`.
    ///
    /// See [Section 12.2 of RFC 4880].
    ///
    /// [Section 12.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-12.2
    pub fn keyid(&self) -> KeyID {
        self.fingerprint().into()
    }
}

macro_rules! impl_common_secret_functions_v6 {
    ($t: ident) => {
        /// Secret key material handling.
        impl<R> Key6<$t, R>
        where R: KeyRole,
        {
            /// Takes the `Key`'s `SecretKeyMaterial`, if any.
            pub fn take_secret(mut self)
                               -> (Key6<PublicParts, R>, Option<SecretKeyMaterial>)
            {
                let old = std::mem::replace(&mut self.common.secret, None);
                (self.parts_into_public(), old)
            }

            /// Adds the secret key material to the `Key`, returning
            /// the old secret key material, if any.
            pub fn add_secret(mut self, secret: SecretKeyMaterial)
                              -> (Key6<SecretParts, R>, Option<SecretKeyMaterial>)
            {
                let old = std::mem::replace(&mut self.common.secret, Some(secret));
                (self.parts_into_secret().expect("secret just set"), old)
            }

            /// Takes the `Key`'s `SecretKeyMaterial`, if any.
            pub fn steal_secret(&mut self) -> Option<SecretKeyMaterial>
            {
                std::mem::replace(&mut self.common.secret, None)
            }
        }
    }
}
impl_common_secret_functions_v6!(PublicParts);
impl_common_secret_functions_v6!(UnspecifiedParts);

/// Secret key handling.
impl<R> Key6<SecretParts, R>
where R: KeyRole,
{
    /// Gets the `Key`'s `SecretKeyMaterial`.
    pub fn secret(&self) -> &SecretKeyMaterial {
        self.common.secret()
    }

    /// Gets a mutable reference to the `Key`'s `SecretKeyMaterial`.
    pub fn secret_mut(&mut self) -> &mut SecretKeyMaterial {
        self.common.secret_mut()
    }

    /// Takes the `Key`'s `SecretKeyMaterial`.
    pub fn take_secret(mut self)
                       -> (Key6<PublicParts, R>, SecretKeyMaterial)
    {
        let old = std::mem::replace(&mut self.common.secret, None);
        (self.parts_into_public(),
         old.expect("Key<SecretParts, _> has a secret key material"))
    }

    /// Adds `SecretKeyMaterial` to the `Key`.
    ///
    /// This function returns the old secret key material, if any.
    pub fn add_secret(mut self, secret: SecretKeyMaterial)
                      -> (Key6<SecretParts, R>, SecretKeyMaterial)
    {
        let old = std::mem::replace(&mut self.common.secret, Some(secret));
        (self.parts_into_secret().expect("secret just set"),
         old.expect("Key<SecretParts, _> has a secret key material"))
    }

    /// Decrypts the secret key material using `password`.
    ///
    /// In OpenPGP, secret key material can be [protected with a
    /// password].  The password is usually hardened using a [KDF].
    ///
    /// Refer to the documentation of [`Key::decrypt_secret`] for
    /// details.
    ///
    /// This function returns an error if the secret key material is
    /// not encrypted or the password is incorrect.
    ///
    /// [protected with a password]: https://tools.ietf.org/html/rfc4880#section-5.5.3
    /// [KDF]: https://tools.ietf.org/html/rfc4880#section-3.7
    /// [`Key::decrypt_secret`]: super::Key::decrypt_secret()
    pub fn decrypt_secret(mut self, password: &Password) -> Result<Self> {
        self.common = self.common.decrypt_secret(password)?;
        Ok(self)
    }

    /// Encrypts the secret key material using `password`.
    ///
    /// In OpenPGP, secret key material can be [protected with a
    /// password].  The password is usually hardened using a [KDF].
    ///
    /// Refer to the documentation of [`Key::encrypt_secret`] for
    /// details.
    ///
    /// This returns an error if the secret key material is already
    /// encrypted.
    ///
    /// [protected with a password]: https://tools.ietf.org/html/rfc4880#section-5.5.3
    /// [KDF]: https://tools.ietf.org/html/rfc4880#section-3.7
    /// [`Key::encrypt_secret`]: super::Key::encrypt_secret()
    pub fn encrypt_secret(mut self, password: &Password)
                          -> Result<Key6<SecretParts, R>>
    {
        self.common = self.common.encrypt_secret(password)?;
        Ok(self)
    }
}

impl<P, R> From<Key6<P, R>> for super::Key<P, R>
where P: KeyParts,
      R: KeyRole,
{
    fn from(p: Key6<P, R>) -> Self {
        super::Key::V6(p)
    }
}

#[cfg(test)]
use crate::packet::key::{
    PrimaryRole,
    SubordinateRole,
    UnspecifiedRole,
};

#[cfg(test)]
impl Arbitrary for Key6<PublicParts, PrimaryRole> {
    fn arbitrary(g: &mut Gen) -> Self {
        Key6::from_common(Key4::arbitrary(g))
    }
}

#[cfg(test)]
impl Arbitrary for Key6<PublicParts, SubordinateRole> {
    fn arbitrary(g: &mut Gen) -> Self {
        Key6::from_common(Key4::arbitrary(g))
    }
}

#[cfg(test)]
impl Arbitrary for Key6<PublicParts, UnspecifiedRole> {
    fn arbitrary(g: &mut Gen) -> Self {
        Key6::from_common(Key4::arbitrary(g))
    }
}

#[cfg(test)]
impl Arbitrary for Key6<SecretParts, PrimaryRole> {
    fn arbitrary(g: &mut Gen) -> Self {
        Key6::from_common(Key4::arbitrary(g))
    }
}

#[cfg(test)]
impl Arbitrary for Key6<SecretParts, SubordinateRole> {
    fn arbitrary(g: &mut Gen) -> Self {
        Key6::from_common(Key4::arbitrary(g))
    }
}
