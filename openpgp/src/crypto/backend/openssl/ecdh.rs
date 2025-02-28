//! Elliptic Curve Diffie-Hellman.
use std::convert::TryInto;

use crate::crypto::ecdh::{decrypt_unwrap, encrypt_wrap};
use crate::crypto::mpi;
use crate::crypto::mpi::{Ciphertext, SecretKeyMaterial};
use crate::crypto::SessionKey;
use crate::packet::{key, Key};
use crate::types::Curve;
use crate::{Error, Result};

use openssl::bn::BigNum;
use openssl::derive::Deriver;
use openssl::pkey::PKey;
use openssl::pkey_ecdsa::{PKeyEcdsaBuilder, PKeyEcdsaParams};

/// Wraps a session key using Elliptic Curve Diffie-Hellman.
pub fn encrypt<R>(
    recipient: &Key<key::PublicParts, R>,
    session_key: &SessionKey,
) -> Result<Ciphertext>
where
    R: key::KeyRole,
{
    let (curve, q) = match recipient.mpis() {
        mpi::PublicKey::ECDH { curve, q, .. } => (curve, q),
        _ => return Err(Error::InvalidArgument("Expected an ECDHPublicKey".into()).into()),
    };
    if curve == &Curve::Cv25519 {
        return Err(Error::InvalidArgument("implemented elsewhere".into()).into());
    }

    let recipient_key = PKeyEcdsaBuilder::<openssl::pkey::Public>::new(
            curve.try_into()?,
            q.value(),
            None
        )?
        .build()?;

    let key = PKey::<openssl::pkey::Private>::ec_gen(curve.try_into()?)?;
    let params = PKeyEcdsaParams::<openssl::pkey::Private>::from_pkey(&key)?;

    let q = mpi::MPI::new(params.public_key()?);

    let mut deriver = Deriver::new(&key)?;
    deriver.set_peer(&recipient_key)?;

    let secret = deriver.derive_to_vec()?.into();

    encrypt_wrap(recipient, session_key, q, &secret)
}

/// Unwraps a session key using Elliptic Curve Diffie-Hellman.
pub fn decrypt<R>(
    recipient: &Key<key::PublicParts, R>,
    recipient_sec: &SecretKeyMaterial,
    ciphertext: &Ciphertext,
    plaintext_len: Option<usize>,
) -> Result<SessionKey>
where
    R: key::KeyRole,
{
    let (curve, scalar, e, q) = match (recipient.mpis(), recipient_sec, ciphertext) {
        (
            mpi::PublicKey::ECDH {
                ref curve, ref q, ..
            },
            SecretKeyMaterial::ECDH { ref scalar },
            Ciphertext::ECDH { ref e, .. },
        ) => (curve, scalar, e, q),
        _ => return Err(Error::InvalidArgument("Expected an ECDHPublicKey".into()).into()),
    };

    if curve == &Curve::Cv25519 {
        return Err(Error::InvalidArgument("implemented elsewhere".into()).into());
    }

    let b_scalar: BigNum = scalar.try_into()?;
    let key = PKeyEcdsaBuilder::<openssl::pkey::Private>::new(
            curve.try_into()?,
            q.value(),
            Some(&b_scalar)
        )?
        .build()?;

    let recipient_key = PKeyEcdsaBuilder::<openssl::pkey::Public>::new(
            curve.try_into()?,
            e.value(),
            None
        )?
        .build()?;

    let mut deriver = Deriver::new(&key)?;
    deriver.set_peer(&recipient_key)?;
    let secret = deriver.derive_to_vec()?.into();

    decrypt_unwrap(recipient.role_as_unspecified(), &secret, ciphertext,
                   plaintext_len)
}
