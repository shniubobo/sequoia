//! Elliptic Curve Diffie-Hellman.
use std::convert::{TryFrom, TryInto};

use crate::crypto::ecdh::{decrypt_unwrap, encrypt_wrap};
use crate::crypto::mpi;
use crate::crypto::mpi::{Ciphertext, SecretKeyMaterial};
use crate::crypto::SessionKey;
use crate::packet::{key, Key};
use crate::types::Curve;
use crate::{Error, Result};

use openssl::bn::BigNum;
use openssl::derive::Deriver;
use openssl::ossl_param::OsslParamBuilder;
use openssl::pkey::PKey;
use openssl::pkey_ctx::PkeyCtx;
use openssl::nid::Nid;

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

    let nid: Nid = curve.try_into()?;

    let mut bld = OsslParamBuilder::new()?;
    bld.add_utf8_string("group\0", nid.short_name()?)?;
    bld.add_octet_string("pub\0", q.value())?;
    let params = bld.to_params()?;
    let mut ctx = PkeyCtx::new_from_name(None, "EC", None)?;
    ctx.fromdata_init()?;
    let recipient_key = PKey::<openssl::pkey::Public>::fromdata(ctx, params)?;

    let key = PKey::<openssl::pkey::Private>::ec_gen(nid.short_name()?)?;
    let params = key.todata(0x87)?; // FIXME magic number

    let pubkey = params.locate("pub\0")?.get_octet_string()?;
    let q = mpi::MPI::new(pubkey);

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

    let nid: Nid = curve.try_into()?;

    let privkey = BigNum::from_slice(scalar.value())?;
    let mut bld = OsslParamBuilder::new()?;
    bld.add_utf8_string("group\0", nid.short_name()?)?;
    bld.add_octet_string("pub\0", q.value())?;
    bld.add_bn("priv\0", &privkey)?;
    let params = bld.to_params()?;
    let mut ctx = PkeyCtx::new_from_name(None, "EC", None)?;
    ctx.fromdata_init()?;
    let key = PKey::<openssl::pkey::Private>::fromdata(ctx, params)?;

    let mut bld = OsslParamBuilder::new()?;
    bld.add_utf8_string("group\0", nid.short_name()?)?;
    bld.add_octet_string("pub\0", e.value())?;
    let params = bld.to_params()?;
    let mut ctx = PkeyCtx::new_from_name(None, "EC", None)?;
    ctx.fromdata_init()?;
    let recipient_key = PKey::<openssl::pkey::Public>::fromdata(ctx, params)?;

    let key = PKey::<_>::try_from(key)?;
    let mut deriver = Deriver::new(&key)?;
    deriver.set_peer(&recipient_key)?;
    let secret = deriver.derive_to_vec()?.into();

    decrypt_unwrap(recipient.role_as_unspecified(), &secret, ciphertext,
                   plaintext_len)
}
