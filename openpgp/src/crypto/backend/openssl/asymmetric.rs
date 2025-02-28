use crate::{Error, Result};

use crate::crypto::asymmetric::KeyPair;
use crate::crypto::backend::interface::Asymmetric;
use crate::crypto::mpi;
use crate::crypto::mpi::{ProtectedMPI, MPI};
use crate::crypto::mem::Protected;
use crate::crypto::SessionKey;
use crate::packet::key::{Key4, SecretParts};
use crate::packet::{key, Key};
use crate::types::{Curve, HashAlgorithm, PublicKeyAlgorithm};
use std::convert::{TryFrom, TryInto};
use std::time::SystemTime;

use openssl::bn::{BigNum, BigNumRef, BigNumContext};
use openssl::derive::Deriver;
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::ossl_param::OsslParamBuilder;
use openssl::pkey_ctx::PkeyCtx;
use openssl::rsa::{Padding};
use openssl::sign::Signer as OpenSslSigner;
use openssl::sign::Verifier;

impl Asymmetric for super::Backend {
    fn supports_algo(algo: PublicKeyAlgorithm) -> bool {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match algo {
            X25519 | Ed25519 |
            X448 | Ed448 |
            RSAEncryptSign | RSAEncrypt | RSASign => true,
            DSA => true,
            ECDH | ECDSA | EdDSA => true,
            ElGamalEncrypt | ElGamalEncryptSign |
            Private(_) | Unknown(_)
                => false,
        }
    }

    fn supports_curve(curve: &Curve) -> bool {
        if matches!(curve, Curve::Ed25519 | Curve::Cv25519) {
            // 25519-based algorithms are special-cased and supported
            true
        } else {
            // the rest of EC algorithms are supported via the same
            // codepath
            if let Ok(nid) = openssl::nid::Nid::try_from(curve) {
                openssl::ec::EcGroup::from_curve_name(nid).is_ok()
            } else {
                false
            }
        }
    }

    fn x25519_generate_key() -> Result<(Protected, [u8; 32])> {
        let pair = openssl::pkey::PKey::generate_x25519()?;
        Ok((pair.raw_private_key()?.into(),
            pair.raw_public_key()?.as_slice().try_into()?))
    }

    fn x25519_derive_public(secret: &Protected) -> Result<[u8; 32]> {
        let key = PKey::private_key_from_raw_bytes(
            secret, openssl::pkey::Id::X25519)?;
        Ok(key.raw_public_key()?.as_slice().try_into()?)
    }

    fn x25519_shared_point(secret: &Protected, public: &[u8; 32])
                           -> Result<Protected> {
        let public = PKey::public_key_from_raw_bytes(
            public, openssl::pkey::Id::X25519)?;
        let secret = PKey::private_key_from_raw_bytes(
            secret, openssl::pkey::Id::X25519)?;

        let mut deriver = Deriver::new(&secret)?;
        deriver.set_peer(&public)?;
        Ok(deriver.derive_to_vec()?.into())
    }

    fn x448_generate_key() -> Result<(Protected, [u8; 56])> {
        let pair = openssl::pkey::PKey::generate_x448()?;
        Ok((pair.raw_private_key()?.into(),
            pair.raw_public_key()?.as_slice().try_into()?))
    }

    fn x448_derive_public(secret: &Protected) -> Result<[u8; 56]> {
        let key = PKey::private_key_from_raw_bytes(
            secret, openssl::pkey::Id::X448)?;
        Ok(key.raw_public_key()?.as_slice().try_into()?)
    }

    fn x448_shared_point(secret: &Protected, public: &[u8; 56])
                           -> Result<Protected> {
        let public = PKey::public_key_from_raw_bytes(
            public, openssl::pkey::Id::X448)?;
        let secret = PKey::private_key_from_raw_bytes(
            secret, openssl::pkey::Id::X448)?;

        let mut deriver = Deriver::new(&secret)?;
        deriver.set_peer(&public)?;
        Ok(deriver.derive_to_vec()?.into())
    }

    fn ed25519_generate_key() -> Result<(Protected, [u8; 32])> {
        let pair = openssl::pkey::PKey::generate_ed25519()?;
        Ok((pair.raw_private_key()?.into(),
            pair.raw_public_key()?.as_slice().try_into()?))
    }

    fn ed25519_derive_public(secret: &Protected) -> Result<[u8; 32]> {
        let key = PKey::private_key_from_raw_bytes(
            secret, openssl::pkey::Id::ED25519)?;
        Ok(key.raw_public_key()?.as_slice().try_into()?)
    }

    fn ed25519_sign(secret: &Protected, _public: &[u8; 32], digest: &[u8])
                    -> Result<[u8; 64]> {
        let key = PKey::private_key_from_raw_bytes(
            secret, openssl::pkey::Id::ED25519)?;

        let mut signer = OpenSslSigner::new_without_digest(&key)?;
        Ok(signer.sign_oneshot_to_vec(digest)?.as_slice().try_into()?)
    }

    fn ed25519_verify(public: &[u8; 32], digest: &[u8], signature: &[u8; 64])
                      -> Result<bool> {
        let key = PKey::public_key_from_raw_bytes(
            public, openssl::pkey::Id::ED25519)?;
        let mut verifier = Verifier::new_without_digest(&key)?;
        Ok(verifier.verify_oneshot(signature, digest)?)
    }

    fn ed448_generate_key() -> Result<(Protected, [u8; 57])> {
        let pair = openssl::pkey::PKey::generate_ed448()?;
        Ok((pair.raw_private_key()?.into(),
            pair.raw_public_key()?.as_slice().try_into()?))
    }

    fn ed448_derive_public(secret: &Protected) -> Result<[u8; 57]> {
        let key = PKey::private_key_from_raw_bytes(
            secret, openssl::pkey::Id::ED448)?;
        Ok(key.raw_public_key()?.as_slice().try_into()?)
    }

    fn ed448_sign(secret: &Protected, _public: &[u8; 57], digest: &[u8])
                    -> Result<[u8; 114]> {
        let key = PKey::private_key_from_raw_bytes(
            secret, openssl::pkey::Id::ED448)?;

        let mut signer = OpenSslSigner::new_without_digest(&key)?;
        Ok(signer.sign_oneshot_to_vec(digest)?.as_slice().try_into()?)
    }

    fn ed448_verify(public: &[u8; 57], digest: &[u8], signature: &[u8; 114])
                      -> Result<bool> {
        let key = PKey::public_key_from_raw_bytes(
            public, openssl::pkey::Id::ED448)?;
        let mut verifier = Verifier::new_without_digest(&key)?;
        Ok(verifier.verify_oneshot(signature, digest)?)
    }

    fn dsa_generate_key(p_bits: usize)
                        -> Result<(MPI, MPI, MPI, MPI, ProtectedMPI)>
    {
        use openssl::dsa::*;
        let key = Dsa::<openssl::pkey::Private>::generate(p_bits.try_into()?)?;
        Ok((key.p().into(), key.q().into(), key.g().into(),
            key.pub_key().into(), key.priv_key().into()))
    }
}

impl TryFrom<&ProtectedMPI> for BigNum {
    type Error = anyhow::Error;
    fn try_from(mpi: &ProtectedMPI) -> std::result::Result<BigNum, anyhow::Error> {
        let mut bn = BigNum::new_secure()?;
        bn.copy_from_slice(mpi.value())?;
        Ok(bn)
    }
}

impl From<&BigNumRef> for ProtectedMPI {
    fn from(bn: &BigNumRef) -> Self {
        bn.to_vec().into()
    }
}

impl From<BigNum> for ProtectedMPI {
    fn from(bn: BigNum) -> Self {
        bn.to_vec().into()
    }
}

impl From<BigNum> for MPI {
    fn from(bn: BigNum) -> Self {
        bn.to_vec().into()
    }
}

impl TryFrom<&MPI> for BigNum {
    type Error = anyhow::Error;
    fn try_from(mpi: &MPI) -> std::result::Result<BigNum, anyhow::Error> {
        Ok(BigNum::from_slice(mpi.value())?)
    }
}

impl From<&BigNumRef> for MPI {
    fn from(bn: &BigNumRef) -> Self {
        bn.to_vec().into()
    }
}

impl TryFrom<&Curve> for Nid {
    type Error = crate::Error;
    fn try_from(curve: &Curve) -> std::result::Result<Nid, crate::Error> {
        Ok(match curve {
            Curve::NistP256 => Nid::X9_62_PRIME256V1,
            Curve::NistP384 => Nid::SECP384R1,
            Curve::NistP521 => Nid::SECP521R1,
            Curve::BrainpoolP256 => Nid::BRAINPOOL_P256R1,
            Curve::BrainpoolP384 => Nid::BRAINPOOL_P384R1,
            Curve::BrainpoolP512 => Nid::BRAINPOOL_P512R1,
            Curve::Ed25519 | // Handled differently.
            Curve::Cv25519 | // Handled differently.
            Curve::Unknown(_) =>
                return Err(crate::Error::UnsupportedEllipticCurve(curve.clone()).into()),
        })
    }
}

impl KeyPair {
    pub(crate) fn sign_backend(&self,
                               secret: &mpi::SecretKeyMaterial,
                               hash_algo: HashAlgorithm,
                               digest: &[u8])
                               -> Result<mpi::Signature>
    {
        use crate::PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match (self.public().pk_algo(), self.public().mpis(), secret) {
                (
                    RSAEncryptSign,
                    mpi::PublicKey::RSA { e, n },
                    mpi::SecretKeyMaterial::RSA { p, q, d, .. },
                )
                | (
                    RSASign,
                    mpi::PublicKey::RSA { e, n },
                    mpi::SecretKeyMaterial::RSA { p, q, d, .. },
                ) => {
                    let n = BigNum::from_slice(n.value())?;
                    let e = BigNum::from_slice(e.value())?;
                    let d = BigNum::from_slice(d.value())?;
                    let p = BigNum::from_slice(p.value())?;
                    let q = BigNum::from_slice(q.value())?;

                    let mut bld = OsslParamBuilder::new()?;
                    bld.add_bn("n\0", &n)?;
                    bld.add_bn("e\0", &e)?;
                    bld.add_bn("d\0", &d)?;
                    bld.add_bn("rsa-factor1\0", &p)?;
                    bld.add_bn("rsa-factor2\0", &q)?;
                    let params = bld.to_params()?;
                    let mut ctx = PkeyCtx::new_from_name(None, "RSA", None)?;
                    ctx.fromdata_init()?;
                    let key = PKey::<openssl::pkey::Private>::fromdata(ctx, params)?;

                    let mut signature: Vec<u8> = vec![];

                    const MAX_OID_SIZE: usize = 20;
                    let mut v = Vec::with_capacity(MAX_OID_SIZE + digest.len());
                    v.extend(hash_algo.oid()?);
                    v.extend(digest);

                    let mut ctx = PkeyCtx::new(&key)?;
                    ctx.sign_init()?;
                    ctx.sign_to_vec(&v, &mut signature)?;

                    Ok(mpi::Signature::RSA {
                        s: signature.into(),
                    })
                }
                (
                    PublicKeyAlgorithm::DSA,
                    mpi::PublicKey::DSA { p, q, g, y },
                    mpi::SecretKeyMaterial::DSA { x },
                ) => {
                    use openssl::dsa::DsaSig;

                    let p = BigNum::from_slice(p.value())?;
                    let q = BigNum::from_slice(q.value())?;
                    let g = BigNum::from_slice(g.value())?;
                    let x = BigNum::from_slice(x.value())?;
                    let y = BigNum::from_slice(y.value())?;

                    let mut bld = OsslParamBuilder::new()?;
                    bld.add_bn("p\0", &p)?;
                    bld.add_bn("q\0", &q)?;
                    bld.add_bn("g\0", &g)?;
                    bld.add_bn("priv\0", &x)?;
                    bld.add_bn("pub\0", &y)?;
                    let params = bld.to_params()?;
                    let mut ctx = PkeyCtx::new_from_name(None, "DSA", None)?;
                    ctx.fromdata_init()?;
                    let key = PKey::<openssl::pkey::Private>::fromdata(ctx, params)?;

                    let mut ctx = PkeyCtx::new(&key)?;
                    ctx.sign_init()?;
                    let mut signature = vec![];
                    ctx.sign_to_vec(&digest, &mut signature)?;
                    let signature = DsaSig::from_der(&signature)?;

                    Ok(mpi::Signature::DSA {
                        r: signature.r().to_vec().into(),
                        s: signature.s().to_vec().into(),
                    })
                }
                (
                    PublicKeyAlgorithm::ECDSA,
                    mpi::PublicKey::ECDSA { curve, q },
                    mpi::SecretKeyMaterial::ECDSA { scalar },
                ) => {
                    let nid: Nid = curve.try_into()?;
                    let privkey = BigNum::from_slice(scalar.value())?;

                    let mut bld = OsslParamBuilder::new()?;
                    bld.add_utf8_string("group\0", nid.short_name()?)?;
                    bld.add_octet_string("pub\0", q.value())?;
                    bld.add_bn("priv\0", &privkey)?;
                    let params = bld.to_params()?;
                    let mut ctx = PkeyCtx::new_from_name(None, "EC", None)?;
                    ctx.fromdata_init().unwrap();
                    let key = PKey::<openssl::pkey::Private>::fromdata(ctx, params)?;

                    let mut ctx = PkeyCtx::new(&key)?;
                    ctx.sign_init()?;
                    let mut signature: Vec<u8> = vec![];
                    ctx.sign_to_vec(&digest, &mut signature)?;

                    let sig = EcdsaSig::from_der(&signature)?;

                    Ok(mpi::Signature::ECDSA {
                        r: sig.r().into(),
                        s: sig.s().into(),
                    })
                }

                (pk_algo, _, _) => Err(crate::Error::InvalidOperation(format!(
                    "unsupported combination of algorithm {:?}, key {:?}, \
                        and secret key {:?} by OpenSSL backend",
                    pk_algo,
                    self.public(),
                    self.secret()
                ))
                .into()),
        }
    }
}

impl KeyPair {
    pub(crate) fn decrypt_backend(
        &self,
        secret: &mpi::SecretKeyMaterial,
        ciphertext: &mpi::Ciphertext,
        plaintext_len: Option<usize>,
    ) -> Result<SessionKey> {
        use crate::crypto::mpi::PublicKey;

        Ok(match (self.public().mpis(), secret, ciphertext) {
                (
                    PublicKey::RSA { ref e, ref n },
                    mpi::SecretKeyMaterial::RSA {
                        ref p,
                        ref q,
                        ref d,
                        ..
                    },
                    mpi::Ciphertext::RSA { ref c },
                ) => {
                    let n = BigNum::from_slice(n.value())?;
                    let e = BigNum::from_slice(e.value())?;
                    let d = BigNum::from_slice(d.value())?;
                    let p = BigNum::from_slice(p.value())?;
                    let q = BigNum::from_slice(q.value())?;

                    let mut bld = OsslParamBuilder::new()?;
                    bld.add_bn("n\0", &n)?;
                    bld.add_bn("e\0", &e)?;
                    bld.add_bn("d\0", &d)?;
                    bld.add_bn("rsa-factor1\0", &p)?;
                    bld.add_bn("rsa-factor2\0", &q)?;
                    let params = bld.to_params()?;
                    let mut ctx = PkeyCtx::new_from_name(None, "RSA", None)?;
                    ctx.fromdata_init()?;
                    let key = PKey::<openssl::pkey::Private>::fromdata(ctx, params)?;

                    let mut ctx = PkeyCtx::new(&key)?;
                    ctx.decrypt_init()?;
                    ctx.set_rsa_padding(Padding::PKCS1)?;
                    let mut buf: Protected = vec![0; key.size().try_into()?].into();
                    let encrypted_len = ctx.decrypt(c.value(), Some(&mut buf))?;
                    buf[..encrypted_len].into()
                }

                (
                    PublicKey::ECDH { .. },
                    mpi::SecretKeyMaterial::ECDH { .. },
                    mpi::Ciphertext::ECDH { .. },
                ) => crate::crypto::ecdh::decrypt(self.public(), secret,
                                                  ciphertext,
                                                  plaintext_len)?,

                (public, secret, ciphertext) => {
                    return Err(crate::Error::InvalidOperation(format!(
                        "unsupported combination of key pair {:?}/{:?} \
                     and ciphertext {:?}",
                        public, secret, ciphertext
                    ))
                    .into())
                }
        })
    }
}

impl<P: key::KeyParts, R: key::KeyRole> Key<P, R> {
    /// Encrypts the given data with this key.
    pub(crate) fn encrypt_backend(&self, data: &SessionKey) -> Result<mpi::Ciphertext> {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match self.pk_algo() {
            RSAEncryptSign | RSAEncrypt => match self.mpis() {
                mpi::PublicKey::RSA { e, n } => {
                    // The ciphertext has the length of the modulus.
                    let ciphertext_len = n.value().len();
                    if data.len() + 11 > ciphertext_len {
                        return Err(crate::Error::InvalidArgument(
                            "Plaintext data too large".into(),
                        )
                        .into());
                    }

                    let e = BigNum::from_slice(e.value())?;
                    let n = BigNum::from_slice(n.value())?;

                    let mut bld = OsslParamBuilder::new()?;
                    bld.add_bn("n\0", &n)?;
                    bld.add_bn("e\0", &e)?;
                    let params = bld.to_params()?;
                    let mut ctx = PkeyCtx::new_from_name(None, "RSA", None)?;
                    ctx.fromdata_init()?;
                    let key = PKey::<openssl::pkey::Public>::fromdata(ctx, params)?;

                    // The ciphertext has the length of the modulus.
                    let mut buf = vec![0; key.size().try_into()?];

                    let mut ctx = PkeyCtx::new(&key)?;
                    ctx.encrypt_init()?;
                    ctx.set_rsa_padding(Padding::PKCS1)?;
                    ctx.encrypt_to_vec(data, &mut buf)?;

                    Ok(mpi::Ciphertext::RSA {
                        c: buf.into(),
                    })
                }
                pk => Err(crate::Error::MalformedPacket(format!(
                    "Key: Expected RSA public key, got {:?}",
                    pk
                ))
                .into()),
            },

            ECDH => crate::crypto::ecdh::encrypt(self.parts_as_public(), data),

            RSASign | DSA | ECDSA | EdDSA | Ed25519 | Ed448 =>
                Err(Error::InvalidOperation(
                    format!("{} is not an encryption algorithm", self.pk_algo())
                ).into()),

            ElGamalEncrypt | ElGamalEncryptSign |
            X25519 | X448 |
            Private(_) | Unknown(_) =>
                Err(Error::UnsupportedPublicKeyAlgorithm(self.pk_algo()).into()),
        }
    }

    /// Verifies the given signature.
    pub(crate) fn verify_backend(
        &self,
        sig: &mpi::Signature,
        hash_algo: HashAlgorithm,
        digest: &[u8],
    ) -> Result<()> {
        let ok = match (self.mpis(), sig) {
            (mpi::PublicKey::RSA { e, n }, mpi::Signature::RSA { s }) => {
                let e = BigNum::from_slice(e.value())?;
                let n = BigNum::from_slice(n.value())?;

               let mut bld = OsslParamBuilder::new()?;
               bld.add_bn("n\0", &n)?;
               bld.add_bn("e\0", &e)?;
               let params = bld.to_params()?;
               let mut ctx = PkeyCtx::new_from_name(None, "RSA", None)?;
               ctx.fromdata_init()?;
               let key = PKey::<openssl::pkey::Public>::fromdata(ctx, params)?;

                let signature = s.value();
                let mut v = vec![];
                v.extend(hash_algo.oid()?);
                v.extend(digest);

                let mut ctx = PkeyCtx::new(&key)?;
                ctx.verify_init()?;
                ctx.verify(&v, signature)?
            }
            (mpi::PublicKey::DSA { p, q, g, y }, mpi::Signature::DSA { r, s }) => {
                use openssl::dsa::DsaSig;

                let p = BigNum::from_slice(p.value())?;
                let q = BigNum::from_slice(q.value())?;
                let g = BigNum::from_slice(g.value())?;
                let y = BigNum::from_slice(y.value())?;

                let mut bld = OsslParamBuilder::new()?;
                bld.add_bn("p\0", &p)?;
                bld.add_bn("q\0", &q)?;
                bld.add_bn("g\0", &g)?;
                bld.add_bn("pub\0", &y)?;
                let params = bld.to_params()?;
                let mut ctx = PkeyCtx::new_from_name(None, "DSA", None)?;
                ctx.fromdata_init()?;
                let key = PKey::<openssl::pkey::Public>::fromdata(ctx, params)?;

                let r = r.try_into()?;
                let s = s.try_into()?;
                let signature = DsaSig::from_private_components(r, s)?;
                let mut ctx = PkeyCtx::new(&key)?;
                ctx.verify_init()?;
                ctx.verify(&digest, &signature.to_der()?)?
            }
            (mpi::PublicKey::ECDSA { curve, q }, mpi::Signature::ECDSA { s, r }) => {
                let nid: Nid = curve.try_into()?;

                let mut bld = OsslParamBuilder::new()?;
                bld.add_utf8_string("group\0", nid.short_name()?)?;
                bld.add_octet_string("pub\0", q.value())?;
                let params = bld.to_params().unwrap();
                let mut ctx = PkeyCtx::new_from_name(None, "EC", None)?;
                ctx.fromdata_init().unwrap();
                let key = PKey::<openssl::pkey::Public>::fromdata(ctx, params)?;

                let sig = EcdsaSig::from_private_components(
                    r.try_into()?,
                    s.try_into()?,
                )?;

                let mut ctx = PkeyCtx::new(&key)?;
                ctx.verify_init()?;
                ctx.verify(digest, &sig.to_der()?)?
            }
            _ => {
                return Err(crate::Error::MalformedPacket(format!(
                    "unsupported combination of key {} and signature {:?}.",
                    self.pk_algo(),
                    sig
                ))
                .into())
            }
        };

        if ok {
            Ok(())
        } else {
            Err(crate::Error::ManipulatedMessage.into())
        }
    }
}

impl<R> Key4<SecretParts, R>
where
    R: key::KeyRole,
{
    /// Creates a new OpenPGP public key packet for an existing RSA key.
    ///
    /// The RSA key will use public exponent `e` and modulo `n`. The key will
    /// have its creation date set to `ctime` or the current time if `None`
    /// is given.
    pub fn import_secret_rsa<T>(d: &[u8], p: &[u8], q: &[u8], ctime: T) -> Result<Self>
    where
        T: Into<Option<SystemTime>>,
    {
        // RFC 4880: `p < q`
        let (p, q) = crate::crypto::rsa_sort_raw_pq(p, q);

        let mut big_p = BigNum::new_secure()?;
        big_p.copy_from_slice(p)?;
        let mut big_q = BigNum::new_secure()?;
        big_q.copy_from_slice(q)?;
        let n = &big_p * &big_q;

        let mut one = BigNum::new_secure()?;
        one.copy_from_slice(&[1])?;
        let big_phi = &(&big_p - &one) * &(&big_q - &one);

        let mut ctx = BigNumContext::new_secure()?;

        let mut e = BigNum::new_secure()?;
        let mut d_bn = BigNum::new_secure()?;
        d_bn.copy_from_slice(d)?;
        e.mod_inverse(&d_bn, &big_phi, &mut ctx)?; // e ≡ d⁻¹ (mod 𝜙)

        let mut u = BigNum::new_secure()?;
        u.mod_inverse(&big_p, &big_q, &mut ctx)?; // RFC 4880: u ≡ p⁻¹ (mod q)

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::RSAEncryptSign,
            mpi::PublicKey::RSA {
                e: e.into(),
                n: n.into(),
            },
            mpi::SecretKeyMaterial::RSA {
                d: d_bn.into(),
                p: p.into(),
                q: q.into(),
                u: u.into(),
            }
            .into(),
        )
    }

    /// Generates a new RSA key with a public modulus of size `bits`.
    pub fn generate_rsa(bits: usize) -> Result<Self> {
        let mut ctx = PkeyCtx::new_from_name(None, "RSA", None)?;
        ctx.keygen_init()?;

        let mut bld = OsslParamBuilder::new()?;
        bld.add_uint("bits\0", bits.try_into()?)?;
        let params = bld.to_params()?;
        ctx.set_params(params)?;
        let key = ctx.generate()?;

        let params = key.todata(0x87)?; // FIXME magic number
        let e = params.locate("e\0")?.get_bn()?;
        let n = params.locate("n\0")?.get_bn()?;
        let d = params.locate("d\0")?.get_bn()?;
        let p = params.locate("rsa-factor1\0")?.get_bn()?;
        let q = params.locate("rsa-factor2\0")?.get_bn()?;

        // RFC 4880: `p < q`
        let (p, q) = rsa_sort_pq(p, q);

        let mut ctx = BigNumContext::new_secure()?;
        let mut u = BigNum::new_secure()?;
        u.mod_inverse(p, q, &mut ctx)?;

        Self::with_secret(
            crate::now(),
            PublicKeyAlgorithm::RSAEncryptSign,
            mpi::PublicKey::RSA {
                e: e.into(),
                n: n.into(),
            },
            mpi::SecretKeyMaterial::RSA {
                d: d.into(),
                p: p.into(),
                q: q.into(),
                u: u.into(),
            }
            .into(),
        )
    }

    /// Generates a new ECC key over `curve`.
    ///
    /// If `for_signing` is false a ECDH key, if it's true either a
    /// EdDSA or ECDSA key is generated.  Giving `for_signing == true` and
    /// `curve == Cv25519` will produce an error. Likewise
    /// `for_signing == false` and `curve == Ed25519` will produce an error.
    pub(crate) fn generate_ecc_backend(for_signing: bool, curve: Curve)
                                       -> Result<(PublicKeyAlgorithm,
                                                  mpi::PublicKey,
                                                  mpi::SecretKeyMaterial)>
    {
        let nid: Nid = (&curve).try_into()?;
        let key = PKey::<openssl::pkey::Private>::ec_gen(nid.short_name()?)?;

        let params = key.todata(0x87)?; // FIXME magic number

        let hash = crate::crypto::ecdh::default_ecdh_kdf_hash(&curve);
        let sym = crate::crypto::ecdh::default_ecdh_kek_cipher(&curve);

        let pubkey = params.locate("pub\0")?.get_octet_string()?;
        let q = MPI::new(pubkey);
        let privkey = params.locate("priv\0")?.get_bn()?;
        let scalar = privkey.to_vec().into();

        if for_signing {
            Ok((
                PublicKeyAlgorithm::ECDSA,
                mpi::PublicKey::ECDSA { curve, q },
                mpi::SecretKeyMaterial::ECDSA { scalar },
            ))
        } else {
            Ok((
                PublicKeyAlgorithm::ECDH,
                mpi::PublicKey::ECDH {
                    curve,
                    q,
                    hash,
                    sym,
                },
                mpi::SecretKeyMaterial::ECDH { scalar },
            ))
        }
    }
}

/// Given the secret prime values `p` and `q`, returns the pair of
/// primes so that the smaller one comes first.
///
/// Section 5.5.3 of RFC4880 demands that `p < q`.  This function can
/// be used to order `p` and `q` accordingly.
///
/// Note: even though this function seems trivial, we introduce it as
/// explicit abstraction.  The reason is that the function's
/// expression also "works" (as in it compiles) for byte slices, but
/// does the wrong thing, see [`crate::crypto::rsa_sort_raw_pq`].
fn rsa_sort_pq<'a>(p: &'a BigNumRef, q: &'a BigNumRef)
                   -> (&'a BigNumRef, &'a BigNumRef)
{
    if p < q {
        (p, q)
    } else {
        (q, p)
    }
}
