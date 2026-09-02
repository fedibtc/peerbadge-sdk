//! Issuer-side PBRSA issuance operations.

#[cfg(not(feature = "sys-rng"))]
use blind_rsa_signatures::DefaultRng;
use blind_rsa_signatures::{
    pbrsa::PartiallyBlindKeyPairSha384PSSDeterministic,
    reexports::rand::{
        self,
        rand_core::{Infallible, TryCryptoRng, TryRng, UnwrapErr},
        rngs::SysRng,
    },
};
use serde_json::Value;

use crate::{
    canonicalize_pbrsa_info, CredentialsError, IssuanceRequest, IssuanceResponse, Issuer,
    IssuerAuthority, IssuerId, IssuerSecretKeys, ProtocolV1, Revocation, RevocationLocation,
    RevocationProof, SchnorrSignatureProof, SignedCredential, SignedRevocation,
};

pub const ISSUER_MODULUS_BITS: usize = 2048;
const KEYGEN_PROGRESS_RANDOM_DRAWS: u64 = 100_000;

fn default_pbrsa_rng() -> impl TryCryptoRng<Error = Infallible> {
    #[cfg(feature = "sys-rng")]
    {
        UnwrapErr(SysRng)
    }

    #[cfg(not(feature = "sys-rng"))]
    {
        DefaultRng
    }
}

struct KeygenProgressRng<R> {
    inner: R,
    rng_strategy: &'static str,
    random_draws: u64,
    next_progress_log_at: u64,
}

impl<R> KeygenProgressRng<R> {
    fn new(inner: R, rng_strategy: &'static str) -> Self {
        tracing::info!(rng_strategy, "issuer RSA keygen started");
        Self {
            inner,
            rng_strategy,
            random_draws: 0,
            next_progress_log_at: KEYGEN_PROGRESS_RANDOM_DRAWS,
        }
    }

    fn random_draws(&self) -> u64 {
        self.random_draws
    }

    fn record_random_draw(&mut self) {
        self.random_draws += 1;
        if self.random_draws >= self.next_progress_log_at {
            tracing::info!(
                rng_strategy = self.rng_strategy,
                random_draws = self.random_draws,
                "issuer RSA keygen still running"
            );
            self.next_progress_log_at += KEYGEN_PROGRESS_RANDOM_DRAWS;
        }
    }
}

impl<R: TryRng> TryRng for KeygenProgressRng<R> {
    type Error = R::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let value = self.inner.try_next_u32()?;
        self.record_random_draw();
        Ok(value)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let value = self.inner.try_next_u64()?;
        self.record_random_draw();
        Ok(value)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.inner.try_fill_bytes(dst)?;
        self.record_random_draw();
        Ok(())
    }
}

impl<R: TryCryptoRng> TryCryptoRng for KeygenProgressRng<R> {}

/// Runtime issuer context containing issuer identity and PBRSA signing key.
#[derive(Clone)]
pub struct IssuerContext {
    identity_keys: nostr::Keys,
    key_pair: PartiallyBlindKeyPairSha384PSSDeterministic,
}

impl IssuerContext {
    /// Generate an issuer context with fresh Nostr identity and PBRSA key pairs.
    #[cfg(not(feature = "sys-rng"))]
    pub fn generate() -> Result<Self, CredentialsError> {
        Self::generate_with_thread_rng()
    }

    /// Generate an issuer context with fresh Nostr identity and PBRSA key pairs.
    #[cfg(feature = "sys-rng")]
    pub fn generate() -> Result<Self, CredentialsError> {
        Self::generate_with_system_rng()
    }

    /// Generate an issuer context using a thread-local CSPRNG seeded from the system RNG.
    pub fn generate_with_thread_rng() -> Result<Self, CredentialsError> {
        Self::generate_with_rng_source("thread_rng", rand::rng())
    }

    /// Generate an issuer context using direct system randomness for each keygen draw.
    pub fn generate_with_system_rng() -> Result<Self, CredentialsError> {
        Self::generate_with_rng_source("system_rng", UnwrapErr(SysRng))
    }

    fn generate_with_rng_source<R>(
        rng_strategy: &'static str,
        rng: R,
    ) -> Result<Self, CredentialsError>
    where
        R: TryCryptoRng<Error = Infallible>,
    {
        let span = tracing::info_span!(
            "issuer_rsa_keygen",
            modulus_bits = ISSUER_MODULUS_BITS,
            rng_strategy
        );
        let _span_guard = span.enter();
        let mut rng = KeygenProgressRng::new(rng, rng_strategy);
        let generated = Self::generate_with_rng(nostr::Keys::generate(), &mut rng);
        match &generated {
            Ok(_) => tracing::info!(
                rng_strategy,
                random_draws = rng.random_draws(),
                "issuer RSA keygen finished"
            ),
            Err(error) => tracing::warn!(
                rng_strategy,
                random_draws = rng.random_draws(),
                %error,
                "issuer RSA keygen failed"
            ),
        }
        generated
    }

    pub(crate) fn generate_with_rng(
        identity_keys: nostr::Keys,
        rng: &mut (impl blind_rsa_signatures::reexports::rsa::rand_core::CryptoRng + ?Sized),
    ) -> Result<Self, CredentialsError> {
        Ok(Self {
            identity_keys,
            key_pair: PartiallyBlindKeyPairSha384PSSDeterministic::generate(
                rng,
                ISSUER_MODULUS_BITS,
            )?,
        })
    }

    /// Build and sign this issuer's public metadata.
    ///
    /// The returned authority binds the issuer's derived Nostr identity key to the
    /// current PBRSA issuance public key and the supplied revocation locations.
    pub fn issuer_authority(
        &self,
        revocation: Vec<RevocationLocation>,
    ) -> Result<IssuerAuthority, CredentialsError> {
        self.issuer_authority_with_rng(revocation, &mut nostr::secp256k1::rand::rngs::OsRng)
    }

    pub(crate) fn issuer_authority_with_rng(
        &self,
        revocation: Vec<RevocationLocation>,
        rng: &mut (impl nostr::secp256k1::rand::Rng + nostr::secp256k1::rand::CryptoRng),
    ) -> Result<IssuerAuthority, CredentialsError> {
        let issuer = Issuer {
            issuer_id_pubkey: self.issuer_id(),
            issuance_key: self.key_pair.pk.clone(),
            revocation,
        };
        let signature = self.sign_identity_digest_with_rng(issuer.digest()?, rng);

        Ok(IssuerAuthority {
            version: ProtocolV1,
            issuer,
            proof: SchnorrSignatureProof { signature },
        })
    }

    fn issuer_id(&self) -> IssuerId {
        IssuerId(self.identity_keys.public_key())
    }

    /// Export this issuer's identity and issuance secret keys.
    pub fn export_secret_key(&self) -> Result<IssuerSecretKeys, CredentialsError> {
        Ok(IssuerSecretKeys {
            issuer_id_secret_key: self.identity_keys.secret_key().to_secret_hex(),
            issuance_secret_key: self.key_pair.sk.to_der()?,
        })
    }

    /// Import an issuer context from previously exported secret keys.
    pub fn import_secret_key(secret_key: &IssuerSecretKeys) -> Result<Self, CredentialsError> {
        let identity_keys = nostr::Keys::parse(&secret_key.issuer_id_secret_key)?;
        let secret_key =
            blind_rsa_signatures::pbrsa::PartiallyBlindSecretKeySha384PSSDeterministic::from_der(
                &secret_key.issuance_secret_key,
            )?;
        let public_key = secret_key.public_key()?;
        Ok(Self {
            identity_keys,
            key_pair: PartiallyBlindKeyPairSha384PSSDeterministic {
                pk: public_key,
                sk: secret_key,
            },
        })
    }

    /// Issue a blind signature over a holder issuance request.
    pub fn issue_credential(
        &self,
        info: Value,
        request: &IssuanceRequest,
    ) -> Result<IssuanceResponse, CredentialsError> {
        self.issue_credential_with_rng(info, request, &mut default_pbrsa_rng())
    }

    pub(crate) fn issue_credential_with_rng(
        &self,
        info: Value,
        request: &IssuanceRequest,
        rng: &mut (impl blind_rsa_signatures::reexports::rsa::rand_core::TryCryptoRng + ?Sized),
    ) -> Result<IssuanceResponse, CredentialsError> {
        let issuer_id = self.issuer_id();
        let metadata = canonicalize_pbrsa_info(ProtocolV1, &issuer_id, &info)?;
        let secret_key = self.key_pair.derive_secret_key_for_metadata(&metadata)?;
        Ok(IssuanceResponse {
            version: ProtocolV1,
            issuer_id,
            info,
            blind_signature: secret_key.blind_sign_with_rng(rng, &request.blinded_message)?,
        })
    }

    /// Build and sign the revocation for a finalized credential issued by this issuer.
    ///
    /// This computes the finalized credential digest and binds it to this issuer
    /// identity. It does not publish or transport the revocation; those concerns
    /// live outside the core protocol.
    pub fn revoke_credential(
        &self,
        credential: &SignedCredential,
    ) -> Result<SignedRevocation, CredentialsError> {
        self.revoke_credential_with_rng(credential, &mut nostr::secp256k1::rand::rngs::OsRng)
    }

    pub(crate) fn revoke_credential_with_rng(
        &self,
        credential: &SignedCredential,
        rng: &mut (impl nostr::secp256k1::rand::Rng + nostr::secp256k1::rand::CryptoRng),
    ) -> Result<SignedRevocation, CredentialsError> {
        let issuer_id = self.issuer_id();
        if credential.credential.issuer_id_pubkey != issuer_id {
            return Err(CredentialsError::IssuerIdMismatch);
        }

        let revocation = Revocation {
            credential_digest: crate::CredentialDigest(credential.credential.digest()?),
        };

        let signature = self.sign_identity_digest_with_rng(revocation.digest()?, rng);

        Ok(SignedRevocation {
            version: ProtocolV1,
            revocation,
            proof: RevocationProof {
                issuer_id_pubkey: issuer_id,
                signature,
            },
        })
    }

    fn sign_identity_digest_with_rng(
        &self,
        digest: sha2::digest::Output<sha2::Sha256>,
        rng: &mut (impl nostr::secp256k1::rand::Rng + nostr::secp256k1::rand::CryptoRng),
    ) -> nostr::secp256k1::schnorr::Signature {
        self.identity_keys.sign_schnorr_with_ctx(
            nostr::SECP256K1,
            &nostr::secp256k1::Message::from_digest(digest.into()),
            rng,
        )
    }
}
