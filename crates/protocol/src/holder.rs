//! Holder-side PBRSA issuance operations.

use core::convert::Infallible;

#[cfg(feature = "sys-rng")]
use blind_rsa_signatures::reexports::rand::{rand_core::UnwrapErr, rngs::SysRng};
#[cfg(not(feature = "sys-rng"))]
use blind_rsa_signatures::DefaultRng;
use blind_rsa_signatures::{
    reexports::rand::rand_core::TryCryptoRng, BlindMessage, BlindingResult, MessageRandomizer,
    Secret,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::serde_as;

use crate::serde::Base64UrlUnpadded;
use crate::{
    canonicalize_pbrsa_blind_msg, canonicalize_pbrsa_info,
    verifier::{credential_holder_id, verify_credential_with_key},
    Credential, CredentialProof, CredentialsError, HolderAuthorization, HolderAuthorizationRequest,
    HolderId, IssuanceRequest, IssuanceResponse, IssuerId, PbrsaPublicKey, ProtocolV1,
    SchnorrSignatureProof, SignedCredential, Timestamp,
};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PendingIssuanceStep {
    WaitingForIssuerResponse,
}

/// Runtime holder context containing holder identity keys.
#[derive(Clone)]
pub struct HolderContext {
    identity_keys: nostr::Keys,
}

impl HolderContext {
    /// Generate a holder context with fresh Nostr identity keys.
    pub fn generate() -> Self {
        Self::generate_with_rng(&mut nostr::secp256k1::rand::rngs::OsRng)
    }

    pub(crate) fn generate_with_rng(
        rng: &mut (impl nostr::secp256k1::rand::Rng + nostr::secp256k1::rand::CryptoRng),
    ) -> Self {
        Self {
            identity_keys: nostr::Keys::generate_with_rng(rng),
        }
    }

    /// Import a holder context from a Nostr secret key string.
    pub fn import_secret_key(secret_key: &str) -> Result<Self, CredentialsError> {
        Ok(Self {
            identity_keys: nostr::Keys::parse(secret_key)?,
        })
    }

    /// Export this holder's Nostr secret key as a hex string.
    pub fn export_secret_key(&self) -> String {
        self.identity_keys.secret_key().to_secret_hex()
    }

    /// Return this holder's Nostr public key.
    pub fn public_key(&self) -> nostr::PublicKey {
        self.identity_keys.public_key()
    }

    /// Return this holder's protocol holder id.
    pub fn holder_id(&self) -> HolderId {
        HolderId(self.identity_keys.public_key())
    }

    /// Create a signed authorization allowing an auxiliary subject key to use a credential.
    ///
    /// The SDK derives this holder's id and credential digest from the supplied
    /// credential before signing the canonical authorization statement. Consent
    /// UI, storage, transport, and subject-key custody remain application
    /// concerns.
    pub fn authorize_credential_use(
        &self,
        request: HolderAuthorizationRequest,
        credential: &SignedCredential,
    ) -> Result<HolderAuthorization, CredentialsError> {
        self.authorize_credential_use_at_time(request, credential, current_unix_timestamp()?)
    }

    /// Create a signed authorization using an explicit issuance timestamp.
    pub fn authorize_credential_use_at_time(
        &self,
        request: HolderAuthorizationRequest,
        credential: &SignedCredential,
        issued_at: impl Into<Timestamp>,
    ) -> Result<HolderAuthorization, CredentialsError> {
        self.authorize_credential_use_with_rng_at_time(
            request,
            credential,
            issued_at.into(),
            &mut nostr::secp256k1::rand::rngs::OsRng,
        )
    }

    pub(crate) fn authorize_credential_use_with_rng_at_time(
        &self,
        request: HolderAuthorizationRequest,
        credential: &SignedCredential,
        issued_at: impl Into<Timestamp>,
        rng: &mut (impl nostr::secp256k1::rand::Rng + nostr::secp256k1::rand::CryptoRng),
    ) -> Result<HolderAuthorization, CredentialsError> {
        let holder_id = self.holder_id();
        if credential_holder_id(credential)? != holder_id {
            return Err(CredentialsError::HolderIdMismatch);
        }

        let authorization = request.into_statement(holder_id, issued_at.into(), credential)?;
        let signature = self.sign_identity_digest_with_rng(authorization.digest()?, rng);

        Ok(HolderAuthorization {
            version: ProtocolV1,
            authorization,
            proof: SchnorrSignatureProof { signature },
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

/// Holder-side pending issuance state.
#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingIssuance {
    pub version: ProtocolV1,
    step: PendingIssuanceStep,
    pub issuer_id: IssuerId,
    pub info: Value,
    pub blind_msg: Value,
    #[serde_as(as = "Base64UrlUnpadded")]
    blind_message: Vec<u8>,
    #[serde_as(as = "Base64UrlUnpadded")]
    secret: Vec<u8>,
    #[serde_as(as = "Option<Base64UrlUnpadded>")]
    msg_randomizer: Option<Vec<u8>>,
}

impl PendingIssuance {
    /// Create a holder issuance request and local pending state.
    pub fn create_request(
        issuer_public_key: &PbrsaPublicKey,
        issuer_id: IssuerId,
        info: Value,
        blind_msg: Value,
    ) -> Result<(IssuanceRequest, Self), CredentialsError> {
        let mut rng = default_pbrsa_rng();

        Self::create_request_with_rng(issuer_public_key, issuer_id, info, blind_msg, &mut rng)
    }

    pub(crate) fn create_request_with_rng(
        issuer_public_key: &PbrsaPublicKey,
        issuer_id: IssuerId,
        info: Value,
        blind_msg: Value,
        rng: &mut (impl blind_rsa_signatures::reexports::rsa::rand_core::CryptoRng + ?Sized),
    ) -> Result<(IssuanceRequest, Self), CredentialsError> {
        let metadata = canonicalize_pbrsa_info(ProtocolV1, &issuer_id, &info)?;
        let message = canonicalize_pbrsa_blind_msg(ProtocolV1, &blind_msg)?;
        let public_key = issuer_public_key.derive_public_key_for_metadata(&metadata)?;
        let blinding_result = public_key.blind(rng, &message, Some(&metadata))?;
        let blinded_message = blinding_result.blind_message.clone();

        let request = IssuanceRequest {
            version: ProtocolV1,
            blinded_message,
        };
        let pending = Self {
            version: ProtocolV1,
            step: PendingIssuanceStep::WaitingForIssuerResponse,
            issuer_id,
            info,
            blind_msg,
            blind_message: blinding_result.blind_message.0,
            secret: blinding_result.secret.0,
            msg_randomizer: blinding_result
                .msg_randomizer
                .map(|msg_randomizer| msg_randomizer.0.to_vec()),
        };

        Ok((request, pending))
    }

    /// Export app-storable holder-side pending issuance state.
    ///
    /// The exported state is sensitive issuance material. It is needed to
    /// finalize one issuer response after a process or browser reload.
    pub fn export_state(&self) -> Result<String, CredentialsError> {
        Ok(serde_json::to_string(self)?)
    }

    /// Import app-stored holder-side pending issuance state.
    pub fn import_state(state: &str) -> Result<Self, CredentialsError> {
        serde_json::from_str(state).map_err(invalid_pending_issuance_state)
    }

    /// Finalize an issuer response into a holder credential.
    pub fn finalize(
        self,
        issuer_public_key: &PbrsaPublicKey,
        response: &IssuanceResponse,
    ) -> Result<SignedCredential, CredentialsError> {
        if response.issuer_id != self.issuer_id {
            return Err(CredentialsError::IssuerIdMismatch);
        }
        if response.info != self.info {
            return Err(CredentialsError::InfoMismatch);
        }

        let metadata = canonicalize_pbrsa_info(ProtocolV1, &self.issuer_id, &self.info)?;
        let message = canonicalize_pbrsa_blind_msg(ProtocolV1, &self.blind_msg)?;
        let public_key = issuer_public_key.derive_public_key_for_metadata(&metadata)?;
        let blinding_result = self.blinding_result()?;
        let signature = public_key.finalize(
            &response.blind_signature,
            &blinding_result,
            &message,
            Some(&metadata),
        )?;
        let credential = SignedCredential {
            version: ProtocolV1,
            credential: Credential {
                issuer_id_pubkey: self.issuer_id,
                info: self.info,
                blind_msg: self.blind_msg,
            },
            proof: CredentialProof { signature },
        };
        verify_credential_with_key(issuer_public_key, &credential)?;
        Ok(credential)
    }

    fn blinding_result(&self) -> Result<BlindingResult, CredentialsError> {
        let msg_randomizer = self
            .msg_randomizer
            .as_ref()
            .map(|msg_randomizer| {
                let msg_randomizer: [u8; 32] =
                    msg_randomizer.as_slice().try_into().map_err(|_| {
                        CredentialsError::InvalidPendingIssuanceState(format!(
                            "message randomizer must be 32 bytes, got {}",
                            msg_randomizer.len()
                        ))
                    })?;
                Ok::<MessageRandomizer, CredentialsError>(MessageRandomizer(msg_randomizer))
            })
            .transpose()?;

        Ok(BlindingResult {
            blind_message: BlindMessage(self.blind_message.clone()),
            secret: Secret(self.secret.clone()),
            msg_randomizer,
        })
    }
}

fn invalid_pending_issuance_state(error: impl ToString) -> CredentialsError {
    CredentialsError::InvalidPendingIssuanceState(error.to_string())
}

pub(crate) fn current_unix_timestamp() -> Result<Timestamp, CredentialsError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| Timestamp(duration.as_secs()))
        .map_err(|_| CredentialsError::VerificationFailed)
}
