//! Verifier-side PBRSA credential verification operations.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    canonicalize_pbrsa_blind_msg, canonicalize_pbrsa_info, holder::current_unix_timestamp,
    CredentialDigest, CredentialsError, HolderAuthorization, HolderId, IssuerAuthority, IssuerId,
    PbrsaPublicKey, ProtocolV1, Revocation, SignedCredential, SignedRevocation, Timestamp,
};

/// Stateful verifier for trusted issuers, revocations, and credentials.
#[derive(Clone, Default)]
pub struct VerificationContext {
    issuers: BTreeMap<IssuerId, PbrsaPublicKey>,
    revocations: BTreeSet<(IssuerId, Revocation)>,
}

impl VerificationContext {
    /// Create an empty verifier context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify and trust an issuer authority for subsequent credential checks.
    pub fn add_issuer_authority(
        &mut self,
        authority: &IssuerAuthority,
    ) -> Result<(), CredentialsError> {
        let issuer = authority.verify()?;
        self.issuers
            .insert(issuer.issuer_id_pubkey.clone(), issuer.issuance_key.clone());

        Ok(())
    }

    /// Verify and store a signed revocation from a trusted issuer.
    pub fn add_revocation(
        &mut self,
        signed_revocation: &SignedRevocation,
    ) -> Result<(), CredentialsError> {
        let revocation = signed_revocation.verify()?;
        if !self
            .issuers
            .contains_key(&signed_revocation.proof.issuer_id_pubkey)
        {
            return Err(CredentialsError::UnknownIssuer);
        }

        self.revocations
            .insert((signed_revocation.proof.issuer_id_pubkey.clone(), revocation));
        Ok(())
    }

    /// Verify a finalized credential against trusted issuers and revocations.
    pub fn verify_credential(&self, credential: &SignedCredential) -> Result<(), CredentialsError> {
        let issuer_public_key = self
            .issuers
            .get(&credential.credential.issuer_id_pubkey)
            .ok_or(CredentialsError::UnknownIssuer)?;

        verify_credential_with_key(issuer_public_key, credential)?;

        let revocation = Revocation {
            credential_digest: CredentialDigest(credential.credential.digest()?),
        };

        if self
            .revocations
            .contains(&(credential.credential.issuer_id_pubkey.clone(), revocation))
        {
            return Err(CredentialsError::CredentialRevoked);
        }

        Ok(())
    }

    /// Verify a credential and a holder authorization.
    ///
    /// The SDK verifies signatures, issuer trust, credential revocation state,
    /// credential binding, holder binding, and the authorization issued-at time.
    /// Application policy still owns live proof that the caller controls
    /// `authorization.authorization.subject_pubkey`.
    pub fn verify_credential_authorization(
        &self,
        credential: &SignedCredential,
        authorization: &HolderAuthorization,
    ) -> Result<(), CredentialsError> {
        self.verify_credential_authorization_at_time(
            credential,
            authorization,
            current_unix_timestamp()?,
        )
    }

    /// Verify a credential and holder authorization using an explicit timestamp.
    pub fn verify_credential_authorization_at_time(
        &self,
        credential: &SignedCredential,
        authorization: &HolderAuthorization,
        now: impl Into<Timestamp>,
    ) -> Result<(), CredentialsError> {
        self.verify_credential(credential)?;

        let authorization = authorization.verify()?;
        let now = now.into();
        let credential_holder_id = credential_holder_id(credential)?;

        if credential_holder_id != authorization.holder_id_pubkey {
            return Err(CredentialsError::HolderIdMismatch);
        }

        if now < authorization.issued_at {
            return Err(CredentialsError::AuthorizationNotYetValid);
        }

        let expected_credential_digest = CredentialDigest(credential.credential.digest()?);

        if authorization.credential_digest != expected_credential_digest {
            return Err(CredentialsError::AuthorizationCredentialDigestMismatch);
        }

        Ok(())
    }
}

pub(crate) fn credential_holder_id(
    credential: &SignedCredential,
) -> Result<HolderId, CredentialsError> {
    let Some(holder_id) = credential.credential.blind_msg.as_str() else {
        return Err(CredentialsError::VerificationFailed);
    };

    holder_id
        .parse::<HolderId>()
        .map_err(|_| CredentialsError::VerificationFailed)
}

pub(crate) fn verify_credential_with_key(
    issuer_public_key: &PbrsaPublicKey,
    credential: &SignedCredential,
) -> Result<(), CredentialsError> {
    let metadata = canonicalize_pbrsa_info(
        ProtocolV1,
        &credential.credential.issuer_id_pubkey,
        &credential.credential.info,
    )?;
    let message = canonicalize_pbrsa_blind_msg(ProtocolV1, &credential.credential.blind_msg)?;
    let public_key = issuer_public_key.derive_public_key_for_metadata(&metadata)?;
    public_key.verify(&credential.proof.signature, None, &message, Some(&metadata))?;
    Ok(())
}
