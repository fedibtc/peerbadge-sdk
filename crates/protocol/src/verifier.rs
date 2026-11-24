//! Verifier-side PBRSA credential verification operations.

use std::collections::{BTreeMap, BTreeSet};

use blind_rsa_signatures::Signature as PbrsaSignature;

use crate::{
    canonicalize_pbrsa_blind_msg, canonicalize_pbrsa_info, holder::current_unix_timestamp,
    Credential, CredentialDigest, CredentialsError, HolderAuthorization, HolderId, IssuerAuthority,
    IssuerId, MultiSignerCredential, PbrsaPublicKey, ProtocolV1, Revocation, SignedCredential,
    SignedRevocation, Timestamp,
};

/// Stateful verifier for trusted issuers, revocations, and credentials.
#[derive(Clone, Default)]
pub struct VerificationContext {
    issuers: BTreeMap<IssuerId, PbrsaPublicKey>,
    revocations: BTreeSet<(IssuerId, Revocation)>,
    multi_signer_groups: BTreeMap<IssuerId, MultiSignerGroup>,
}

/// Member issuers trusted for one multi-signer group id, and how many must sign.
#[derive(Clone)]
struct MultiSignerGroup {
    members: BTreeMap<IssuerId, PbrsaPublicKey>,
    threshold: usize,
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
        verify_authorization_for_payload(&credential.credential, authorization, now.into())
    }

    /// Trust a multi-signer group for subsequent multi-signer credential checks.
    ///
    /// `group_id` is the identifier the group's credentials are issued under.
    /// It authorizes nothing; trust comes only from the listed member issuer
    /// authorities, each verified like [`Self::add_issuer_authority`]. A
    /// multi-signer credential is accepted when at least `threshold` distinct
    /// members have valid signatures on it.
    ///
    /// Members are trusted for this group only; they are not added as
    /// single-issuer authorities. Adding a group with an id already configured
    /// replaces it.
    pub fn add_multi_signer_group(
        &mut self,
        group_id: IssuerId,
        member_authorities: &[IssuerAuthority],
        threshold: usize,
    ) -> Result<(), CredentialsError> {
        let invalid = |reason: &str| CredentialsError::InvalidMultiSignerGroup(reason.to_owned());

        let mut members = BTreeMap::new();
        for authority in member_authorities {
            let issuer = authority.verify()?;
            if issuer.issuer_id_pubkey == group_id {
                return Err(invalid("group id must differ from every member issuer id"));
            }
            if members
                .values()
                .any(|issuance_key| *issuance_key == issuer.issuance_key)
            {
                return Err(invalid("member issuers must have distinct issuance keys"));
            }
            if members
                .insert(issuer.issuer_id_pubkey, issuer.issuance_key)
                .is_some()
            {
                return Err(invalid("member issuers must be listed once"));
            }
        }
        if threshold == 0 {
            return Err(invalid("threshold must be at least 1"));
        }
        if threshold > members.len() {
            return Err(invalid("threshold exceeds the number of member issuers"));
        }

        self.multi_signer_groups
            .insert(group_id, MultiSignerGroup { members, threshold });
        Ok(())
    }

    /// Return the trusted members of the credential's group whose signatures
    /// on the credential are valid.
    ///
    /// Proofs from issuers that are not members of the configured group, and
    /// proofs that fail verification, are ignored. A member with several valid
    /// proofs appears once. This applies no threshold; use it to apply your own
    /// policy, or call [`Self::verify_multi_signer_credential`].
    pub fn valid_multi_signer_members(
        &self,
        credential: &MultiSignerCredential,
    ) -> Result<BTreeSet<IssuerId>, CredentialsError> {
        let group = self
            .multi_signer_groups
            .get(&credential.credential.issuer_id_pubkey)
            .ok_or(CredentialsError::UnknownIssuer)?;

        let mut valid_members = BTreeSet::new();
        for proof in &credential.proofs {
            if valid_members.contains(&proof.issuer_id_pubkey) {
                continue;
            }
            let Some(issuance_key) = group.members.get(&proof.issuer_id_pubkey) else {
                continue;
            };
            if verify_signature_with_key(issuance_key, &credential.credential, &proof.signature)
                .is_ok()
            {
                valid_members.insert(proof.issuer_id_pubkey.clone());
            }
        }

        Ok(valid_members)
    }

    /// Verify a multi-signer credential against its configured group.
    ///
    /// Fails with [`CredentialsError::UnknownIssuer`] when no group is
    /// configured for the credential's `issuer_id_pubkey`, and with
    /// [`CredentialsError::MultiSignerThresholdNotMet`] when fewer than the
    /// group threshold of distinct trusted members signed validly.
    ///
    /// Revocations are not checked for multi-signer credentials.
    pub fn verify_multi_signer_credential(
        &self,
        credential: &MultiSignerCredential,
    ) -> Result<(), CredentialsError> {
        let threshold = self
            .multi_signer_groups
            .get(&credential.credential.issuer_id_pubkey)
            .ok_or(CredentialsError::UnknownIssuer)?
            .threshold;
        let valid = self.valid_multi_signer_members(credential)?.len();
        if valid < threshold {
            return Err(CredentialsError::MultiSignerThresholdNotMet { valid, threshold });
        }

        Ok(())
    }

    /// Verify a multi-signer credential and a holder authorization.
    ///
    /// Performs [`Self::verify_multi_signer_credential`] and the same holder
    /// authorization checks as [`Self::verify_credential_authorization`].
    pub fn verify_multi_signer_credential_authorization(
        &self,
        credential: &MultiSignerCredential,
        authorization: &HolderAuthorization,
    ) -> Result<(), CredentialsError> {
        self.verify_multi_signer_credential_authorization_at_time(
            credential,
            authorization,
            current_unix_timestamp()?,
        )
    }

    /// Verify a multi-signer credential and holder authorization using an explicit timestamp.
    pub fn verify_multi_signer_credential_authorization_at_time(
        &self,
        credential: &MultiSignerCredential,
        authorization: &HolderAuthorization,
        now: impl Into<Timestamp>,
    ) -> Result<(), CredentialsError> {
        self.verify_multi_signer_credential(credential)?;
        verify_authorization_for_payload(&credential.credential, authorization, now.into())
    }
}

fn verify_authorization_for_payload(
    credential: &Credential,
    authorization: &HolderAuthorization,
    now: Timestamp,
) -> Result<(), CredentialsError> {
    let authorization = authorization.verify()?;
    let credential_holder_id = credential_holder_id(credential)?;

    if credential_holder_id != authorization.holder_id_pubkey {
        return Err(CredentialsError::HolderIdMismatch);
    }

    if now < authorization.issued_at {
        return Err(CredentialsError::AuthorizationNotYetValid);
    }

    let expected_credential_digest = CredentialDigest(credential.digest()?);

    if authorization.credential_digest != expected_credential_digest {
        return Err(CredentialsError::AuthorizationCredentialDigestMismatch);
    }

    Ok(())
}

pub(crate) fn credential_holder_id(credential: &Credential) -> Result<HolderId, CredentialsError> {
    let Some(holder_id) = credential.blind_msg.as_str() else {
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
    verify_signature_with_key(
        issuer_public_key,
        &credential.credential,
        &credential.proof.signature,
    )
}

/// Verify a PBRSA signature over `credential` under the per-metadata key for
/// its `issuer_id_pubkey` and `info`.
pub(crate) fn verify_signature_with_key(
    issuer_public_key: &PbrsaPublicKey,
    credential: &Credential,
    signature: &PbrsaSignature,
) -> Result<(), CredentialsError> {
    let metadata =
        canonicalize_pbrsa_info(ProtocolV1, &credential.issuer_id_pubkey, &credential.info)?;
    let message = canonicalize_pbrsa_blind_msg(ProtocolV1, &credential.blind_msg)?;
    let public_key = issuer_public_key.derive_public_key_for_metadata(&metadata)?;
    public_key.verify(signature, None, &message, Some(&metadata))?;
    Ok(())
}
