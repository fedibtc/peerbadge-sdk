//! Holder authorization protocol types.
//!
//! These types describe holder-signed authorizations that allow an auxiliary
//! subject key to present holder credentials without sharing the holder key.

use serde::{Deserialize, Serialize};
use sha2::{digest::Output, Digest, Sha256};
use std::str::FromStr;

use crate::{
    canonical::canonicalize_holder_authorization,
    types::{
        verify_identity_signature_with_key, CredentialDigest, HolderId, ProtocolV1,
        SchnorrSignatureProof, SignedCredential, Timestamp,
    },
    CredentialsError,
};

/// Domain separator for holder authorization identity signatures.
pub const HOLDER_AUTHORIZATION_SIGNATURE_DOMAIN_SEPARATOR: &[u8] =
    b"fedi-credential/holder-authorization-signature/v1\0";

/// Public identity of the auxiliary key or actor authorized by the holder.
///
/// V1 keeps this as a Nostr public key, matching `IssuerId` and `HolderId`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SubjectPubkey(pub nostr::PublicKey);

impl FromStr for SubjectPubkey {
    type Err = nostr::key::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        nostr::PublicKey::parse(value).map(Self)
    }
}

/// Request for a holder authorization.
///
/// An auxiliary subject key asks to act under the holder's identity. The holder
/// chooses which credential to authorize separately when signing.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HolderAuthorizationRequest {
    /// The auxiliary key or actor that the holder authorizes.
    pub subject_pubkey: SubjectPubkey,
}

impl HolderAuthorizationRequest {
    /// Convert this application input into the canonical statement to sign.
    pub fn into_statement(
        self,
        holder_id_pubkey: HolderId,
        issued_at: Timestamp,
        credential: &SignedCredential,
    ) -> Result<HolderAuthorizationStatement, CredentialsError> {
        let credential_digest = CredentialDigest(credential.credential.digest()?);

        Ok(HolderAuthorizationStatement {
            holder_id_pubkey,
            subject_pubkey: self.subject_pubkey,
            credential_digest,
            issued_at,
        })
    }
}

/// Unsigned statement authorizing an auxiliary public key to present credentials.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HolderAuthorizationStatement {
    /// The holder making the authorization.
    pub holder_id_pubkey: HolderId,

    /// The auxiliary key or actor that the holder authorizes.
    pub subject_pubkey: SubjectPubkey,

    /// Credential digest this authorization grants the subject permission to present.
    pub credential_digest: CredentialDigest,

    /// Unix timestamp in seconds.
    pub issued_at: Timestamp,
}

impl HolderAuthorizationStatement {
    /// Compute the signature digest for this holder authorization statement.
    pub fn digest(&self) -> Result<Output<Sha256>, CredentialsError> {
        let canonical = canonicalize_holder_authorization(self)?;
        Ok(Sha256::new()
            .chain_update(HOLDER_AUTHORIZATION_SIGNATURE_DOMAIN_SEPARATOR)
            .chain_update(canonical)
            .finalize())
    }
}

/// Holder-signed authorization.
///
/// This intentionally stays close to upstream `SignedCredential { version,
/// credential, proof }`: a versioned signed claim plus a proof. The difference is
/// that this is a direct holder identity signature over an unblinded statement,
/// not an issuer PBRSA proof over a blind-issued credential.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HolderAuthorization {
    /// Protocol version for this shape.
    pub version: ProtocolV1,

    /// Statement signed by the holder.
    pub authorization: HolderAuthorizationStatement,

    /// Holder signature over canonical `authorization` with a versioned domain
    /// separator such as `fedi-credential/holder-authorization-signature/v1\0`.
    pub proof: SchnorrSignatureProof,
}

impl HolderAuthorization {
    /// Compute the signature digest for this holder authorization payload.
    pub fn digest(&self) -> Result<Output<Sha256>, CredentialsError> {
        self.authorization.digest()
    }

    /// Verify this authorization's holder signature and return the statement.
    pub fn verify(&self) -> Result<HolderAuthorizationStatement, CredentialsError> {
        verify_identity_signature_with_key(
            &self.authorization.holder_id_pubkey.0,
            &self.proof.signature,
            nostr::secp256k1::Message::from_digest(self.digest()?.into()),
        )?;

        Ok(self.authorization.clone())
    }
}
