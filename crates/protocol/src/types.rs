use blind_rsa_signatures::{
    BlindMessage as PbrsaBlindMessage, BlindSignature as PbrsaBlindSignature,
    Signature as PbrsaSignature,
};
use nostr::secp256k1::{schnorr::Signature, Message};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use serde_with::serde_as;
use sha2::{digest::Output, Digest, Sha256};
use std::str::FromStr;

use crate::serde::{
    Base64UrlUnpadded, PbrsaPublicKeyBase64UrlUnpadded, SchnorrSignatureBase64UrlUnpadded,
    Sha256DigestBase64UrlUnpadded,
};
use crate::{
    canonicalize_credential, canonicalize_issuer_authority, canonicalize_revocation,
    CredentialsError, PbrsaPublicKey,
};

/// Protocol version marker used by the MVP credential format.
///
/// Version 1 implies the v1 canonicalization and blind-signature suite choices;
/// those are not repeated as per-credential `suite`/`alg` fields.
///
/// Serializes as the JSON number `1`. Deserialization rejects all other version
/// numbers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolV1;

impl Serialize for ProtocolV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(1)
    }
}

impl<'de> Deserialize<'de> for ProtocolV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let version = u16::deserialize(deserializer)?;
        if version == 1 {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format_args!(
                "unsupported protocol version: {version}"
            )))
        }
    }
}

/// Issuer identifier.
///
/// Issuer identities are hard-bound to Nostr public keys.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IssuerId(pub nostr::PublicKey);

impl FromStr for IssuerId {
    type Err = nostr::key::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        nostr::PublicKey::parse(value).map(Self)
    }
}

/// Holder identifier.
///
/// Holder identities are Nostr public keys encoded with the SDK's existing
/// Nostr key serialization.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HolderId(pub nostr::PublicKey);

impl FromStr for HolderId {
    type Err = nostr::key::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        nostr::PublicKey::parse(value).map(Self)
    }
}

/// Unix timestamp in seconds.
///
/// Serializes as a JSON number while keeping protocol timestamp fields strongly
/// typed in Rust.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Timestamp(pub u64);

impl Timestamp {
    /// Return the timestamp as seconds since the Unix epoch.
    pub const fn as_secs(self) -> u64 {
        self.0
    }
}

impl From<u64> for Timestamp {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Timestamp> for u64 {
    fn from(value: Timestamp) -> Self {
        value.0
    }
}

/// SHA-256 digest of a finalized credential payload.
#[serde_as]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialDigest(#[serde_as(as = "Sha256DigestBase64UrlUnpadded")] pub Output<Sha256>);

impl From<Output<Sha256>> for CredentialDigest {
    fn from(value: Output<Sha256>) -> Self {
        Self(value)
    }
}

/// JSON-friendly issuer secret export.
#[serde_as]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerSecretKeys {
    pub issuer_id_secret_key: String,
    #[serde_as(as = "Base64UrlUnpadded")]
    pub issuance_secret_key: Vec<u8>,
}

/// Signed issuer metadata used by verifiers before accepting credentials.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerAuthority {
    pub version: ProtocolV1,
    pub issuer: Issuer,
    pub proof: SchnorrSignatureProof,
}

/// Schnorr signature proof encoded for JSON.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchnorrSignatureProof {
    #[serde_as(as = "SchnorrSignatureBase64UrlUnpadded")]
    pub signature: Signature,
}

impl IssuerAuthority {
    /// Compute the signature digest for this issuer authority payload.
    pub fn digest(&self) -> Result<Output<Sha256>, CredentialsError> {
        self.issuer.digest()
    }

    /// Verify this issuer authority's identity signature and return the issuer metadata.
    pub fn verify(&self) -> Result<Issuer, CredentialsError> {
        validate_revocation_locations(&self.issuer.revocation)?;

        verify_identity_signature(
            &self.issuer.issuer_id_pubkey,
            &self.proof.signature,
            Message::from_digest(self.digest()?.into()),
        )?;

        Ok(self.issuer.clone())
    }
}

/// Issuer metadata signed by the issuer identity key.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issuer {
    pub issuer_id_pubkey: IssuerId,
    /// PBRSA public key used to verify credentials.
    ///
    /// Serializes as DER encoded with unpadded URL-safe base64.
    #[serde_as(as = "PbrsaPublicKeyBase64UrlUnpadded")]
    pub issuance_key: PbrsaPublicKey,
    pub revocation: Vec<RevocationLocation>,
}

impl Issuer {
    /// Compute the signature digest for this issuer metadata.
    pub fn digest(&self) -> Result<Output<Sha256>, CredentialsError> {
        let canonical = canonicalize_issuer_authority(self)?;
        Ok(Sha256::new()
            .chain_update(ISSUER_AUTHORITY_SIGNATURE_DOMAIN_SEPARATOR)
            .chain_update(canonical)
            .finalize())
    }
}

/// Location where issuer revocations may be published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationLocation {
    pub protocol: String,
    pub location: String,
}

/// Signed revocation wire object.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRevocation {
    pub version: ProtocolV1,
    pub revocation: Revocation,
    pub proof: RevocationProof,
}

/// Issuer proof for a signed revocation.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationProof {
    pub issuer_id_pubkey: IssuerId,
    #[serde_as(as = "SchnorrSignatureBase64UrlUnpadded")]
    pub signature: Signature,
}

impl SignedRevocation {
    /// Compute the signature digest for this revocation payload.
    pub fn digest(&self) -> Result<Output<Sha256>, CredentialsError> {
        self.revocation.digest()
    }

    /// Verify this revocation's issuer signature and return the revocation payload.
    pub fn verify(&self) -> Result<Revocation, CredentialsError> {
        verify_identity_signature(
            &self.proof.issuer_id_pubkey,
            &self.proof.signature,
            Message::from_digest(self.digest()?.into()),
        )?;

        Ok(self.revocation.clone())
    }
}

/// Revocation payload signed by the issuer identity key.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Revocation {
    /// SHA-256 digest of the finalized credential.
    pub credential_digest: CredentialDigest,
}

impl Revocation {
    /// Compute the signature digest for this revocation payload.
    pub fn digest(&self) -> Result<Output<Sha256>, CredentialsError> {
        let canonical = canonicalize_revocation(self)?;
        Ok(Sha256::new()
            .chain_update(REVOCATION_SIGNATURE_DOMAIN_SEPARATOR)
            .chain_update(canonical)
            .finalize())
    }
}

/// Domain separator for issuer authority identity signatures.
pub const ISSUER_AUTHORITY_SIGNATURE_DOMAIN_SEPARATOR: &[u8] =
    b"fedi-credential/issuer-authority-signature/v1\0";

/// Domain separator for revocation identity signatures.
pub const REVOCATION_SIGNATURE_DOMAIN_SEPARATOR: &[u8] =
    b"fedi-credential/revocation-signature/v1\0";

fn validate_revocation_locations(locations: &[RevocationLocation]) -> Result<(), CredentialsError> {
    if locations
        .iter()
        .any(|location| location.protocol.is_empty() || location.location.is_empty())
    {
        return Err(CredentialsError::VerificationFailed);
    }

    Ok(())
}

fn verify_identity_signature(
    issuer_id: &IssuerId,
    signature: &Signature,
    message: Message,
) -> Result<(), CredentialsError> {
    verify_identity_signature_with_key(&issuer_id.0, signature, message)
}

pub(crate) fn verify_identity_signature_with_key(
    identity_public_key: &nostr::PublicKey,
    signature: &Signature,
    message: Message,
) -> Result<(), CredentialsError> {
    let public_key = identity_public_key
        .xonly()
        .map_err(|_| CredentialsError::VerificationFailed)?;

    nostr::SECP256K1
        .verify_schnorr(signature, &message, &public_key)
        .map_err(|_| CredentialsError::VerificationFailed)
}

/// Domain separator prepended to canonical credential JSON before hashing.
pub const CREDENTIAL_DIGEST_DOMAIN_SEPARATOR: &[u8] = b"fedi-credential/credential-digest/v1\0";

/// Final holder credential.
///
/// `info` is the JSON value visible to the issuer during issuance.
/// `blind_msg` is the JSON value hidden from the issuer while signing and
/// disclosed in the final credential. For the current Fedi/Nostr use case this
/// will likely contain a Nostr holder public key, but that is application data,
/// not a protocol-level field.
///
/// The credential revocation digest is computed over the canonical credential
/// payload, excluding the proof.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedCredential {
    pub version: ProtocolV1,
    pub credential: Credential,
    pub proof: CredentialProof,
}

/// Final credential payload signed by the issuance key.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Credential {
    pub issuer_id_pubkey: IssuerId,
    pub info: Value,
    pub blind_msg: Value,
}

/// Issuance proof for a finalized credential payload.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CredentialProof {
    /// PBRSA credential signature bytes.
    ///
    /// Serializes as unpadded URL-safe base64.
    #[serde_as(as = "Base64UrlUnpadded")]
    pub signature: PbrsaSignature,
}

impl Credential {
    /// Compute the revocation digest for this credential payload.
    pub fn digest(&self) -> Result<Output<Sha256>, CredentialsError> {
        let canonical = canonicalize_credential(self)?;

        let mut hasher = Sha256::new();
        hasher.update(CREDENTIAL_DIGEST_DOMAIN_SEPARATOR);
        hasher.update(canonical);
        Ok(hasher.finalize())
    }
}

/// Request produced by a holder during issuance.
///
/// The holder keeps the original unblinded `blind_msg` locally and sends only
/// the blinded message to the issuer.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceRequest {
    pub version: ProtocolV1,
    /// PBRSA blinded message bytes sent by the holder during issuance.
    ///
    /// Serializes as unpadded URL-safe base64.
    #[serde_as(as = "Base64UrlUnpadded")]
    pub blinded_message: PbrsaBlindMessage,
}

/// Response produced by an issuer during issuance.
///
/// The response includes the issuer-selected `info` JSON and the blind signature.
/// The holder combines this with their original unblinded `blind_msg` and
/// deterministic message preparation to assemble a final [`SignedCredential`].
#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IssuanceResponse {
    pub version: ProtocolV1,
    pub issuer_id: IssuerId,
    pub info: Value,
    /// PBRSA blind signature bytes returned by the issuer during issuance.
    ///
    /// Serializes as unpadded URL-safe base64.
    #[serde_as(as = "Base64UrlUnpadded")]
    pub blind_signature: PbrsaBlindSignature,
}

#[cfg(test)]
mod tests {
    use blind_rsa_signatures::Signature as PbrsaSignature;
    use serde_json::json;
    use sha2::Digest;

    use super::*;

    fn credential() -> SignedCredential {
        SignedCredential {
            version: ProtocolV1,
            credential: Credential {
                issuer_id_pubkey: IssuerId(nostr::PublicKey::from_byte_array([1u8; 32])),
                info: json!({
                    "z": 1,
                    "a": {
                        "b": true,
                        "a": false,
                    },
                }),
                blind_msg: json!({
                    "holder": "alice",
                    "nonce": 7,
                }),
            },
            proof: CredentialProof {
                signature: PbrsaSignature(vec![1, 2, 3, 4]),
            },
        }
    }

    #[test]
    fn digest_hashes_domain_separator_and_canonical_credential_json() {
        let credential = credential();

        let canonical = canonicalize_credential(&credential.credential).unwrap();
        let expected = Sha256::new()
            .chain_update(CREDENTIAL_DIGEST_DOMAIN_SEPARATOR)
            .chain_update(canonical)
            .finalize();

        assert_eq!(credential.credential.digest().unwrap(), expected);
    }

    #[test]
    fn digest_excludes_signature() {
        let mut first = credential();
        let mut second = credential();
        first.proof.signature = PbrsaSignature(vec![1, 2, 3, 4]);
        second.proof.signature = PbrsaSignature(vec![1, 2, 3, 5]);

        assert_eq!(
            first.credential.digest().unwrap(),
            second.credential.digest().unwrap()
        );
    }
}
