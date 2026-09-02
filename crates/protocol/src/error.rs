//! Shared PeerBadge protocol error handling.

pub use blind_rsa_signatures::pbrsa::PartiallyBlindPublicKeySha384PSSDeterministic as PbrsaPublicKey;
use thiserror::Error;

/// Error returned by PeerBadge protocol operations.
#[derive(Debug, Error)]
pub enum CredentialsError {
    #[error("blind RSA operation failed: {0}")]
    BlindRsa(#[from] blind_rsa_signatures::Error),
    #[error("failed to build canonicalized payload: {0}")]
    Canonicalize(#[from] serde_json::Error),
    #[error("invalid Nostr key: {0}")]
    NostrKey(#[from] nostr::key::Error),
    #[error("issuer_id does not match")]
    IssuerIdMismatch,
    #[error("holder_id does not match")]
    HolderIdMismatch,
    #[error("issuance response info does not match")]
    InfoMismatch,
    #[error("invalid pending issuance state: {0}")]
    InvalidPendingIssuanceState(String),
    #[error("unknown issuer")]
    UnknownIssuer,
    #[error("credential has been revoked")]
    CredentialRevoked,
    #[error("credential digest is not authorized")]
    AuthorizationCredentialDigestMismatch,
    #[error("authorization is not yet valid")]
    AuthorizationNotYetValid,
    #[error("verification failed")]
    VerificationFailed,
}
