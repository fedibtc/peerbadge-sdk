//! The `fedi-trust-score-v1.0` badge schema.
//!
//! A trust-score badge spans both application-data fields of a credential:
//!
//! - `info` (attester-visible, attester-attested):
//!   `{"schema": "fedi-trust-score-v1.0", "trust_level": <u64>}`. Unknown
//!   extra keys are tolerated by the parser to leave room for additive future
//!   revisions.
//! - `blind_msg` (hidden from the attester during blind issuance, revealed at
//!   presentation): the holder pubkey as a JSON string in canonical lowercase
//!   hex, binding the badge to the holder.
//!
//! This shape is normative for `v1.0` because it is what the shipped PeerBadge
//! issuer produces; verifiers adapt to it, not the other way around.
//!
//! `trust_level` is bounded to the documented trust model: the "Fedi
//! Verification (Eng)" product document defines a 12-level model ("The Trust
//! model will comprise of 12 levels"), of which Fedi issues 3, 6, and 9. The
//! schema enforces the `1..=12` range; which levels are *acceptable* remains
//! caller policy. The tight bound also keeps native (u64) and JavaScript
//! (f64) verifiers exactly agreed on every representable level.
//!
//! `fedi-trust-score-v1.0` badges attest **holders** (persons). A credential
//! about any other subject MUST use a new schema string, never this one with
//! extra annotations.
//!
//! # Future work: `issuance_epoch`
//!
//! Earlier verifier-side drafts required a coarse `issuance_epoch` batch id in
//! `info`. No verifier policy ever consumed it and the shipped issuer does not
//! emit it, so `v1.0` defines no such field. The privacy rationale stands (any
//! batch marker must be coarse, never a unique issuance timestamp, to preserve
//! the holder anonymity set) and a future `v1.1` may reintroduce it as a
//! policy input. Version-string batching makes this safe to defer: when
//! epoch-aware policy arrives, all `v1.0` badges constitute their own coarse
//! cohort and can be aged out or reissued as a batch.

use peerbadge_protocol::Credential;
use serde_json::Value;

/// `info.schema` identifier for trust-score badges, revision v1.0.
pub const TRUST_SCORE_SCHEMA_V1: &str = "fedi-trust-score-v1.0";

/// Lowest legal `trust_level` in the documented 12-level trust model.
pub const TRUST_SCORE_LEVEL_MIN: u64 = 1;

/// Highest legal `trust_level` in the documented 12-level trust model.
pub const TRUST_SCORE_LEVEL_MAX: u64 = 12;

/// Parsed payload of a `fedi-trust-score-v1.0` badge.
///
/// Whether the `trust_level` is acceptable remains caller policy; this type
/// only attests that the credential carries the schema correctly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustScoreBadgeV1 {
    /// Public result of attester-private scoring.
    pub trust_level: u64,

    /// Holder pubkey bound by the revealed `blind_msg`.
    pub holder_pubkey: nostr::PublicKey,
}

/// Schema-level rejection reasons for [`parse_trust_score_badge_v1`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TrustScoreSchemaError {
    /// `credential.info` is not a JSON object.
    #[error("credential info is not a JSON object")]
    InfoNotObject,

    /// `info.schema` is missing or not `fedi-trust-score-v1.0`.
    #[error("credential info schema is missing or not \"{TRUST_SCORE_SCHEMA_V1}\"")]
    WrongSchema,

    /// `info.trust_level` is missing or not an unsigned integer.
    #[error("credential info trust_level is missing or not an unsigned integer")]
    InvalidTrustLevel,

    /// `info.trust_level` is outside the documented `1..=12` trust model.
    #[error(
        "credential info trust_level is outside the \
         {TRUST_SCORE_LEVEL_MIN}..={TRUST_SCORE_LEVEL_MAX} trust model range"
    )]
    TrustLevelOutOfRange,

    /// `credential.blind_msg` is not a canonical lowercase hex holder pubkey
    /// string.
    #[error("credential blind_msg is not a canonical lowercase hex holder pubkey")]
    InvalidHolderBinding,
}

/// Build the issuance `info` value for a trust-score badge.
///
/// Rejects levels outside `1..=12` so an issuer bug surfaces as an error at
/// the source instead of a signed badge carrying an illegal level.
pub fn trust_score_info_v1(trust_level: u64) -> Result<Value, TrustScoreSchemaError> {
    validate_trust_level(trust_level)?;
    Ok(serde_json::json!({
        "schema": TRUST_SCORE_SCHEMA_V1,
        "trust_level": trust_level,
    }))
}

fn validate_trust_level(trust_level: u64) -> Result<(), TrustScoreSchemaError> {
    if !(TRUST_SCORE_LEVEL_MIN..=TRUST_SCORE_LEVEL_MAX).contains(&trust_level) {
        return Err(TrustScoreSchemaError::TrustLevelOutOfRange);
    }
    Ok(())
}

/// Build the issuance `blind_msg` value binding the badge to a holder.
pub fn trust_score_blind_msg_v1(holder_pubkey: &nostr::PublicKey) -> Value {
    Value::String(holder_pubkey.to_string())
}

/// Parse a cryptographically verified credential as a trust-score badge.
///
/// This is the application-level schema check layered on top of protocol
/// verification; it performs no signature checks itself. Unknown extra keys in
/// `info` are tolerated.
pub fn parse_trust_score_badge_v1(
    credential: &Credential,
) -> Result<TrustScoreBadgeV1, TrustScoreSchemaError> {
    let info = credential
        .info
        .as_object()
        .ok_or(TrustScoreSchemaError::InfoNotObject)?;

    if info.get("schema").and_then(Value::as_str) != Some(TRUST_SCORE_SCHEMA_V1) {
        return Err(TrustScoreSchemaError::WrongSchema);
    }

    let trust_level = info
        .get("trust_level")
        .and_then(Value::as_u64)
        .ok_or(TrustScoreSchemaError::InvalidTrustLevel)?;
    validate_trust_level(trust_level)?;

    let holder_hex = credential
        .blind_msg
        .as_str()
        .ok_or(TrustScoreSchemaError::InvalidHolderBinding)?;
    let holder_pubkey = nostr::PublicKey::parse(holder_hex)
        .map_err(|_| TrustScoreSchemaError::InvalidHolderBinding)?;
    // Round-trip to reject non-canonical encodings (uppercase hex) that would
    // otherwise alias the same key under different credential digests.
    if holder_pubkey.to_string() != holder_hex {
        return Err(TrustScoreSchemaError::InvalidHolderBinding);
    }

    Ok(TrustScoreBadgeV1 {
        trust_level,
        holder_pubkey,
    })
}

#[cfg(test)]
mod tests {
    use peerbadge_protocol::IssuerId;
    use nostr::nips::nip19::ToBech32;

    use super::*;

    const HOLDER_HEX: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn credential(info: Value, blind_msg: Value) -> Credential {
        Credential {
            issuer_id_pubkey: IssuerId(nostr::PublicKey::parse(HOLDER_HEX).expect("valid key")),
            info,
            blind_msg,
        }
    }

    #[test]
    fn parses_the_shipped_issuer_shape() {
        let credential = credential(
            serde_json::json!({"schema": TRUST_SCORE_SCHEMA_V1, "trust_level": 9}),
            Value::String(HOLDER_HEX.to_owned()),
        );

        let badge = parse_trust_score_badge_v1(&credential).expect("parses");
        assert_eq!(badge.trust_level, 9);
        assert_eq!(badge.holder_pubkey.to_string(), HOLDER_HEX);
    }

    #[test]
    fn constructors_round_trip_through_the_parser() {
        let holder = nostr::PublicKey::parse(HOLDER_HEX).expect("valid key");
        for trust_level in TRUST_SCORE_LEVEL_MIN..=TRUST_SCORE_LEVEL_MAX {
            let credential = credential(
                trust_score_info_v1(trust_level).expect("legal level"),
                trust_score_blind_msg_v1(&holder),
            );

            let badge = parse_trust_score_badge_v1(&credential).expect("parses");
            assert_eq!(badge.trust_level, trust_level);
            assert_eq!(badge.holder_pubkey, holder);
        }
    }

    #[test]
    fn constructor_rejects_out_of_range_levels() {
        for trust_level in [0, 13, u64::MAX] {
            assert_eq!(
                trust_score_info_v1(trust_level),
                Err(TrustScoreSchemaError::TrustLevelOutOfRange)
            );
        }
    }

    #[test]
    fn parser_rejects_out_of_range_levels() {
        for info in [
            serde_json::json!({"schema": TRUST_SCORE_SCHEMA_V1, "trust_level": 0}),
            serde_json::json!({"schema": TRUST_SCORE_SCHEMA_V1, "trust_level": 13}),
            serde_json::json!({"schema": TRUST_SCORE_SCHEMA_V1, "trust_level": u64::MAX}),
        ] {
            let credential = credential(info, Value::String(HOLDER_HEX.to_owned()));
            assert_eq!(
                parse_trust_score_badge_v1(&credential),
                Err(TrustScoreSchemaError::TrustLevelOutOfRange)
            );
        }
    }

    #[test]
    fn tolerates_unknown_info_keys() {
        let credential = credential(
            serde_json::json!({
                "schema": TRUST_SCORE_SCHEMA_V1,
                "trust_level": 6,
                "subject_type": "holder",
                "issuance_epoch": "2026-Q1",
            }),
            Value::String(HOLDER_HEX.to_owned()),
        );

        assert_eq!(
            parse_trust_score_badge_v1(&credential)
                .expect("parses")
                .trust_level,
            6
        );
    }

    #[test]
    fn rejects_wrong_or_missing_schema() {
        for info in [
            serde_json::json!({"trust_level": 3}),
            serde_json::json!({"schema": "fedi-trust-score-v2.0", "trust_level": 3}),
        ] {
            let credential = credential(info, Value::String(HOLDER_HEX.to_owned()));
            assert_eq!(
                parse_trust_score_badge_v1(&credential),
                Err(TrustScoreSchemaError::WrongSchema)
            );
        }
    }

    #[test]
    fn rejects_non_object_info() {
        let credential = credential(Value::String("nope".to_owned()), Value::Null);
        assert_eq!(
            parse_trust_score_badge_v1(&credential),
            Err(TrustScoreSchemaError::InfoNotObject)
        );
    }

    #[test]
    fn rejects_missing_or_non_integer_trust_level() {
        for info in [
            serde_json::json!({"schema": TRUST_SCORE_SCHEMA_V1}),
            serde_json::json!({"schema": TRUST_SCORE_SCHEMA_V1, "trust_level": 3.5}),
            serde_json::json!({"schema": TRUST_SCORE_SCHEMA_V1, "trust_level": -1}),
            serde_json::json!({"schema": TRUST_SCORE_SCHEMA_V1, "trust_level": "9"}),
        ] {
            let credential = credential(info, Value::String(HOLDER_HEX.to_owned()));
            assert_eq!(
                parse_trust_score_badge_v1(&credential),
                Err(TrustScoreSchemaError::InvalidTrustLevel)
            );
        }
    }

    #[test]
    fn rejects_non_canonical_holder_bindings() {
        let npub = nostr::PublicKey::parse(HOLDER_HEX)
            .expect("valid key")
            .to_bech32()
            .expect("bech32 encodes");
        for blind_msg in [
            Value::Null,
            serde_json::json!({"holder_public_key": HOLDER_HEX}),
            Value::String(HOLDER_HEX.to_uppercase()),
            Value::String(npub),
            Value::String("not-a-key".to_owned()),
        ] {
            let credential = credential(trust_score_info_v1(3).expect("legal level"), blind_msg);
            assert_eq!(
                parse_trust_score_badge_v1(&credential),
                Err(TrustScoreSchemaError::InvalidHolderBinding)
            );
        }
    }
}
