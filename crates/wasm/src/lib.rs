use peerbadge_protocol as protocol;
use peerbadge_schemas as schemas;
use serde::{de::DeserializeOwned, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const TYPESCRIPT_SURFACE: &'static str = r#"
/** Any JSON value accepted by credential info and blind-message fields. */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { readonly [key: string]: JsonValue };

/** Holder-created request sent to an issuer during credential issuance. */
export interface IssuanceRequest {
  readonly version: 1;
  /** Unpadded URL-safe base64 encoded PBRSA blinded message. */
  readonly blinded_message: string;
}

/** Issuer-created response containing the blind signature for an issuance request. */
export interface IssuanceResponse {
  readonly version: 1;
  /** Nostr public key identifying the issuer that signed the response. */
  readonly issuer_id: string;
  /** Issuer-visible credential information bound into the blind signature. */
  readonly info: JsonValue;
  /** Unpadded URL-safe base64 encoded PBRSA blind signature. */
  readonly blind_signature: string;
}

/** Exported issuer secret material for application-managed backup or restore. */
export interface IssuerSecretKeys {
  /** Nostr issuer identity secret key encoded as hex. */
  readonly issuer_id_secret_key: string;
  /** Unpadded URL-safe base64 encoded PBRSA issuance secret key. */
  readonly issuance_secret_key: string;
}

/** Final credential presented by a holder to a verifier. */
export interface SignedCredential {
  readonly version: 1;
  readonly credential: Credential;
  readonly proof: CredentialProof;
}

/** Holder-signed authorization allowing an auxiliary subject key to use credentials. */
export interface HolderAuthorization {
  readonly version: 1;
  readonly authorization: HolderAuthorizationStatement;
  readonly proof: SchnorrSignatureProof;
}

/** Input for `HolderContext.authorizeCredentialUse`. */
export interface HolderAuthorizationRequest {
  /** External application's Nostr subject public key. */
  readonly subject_pubkey: string;
}

/** Holder statement signed by `HolderContext.authorizeCredentialUse` and returned in `HolderAuthorization`. */
export interface HolderAuthorizationStatement {
  /** Nostr public key identifying the holder. */
  readonly holder_id_pubkey: string;
  /** External application's Nostr subject public key. */
  readonly subject_pubkey: string;
  /** Credential digest this authorization allows the subject to present. */
  readonly credential_digest: CredentialDigest;
  /** Unix timestamp in seconds. */
  readonly issued_at: Timestamp;
}

/** Unpadded URL-safe base64 encoded canonical credential digest. */
export type CredentialDigest = string;

/** Unix timestamp in seconds. */
export type Timestamp = number;

/** Credential payload signed by the issuer's issuance key. */
export interface Credential {
  /** Nostr public key identifying the issuer. */
  readonly issuer_id_pubkey: string;
  /** Credential information that was visible to the issuer during issuance. */
  readonly info: JsonValue;
  /** Holder-controlled value hidden during issuance and disclosed in the final credential. */
  readonly blind_msg: JsonValue;
}

/** Proof over a finalized credential payload. */
export interface CredentialProof {
  /** Unpadded URL-safe base64 encoded PBRSA credential signature. */
  readonly signature: string;
}

/** Signed issuer metadata that verifiers trust before accepting credentials. */
export interface IssuerAuthority {
  readonly version: 1;
  readonly issuer: Issuer;
  readonly proof: SchnorrSignatureProof;
}

/** Schnorr signature proof encoded for JSON transport. */
export interface SchnorrSignatureProof {
  readonly signature: string;
}

/** Public issuer metadata bound into an issuer authority. */
export interface Issuer {
  /** Nostr public key identifying the issuer. */
  readonly issuer_id_pubkey: string;
  /** Unpadded URL-safe base64 encoded PBRSA issuance public key. */
  readonly issuance_key: string;
  /** Locations where applications may fetch this issuer's revocations. */
  readonly revocation: readonly RevocationLocation[];
}

/** Issuer-signed credential revocation object. */
export interface SignedRevocation {
  readonly version: 1;
  readonly revocation: Revocation;
  readonly proof: RevocationProof;
}

/** Issuer identity proof for a signed revocation. */
export interface RevocationProof {
  /** Nostr public key identifying the issuer that signed the revocation. */
  readonly issuer_id_pubkey: string;
  /** Schnorr signature over the revocation payload. */
  readonly signature: string;
}

/** Revocation payload signed by an issuer identity key. */
export interface Revocation {
  /** Unpadded URL-safe base64 encoded SHA-256 digest. */
  readonly credential_digest: CredentialDigest;
}

/** Application-owned location where issuer revocations may be published. */
export interface RevocationLocation {
  /** Transport or publication protocol name, such as "nostr". */
  readonly protocol: string;
  /** Protocol-specific location, such as a relay URL. */
  readonly location: string;
}

/** Result of creating a holder issuance request. */
export interface PendingIssuanceResult {
  /** Request to send to the issuer. */
  readonly request: IssuanceRequest;
  /** Local holder state required to finalize the issuer response. */
  readonly pending: PendingIssuance;
}
"#;

fn from_js<T: DeserializeOwned>(value: JsValue) -> Result<T, JsError> {
    serde_wasm_bindgen::from_value(value).map_err(|error| JsError::new(&error.to_string()))
}

fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsError> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| JsError::new(&error.to_string()))
}

fn current_unix_timestamp() -> Result<u64, JsError> {
    let seconds = (js_sys::Date::now() / 1000.0).floor();
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(JsError::new("current time must be non-negative"));
    }

    Ok(seconds as u64)
}

fn reflect_error(error: JsValue) -> JsError {
    JsError::new(
        &error
            .as_string()
            .unwrap_or_else(|| "failed to set JS object property".to_owned()),
    )
}

/// Install a tracing subscriber that forwards Rust tracing events to the JavaScript console.
///
/// Returns `true` when this call installs the subscriber. Returns `false` when another global
/// tracing subscriber is already installed.
#[wasm_bindgen(js_name = initTracing)]
pub fn init_tracing() -> bool {
    tracing_wasm::try_set_as_global_default().is_ok()
}

#[wasm_bindgen]
#[derive(Clone)]
/// Issuer-side context for creating issuer authorities, issuing credentials, and revoking credentials.
pub struct IssuerContext {
    inner: protocol::IssuerContext,
}

#[wasm_bindgen]
impl IssuerContext {
    /// Generate a new issuer context with fresh issuer identity and issuance keys.
    #[wasm_bindgen(js_name = generate)]
    pub fn generate() -> Result<IssuerContext, JsError> {
        Ok(Self {
            inner: protocol::IssuerContext::generate()?,
        })
    }

    /// Generate a new issuer context using a thread-local CSPRNG seeded from the system RNG.
    #[wasm_bindgen(js_name = generateWithThreadRng)]
    pub fn generate_with_thread_rng() -> Result<IssuerContext, JsError> {
        Ok(Self {
            inner: protocol::IssuerContext::generate_with_thread_rng()?,
        })
    }

    /// Generate a new issuer context using direct system randomness for each keygen draw.
    #[wasm_bindgen(js_name = generateWithSystemRng)]
    pub fn generate_with_system_rng() -> Result<IssuerContext, JsError> {
        Ok(Self {
            inner: protocol::IssuerContext::generate_with_system_rng()?,
        })
    }

    /// Import an issuer context from previously exported issuer secret keys.
    #[wasm_bindgen(js_name = importSecretKey)]
    pub fn import_secret_key(
        #[wasm_bindgen(unchecked_param_type = "IssuerSecretKeys")] secret_key: JsValue,
    ) -> Result<IssuerContext, JsError> {
        let secret_key: protocol::IssuerSecretKeys = from_js(secret_key)?;
        Ok(Self {
            inner: protocol::IssuerContext::import_secret_key(&secret_key)?,
        })
    }

    /// Export this issuer's secret keys for application-managed backup or restore.
    #[wasm_bindgen(js_name = exportSecretKey, unchecked_return_type = "IssuerSecretKeys")]
    pub fn export_secret_key(&self) -> Result<JsValue, JsError> {
        to_js(&self.inner.export_secret_key()?)
    }

    /// Issue a blind signature response for a holder issuance request.
    #[wasm_bindgen(js_name = issueCredential, unchecked_return_type = "IssuanceResponse")]
    pub fn issue_credential(
        &self,
        #[wasm_bindgen(unchecked_param_type = "JsonValue")] info: JsValue,
        #[wasm_bindgen(unchecked_param_type = "IssuanceRequest")] request: JsValue,
    ) -> Result<JsValue, JsError> {
        let info: serde_json::Value = from_js(info)?;
        let request: protocol::IssuanceRequest = from_js(request)?;
        to_js(&self.inner.issue_credential(info, &request)?)
    }

    /// Build and sign this issuer's public authority with its revocation locations.
    #[wasm_bindgen(js_name = issuerAuthority, unchecked_return_type = "IssuerAuthority")]
    pub fn issuer_authority(
        &self,
        #[wasm_bindgen(unchecked_param_type = "readonly RevocationLocation[]")] revocation: JsValue,
    ) -> Result<JsValue, JsError> {
        let revocation: Vec<protocol::RevocationLocation> = from_js(revocation)?;
        to_js(&self.inner.issuer_authority(revocation)?)
    }

    /// Sign a revocation for a finalized credential issued by this issuer.
    #[wasm_bindgen(js_name = revokeCredential, unchecked_return_type = "SignedRevocation")]
    pub fn revoke_credential(
        &self,
        #[wasm_bindgen(unchecked_param_type = "SignedCredential")] credential: JsValue,
    ) -> Result<JsValue, JsError> {
        let credential: protocol::SignedCredential = from_js(credential)?;
        to_js(&self.inner.revoke_credential(&credential)?)
    }
}

#[wasm_bindgen]
#[derive(Clone)]
/// Holder-side context for generating holder identity keys.
pub struct HolderContext {
    inner: protocol::HolderContext,
}

#[wasm_bindgen]
impl HolderContext {
    /// Generate a new holder context with fresh holder identity keys.
    #[wasm_bindgen(js_name = generate)]
    pub fn generate() -> HolderContext {
        Self {
            inner: protocol::HolderContext::generate(),
        }
    }

    /// Import a holder context from a previously exported holder secret key.
    #[wasm_bindgen(js_name = importSecretKey)]
    pub fn import_secret_key(secret_key: String) -> Result<HolderContext, JsError> {
        Ok(Self {
            inner: protocol::HolderContext::import_secret_key(&secret_key)?,
        })
    }

    /// Export this holder's secret key for application-managed backup or restore.
    #[wasm_bindgen(js_name = exportSecretKey)]
    pub fn export_secret_key(&self) -> String {
        self.inner.export_secret_key()
    }

    /// Return the holder's Nostr public key.
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> String {
        self.inner.public_key().to_string()
    }

    /// Create a signed holder authorization for an auxiliary subject key and selected credential.
    #[wasm_bindgen(js_name = authorizeCredentialUse, unchecked_return_type = "HolderAuthorization")]
    pub fn authorize_credential_use(
        &self,
        #[wasm_bindgen(unchecked_param_type = "HolderAuthorizationRequest")] request: JsValue,
        #[wasm_bindgen(unchecked_param_type = "SignedCredential")] credential: JsValue,
    ) -> Result<JsValue, JsError> {
        let request: protocol::HolderAuthorizationRequest = from_js(request)?;
        let credential: protocol::SignedCredential = from_js(credential)?;
        to_js(&self.inner.authorize_credential_use_at_time(
            request,
            &credential,
            current_unix_timestamp()?,
        )?)
    }
}

#[wasm_bindgen]
/// Holder-side pending issuance state required to finalize one issuer response.
pub struct PendingIssuance {
    inner: protocol::PendingIssuance,
}

#[wasm_bindgen]
impl PendingIssuance {
    /// Create a blinded holder issuance request and local pending issuance state.
    #[wasm_bindgen(js_name = createRequest, unchecked_return_type = "PendingIssuanceResult")]
    pub fn create_request(
        #[wasm_bindgen(unchecked_param_type = "IssuerAuthority")] issuer_authority: JsValue,
        #[wasm_bindgen(unchecked_param_type = "JsonValue")] info: JsValue,
        #[wasm_bindgen(unchecked_param_type = "JsonValue")] blind_msg: JsValue,
    ) -> Result<JsValue, JsError> {
        let issuer_authority: protocol::IssuerAuthority = from_js(issuer_authority)?;
        let info: serde_json::Value = from_js(info)?;
        let blind_msg: serde_json::Value = from_js(blind_msg)?;
        let (request, pending) = protocol::PendingIssuance::create_request(
            &issuer_authority.issuer.issuance_key,
            issuer_authority.issuer.issuer_id_pubkey,
            info,
            blind_msg,
        )?;

        let result = js_sys::Object::new();
        js_sys::Reflect::set(&result, &JsValue::from_str("request"), &to_js(&request)?)
            .map_err(reflect_error)?;
        js_sys::Reflect::set(
            &result,
            &JsValue::from_str("pending"),
            &JsValue::from(PendingIssuance { inner: pending }),
        )
        .map_err(reflect_error)?;
        Ok(result.into())
    }

    /// Export this pending issuance state as a JSON string for application storage.
    #[wasm_bindgen(js_name = exportState)]
    pub fn export_state(&self) -> Result<String, JsError> {
        Ok(self.inner.export_state()?)
    }

    /// Import pending issuance state previously returned by `exportState`.
    #[wasm_bindgen(js_name = importState)]
    pub fn import_state(state: String) -> Result<PendingIssuance, JsError> {
        Ok(Self {
            inner: protocol::PendingIssuance::import_state(&state)?,
        })
    }

    /// Finalize an issuer response into a signed credential.
    #[wasm_bindgen(js_name = finalize, unchecked_return_type = "SignedCredential")]
    pub fn finalize(
        self,
        #[wasm_bindgen(unchecked_param_type = "IssuerAuthority")] issuer_authority: JsValue,
        #[wasm_bindgen(unchecked_param_type = "IssuanceResponse")] response: JsValue,
    ) -> Result<JsValue, JsError> {
        let issuer_authority: protocol::IssuerAuthority = from_js(issuer_authority)?;
        let response: protocol::IssuanceResponse = from_js(response)?;
        if issuer_authority.issuer.issuer_id_pubkey != response.issuer_id {
            return Err(protocol::CredentialsError::IssuerIdMismatch.into());
        }
        to_js(
            &self
                .inner
                .finalize(&issuer_authority.issuer.issuance_key, &response)?,
        )
    }
}

#[wasm_bindgen]
/// Verifier-side context containing trusted issuers and ingested revocations.
pub struct VerificationContext {
    inner: protocol::VerificationContext,
}

#[wasm_bindgen]
impl VerificationContext {
    /// Create an empty verification context.
    #[wasm_bindgen(constructor)]
    pub fn new() -> VerificationContext {
        Self {
            inner: protocol::VerificationContext::new(),
        }
    }

    /// Verify and trust an issuer authority for future credential checks.
    #[wasm_bindgen(js_name = addIssuerAuthority)]
    pub fn add_issuer_authority(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "IssuerAuthority")] issuer_authority: JsValue,
    ) -> Result<(), JsError> {
        let issuer_authority: protocol::IssuerAuthority = from_js(issuer_authority)?;
        Ok(self.inner.add_issuer_authority(&issuer_authority)?)
    }

    /// Verify and store a signed revocation from a trusted issuer.
    #[wasm_bindgen(js_name = addRevocation)]
    pub fn add_revocation(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "SignedRevocation")] revocation: JsValue,
    ) -> Result<(), JsError> {
        let revocation: protocol::SignedRevocation = from_js(revocation)?;
        Ok(self.inner.add_revocation(&revocation)?)
    }

    /// Verify a finalized credential against trusted issuers and ingested revocations.
    #[wasm_bindgen(js_name = verifyCredential)]
    pub fn verify_credential(
        &self,
        #[wasm_bindgen(unchecked_param_type = "SignedCredential")] credential: JsValue,
    ) -> Result<bool, JsError> {
        let credential: protocol::SignedCredential = from_js(credential)?;
        self.inner.verify_credential(&credential)?;
        Ok(true)
    }

    /// Verify a credential and holder authorization.
    #[wasm_bindgen(js_name = verifyCredentialAuthorization)]
    pub fn verify_credential_authorization(
        &self,
        #[wasm_bindgen(unchecked_param_type = "SignedCredential")] credential: JsValue,
        #[wasm_bindgen(unchecked_param_type = "HolderAuthorization")] authorization: JsValue,
    ) -> Result<bool, JsError> {
        let credential: protocol::SignedCredential = from_js(credential)?;
        let authorization: protocol::HolderAuthorization = from_js(authorization)?;

        self.inner.verify_credential_authorization_at_time(
            &credential,
            &authorization,
            current_unix_timestamp()?,
        )?;
        Ok(true)
    }
}

#[wasm_bindgen(typescript_custom_section)]
const TYPESCRIPT_SCHEMAS_SURFACE: &'static str = r#"
/** Parsed payload of a `fedi-trust-score-v1.0` badge. */
export interface TrustScoreBadgeV1 {
  /** Public result of attester-private scoring; acceptability is caller policy. */
  readonly trust_level: number;
  /** Holder Nostr public key bound by the revealed `blind_msg`, canonical lowercase hex. */
  readonly holder_pubkey: string;
}
"#;

/// The `info.schema` identifier for trust-score badges, revision v1.0.
#[wasm_bindgen(js_name = trustScoreSchemaV1)]
pub fn trust_score_schema_v1() -> String {
    schemas::TRUST_SCORE_SCHEMA_V1.to_owned()
}

/// Build the issuance `info` value for a `fedi-trust-score-v1.0` badge.
///
/// Rejects anything but an integer in the documented `1..=12` trust model —
/// no silent truncation or wrap-around of illegal inputs.
#[wasm_bindgen(js_name = trustScoreInfoV1, unchecked_return_type = "JsonValue")]
pub fn trust_score_info_v1(trust_level: f64) -> Result<JsValue, JsError> {
    if !trust_level.is_finite() || trust_level.fract() != 0.0 || trust_level < 0.0 {
        return Err(JsError::new("trust_level must be a non-negative integer"));
    }
    to_js(&schemas::trust_score_info_v1(trust_level as u64)?)
}

/// Build the issuance `blind_msg` value binding a `fedi-trust-score-v1.0` badge to a holder.
#[wasm_bindgen(js_name = trustScoreBlindMsgV1, unchecked_return_type = "JsonValue")]
pub fn trust_score_blind_msg_v1(holder_pubkey: String) -> Result<JsValue, JsError> {
    let holder: protocol::HolderId = holder_pubkey
        .parse()
        .map_err(|_| JsError::new("holder_pubkey is not a valid Nostr public key"))?;
    to_js(&schemas::trust_score_blind_msg_v1(&holder.0))
}

/// Parse a cryptographically verified credential as a `fedi-trust-score-v1.0` badge.
///
/// Schema validation only — verify the credential (and any holder authorization)
/// with a `VerificationContext` first.
#[wasm_bindgen(js_name = parseTrustScoreBadgeV1, unchecked_return_type = "TrustScoreBadgeV1")]
pub fn parse_trust_score_badge_v1(
    #[wasm_bindgen(unchecked_param_type = "SignedCredential")] credential: JsValue,
) -> Result<JsValue, JsError> {
    let credential: protocol::SignedCredential = from_js(credential)?;
    let badge = schemas::parse_trust_score_badge_v1(&credential.credential)?;
    to_js(&serde_json::json!({
        "trust_level": badge.trust_level,
        "holder_pubkey": badge.holder_pubkey.to_string(),
    }))
}
