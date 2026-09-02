# peerbadge-protocol

Rust-facing implementation of the PeerBadge protocol for issuing, holding, verifying, and revoking privacy-preserving credentials with partially blind RSA signatures.

This crate owns the protocol-sensitive pieces: issuer and holder key handling, holder blinding, issuer partial blind signing, holder finalization, holder authorization signing, credential verification, signed issuer metadata, signed revocations, canonicalization, and typed error handling.

It deliberately does not own application concerns such as persistence, QR codes, Nostr relay I/O, HTTP fetching, UI state, subject-key custody, verifier policy, or revocation list refresh jobs. Credential `info` and `blind_msg` are arbitrary `serde_json::Value` objects; callers decide what their schemas and claims mean.

## Usage

```rust
use peerbadge_protocol::{
    HolderAuthorizationRequest, HolderContext, IssuerContext, PendingIssuance,
    RevocationLocation, SubjectPubkey, VerificationContext,
};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let credential_info = json!({
        "schema": "example-membership-v1.0",
        "trust_level": 7,
    });

    let revocation_locations = vec![RevocationLocation {
        protocol: "nostr".to_owned(),
        location: "wss://relay.example.com".to_owned(),
    }];

    // Issuer creates signed public metadata for verifiers and holders.
    let issuer = IssuerContext::generate()?;
    let issuer_authority = issuer.issuer_authority(revocation_locations)?;

    // Holder creates a blinded issuance request and keeps pending state locally.
    let holder = HolderContext::generate();
    let blind_msg = json!(holder.public_key());
    let (request, pending) = PendingIssuance::create_request(
        &issuer_authority.issuer.issuance_key,
        issuer_authority.issuer.issuer_id_pubkey.clone(),
        credential_info.clone(),
        blind_msg,
    )?;

    // Issuer signs the blinded request while binding the visible credential info.
    let response = issuer.issue_credential(credential_info, &request)?;

    // Holder unblinds and finalizes the response into a verifiable credential.
    let credential = pending.finalize(&issuer_authority.issuer.issuance_key, &response)?;

    // Verifier must trust the issuer authority before accepting credentials.
    let mut verifier = VerificationContext::new();
    verifier.add_issuer_authority(&issuer_authority)?;
    verifier.verify_credential(&credential)?;

    // Holder authorizes an external application subject key to use this credential.
    let subject_pubkey: SubjectPubkey = "33".repeat(32).parse()?;
    let authorization = holder.authorize_credential_use(
        HolderAuthorizationRequest { subject_pubkey },
        &credential,
    )?;
    verifier.verify_credential_authorization(&credential, &authorization)?;

    // Issuer can revoke a finalized credential. Transport/publication is app-owned.
    let signed_revocation = issuer.revoke_credential(&credential)?;
    verifier.add_revocation(&signed_revocation)?;
    assert!(verifier.verify_credential(&credential).is_err());

    Ok(())
}
```

## Public API

The high-level API is organized around runtime contexts and wire structs:

- `IssuerContext`: generate/import/export issuer identity and issuance keys, create signed issuer authorities, issue credentials, and create signed revocations
- `HolderContext`: generate/import/export holder identity keys, expose the holder public key, and authorize external app keys to use credentials
- `PendingIssuance`: create holder issuance requests and retain the unblinding state needed to finalize an issuer response
- `VerificationContext`: trust signed issuer authorities, verify signed revocations, verify finalized credentials, and verify holder authorizations
- `IssuerAuthority`, `IssuanceRequest`, `IssuanceResponse`, `SignedCredential`, `HolderAuthorization`, and `SignedRevocation`: serde-compatible protocol wire objects

All fallible operations return `Result<_, CredentialsError>`. Important verification failures include `UnknownIssuer`, `CredentialRevoked`, `IssuerIdMismatch`, `InfoMismatch`, `HolderIdMismatch`, `AuthorizationCredentialDigestMismatch`, `AuthorizationNotYetValid`, and `VerificationFailed`.

## Credential Flow

The finalized `SignedCredential` contains issuer-visible `info`, holder-hidden `blind_msg`, and an unblinded PBRSA signature. When serialized with `serde_json`, it has this shape:

```json
{
  "version": 1,
  "credential": {
    "issuer_id_pubkey": "nostr-issuer-public-key",
    "info": {
      "schema": "example-membership-v1.0",
      "trust_level": 7
    },
    "blind_msg": "anonymous-holder-public-key"
  },
  "proof": {
    "signature": "base64url-rsa-signature"
  }
}
```

During issuance, `info` is public to the issuer and `blind_msg` is hidden from the issuer while signing. `PendingIssuance::create_request` canonicalizes both values into the PBRSA metadata/message split, returns the blinded `IssuanceRequest`, and stores local unblinding state. `IssuerContext::issue_credential` signs the blinded request with the issuer's issuance key and visible `info`. `PendingIssuance::finalize` checks that the response matches the original issuer and `info`, unblinds the signature, builds a `SignedCredential`, and verifies it before returning.

For holder authorization verification, the current Fedi/Nostr convention is
that `credential.blind_msg` contains the holder public key string. The SDK uses
that value to bind a `HolderAuthorization` to the presented credential.

## Serialization

Protocol structs derive `Serialize` and `Deserialize` for stable JSON transport. Byte fields serialize as unpadded URL-safe base64 strings, including PBRSA public keys, blinded messages, blind signatures, finalized credential signatures, Schnorr signatures, and credential digests. `ProtocolV1` serializes as the JSON number `1` and rejects other versions during deserialization.

Canonical protocol inputs use RFC 8785/JCS encoding before signing or hashing. The crate exposes canonicalization helpers for advanced integrations:

- `canonicalize_pbrsa_info`
- `canonicalize_pbrsa_blind_msg`
- `canonicalize_issuer_authority`
- `canonicalize_revocation`
- `canonicalize_credential`
- `canonicalize_holder_authorization`

Most applications should use the context APIs instead of calling these helpers directly.

## Key Persistence

Issuer keys can be exported and imported with `IssuerSecretKeys`:

```rust
use peerbadge_protocol::IssuerContext;

let issuer = IssuerContext::generate()?;
let secret_keys = issuer.export_secret_key()?;
let imported = IssuerContext::import_secret_key(&secret_keys)?;

assert_eq!(
    issuer.issuer_authority(vec![])?.issuer.issuer_id_pubkey,
    imported.issuer_authority(vec![])?.issuer.issuer_id_pubkey,
);
```

Holder keys can be exported and imported as a string secret key:

```rust
use peerbadge_protocol::HolderContext;

let holder = HolderContext::generate();
let secret_key = holder.export_secret_key();
let imported = HolderContext::import_secret_key(&secret_key)?;

assert_eq!(holder.public_key(), imported.public_key());
```

## Development

From the repository root:

```sh
devenv shell
pnpm run test:rust
```

Or run the Rust workspace directly:

```sh
cargo test --workspace
```
