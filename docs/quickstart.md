---
title: Quickstart
---

# Quickstart

This guide shows the smallest useful TypeScript flow with the npm package:
create an issuer authority, create a holder issuance request, issue a blind
signature, finalize a credential, authorize an external app to use it, verify
the authorization, and then revoke the credential.

## Imports

The high-level API is organized around runtime contexts:

```ts
import type {
  HolderAuthorizationRequest,
  JsonValue,
  RevocationLocation,
} from "@fedibtc/peerbadge-sdk-wasm";
import {
  HolderContext,
  IssuerContext,
  PendingIssuance,
  VerificationContext,
} from "@fedibtc/peerbadge-sdk-wasm";
```

## Full Flow

```ts
const credentialInfo = {
  schema: "example-membership-v1.0",
  trust_level: 7,
} satisfies JsonValue;

> The schema strings in these examples are placeholders. Deployed first-party
> schemas (such as `fedi-trust-score-v1.0`) are defined once in
> [`crates/schemas`](../crates/schemas) — use its constructors and parsers instead
> of hand-building `info`, and never reuse a deployed schema string for a new
> credential type.


const revocationLocations = [
  {
    protocol: "nostr",
    location: "wss://relay.example.com",
  },
] satisfies readonly RevocationLocation[];

// Issuer: create a signed public issuer authority.
const issuer = IssuerContext.generate();
const issuerAuthority = issuer.issuerAuthority(revocationLocations);

// Holder: create a blinded issuance request and keep pending state locally.
const holder = HolderContext.generate();
const blindMsg = holder.publicKey;
const { request, pending } = PendingIssuance.createRequest(
  issuerAuthority,
  credentialInfo,
  blindMsg,
);

// Issuer: bind visible credential info and blind-sign the holder request.
const response = issuer.issueCredential(credentialInfo, request);

// Holder: unblind the response and finalize the credential.
const credential = pending.finalize(issuerAuthority, response);

// Verifier: trust the issuer authority before accepting credentials.
const verifier = new VerificationContext();
verifier.addIssuerAuthority(issuerAuthority);

const verified = verifier.verifyCredential(credential);
console.log(verified); // true

// Holder: authorize an external application subject key to use this credential.
// Subject-key generation and live proof-of-possession are application-owned.
const subjectPubkey = "33".repeat(32);
const holderAuthorizationRequest = {
  subject_pubkey: subjectPubkey,
} satisfies HolderAuthorizationRequest;
const holderAuthorization = holder.authorizeCredentialUse(
  holderAuthorizationRequest,
  credential,
);

// Verifier: check the credential, holder authorization, holder binding,
// authorized credential digest, and authorization issued-at time.
const authorized = verifier.verifyCredentialAuthorization(
  credential,
  holderAuthorization,
);
console.log(authorized); // true

// Issuer: create a signed revocation for the finalized credential.
const signedRevocation = issuer.revokeCredential(credential);

// Verifier: ingest revocations before presenting a credential as accepted.
verifier.addRevocation(signedRevocation);

try {
  verifier.verifyCredential(credential);
} catch (error) {
  console.log(error instanceof Error ? error.message : error);
  // credential has been revoked
}
```

## Important Fields

`credentialInfo` is visible to the issuer during signing and becomes
`credential.info` in the final credential.

`blindMsg` is hidden from the issuer during signing and becomes
`credential.blind_msg` after finalization. For the current Fedi/Nostr use case,
this is usually the holder's public key, but the SDK accepts any JSON value.
Holder authorization verification expects the common Fedi/Nostr shape where
`credential.blind_msg` is the holder public key string.

`HolderAuthorizationRequest` names the subject key asking to act under the
holder identity. The holder chooses the selected credential separately when
signing. The SDK derives the signed `credential_digest` from that credential and
sets the authorization `issued_at` field.

## Persisting Pending Issuance

If the holder may reload or leave the page before receiving the issuer response,
store the pending state:

```ts
const credentialInfo = {
  schema: "example-membership-v1.0",
  trust_level: 7,
} satisfies JsonValue;

const { request, pending } = PendingIssuance.createRequest(
  issuerAuthority,
  credentialInfo,
  blindMsg,
);

const pendingState = pending.exportState();
localStorage.setItem("pending-issuance", pendingState);

// Send request to the issuer through your application transport.
```

Import that state before finalizing:

```ts
const pendingState = localStorage.getItem("pending-issuance");

if (!pendingState) {
  throw new Error("missing pending issuance state");
}

const importedPending = PendingIssuance.importState(pendingState);

// Receive the issuer's response through your application transport.
const response = await receiveIssuanceResponse();
const credential = importedPending.finalize(issuerAuthority, response);
localStorage.removeItem("pending-issuance");
```

The exported pending state is sensitive holder-side issuance material. Do not
log it or send it to the issuer.

## What This Example Omits

The SDK owns protocol-sensitive operations:

- Key generation and import/export.
- Issuer authority signing.
- Holder blinding and pending issuance state.
- Issuer blind signing.
- Holder finalization.
- Holder authorization signing.
- Credential verification.
- Holder authorization verification.
- Revocation signing and verification.
- Canonical JSON encoding used by signatures and digests.

Your app still owns:

- Storage for keys, pending issuance state, credentials, and trusted issuers.
- Storage and transport for holder authorizations.
- QR code generation and scanning.
- Nostr relay, HTTP, file, or other transport.
- UI state and user confirmation.
- Subject-key generation, custody, and proof-of-possession.
- Verifier policy and trust-list management.
- Revocation refresh jobs.

## Source Of Truth

The quickstart mirrors the tested flows in `test/full-issuance-flow.test.ts` and
`test/credential.test.ts`. Future examples should stay close to those tests or
be compiled directly in CI.
