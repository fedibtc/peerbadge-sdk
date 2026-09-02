---
title: Verification And Revocation
---

# Verification And Revocation

Verification is stateful. A verifier must first trust one or more issuer authorities
before it can accept credentials from those issuers.

```ts
const verifier = new VerificationContext();

verifier.addIssuerAuthority(issuerAuthority);
verifier.verifyCredential(credential); // true
```

If the issuer is unknown, verification throws an error.

```ts
const verifier = new VerificationContext();

verifier.verifyCredential(credential); // throws: unknown issuer
```

## Holder Authorizations

Wallets can authorize an external application subject key to use selected
credentials. The verifier checks the credential and holder authorization
together.

```ts
verifier.addIssuerAuthority(issuerAuthority);
verifier.verifyCredentialAuthorization(credential, holderAuthorization); // true
```

This SDK check verifies issuer trust, credential revocation state, the holder
authorization signature, holder binding, authorized credential digest, and
authorization issued-at time. The verifier application still checks subject-key
proof-of-possession and credential-schema policy.

## Revocations

Issuers revoke credentials by signing the digest of a finalized credential.
Transport and publication are application concerns.

```ts
const signedRevocation = issuer.revokeCredential(credential);

verifier.addIssuerAuthority(issuerAuthority);
verifier.addRevocation(signedRevocation);
verifier.verifyCredential(credential); // throws: credential has been revoked
```

Verifiers should ingest revocations from every location they trust for an issuer
before presenting a credential as accepted.

## Current Error Model

The WASM API currently reports validation and verification failures as thrown
JavaScript errors. Machine-readable result codes are still a planned API
improvement.
