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

## Multi-Signer Credentials

A verifier trusts a multi-signer group by configuring its group id, the member
issuer authorities it trusts for that group, and a threshold. Each member
authority is verified like `addIssuerAuthority()`. Members are trusted for the
group only; configuring a group does not trust its members as single issuers.

```ts
const verifier = new VerificationContext();

// Any two of the community's three issuers.
verifier.addMultiSignerGroup(groupId, [issuerA, issuerB, issuerC], 2);
verifier.verifyMultiSignerCredential(credential); // true
verifier.verifyMultiSignerCredentialAuthorization(credential, holderAuthorization); // true
```

Verification counts valid signatures from distinct trusted members:

- A proof tagged with an issuer that is not a configured member is ignored.
- A proof that does not verify under its tagged member's issuance key is ignored.
- Several proofs by the same member count once.
- Fewer than the threshold of valid members fails with an error naming both
  counts.

`addMultiSignerGroup()` rejects a threshold of 0 or above the number of
members, a member listed twice, two members sharing an issuance key, and a group
id equal to a member's id.

To apply your own policy instead of a fixed threshold, ask which members signed:

```ts
const signers = verifier.validMultiSignerMembers(credential); // member issuer ids
```

`verifyMultiSignerCredentialAuthorization()` performs the same holder
authorization checks as `verifyCredentialAuthorization()` over the credential
payload. The digest ignores proofs, so authorizations stay valid when the holder
adds further member proofs.

### Known Gap: Multi-Signer Revocation

Revocation is not yet defined for multi-signer credentials.
`verifyMultiSignerCredential()` does not consult ingested revocations, and
`revokeCredential()` only accepts single-issuer credentials. The options for a
follow-up are:

- **Any trusted member can revoke.** Simple and fast, but one member can
  withdraw a credential the others agreed on.
- **A threshold of members must revoke.** Symmetric with issuance, but
  revocation needs coordination and a revocation format that collects several
  member signatures.

Until this is decided, verifiers that need to withdraw multi-signer credentials
must do so through their own policy, for example by removing a member from the
group or checking `info` against their own lists.

## Current Error Model

The WASM API currently reports validation and verification failures as thrown
JavaScript errors. Machine-readable result codes are still a planned API
improvement.
