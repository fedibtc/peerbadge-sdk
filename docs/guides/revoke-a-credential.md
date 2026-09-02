---
title: Revoke A Credential
---

# Revoke A Credential

Issuers revoke a finalized credential by signing its credential digest.

```ts
const signedRevocation = issuer.revokeCredential(credential);
```

The returned `SignedRevocation` is a transportable JSON object. The SDK does not
publish it to relays, HTTP endpoints, files, or QR codes.

## Ingest Revocations

Verifiers must trust the issuer authority before accepting revocations from that
issuer.

```ts
const verifier = new VerificationContext();

verifier.addIssuerAuthority(issuerAuthority);
verifier.addRevocation(signedRevocation);
```

After a matching revocation is ingested, the credential is rejected.

```ts
try {
  verifier.verifyCredential(credential);
} catch (error) {
  console.log(error instanceof Error ? error.message : error);
  // credential has been revoked
}
```

## Publication Is App-Owned

Issuer authorities contain `revocation` locations so applications can advertise
where revocations may be found.

```ts
const issuerAuthority = issuer.issuerAuthority([
  {
    protocol: "nostr",
    location: "wss://relay.example.com",
  },
]);
```

Your application decides how to publish, fetch, cache, and refresh revocations.
Before presenting a credential as accepted, verifiers should ingest revocations
from every location they trust for that issuer.
