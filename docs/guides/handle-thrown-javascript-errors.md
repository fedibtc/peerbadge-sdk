---
title: Handle Thrown JavaScript Errors
---

# Handle Thrown JavaScript Errors

The WASM API currently reports validation and verification failures by throwing
JavaScript errors. Methods that parse, verify, finalize, or import protocol
objects can throw.

```ts
try {
  verifier.verifyCredential(credential);
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
}
```

## Common Failure Points

`addIssuerAuthority()` can throw when an issuer authority is malformed or its proof
does not verify.

`PendingIssuance.importState()` can throw when exported state is malformed or
uses an unsupported version.

`PendingIssuance.finalize()` can throw when the issuer authority, response, pending
state, or visible `info` do not match.

`VerificationContext.verifyCredential()` can throw when the issuer is unknown,
the credential proof fails, or the credential has been revoked.

`HolderContext.authorizeCredentialUse()` can throw when the request contains an
invalid subject key, when the credential shape is invalid, or when the selected
credential is not bound to the signing holder.

`VerificationContext.verifyCredentialAuthorization()` can throw when the
credential fails verification, the holder authorization proof fails, the
credential digest is not authorized, the credential holder does not
match the authorization holder, or the authorization `issued_at` is in the
future.

`IssuerContext.importSecretKey()` and `HolderContext.importSecretKey()` can
throw when stored secret material is malformed.

## Recommended Pattern

Keep protocol failures separate from application transport failures:

```ts
async function verifyPresentedCredential() {
  const verifier = new VerificationContext();
  verifier.addIssuerAuthority(issuerAuthority);

  for (const revocation of revocations) {
    verifier.addRevocation(revocation);
  }

  return verifier.verifyCredential(credential);
}

try {
  await verifyPresentedCredential();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  // Show a generic rejection to users. Log detailed messages only where safe.
  console.warn("credential rejected", message);
}
```

Machine-readable error codes or result objects are a planned API improvement.
For now, avoid depending on exact error message strings for product logic.
