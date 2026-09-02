---
title: Persist Pending Issuance
---

# Persist Pending Issuance

`PendingIssuance` is holder-side state created with an issuance request. It must
survive until the holder receives the issuer response.

Use `exportState()` if the holder may reload, close the app, or move issuance
across screens before finalization.

## Export State

```ts
const { request, pending } = PendingIssuance.createRequest(
  issuerAuthority,
  credentialInfo,
  blindMsg,
);

const pendingState = pending.exportState();

await appStorage.set("pending-issuance", pendingState);
await appTransport.sendIssuanceRequest(request);
```

The exported state is a versioned JSON string. Treat it as sensitive holder-side
issuance material. It is not a long-term holder private key, but it is required
to finalize the issuer response.

## Import State

```ts
const pendingState = await appStorage.get("pending-issuance");

if (!pendingState) {
  throw new Error("missing pending issuance state");
}

const pending = PendingIssuance.importState(pendingState);
const credential = pending.finalize(issuerAuthority, response);

await appStorage.delete("pending-issuance");
```

`finalize()` is a one-shot operation. After a pending issuance is finalized, do
not reuse that state for another issuer response.

## Mismatch Failures

Finalization rejects mismatched inputs, including:

- An issuer authority with the wrong issuer identity.
- An issuer authority with the wrong issuance key.
- An issuer response whose `info` does not match the holder request.
- A response created for a different `IssuanceRequest`.
- Malformed or unknown-version pending state.

Handle those failures as protocol errors and restart issuance from a fresh
holder request.
