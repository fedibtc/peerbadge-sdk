---
title: Issue A Credential
---

# Issue A Credential

Issuance has three actors:

- The issuer publishes an `IssuerAuthority`.
- The holder creates an `IssuanceRequest` and keeps `PendingIssuance`.
- The issuer returns an `IssuanceResponse`, which the holder finalizes into a
  `SignedCredential`.

## Issuer Setup

```ts
import type { JsonValue, RevocationLocation } from "@fedibtc/peerbadge-sdk-wasm";
import {
  HolderContext,
  IssuerContext,
  PendingIssuance,
} from "@fedibtc/peerbadge-sdk-wasm";

const issuer = IssuerContext.generate();

const revocationLocations = [
  {
    protocol: "nostr",
    location: "wss://relay.example.com",
  },
] satisfies readonly RevocationLocation[];

const issuerAuthority = issuer.issuerAuthority(revocationLocations);
```

Applications decide how holders and verifiers receive the issuer authority. The SDK
only creates and verifies the signed authority.

## Holder Request

```ts
const credentialInfo = {
  schema: "example-membership-v1.0",
  trust_level: 7,
} satisfies JsonValue;

const holder = HolderContext.generate();
const blindMsg = holder.publicKey;

const { request, pending } = PendingIssuance.createRequest(
  issuerAuthority,
  credentialInfo,
  blindMsg,
);
```

Send `request` to the issuer. Keep `pending` local to the holder; it is needed
to unblind exactly one matching issuer response.

## Issuer Response

```ts
const response = issuer.issueCredential(credentialInfo, request);
```

The issuer must use the same `credentialInfo` that the holder used when creating
the request. Finalization rejects a response whose `info` does not match the
holder's pending state.

## Holder Finalization

```ts
const credential = pending.finalize(issuerAuthority, response);
```

The finalized `credential` can be stored by the holder and presented to
verifiers. It contains visible `credential.info`, disclosed
`credential.blind_msg`, and the issuer proof signature.

## Application Responsibilities

The SDK does not authenticate transport, choose credential schemas, decide who
is allowed to issue, or persist holder state. Your application should decide
those policies before calling the SDK methods.
