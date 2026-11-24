---
title: Issue A Multi-Signer Credential
---

# Issue A Multi-Signer Credential

A multi-signer credential is one ordinary credential signed by several member
issuers. Verifiers accept it when enough trusted members signed. See
[Protocol Flow](../protocol-flow.md#multi-signer-issuance) for how it works.

This guide follows a community whose three issuers agree that any two of them
must sign a membership credential.

## Choose A Group Id

The group id is a fixed Nostr public key that names the group. It is written
into the credential as `issuer_id_pubkey`, but it authorizes nothing and signs
nothing: pick any constant, and do not rely on anyone holding its private key.
It must differ from every member's own issuer id.

```ts
const groupId = "…64 hex characters…";
```

Each member is an ordinary issuer with its own `IssuerContext` and
`IssuerAuthority`:

```ts
const memberAuthorities = [issuerA, issuerB, issuerC].map((issuer) =>
  issuer.issuerAuthority(revocationLocations),
);
```

## Request A Signature From Each Member

The holder creates one request per member. Each request is blinded separately
under that member's issuance key, so members cannot link their requests.

```ts
import {
  MultiSignerPendingIssuance,
  mergeMultiSignerCredentials,
} from "@fedibtc/peerbadge-sdk-wasm";

const info = { schema: "example-membership-v1.0", level: 2 };
const blindMsg = holder.publicKey;

const { request, pending } = MultiSignerPendingIssuance.createRequest(
  groupId,
  memberAuthorities[0],
  info,
  blindMsg,
);
```

`pending` can be saved with `exportState()` and restored with
`MultiSignerPendingIssuance.importState()`, like `PendingIssuance`.

## Sign As A Member

The member issuer signs under the group id instead of its own id:

```ts
const response = issuerA.issueMultiSignerCredential(groupId, info, request);
// response.issuer_id is issuerA's id, response.group_id is groupId
```

## Finalize And Merge

Each finalization yields a credential carrying that member's proof. Merge them
into one credential:

```ts
const byA = pendingForA.finalize(memberAuthorities[0], responseFromA);
const byB = pendingForB.finalize(memberAuthorities[1], responseFromB);

const credential = mergeMultiSignerCredentials(byA, byB);
// credential.proofs: [{ issuer_id_pubkey: A, ... }, { issuer_id_pubkey: B, ... }]
```

A holder can merge in a further member's proof later. The credential digest does
not change, so holder authorizations already signed stay valid.

## Authorize And Verify

One holder authorization covers the credential:

```ts
const authorization = holder.authorizeMultiSignerCredentialUse(
  { subject_pubkey: subjectPubkey },
  credential,
);

const verifier = new VerificationContext();
verifier.addMultiSignerGroup(groupId, memberAuthorities, 2);
verifier.verifyMultiSignerCredentialAuthorization(credential, authorization); // true
```

## Rotate A Key Without Reissuing

A single issuer can use the same mechanism to rotate keys. It runs two member
identities under one group id, signs every credential with both, and verifiers
configure threshold 1:

```ts
verifier.addMultiSignerGroup(groupId, [currentKey, nextKey], 1);
```

To retire `currentKey`, the issuer publishes a new member authority and
verifiers reconfigure the group with `[nextKey, newKey]`. Existing credentials
keep verifying through their `nextKey` proof, so nobody has to be reissued.

## Revocation

Revocation is not yet defined for multi-signer credentials. See
[Verification And Revocation](../verification-and-revocation.md#known-gap-multi-signer-revocation).
