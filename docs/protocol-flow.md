---
title: Protocol Flow
---

# Protocol Flow

The issuance protocol separates issuer-visible credential information from the
holder-hidden value that is blinded during signing.

## Issuance

```mermaid
sequenceDiagram
  participant I as Issuer
  participant H as Holder

  I->>I: Generate issuer keys
  I->>H: Share signed IssuerAuthority
  H->>H: Choose blind_msg and credential info
  H->>H: Create IssuanceRequest and PendingIssuance
  H->>I: Send IssuanceRequest
  I->>I: Bind visible info and blind-sign request
  I->>H: Send IssuanceResponse
  H->>H: Finalize response into SignedCredential
```

## Verification

```mermaid
sequenceDiagram
  participant V as Verifier
  participant I as Issuer
  participant H as Holder

  I->>V: Share trusted IssuerAuthority
  H->>V: Present SignedCredential
  V->>V: Verify issuer is trusted
  V->>V: Verify credential signature
  V->>V: Check ingested revocations
```

## Holder Authorization

```mermaid
sequenceDiagram
  participant W as Holder Wallet
  participant A as External App
  participant V as Verifier

  A->>W: Share subject_pubkey
  W->>W: Select SignedCredential
  W->>W: Sign HolderAuthorization
  W->>A: Send HolderAuthorization
  A->>V: Present SignedCredential and HolderAuthorization
  V->>V: Verify credential and holder authorization
  V->>V: Apply subject_pubkey and credential policy
```

The SDK signs holder authorizations with the holder identity key and derives
the credential digest from the selected `SignedCredential`. The verifier-side SDK
check verifies the credential, holder authorization signature, holder binding,
authorized credential digest, and authorization issued-at time. Subject-key
proof-of-possession, credential schema policy, storage, and transport stay in
the application.

## Revocation

```mermaid
sequenceDiagram
  participant I as Issuer
  participant V as Verifier

  I->>I: Compute credential digest
  I->>I: Sign SignedRevocation
  I->>V: Publish or transport revocation
  V->>V: Verify revocation issuer signature
  V->>V: Reject matching credential digest
```

`credential.info` is visible to the issuer during signing. `credential.blind_msg`
is hidden from the issuer during signing and disclosed in the final credential.

## Multi-Signer Issuance

A multi-signer credential is the same protocol used a different way: several
member issuers each sign one ordinary credential, and verifiers require a
threshold of them. Nothing in the wire format version changes; every object is
still `version: 1`.

- The credential is an ordinary `Credential` whose `issuer_id_pubkey` is a
  **group id**: a fixed Nostr public key that names the group. The group id
  authorizes nothing, signs nothing, and nobody needs its private key. Trust
  comes only from the member issuers that a verifier configures for it.
- Each member is an ordinary issuer with its own `IssuerAuthority`. It signs
  with its own issuance key, but binds the group id instead of its own id into
  the signature, so a member's group signature is never valid as that member's
  own single-issuer credential, and a single-issuer signature never counts for
  the group.
- The holder blinds a separate request for each member, finalizes each response
  into that member's proof, and merges the proofs into one
  `MultiSignerCredential`: the credential plus a list of proofs, each tagged
  with the member issuer id that made it.

```mermaid
sequenceDiagram
  participant H as Holder
  participant A as Member A
  participant B as Member B

  A->>H: Share member IssuerAuthority
  B->>H: Share member IssuerAuthority
  H->>H: Create one MultiSignerPendingIssuance per member
  H->>A: Send IssuanceRequest blinded for A
  H->>B: Send IssuanceRequest blinded for B
  A->>A: Blind-sign binding group id and info
  B->>B: Blind-sign binding group id and info
  A->>H: Send MultiSignerIssuanceResponse
  B->>H: Send MultiSignerIssuanceResponse
  H->>H: Finalize each response and merge into MultiSignerCredential
```

```mermaid
sequenceDiagram
  participant V as Verifier
  participant H as Holder

  V->>V: Configure group id, trusted member authorities, threshold t
  H->>V: Present MultiSignerCredential
  V->>V: Verify each proof under its tagged member's key
  V->>V: Ignore unknown members, count each member once
  V->>V: Accept when at least t members signed validly
```

The credential digest is computed over the credential payload only, exactly as
for a single-issuer credential. One `HolderAuthorization` therefore covers the
multi-signer credential, and a holder can merge in further member proofs later
without invalidating authorizations it already signed.

Multi-signer issuance suits any case where more than one key should stand
behind a credential, for example:

- **A community with three issuers, any two of which must agree.** The
  community picks a group id and publishes its three issuers' authorities.
  Holders collect two or three member signatures; verifiers configure the group
  with threshold 2. Losing or retiring one issuer does not stop issuance or
  invalidate existing credentials.
- **One issuer that keeps two keys so it can rotate one without reissuing.**
  The issuer runs two member identities under one group id and signs every
  credential with both; verifiers configure threshold 1. To rotate, it
  publishes a new member, verifiers swap the retired member for the new one,
  and existing credentials keep verifying through the remaining key.

What the group and its credentials mean (schemas, levels, which members are
current) stays in `info` and in the verifier's policy.

Revocation of multi-signer credentials is not defined yet; see
[Verification And Revocation](verification-and-revocation.md#multi-signer-credentials).
