---
title: Choose Info Vs Blind Msg
---

# Choose Info Vs Blind Msg

Issuance binds two pieces of credential data:

- `info`: visible to the issuer during signing.
- `blind_msg`: hidden from the issuer during signing, then disclosed in the
  finalized credential.

Both fields accept any JSON value.

## Use `info` For Issuer-Visible Claims

Put data in `info` when the issuer must see it to decide whether to issue or
what to issue.

```ts
const credentialInfo = {
  schema: "example-membership-v1.0",
  trust_level: 7,
  issued_at: "2026-05-22T00:00:00Z",
} satisfies JsonValue;
```

The issuer signs `info` into the credential. Verifiers can inspect it later as
`credential.credential.info`.

## Use `blind_msg` For Holder-Hidden Issuance Data

Put data in `blind_msg` when the issuer should not see it during signing.

```ts
const holder = HolderContext.generate();
const blindMsg = holder.publicKey;

const { request, pending } = PendingIssuance.createRequest(
  issuerAuthority,
  credentialInfo,
  blindMsg,
);
```

The issuer receives only the blinded request. The final credential discloses the
value as `credential.credential.blind_msg`.

Holder authorization verification uses the current Fedi/Nostr convention where
`credential.credential.blind_msg` is the holder public key string. If an
application chooses a different `blind_msg` schema, plain credential
verification still works, but holder authorization verification will not be able
to bind the credential to the holder key.

## Privacy Boundary

Blinding protects `blind_msg` during issuance. It does not keep `blind_msg`
secret forever. Anyone who receives the finalized credential can read it.

Use application-level policy for anything beyond this issuance privacy boundary,
such as selective disclosure, transport encryption, credential storage, and
which credential fields a verifier should display.
