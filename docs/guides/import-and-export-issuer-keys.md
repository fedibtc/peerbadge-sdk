---
title: Import And Export Issuer Keys
---

# Import And Export Issuer Keys

Issuer contexts contain two kinds of secret material:

- An issuer identity secret key used to sign issuer authorities and revocations.
- An issuance secret key used for blind credential signing.

Export issuer keys when your application needs backup, restore, or stable issuer
identity across restarts.

## Export

```ts
const issuer = IssuerContext.generate();
const issuerSecretKeys = issuer.exportSecretKey();

await secureStorage.set("issuer-secret-keys", issuerSecretKeys);
```

`issuerSecretKeys` has this shape:

```ts
type IssuerSecretKeys = {
  readonly issuer_id_secret_key: string;
  readonly issuance_secret_key: string;
};
```

## Import

```ts
const issuerSecretKeys = await secureStorage.get("issuer-secret-keys");

if (!issuerSecretKeys) {
  throw new Error("missing issuer secret keys");
}

const issuer = IssuerContext.importSecretKey(issuerSecretKeys);
const issuerAuthority = issuer.issuerAuthority(revocationLocations);
```

Imported issuer keys preserve the issuer identity public key and issuance public
key. Verifiers that already trust the issuer identity can continue to recognize
credentials from the restored issuer.

## Handling Bad Keys

`IssuerContext.importSecretKey()` throws if the key material is malformed. Treat
that as a storage or backup integrity failure; do not silently generate a new
issuer unless rotating identity is intentional.
