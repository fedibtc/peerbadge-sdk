---
title: Import And Export Holder Keys
---

# Import And Export Holder Keys

`HolderContext` manages a holder identity key. In the current Fedi/Nostr use
case, applications often use `holder.publicKey` as the blinded message during
issuance.

## Generate

```ts
const holder = HolderContext.generate();
const blindMsg = holder.publicKey;
```

`publicKey` is safe to use as a public holder identifier. The holder secret key
must remain private to the holder application.

The same holder identity key signs holder authorizations when a wallet allows
an external application key to use a selected credential. The external
application receives the signed `HolderAuthorization`, not the holder secret
key.

## Export

```ts
const holderSecretKey = holder.exportSecretKey();

await secureStorage.set("holder-secret-key", holderSecretKey);
```

The exported holder secret key is a string. Store it in application-managed
secure storage.

## Import

```ts
const holderSecretKey = await secureStorage.get("holder-secret-key");

if (!holderSecretKey) {
  throw new Error("missing holder secret key");
}

const holder = HolderContext.importSecretKey(holderSecretKey);
console.log(holder.publicKey);
```

Importing the same secret key restores the same holder public key.

## Relation To Pending Issuance

Holder keys and pending issuance state are separate. A holder key can be
long-lived. `PendingIssuance` is temporary state for one issuance request and
must be persisted separately if issuance crosses a reload.
