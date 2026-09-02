# PeerBadge SDK

WebAssembly bindings for the [PeerBadge protocol](https://peerbadge.org/), built on partially blind RSA verifiable credentials.

The library is intended to own the protocol-sensitive pieces of credential issuance and verification: holder blinding, issuer partial blind signing, holder finalization, holder authorization signing, runtime validation, and the WASM/TypeScript API surface around those operations.

It deliberately does not own app concerns such as browser storage, QR codes, Nostr relay I/O, HTTP fetching, UI state, subject-key custody, verifier policy, or revocation list refresh jobs.

Documentation is available at [fedibtc.github.io/peerbadge-sdk](https://fedibtc.github.io/peerbadge-sdk/). The source repository is [`fedibtc/peerbadge-sdk`](https://github.com/fedibtc/peerbadge-sdk).

The generated npm package is `@fedibtc/peerbadge-sdk-wasm`. In this repository, tests import from the generated `pkg/peerbadge_wasm.js` file after `pnpm run build`.

## Issuance Flow

The protocol separates issuer-visible credential information from the holder-hidden message that is blinded during issuance. For the current Fedi/Nostr use case, the hidden message is usually the holder's public key, but protocol methods accept any JSON value.

```ts
import type {
  HolderAuthorizationRequest,
  JsonValue,
  RevocationLocation,
} from "@fedibtc/peerbadge-sdk-wasm";
import {
  HolderContext,
  IssuerContext,
  PendingIssuance,
  VerificationContext,
} from "@fedibtc/peerbadge-sdk-wasm";

const credentialInfo = {
  schema: "example-membership-v1.0",
  trust_level: 7,
} satisfies JsonValue;

> The schema strings in these examples are placeholders. Deployed first-party
> schemas (such as `fedi-trust-score-v1.0`) are defined once in
> [`crates/schemas`](crates/schemas) — use its constructors and parsers instead
> of hand-building `info`, and never reuse a deployed schema string for a new
> credential type.


const revocationLocations = [
  {
    protocol: "nostr",
    location: "wss://relay.example.com",
  },
] satisfies readonly RevocationLocation[];

// Issuer creates signed public metadata for verifiers and holders.
const issuer = IssuerContext.generate();
const issuerAuthority = issuer.issuerAuthority(revocationLocations);

// Holder creates a blinded issuance request and keeps pending state locally.
const holder = HolderContext.generate();
const blindMsg = holder.publicKey;
const { request, pending } = PendingIssuance.createRequest(
  issuerAuthority,
  credentialInfo,
  blindMsg,
);

// Issuer signs the blinded request while binding the visible credential info.
const response = issuer.issueCredential(credentialInfo, request);

// Holder unblinds and finalizes the response into a verifiable credential.
const credential = pending.finalize(issuerAuthority, response);

// Verifier must trust the issuer authority before accepting credentials.
const verifier = new VerificationContext();
verifier.addIssuerAuthority(issuerAuthority);
verifier.verifyCredential(credential); // true

// Holder can authorize an external app key to use a selected credential.
// Subject-key generation, storage, and live authentication are app-owned.
const subjectPubkey = "33".repeat(32);
const holderAuthorizationRequest = {
  subject_pubkey: subjectPubkey,
} satisfies HolderAuthorizationRequest;
const holderAuthorization = holder.authorizeCredentialUse(
  holderAuthorizationRequest,
  credential,
);

verifier.verifyCredentialAuthorization(credential, holderAuthorization); // true

// Issuer can revoke a finalized credential. Transport/publication is app-owned.
const signedRevocation = issuer.revokeCredential(credential);
verifier.addRevocation(signedRevocation);
verifier.verifyCredential(credential); // throws: credential has been revoked
```

The finalized credential has this shape:

```ts
{
  version: 1,
  credential: {
    issuer_id_pubkey: "nostr-issuer-public-key",
    info: {
      schema: "example-membership-v1.0",
      trust_level: 7,
    },
    blind_msg: "anonymous-holder-public-key",
  },
  proof: {
    signature: "base64url-rsa-signature",
  },
}
```

During issuance, `credential.info` is public and `credential.blind_msg` is blinded. The holder creates an `IssuanceRequest` plus local pending state, the issuer returns an `IssuanceResponse`, and the holder finalizes that response into the credential shape above. The issuer partially blind-signs both pieces together: `blind_msg` is the hidden payload, and `info` is the visible credential data.

Holder authorization lets a wallet grant an external application key permission
to use a selected credential without sharing the holder secret key. For the
current authorization verifier, the finalized credential's `blind_msg` must be
the holder public key string used by `HolderContext.publicKey`.

```ts
interface HolderAuthorizationRequest {
  readonly subject_pubkey: string;
}

interface HolderAuthorization {
  readonly version: 1;
  readonly authorization: HolderAuthorizationStatement;
  readonly proof: SchnorrSignatureProof;
}

interface HolderAuthorizationStatement {
  readonly holder_id_pubkey: string;
  readonly subject_pubkey: string;
  readonly credential_digest: CredentialDigest;
  readonly issued_at: Timestamp;
}

type CredentialDigest = string;
type Timestamp = number;
```

`HolderContext.authorizeCredentialUse` derives `holder_id_pubkey`,
`credential_digest` and `issued_at`. Verifiers call
`VerificationContext.verifyCredentialAuthorization` to check the credential,
holder authorization signature, holder binding, authorized credential digest,
and issued-at time. Applications still check that the current caller controls
`authorization.subject_pubkey`, and they apply schema-specific policy to the
credential.

`PendingIssuance` can be exported as a versioned string and imported again after a browser reload:

```ts
const { request, pending } = PendingIssuance.createRequest(
  issuerAuthority,
  info,
  blindMsg,
);
const pendingState = pending.exportState();

// Store request and pendingState in application storage while issuance is pending.
const importedPending = PendingIssuance.importState(pendingState);
const credential = importedPending.finalize(issuerAuthority, response);
```

The exported pending issuance state is sensitive holder-side issuance material. It is not a long-term holder private key, but it is required to unblind and finalize the issuer response, so applications should avoid logging or sharing it.

## Public API

The current high-level API is organized around runtime contexts:

- `IssuerContext`: generate/import/export issuer keys, create signed issuer authorities, issue credentials, and create signed revocations
- `PendingIssuance`: create holder issuance requests and finalize issuer responses
- `HolderContext`: generate/import/export holder identity keys and authorize external app keys to use credentials
- `VerificationContext`: trust issuer authorities, ingest revocations, verify credentials, and verify holder authorizations

All validation failures cross the WASM boundary as thrown JavaScript errors. `VerificationContext.verifyCredential` and `VerificationContext.verifyCredentialAuthorization` return `true` when their checks pass.

The main methods are:

```ts
class IssuerContext {
  static generate(): IssuerContext;
  static importSecretKey(secretKey: IssuerSecretKeys): IssuerContext;
  exportSecretKey(): IssuerSecretKeys;
  issuerAuthority(revocation: readonly RevocationLocation[]): IssuerAuthority;
  issueCredential(info: JsonValue, request: IssuanceRequest): IssuanceResponse;
  revokeCredential(credential: SignedCredential): SignedRevocation;
}

class HolderContext {
  static generate(): HolderContext;
  static importSecretKey(secretKey: string): HolderContext;
  exportSecretKey(): string;
  readonly publicKey: string;
  authorizeCredentialUse(
    request: HolderAuthorizationRequest,
    credential: SignedCredential,
  ): HolderAuthorization;
}

class PendingIssuance {
  static createRequest(
    issuerAuthority: IssuerAuthority,
    info: JsonValue,
    blindMsg: JsonValue,
  ): PendingIssuanceResult;

  finalize(
    issuerAuthority: IssuerAuthority,
    response: IssuanceResponse,
  ): SignedCredential;
}

class VerificationContext {
  constructor();
  addIssuerAuthority(issuerAuthority: IssuerAuthority): void;
  addRevocation(revocation: SignedRevocation): void;
  verifyCredential(credential: SignedCredential): boolean;
  verifyCredentialAuthorization(
    credential: SignedCredential,
    authorization: HolderAuthorization,
  ): boolean;
}
```

## Status

This checklist tracks coarse reusable-library readiness rather than every internal implementation detail.

- [x] Rust/WASM build and TypeScript/Rust test workflows
- [x] Runtime issuer, holder, and verifier contexts exposed through WASM/TypeScript
- [x] Signed issuer authority creation and verification
- [x] Holder issuance request flow with retained pending unblinding state
- [x] Issuer issuance response flow with partially blind signing over hidden `blind_msg` plus visible `credential.info`
- [x] Holder finalization into a verifiable credential with an unblinded signature
- [x] Holder authorization signing for external app credential use
- [x] Credential verification against trusted issuer authorities
- [x] Credential digesting plus signed revocation creation and verification
- [x] Revocation-aware credential verification
- [x] Holder authorization verification against credential binding and issued-at time
- [x] RFC 8785/JCS canonical JSON encoding with domain-separated credential, issuer authority, revocation, and holder authorization digests/signatures
- [x] Deterministic protocol snapshots for issuer authorities, issuance messages, credentials, revocations, holder authorizations, and verifier outcomes
- [ ] Expose machine-readable error or verification result codes across the WASM boundary
- [ ] Complete a security review of the pbRSA suite, domain separation, randomness, key handling, replay risk, and malformed input behavior

## Development

```sh
devenv shell
pnpm install
pnpm run build
pnpm test
```

`pnpm run build` builds the WASM package with the speed-oriented Cargo profile and runs `wasm-opt -O3`. Run it inside `devenv shell` so `secp256k1-sys` uses Nix LLVM clang for wasm32 C code.

Useful scripts:

- `pnpm run docs` rebuilds the WASM package, generates the TypeDoc API reference, generates rustdoc, and copies both into `dist/docs/api`; run it inside `devenv shell`.
- `pnpm run docs:serve` rebuilds the full docs site and serves it locally with Vite; run it inside `devenv shell`.
- `pnpm run build:wasm:sys-rng` builds with the old direct system RNG path instead of the default thread RNG.
- `pnpm run test:rust` runs Rust unit tests for the full workspace.
- `pnpm run test:ts` rebuilds the WASM package, typechecks TypeScript, and runs Vitest.
- `pnpm run check` runs typecheck and the full test suite.
- `pnpm run publish:dry-run` builds and validates the generated package before publishing.

## Publishing to npm

Publish `@fedibtc/peerbadge-sdk-wasm` with the **Publish PeerBadge SDK** GitHub Actions workflow. The workflow uses npm trusted publishing, so it does not require an npm token.

1. Set the release version in `package.json` and under `[workspace.package]` in `Cargo.toml`. Do not add a leading `v`.
2. Update the workspace dependency versions and `Cargo.lock` when the Cargo workspace version changes.
3. Merge the version changes into `master`.
4. Open **Actions > Publish PeerBadge SDK > Run workflow** in GitHub.
5. Select `master`, enter the release version, and run the workflow.

The workflow stops if the selected branch is not `master` or if either source version does not match the input. It installs the locked dependencies and runs `pnpm run check`. It then checks the generated package name and version. It also confirms that the version does not already exist on npm. If all checks pass, it publishes the public package from `pkg`.

Run `pnpm run publish:dry-run` inside `devenv shell` if you want to inspect the generated package before you start the workflow.
