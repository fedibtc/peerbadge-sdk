import { beforeAll, describe, expect, it } from "vitest";
import type {
  IssuerAuthority,
  JsonValue,
  RevocationLocation,
  SignedRevocation,
} from "../pkg/peerbadge_wasm.js";
import { PendingIssuance, VerificationContext } from "../pkg/peerbadge_wasm.js";
import { createTestIssuer } from "./fixtures.js";

const revocationLocations = [
  {
    location: "wss://relay.example.com",
    protocol: "nostr",
  },
] satisfies readonly RevocationLocation[];

const credentialInfo = {
  schema: "example-membership-v1.0",
  trust_level: 7,
} satisfies JsonValue;

const blindMessage = "anonymous-holder-public-key";

let issuerAuthority: IssuerAuthority;
let signedRevocation: SignedRevocation;

beforeAll(() => {
  const issuer = createTestIssuer();
  issuerAuthority = issuer.issuerAuthority(revocationLocations);
  const result = PendingIssuance.createRequest(
    issuerAuthority,
    credentialInfo,
    blindMessage,
  );
  const response = issuer.issueCredential(credentialInfo, result.request);
  const credential = result.pending.finalize(issuerAuthority, response);
  signedRevocation = issuer.revokeCredential(credential);
});

describe("issuer authority verification", () => {
  it("accepts a signed issuer authority", () => {
    const context = new VerificationContext();

    expect(context.addIssuerAuthority(issuerAuthority)).toBeUndefined();
  });

  it("rejects tampered issuer authority metadata", () => {
    const context = new VerificationContext();

    expect(() =>
      context.addIssuerAuthority({
        ...issuerAuthority,
        issuer: {
          ...issuerAuthority.issuer,
          revocation: [
            {
              location: "wss://evil.example.com",
              protocol: "nostr",
            },
          ],
        },
      }),
    ).toThrow();
  });
});

describe("revocation verification", () => {
  it("accepts a signed revocation", () => {
    const context = new VerificationContext();

    context.addIssuerAuthority(issuerAuthority);
    expect(context.addRevocation(signedRevocation)).toBeUndefined();
  });

  it("rejects tampered revocation data", () => {
    const context = new VerificationContext();

    context.addIssuerAuthority(issuerAuthority);

    expect(() =>
      context.addRevocation({
        ...signedRevocation,
        revocation: {
          ...signedRevocation.revocation,
          credential_digest: "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg",
        },
      }),
    ).toThrow();
  });
});

describe("verification context", () => {
  it("accepts trusted issuer authorities and their revocations", () => {
    const context = new VerificationContext();

    expect(context.addIssuerAuthority(issuerAuthority)).toBeUndefined();
    expect(context.addRevocation(signedRevocation)).toBeUndefined();
  });

  it("rejects revocations from unknown issuers", () => {
    const context = new VerificationContext();

    expect(() => context.addRevocation(signedRevocation)).toThrow();
  });
});
