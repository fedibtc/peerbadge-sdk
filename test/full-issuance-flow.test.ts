import { describe, expect, it } from "vitest";
import type {
  HolderAuthorizationRequest,
  IssuerAuthority,
  JsonValue,
  RevocationLocation,
  SignedCredential,
} from "../pkg/peerbadge_wasm.js";
import {
  HolderContext,
  IssuerContext,
  PendingIssuance,
  VerificationContext,
} from "../pkg/peerbadge_wasm.js";
import { createTestIssuer } from "./fixtures.js";

const credentialInfo = {
  schema: "example-membership-v1.0",
  trust_level: 7,
} satisfies JsonValue;

const revocationLocations = [
  {
    location: "wss://relay.example.com",
    protocol: "nostr",
  },
] satisfies readonly RevocationLocation[];
const otherIssuerId = "22".repeat(32);
const subjectPubkey = "33".repeat(32);

describe("full credential issuance flow", () => {
  it("issues, verifies, revokes, imports issuer keys, and rejects tampering", () => {
    const issuer = createTestIssuer();
    const issuerAuthority = issuer.issuerAuthority(revocationLocations);
    const issuerId = issuerAuthority.issuer.issuer_id_pubkey;

    expect(issuerAuthority).toMatchObject({
      version: 1,
      issuer: {
        issuer_id_pubkey: issuerId,
        revocation: revocationLocations,
      },
      proof: {
        signature: expect.any(String),
      },
    });
    expect(issuerAuthority.issuer.issuance_key.length).toBeGreaterThan(0);
    const issuerAuthorityVerifier = new VerificationContext();
    expect(
      issuerAuthorityVerifier.addIssuerAuthority(issuerAuthority),
    ).toBeUndefined();

    const holder = HolderContext.generate();
    const blindMsg = holder.publicKey;
    const result = PendingIssuance.createRequest(
      issuerAuthority,
      credentialInfo,
      blindMsg,
    );

    expect(result.request).toMatchObject({
      version: 1,
      blinded_message: expect.any(String),
    });
    expect(result.request.blinded_message.length).toBeGreaterThan(0);
    expect(result.request.blinded_message).not.toBe(blindMsg);
    expect(result.request.blinded_message).not.toContain(blindMsg);

    const response = issuer.issueCredential(credentialInfo, result.request);

    expect(response).toMatchObject({
      version: 1,
      issuer_id: issuerId,
      info: credentialInfo,
      blind_signature: expect.any(String),
    });
    expect(response.blind_signature.length).toBeGreaterThan(0);

    const credential = result.pending.finalize(issuerAuthority, response);

    expect(credential).toMatchObject({
      version: 1,
      credential: {
        issuer_id_pubkey: issuerId,
        info: credentialInfo,
        blind_msg: blindMsg,
      },
      proof: {
        signature: expect.any(String),
      },
    });
    expect(credential.proof.signature.length).toBeGreaterThan(0);

    const signedRevocation = issuer.revokeCredential(credential);

    expect(signedRevocation).toMatchObject({
      version: 1,
      revocation: {
        credential_digest: expect.any(String),
      },
      proof: {
        issuer_id_pubkey: issuerId,
        signature: expect.any(String),
      },
    });
    expect(
      signedRevocation.revocation.credential_digest.length,
    ).toBeGreaterThan(0);

    const holderAuthorizationRequest = {
      subject_pubkey: subjectPubkey,
    } satisfies HolderAuthorizationRequest;
    const issuedAtBefore = Math.floor(Date.now() / 1000);
    const holderAuthorization = holder.authorizeCredentialUse(
      holderAuthorizationRequest,
      credential,
    );
    const issuedAtAfter = Math.floor(Date.now() / 1000);

    expect(holderAuthorization).toMatchObject({
      version: 1,
      authorization: {
        holder_id_pubkey: holder.publicKey,
        subject_pubkey: subjectPubkey,
        credential_digest: signedRevocation.revocation.credential_digest,
      },
      proof: {
        signature: expect.any(String),
      },
    });
    expect(holderAuthorization.authorization.issued_at).toBeGreaterThanOrEqual(
      issuedAtBefore,
    );
    expect(holderAuthorization.authorization.issued_at).toBeLessThanOrEqual(
      issuedAtAfter,
    );
    expect(holderAuthorization.proof.signature.length).toBeGreaterThan(0);

    const authorizationVerifier = new VerificationContext();
    expect(
      authorizationVerifier.addIssuerAuthority(issuerAuthority),
    ).toBeUndefined();
    expect(
      authorizationVerifier.verifyCredentialAuthorization(
        credential,
        holderAuthorization,
      ),
    ).toBe(true);

    const revocationVerifier = new VerificationContext();
    expect(
      revocationVerifier.addIssuerAuthority(issuerAuthority),
    ).toBeUndefined();
    expect(revocationVerifier.addRevocation(signedRevocation)).toBeUndefined();

    const verifier = new VerificationContext();
    expect(() => verifier.verifyCredential(credential)).toThrow(
      /unknown issuer/,
    );
    expect(verifier.addIssuerAuthority(issuerAuthority)).toBeUndefined();
    expect(verifier.verifyCredential(credential)).toBe(true);
    expect(verifier.addRevocation(signedRevocation)).toBeUndefined();
    expect(() => verifier.verifyCredential(credential)).toThrow(
      /credential has been revoked/,
    );

    const importedIssuer = IssuerContext.importSecretKey(
      issuer.exportSecretKey(),
    );
    const importedAuthority = importedIssuer.issuerAuthority([]);

    expect(importedAuthority.issuer.issuer_id_pubkey).toBe(issuerId);
    expect(importedAuthority.issuer.issuance_key).toBe(
      issuerAuthority.issuer.issuance_key,
    );

    const tamperedAuthority = {
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
    } satisfies IssuerAuthority;
    const tamperedCredential = {
      ...credential,
      credential: {
        ...credential.credential,
        blind_msg: "mallory-public-key",
      },
    } satisfies SignedCredential;
    const wrongIssuerCredential = {
      ...credential,
      credential: {
        ...credential.credential,
        issuer_id_pubkey: otherIssuerId,
      },
    } satisfies SignedCredential;
    const tamperVerifier = new VerificationContext();

    expect(() =>
      new VerificationContext().addIssuerAuthority(tamperedAuthority),
    ).toThrow(/verification failed/);
    expect(tamperVerifier.addIssuerAuthority(issuerAuthority)).toBeUndefined();
    expect(() => tamperVerifier.verifyCredential(tamperedCredential)).toThrow(
      /Verification failed|blind RSA operation failed/,
    );
    expect(() => issuer.revokeCredential(wrongIssuerCredential)).toThrow(
      /issuer_id does not match/,
    );
  }, 60_000);
});
