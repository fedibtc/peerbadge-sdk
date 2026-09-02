import { describe, expect, it } from "vitest";
import type {
  IssuerAuthority,
  JsonValue,
  RevocationLocation,
} from "../pkg/peerbadge_wasm.js";
import { IssuerContext, PendingIssuance } from "../pkg/peerbadge_wasm.js";
import { createTestIssuer } from "./fixtures.js";

const otherIssuerId = "22".repeat(32);
const wrongIssuanceKey =
  "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHqlcEXhOsb7YTTOFty0DtofgEZMxIXHDGgfjef6dL7wNZ6EBqknxMfT3s40XP32uKbuen2AzFSOC_ml41YiiZSkMh-PLyrmo9LxtpCDh2SIzRDPFb9PiCMmC0uDtebIh6wffxYon4OGlQghC0cE_GavsswisZVlQoNM9OkfSTetAgMBAAE";
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

function decodePendingState(state: string): Record<string, unknown> {
  return JSON.parse(state) as Record<string, unknown>;
}

describe("credential issuance protocol", () => {
  it("round trips holder request, issuer response, holder finalization, and verification", () => {
    const issuer = createTestIssuer();
    const issuerAuthority = issuer.issuerAuthority(revocationLocations);
    const result = PendingIssuance.createRequest(
      issuerAuthority,
      credentialInfo,
      blindMessage,
    );
    const issuerId = issuerAuthority.issuer.issuer_id_pubkey;

    expect(result.request.version).toBe(1);
    expect(result.request.blinded_message.length).toBeGreaterThan(0);
    expect(result.request.blinded_message).not.toContain(blindMessage);

    const response = issuer.issueCredential(credentialInfo, result.request);
    expect(response).toMatchObject({
      version: 1,
      issuer_id: issuerId,
      info: credentialInfo,
    });
    expect(response.blind_signature.length).toBeGreaterThan(0);

    const credential = result.pending.finalize(issuerAuthority, response);
    expect(credential).toMatchObject({
      version: 1,
      credential: {
        issuer_id_pubkey: issuerId,
        info: credentialInfo,
        blind_msg: blindMessage,
      },
    });
    expect(credential.proof.signature.length).toBeGreaterThan(0);
  });

  it("imports issuer secret keys and public keys from DER", () => {
    const issuer = createTestIssuer();
    const issuerAuthority = issuer.issuerAuthority(revocationLocations);
    const importedIssuer = IssuerContext.importSecretKey(
      issuer.exportSecretKey(),
    );
    const importedAuthority =
      importedIssuer.issuerAuthority(revocationLocations);

    expect(importedAuthority.issuer.issuer_id_pubkey).toBe(
      issuerAuthority.issuer.issuer_id_pubkey,
    );
    expect(importedAuthority.issuer.issuance_key).toBe(
      issuerAuthority.issuer.issuance_key,
    );

    const result = PendingIssuance.createRequest(
      importedAuthority,
      credentialInfo,
      blindMessage,
    );
    const response = importedIssuer.issueCredential(
      credentialInfo,
      result.request,
    );
    expect(result.pending.finalize(importedAuthority, response)).toMatchObject({
      credential: {
        issuer_id_pubkey: issuerAuthority.issuer.issuer_id_pubkey,
        info: credentialInfo,
        blind_msg: blindMessage,
      },
    });
  });

  it("exports and imports pending issuance state across reload", () => {
    const issuer = createTestIssuer();
    const issuerAuthority = issuer.issuerAuthority(revocationLocations);
    const result = PendingIssuance.createRequest(
      issuerAuthority,
      credentialInfo,
      blindMessage,
    );
    const pendingState = result.pending.exportState();

    expect(typeof pendingState).toBe("string");
    expect(pendingState.length).toBeGreaterThan(0);
    expect(decodePendingState(pendingState)).toMatchObject({
      version: 1,
      step: "waiting_for_issuer_response",
    });

    const response = issuer.issueCredential(credentialInfo, result.request);
    const importedPending = PendingIssuance.importState(pendingState);
    const credential = importedPending.finalize(issuerAuthority, response);

    expect(credential).toMatchObject({
      version: 1,
      credential: {
        issuer_id_pubkey: issuerAuthority.issuer.issuer_id_pubkey,
        info: credentialInfo,
        blind_msg: blindMessage,
      },
    });
  });

  it("rejects imported pending finalization with wrong issuer authority or mismatched responses", () => {
    const issuer = createTestIssuer();
    const issuerAuthority = issuer.issuerAuthority(revocationLocations);
    const wrongIssuerAuthority = {
      ...issuerAuthority,
      issuer: {
        ...issuerAuthority.issuer,
        issuance_key: wrongIssuanceKey,
      },
    } satisfies IssuerAuthority;
    const wrongIssuerIdAuthority = {
      ...issuerAuthority,
      issuer: {
        ...issuerAuthority.issuer,
        issuer_id_pubkey: otherIssuerId,
      },
    } satisfies IssuerAuthority;

    const wrongIssuerResult = PendingIssuance.createRequest(
      issuerAuthority,
      credentialInfo,
      blindMessage,
    );
    const wrongIssuerResponse = issuer.issueCredential(
      credentialInfo,
      wrongIssuerResult.request,
    );
    expect(() =>
      PendingIssuance.importState(
        wrongIssuerResult.pending.exportState(),
      ).finalize(wrongIssuerAuthority, wrongIssuerResponse),
    ).toThrow(/blind RSA operation failed/);
    expect(() =>
      PendingIssuance.importState(
        wrongIssuerResult.pending.exportState(),
      ).finalize(wrongIssuerIdAuthority, wrongIssuerResponse),
    ).toThrow(/issuer_id does not match/);

    const differentInfo = {
      ...credentialInfo,
      trust_level: 8,
    } satisfies JsonValue;
    const infoResult = PendingIssuance.createRequest(
      issuerAuthority,
      credentialInfo,
      blindMessage,
    );
    const infoResponse = issuer.issueCredential(
      differentInfo,
      infoResult.request,
    );
    expect(() =>
      PendingIssuance.importState(infoResult.pending.exportState()).finalize(
        issuerAuthority,
        infoResponse,
      ),
    ).toThrow(/issuance response info does not match/);

    const firstResult = PendingIssuance.createRequest(
      issuerAuthority,
      credentialInfo,
      blindMessage,
    );
    const secondResult = PendingIssuance.createRequest(
      issuerAuthority,
      credentialInfo,
      blindMessage,
    );
    const secondResponse = issuer.issueCredential(
      credentialInfo,
      secondResult.request,
    );
    expect(() =>
      PendingIssuance.importState(firstResult.pending.exportState()).finalize(
        issuerAuthority,
        secondResponse,
      ),
    ).toThrow();
  });

  it("rejects malformed and unknown-version pending issuance state", () => {
    const issuer = createTestIssuer();
    const issuerAuthority = issuer.issuerAuthority(revocationLocations);
    const result = PendingIssuance.createRequest(
      issuerAuthority,
      credentialInfo,
      blindMessage,
    );
    const pendingState = result.pending.exportState();
    const unknownVersionState = JSON.stringify({
      ...decodePendingState(pendingState),
      version: 2,
    });

    expect(() => PendingIssuance.importState(unknownVersionState)).toThrow(
      /unsupported protocol version/,
    );
    expect(() => PendingIssuance.importState("not-json")).toThrow(
      /invalid pending issuance state/,
    );
  });

  it("keeps imported pending issuance objects freeable and single-use", () => {
    const issuer = createTestIssuer();
    const issuerAuthority = issuer.issuerAuthority(revocationLocations);
    const result = PendingIssuance.createRequest(
      issuerAuthority,
      credentialInfo,
      blindMessage,
    );
    const pendingState = result.pending.exportState();
    const response = issuer.issueCredential(credentialInfo, result.request);

    const freedPending = PendingIssuance.importState(pendingState);
    freedPending.free();
    expect(() => freedPending.finalize(issuerAuthority, response)).toThrow();

    const singleUsePending = PendingIssuance.importState(pendingState);
    expect(singleUsePending.finalize(issuerAuthority, response)).toMatchObject({
      credential: {
        issuer_id_pubkey: issuerAuthority.issuer.issuer_id_pubkey,
        info: credentialInfo,
        blind_msg: blindMessage,
      },
    });
    expect(() =>
      singleUsePending.finalize(issuerAuthority, response),
    ).toThrow();
  });

  it("rejects malformed issuer secret key inputs", () => {
    expect(() =>
      IssuerContext.importSecretKey({
        issuer_id_secret_key: "not-a-hex-key",
        issuance_secret_key: "AQID",
      }),
    ).toThrow();
  });

  it("rejects finalization with mismatched issuer responses", () => {
    const issuer = createTestIssuer();
    const issuerAuthority = issuer.issuerAuthority(revocationLocations);
    const result = PendingIssuance.createRequest(
      issuerAuthority,
      credentialInfo,
      blindMessage,
    );
    const response = issuer.issueCredential(credentialInfo, result.request);
    const wrongIssuerAuthority = {
      ...issuerAuthority,
      issuer: {
        ...issuerAuthority.issuer,
        issuance_key: wrongIssuanceKey,
      },
    } satisfies IssuerAuthority;

    expect(() =>
      result.pending.finalize(issuerAuthority, {
        ...response,
        issuer_id: otherIssuerId,
      }),
    ).toThrow();
    expect(() =>
      result.pending.finalize(issuerAuthority, {
        ...response,
        info: {
          ...credentialInfo,
          trust_level: 8,
        },
      }),
    ).toThrow();
    expect(() =>
      result.pending.finalize(wrongIssuerAuthority, response),
    ).toThrow();
  });

  it("rejects tampered finalized credentials during finalization checks", () => {
    const issuer = createTestIssuer();
    const issuerAuthority = issuer.issuerAuthority(revocationLocations);
    const result = PendingIssuance.createRequest(
      issuerAuthority,
      credentialInfo,
      blindMessage,
    );
    const response = issuer.issueCredential(credentialInfo, result.request);
    expect(() =>
      result.pending.finalize(issuerAuthority, {
        ...response,
        blind_signature: response.blind_signature.slice(1),
      }),
    ).toThrow();
  });
});
