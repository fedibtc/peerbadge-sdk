import { beforeAll, describe, expect, it } from "vitest";
import type {
  HolderAuthorizationRequest,
  IssuerAuthority,
  IssuerContext,
  JsonValue,
  MultiSignerCredential,
  SignedCredential,
} from "../pkg/peerbadge_wasm.js";
import {
  HolderContext,
  MultiSignerPendingIssuance,
  mergeMultiSignerCredentials,
  PendingIssuance,
  VerificationContext,
} from "../pkg/peerbadge_wasm.js";
import { createTestMemberIssuers } from "./fixtures.js";

// A fixed group identifier with no known private key.
const groupId = "47".repeat(32);
const otherGroupId = "48".repeat(32);
const credentialInfo = {
  schema: "example-membership-v1.0",
  level: 2,
} satisfies JsonValue;
const authorizationRequest = {
  subject_pubkey: "33".repeat(32),
} satisfies HolderAuthorizationRequest;

let issuers: IssuerContext[];
let authorities: IssuerAuthority[];
let members: IssuerAuthority[];
let outsider: IssuerAuthority;
let holder: HolderContext;

beforeAll(() => {
  issuers = createTestMemberIssuers();
  authorities = issuers.map((issuer) => issuer.issuerAuthority([]));
  members = authorities.slice(0, 3);
  outsider = authorities[3];
  holder = HolderContext.generate();
});

function signAs(
  index: number,
  info: JsonValue = credentialInfo,
  blindMsg: JsonValue = holder.publicKey,
  group: string = groupId,
): MultiSignerCredential {
  const { request, pending } = MultiSignerPendingIssuance.createRequest(
    group,
    authorities[index],
    info,
    blindMsg,
  );
  const response = issuers[index].issueMultiSignerCredential(
    group,
    info,
    request,
  );
  expect(response).toMatchObject({
    version: 1,
    group_id: group,
    issuer_id: authorities[index].issuer.issuer_id_pubkey,
    info,
  });
  return pending.finalize(authorities[index], response);
}

function memberId(index: number): string {
  return authorities[index].issuer.issuer_id_pubkey;
}

function groupVerifier(threshold: number): VerificationContext {
  const verifier = new VerificationContext();
  verifier.addMultiSignerGroup(groupId, members, threshold);
  return verifier;
}

describe("multi-signer issuance", () => {
  it("issues a 2 of 3 credential that verifies with one holder authorization", () => {
    const verifier = groupVerifier(2);
    const byFirst = signAs(0);
    const credential = mergeMultiSignerCredentials(byFirst, signAs(2));

    expect(credential).toMatchObject({
      version: 1,
      credential: {
        issuer_id_pubkey: groupId,
        info: credentialInfo,
        blind_msg: holder.publicKey,
      },
    });
    expect(credential.proofs.map((proof) => proof.issuer_id_pubkey)).toEqual([
      memberId(0),
      memberId(2),
    ]);
    expect(verifier.validMultiSignerMembers(credential).sort()).toEqual(
      [memberId(0), memberId(2)].sort(),
    );
    expect(verifier.verifyMultiSignerCredential(credential)).toBe(true);

    const authorization = holder.authorizeMultiSignerCredentialUse(
      authorizationRequest,
      credential,
    );
    expect(
      verifier.verifyMultiSignerCredentialAuthorization(
        credential,
        authorization,
      ),
    ).toBe(true);

    // The authorization signs the ordinary credential digest: the same
    // statement a single-issuer credential with this payload would get.
    const plain = {
      version: 1,
      credential: credential.credential,
      proof: { signature: credential.proofs[0].signature },
    } satisfies SignedCredential;
    expect(
      holder.authorizeCredentialUse(authorizationRequest, plain).authorization
        .credential_digest,
    ).toBe(authorization.authorization.credential_digest);
  });

  it("rejects fewer than threshold distinct trusted members", () => {
    const verifier = groupVerifier(2);
    const byFirst = signAs(0);

    expect(() => verifier.verifyMultiSignerCredential(byFirst)).toThrow(
      "1 valid member signatures, threshold is 2",
    );

    // The same member twice counts once.
    const twice = mergeMultiSignerCredentials(byFirst, signAs(0));
    expect(twice.proofs).toHaveLength(2);
    expect(verifier.validMultiSignerMembers(twice)).toEqual([memberId(0)]);
    expect(() => verifier.verifyMultiSignerCredential(twice)).toThrow();

    // An unknown member's signature is ignored, though valid under its own key.
    const byOutsider = signAs(3);
    const outsiderVerifier = new VerificationContext();
    outsiderVerifier.addMultiSignerGroup(groupId, [outsider], 1);
    expect(outsiderVerifier.verifyMultiSignerCredential(byOutsider)).toBe(true);
    const withOutsider = mergeMultiSignerCredentials(byFirst, byOutsider);
    expect(verifier.validMultiSignerMembers(withOutsider)).toEqual([
      memberId(0),
    ]);
    expect(() => verifier.verifyMultiSignerCredential(withOutsider)).toThrow();

    // A tampered signature is not counted.
    const bySecond = signAs(1);
    const signature = bySecond.proofs[0].signature;
    const flipped = signature[10] === "A" ? "B" : "A";
    const tampered = mergeMultiSignerCredentials(byFirst, {
      ...bySecond,
      proofs: [
        {
          ...bySecond.proofs[0],
          signature: `${signature.slice(0, 10)}${flipped}${signature.slice(11)}`,
        },
      ],
    });
    expect(verifier.validMultiSignerMembers(tampered)).toEqual([memberId(0)]);
    expect(() => verifier.verifyMultiSignerCredential(tampered)).toThrow();
  });

  it("keeps existing authorizations valid when a member signature is added later", () => {
    const verifier = groupVerifier(2);
    const byFirst = signAs(0);
    const authorization = holder.authorizeMultiSignerCredentialUse(
      authorizationRequest,
      byFirst,
    );
    expect(() =>
      verifier.verifyMultiSignerCredentialAuthorization(byFirst, authorization),
    ).toThrow();

    const credential = mergeMultiSignerCredentials(byFirst, signAs(1));
    expect(
      verifier.verifyMultiSignerCredentialAuthorization(
        credential,
        authorization,
      ),
    ).toBe(true);
  });

  it("does not authorize a credential with different info or group id", () => {
    const verifier = groupVerifier(2);
    verifier.addMultiSignerGroup(otherGroupId, members, 2);
    const authorization = holder.authorizeMultiSignerCredentialUse(
      authorizationRequest,
      mergeMultiSignerCredentials(signAs(0), signAs(1)),
    );
    const otherInfo = { ...credentialInfo, level: 3 };
    const otherInfoCredential = mergeMultiSignerCredentials(
      signAs(0, otherInfo),
      signAs(1, otherInfo),
    );
    const otherGroupCredential = mergeMultiSignerCredentials(
      signAs(0, credentialInfo, holder.publicKey, otherGroupId),
      signAs(1, credentialInfo, holder.publicKey, otherGroupId),
    );

    for (const credential of [otherInfoCredential, otherGroupCredential]) {
      expect(verifier.verifyMultiSignerCredential(credential)).toBe(true);
      expect(() =>
        verifier.verifyMultiSignerCredentialAuthorization(
          credential,
          authorization,
        ),
      ).toThrow("credential digest is not authorized");
    }
  });

  it("keeps group signatures and single-issuer signatures apart", () => {
    const groupCredential = signAs(0);
    const singleVerifier = new VerificationContext();
    singleVerifier.addIssuerAuthority(members[0]);

    expect(() =>
      singleVerifier.verifyCredential({
        version: 1,
        credential: {
          ...groupCredential.credential,
          issuer_id_pubkey: memberId(0),
        },
        proof: { signature: groupCredential.proofs[0].signature },
      }),
    ).toThrow();

    const { request, pending } = PendingIssuance.createRequest(
      members[0],
      credentialInfo,
      holder.publicKey,
    );
    const single = pending.finalize(
      members[0],
      issuers[0].issueCredential(credentialInfo, request),
    );
    const verifier = groupVerifier(1);
    const forged = {
      version: 1,
      credential: { ...single.credential, issuer_id_pubkey: groupId },
      proofs: [
        { issuer_id_pubkey: memberId(0), signature: single.proof.signature },
      ],
    } satisfies MultiSignerCredential;
    expect(verifier.validMultiSignerMembers(forged)).toEqual([]);
    expect(() => verifier.verifyMultiSignerCredential(forged)).toThrow();
  });

  it("persists pending state and rejects mismatched responses and merges", () => {
    const { request, pending } = MultiSignerPendingIssuance.createRequest(
      groupId,
      members[0],
      credentialInfo,
      holder.publicKey,
    );
    const restored = MultiSignerPendingIssuance.importState(
      pending.exportState(),
    );
    const response = issuers[0].issueMultiSignerCredential(
      groupId,
      credentialInfo,
      request,
    );
    // A response naming another member does not match the pending state.
    // (Another member cannot sign this request: it was blinded for member 0's key.)
    const wrongMember = { ...response, issuer_id: memberId(1) };
    expect(() =>
      MultiSignerPendingIssuance.importState(pending.exportState()).finalize(
        members[0],
        wrongMember,
      ),
    ).toThrow("issuer_id does not match");

    const credential = restored.finalize(members[0], response);
    expect(groupVerifier(1).verifyMultiSignerCredential(credential)).toBe(true);
    expect(() =>
      mergeMultiSignerCredentials(credential, signAs(1, { level: 9 })),
    ).toThrow("multi-signer credentials do not match");
  });

  it("validates group configuration", () => {
    const verifier = new VerificationContext();

    expect(() => verifier.addMultiSignerGroup(groupId, members, 0)).toThrow();
    expect(() => verifier.addMultiSignerGroup(groupId, members, 4)).toThrow();
    expect(() =>
      verifier.addMultiSignerGroup(memberId(0), members, 1),
    ).toThrow();
    expect(() => verifier.addMultiSignerGroup("not-a-key", members, 1)).toThrow(
      "group_id is not a valid Nostr public key",
    );
    expect(() => verifier.verifyMultiSignerCredential(signAs(0))).toThrow(
      "unknown issuer",
    );
    expect(() =>
      issuers[0].issueMultiSignerCredential(
        memberId(0),
        credentialInfo,
        MultiSignerPendingIssuance.createRequest(
          groupId,
          members[0],
          credentialInfo,
          holder.publicKey,
        ).request,
      ),
    ).toThrow();
  });
});
