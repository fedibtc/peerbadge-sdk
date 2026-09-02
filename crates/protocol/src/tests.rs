use blind_rsa_signatures::Signature as PbrsaSignature;
use serde_json::json;
use std::time::{Duration, Instant};

use crate::{
    Credential, CredentialDigest, CredentialProof, HolderAuthorization, HolderAuthorizationRequest,
    HolderAuthorizationStatement, HolderContext, HolderId, IssuerAuthority, IssuerContext,
    IssuerId, IssuerSecretKeys, PendingIssuance, ProtocolV1, Revocation, RevocationLocation,
    RevocationProof, SchnorrSignatureProof, SignedCredential, SignedRevocation, SubjectPubkey,
    VerificationContext,
};

const TEST_RNG_SEED: u64 = 0x5eed_f00d_cafe_babe;

type NostrRng = nostr::secp256k1::rand::rngs::StdRng;
type PbrsaRng = blind_rsa_signatures::reexports::rand::rngs::StdRng;

// Keygen is super slow which makes the tests take minutes to run.
// This hard codes issuer keys for tests so they run in seconds.
fn test_issuer_secret_keys() -> IssuerSecretKeys {
    serde_json::from_value(json!({
        "issuer_id_secret_key": "76127aa07dc3a3dcad06c8f8835ff997adb9c542868434bc47d16f1c9ba860b8",
        "issuance_secret_key": "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDAQ1EwvOUFvlSU0vvwrRFsZoFtswUS1kdp0zxpmSF1clbKtpuY2TXkhSsOXMtAy2Ci2tCQ1_bqviht3pYTuF2KkBFa_0lbNXf1-jVbjckvWhjVfQoTNUn9QzvUPQklSBEokEXgHjvhI4vASaCWStl7Os5FfZW6MJ7CPNuSLouuIoI9aWTplP2-PD4DC9kzP3sRBSugVvx6CgPjPCq9T1eQzy52Ed18bpY0IKgvBkKnnc2j2JuvDENRDX2KxLHjpymDJhrMC_pSTxSnUMOncozdw-HI7E1I7t59gWiXz0S8Uk5kom2NS2x4QUkFKjpxQwarupAObUhtnDaLjCrszybxAgMBAAECggEAMxqxng7XoWsx-E0MgrC-DN5CUPJgyt0CJnLrf_YgGqPFxiQ7v6kc1h0_kJXBwPtOOHuJLLb6_vKEtI-RvLQoyQf6VQG-cewIcu2K-Ub6zwdXyoduAiUMAbG5WXTP1YUOaoXOzP-8Ut-r6fSoJsrGfCbpZTc4cUEzMdYTVwvgPOyhJr66lD26wWMnJD7hk8qi54lhpWG2fkwR61eSKhO_sBLUYXPywxkGVLRfXVpXZxxr8EDMDsxeD03Y6rZOMAS3-g4xv8-dIGFjbIPH_VsZn8g8eRmtAaaVLoDGfphaOfP5JSYw76QLzj5Y0Slzf3wUaaK3dxbAQoUIKi_RaCb7sQKBgQDRcOQ9hqQTF0g5TovWw8nLwJyCPrbqcjDT6MuQYDWKzKzPeQ6fPcjbpCgme7YCUZZ8AT2n9yZaFWOjNxGyRKps-YcBI2nhmQWzuV_UcmayxtehJ0ee3PyukKs8aJieuBwb9xFzZ5-ekSiDbghmA-wSvHDXoLFf1HDZXhH3XpxgBwKBgQDrANa5p1wmzNcW4Lvh8qkFhE9eGTbKugpxw94I6Qj2RQImupVBySSt1v_pi2771R66foBvspnzaEf505BNppYZ9jh3zLS3jjhztkkK76MOilho0cFHF0328s3AgNI8LFQDYpVp-_rCDb6NwPPLAhEewyecL690xvE_NbUMlTATRwKBgQDCnaZYzZ3053ODXMtwe2ouXQKRvHj4Dbf1kaJmvB_EpEAIYjMGIcFc54Mvj1EngmzVOcnzJCONHccCSQ-2mTvMG2op0qB2s1yrDpxPqyZnBYIlC3zvz-U0yNV1QrRe-DGWgtTCag3WqIf-6OYA9bAOEPDCTV3E8IEUWudS96VTTQKBgQDYbNlT-XHAuf2MsEPX_ubykbuWaZowcc2UoFIn2pXKWBt3F3bGMzx4bP0aVLNNciTuk_os5EssA-nlhpXrLXQnTL8MdZYpRe1vg30ZeUCt73MkdaiOlEPVHh-nHfyANkLZKz13cfyqIoZPflgHqkuiDRC5oqDv5xfeotOuVucDmQKBgH_9bUklrSGmRvIKwPyuaP52vSOWginmXzjRKvOGIleg6RRQs4tlbsVluHeQx7bZQQ4b578NYyK78FWfX1AG1OrbscHN8vUrSTN_viPGn6gXpxL0KDaX8okd7zdixwwxqYD0juxmLlaRSTGTAwUF0f-EkPDuNdisG-gkbbsBRJat",
    }))
    .unwrap()
}

fn test_issuer_context() -> IssuerContext {
    IssuerContext::import_secret_key(&test_issuer_secret_keys()).unwrap()
}

fn issuer_context_with_identity(identity_keys: nostr::Keys) -> IssuerContext {
    let mut secret_keys = test_issuer_secret_keys();
    secret_keys.issuer_id_secret_key = identity_keys.secret_key().to_secret_hex();
    IssuerContext::import_secret_key(&secret_keys).unwrap()
}

fn revocation_signed_by(
    issuer: &IssuerContext,
    credential: &SignedCredential,
    rng: &mut NostrRng,
) -> SignedRevocation {
    let secret_keys = issuer.export_secret_key().unwrap();
    let identity_keys = nostr::Keys::parse(&secret_keys.issuer_id_secret_key).unwrap();
    let revocation = Revocation {
        credential_digest: crate::CredentialDigest(credential.credential.digest().unwrap()),
    };
    let signature = identity_keys.sign_schnorr_with_ctx(
        nostr::SECP256K1,
        &nostr::secp256k1::Message::from_digest(revocation.digest().unwrap().into()),
        rng,
    );

    SignedRevocation {
        version: ProtocolV1,
        revocation,
        proof: RevocationProof {
            issuer_id_pubkey: crate::IssuerId(identity_keys.public_key()),
            signature,
        },
    }
}

fn credential_for_authorization(
    issuer_id_pubkey: IssuerId,
    holder_public_key: nostr::PublicKey,
) -> SignedCredential {
    SignedCredential {
        version: ProtocolV1,
        credential: Credential {
            issuer_id_pubkey,
            info: json!({
                "schema": "fedi-trust-score-v1.0",
                "trust_level": 7,
            }),
            blind_msg: json!(holder_public_key),
        },
        proof: CredentialProof {
            signature: PbrsaSignature(vec![1, 2, 3, 4]),
        },
    }
}

fn holder_authorization_request(
    subject_public_key: nostr::PublicKey,
    holder_public_key: nostr::PublicKey,
) -> (HolderAuthorizationRequest, SignedCredential) {
    let credential = credential_for_authorization(
        IssuerId(nostr::PublicKey::from_byte_array([7u8; 32])),
        holder_public_key,
    );
    let request = HolderAuthorizationRequest {
        subject_pubkey: SubjectPubkey(subject_public_key),
    };

    (request, credential)
}

struct CredentialAuthorizationFixture {
    verifier: VerificationContext,
    holder: HolderContext,
    credential: SignedCredential,
    authorization: HolderAuthorization,
    issued_at: u64,
}

fn issue_credential_for_holder(
    issuer: &IssuerContext,
    issuer_authority: &IssuerAuthority,
    holder: &HolderContext,
    pbrsa_rng: &mut PbrsaRng,
) -> SignedCredential {
    let credential_info = json!({
        "schema": "fedi-trust-score-v1.0",
        "trust_level": 7,
    });
    let blind_msg = json!(holder.public_key());
    let (request, pending) = PendingIssuance::create_request_with_rng(
        &issuer_authority.issuer.issuance_key,
        issuer_authority.issuer.issuer_id_pubkey.clone(),
        credential_info.clone(),
        blind_msg,
        pbrsa_rng,
    )
    .unwrap();
    let response = issuer
        .issue_credential_with_rng(credential_info, &request, pbrsa_rng)
        .unwrap();

    pending
        .finalize(&issuer_authority.issuer.issuance_key, &response)
        .unwrap()
}

fn credential_authorization_fixture() -> CredentialAuthorizationFixture {
    let mut nostr_rng =
        <NostrRng as nostr::secp256k1::rand::SeedableRng>::seed_from_u64(TEST_RNG_SEED);
    let mut pbrsa_rng =
        <PbrsaRng as blind_rsa_signatures::reexports::rand::SeedableRng>::from_seed([9u8; 32]);
    let issuer = test_issuer_context();
    let issuer_authority = issuer
        .issuer_authority_with_rng(vec![], &mut nostr_rng)
        .unwrap();
    let holder = HolderContext::generate_with_rng(&mut nostr_rng);
    let subject = nostr::Keys::generate_with_rng(&mut nostr_rng);
    let credential =
        issue_credential_for_holder(&issuer, &issuer_authority, &holder, &mut pbrsa_rng);
    let issued_at = 1_717_000_000;
    let subject_pubkey = SubjectPubkey(subject.public_key());
    let authorization = holder
        .authorize_credential_use_with_rng_at_time(
            HolderAuthorizationRequest {
                subject_pubkey: subject_pubkey.clone(),
            },
            &credential,
            issued_at,
            &mut nostr_rng,
        )
        .unwrap();
    let mut verifier = VerificationContext::new();
    verifier.add_issuer_authority(&issuer_authority).unwrap();

    CredentialAuthorizationFixture {
        verifier,
        holder,
        credential,
        authorization,
        issued_at,
    }
}

fn authorization_statement_signed_by_holder(
    holder: &HolderContext,
    authorization: HolderAuthorizationStatement,
    rng: &mut NostrRng,
) -> HolderAuthorization {
    let identity_keys = nostr::Keys::parse(&holder.export_secret_key()).unwrap();
    let signature = identity_keys.sign_schnorr_with_ctx(
        nostr::SECP256K1,
        &nostr::secp256k1::Message::from_digest(authorization.digest().unwrap().into()),
        rng,
    );

    HolderAuthorization {
        version: ProtocolV1,
        authorization,
        proof: SchnorrSignatureProof { signature },
    }
}

#[derive(Clone, Debug)]
struct KeygenTiming {
    run: usize,
    elapsed: Duration,
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn env_bool(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            matches!(
                value.as_str(),
                "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
            )
        })
        .unwrap_or(false)
}

fn smoke_test_generated_issuer(issuer: &IssuerContext) {
    let exported = issuer.export_secret_key().unwrap();
    assert!(!exported.issuer_id_secret_key.is_empty());
    assert!(!exported.issuance_secret_key.is_empty());

    let issuer_authority = issuer.issuer_authority(vec![]).unwrap();
    issuer_authority.verify().unwrap();

    let credential_info = json!({
        "schema": "rsa-keygen-smoke-v1",
        "trust_level": 1,
    });
    let holder = HolderContext::generate();
    let blind_msg = json!(holder.public_key());
    let (request, pending) = PendingIssuance::create_request(
        &issuer_authority.issuer.issuance_key,
        issuer_authority.issuer.issuer_id_pubkey.clone(),
        credential_info.clone(),
        blind_msg,
    )
    .unwrap();
    let response = issuer.issue_credential(credential_info, &request).unwrap();
    let credential = pending
        .finalize(&issuer_authority.issuer.issuance_key, &response)
        .unwrap();

    let mut verifier = VerificationContext::new();
    verifier.add_issuer_authority(&issuer_authority).unwrap();
    verifier.verify_credential(&credential).unwrap();
}

fn generate_issuer_for_timing(run: usize, run_count: usize) -> KeygenTiming {
    let started = Instant::now();
    let issuer = IssuerContext::generate().unwrap();
    let elapsed = started.elapsed();

    eprintln!(
        "IssuerContext::generate() RSA keygen run {run}/{run_count} completed in {:.3}s",
        elapsed.as_secs_f64()
    );

    smoke_test_generated_issuer(&issuer);

    KeygenTiming { run, elapsed }
}

fn median_seconds(sorted_seconds: &[f64]) -> f64 {
    let mid = sorted_seconds.len() / 2;
    if sorted_seconds.len() % 2 == 0 {
        (sorted_seconds[mid - 1] + sorted_seconds[mid]) / 2.0
    } else {
        sorted_seconds[mid]
    }
}

fn report_keygen_stats(timings: &[KeygenTiming], wall_elapsed: Duration, concurrent: bool) {
    let mut sorted_by_elapsed = timings.to_vec();
    sorted_by_elapsed.sort_by(|a, b| a.elapsed.as_secs_f64().total_cmp(&b.elapsed.as_secs_f64()));
    let sorted_seconds = sorted_by_elapsed
        .iter()
        .map(|timing| timing.elapsed.as_secs_f64())
        .collect::<Vec<_>>();

    let average = sorted_seconds.iter().sum::<f64>() / sorted_seconds.len() as f64;
    let median = median_seconds(&sorted_seconds);
    let fastest = &sorted_by_elapsed[0];
    let slowest = &sorted_by_elapsed[sorted_by_elapsed.len() - 1];

    eprintln!(
        "IssuerContext::generate() RSA keygen summary: runs={}, concurrent={}, wall={:.3}s, fastest={:.3}s (run {}), slowest={:.3}s (run {}), average={:.3}s, median={:.3}s",
        timings.len(),
        concurrent,
        wall_elapsed.as_secs_f64(),
        fastest.elapsed.as_secs_f64(),
        fastest.run,
        slowest.elapsed.as_secs_f64(),
        slowest.run,
        average,
        median
    );

    let mut by_run = timings.to_vec();
    by_run.sort_by_key(|timing| timing.run);
    for timing in by_run {
        eprintln!(
            "IssuerContext::generate() RSA keygen sample {}: {:.3}s",
            timing.run,
            timing.elapsed.as_secs_f64()
        );
    }
}

#[test]
fn protocol_snapshots() {
    let mut nostr_rng =
        <NostrRng as nostr::secp256k1::rand::SeedableRng>::seed_from_u64(TEST_RNG_SEED);
    let mut pbrsa_seed = [0; 32];
    nostr::secp256k1::rand::RngCore::fill_bytes(&mut nostr_rng, &mut pbrsa_seed);
    let mut pbrsa_rng =
        <PbrsaRng as blind_rsa_signatures::reexports::rand::SeedableRng>::from_seed(pbrsa_seed);

    let credential_info = json!({
        "schema": "fedi-trust-score-v1.0",
        "trust_level": 7,
    });
    // Create issuer metadata before any holder interaction.
    let issuer = test_issuer_context();
    // Keep the Nostr RNG sequence aligned with the original generated-issuer
    // snapshots while avoiding slow safe-prime RSA key generation.
    let _discarded_identity_keys = nostr::Keys::generate_with_rng(&mut nostr_rng);
    let issuer_authority = issuer
        .issuer_authority_with_rng(
            vec![RevocationLocation {
                protocol: "nostr".to_owned(),
                location: "wss://relay.example.com".to_owned(),
            }],
            &mut nostr_rng,
        )
        .unwrap();

    insta::assert_json_snapshot!(issuer_authority, @r###"
    {
      "version": 1,
      "issuer": {
        "issuer_id_pubkey": "edf91ee8ef705ad30cdbffffe86cd1fb08a6114178ed998f7a5ad52e25a67f97",
        "issuance_key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwENRMLzlBb5UlNL78K0RbGaBbbMFEtZHadM8aZkhdXJWyrabmNk15IUrDlzLQMtgotrQkNf26r4obd6WE7hdipARWv9JWzV39fo1W43JL1oY1X0KEzVJ_UM71D0JJUgRKJBF4B474SOLwEmglkrZezrORX2VujCewjzbki6LriKCPWlk6ZT9vjw-AwvZMz97EQUroFb8egoD4zwqvU9XkM8udhHdfG6WNCCoLwZCp53No9ibrwxDUQ19isSx46cpgyYazAv6Uk8Up1DDp3KM3cPhyOxNSO7efYFol89EvFJOZKJtjUtseEFJBSo6cUMGq7qQDm1IbZw2i4wq7M8m8QIDAQAB",
        "revocation": [
          {
            "protocol": "nostr",
            "location": "wss://relay.example.com"
          }
        ]
      },
      "proof": {
        "signature": "2xoKYBx5zOvhInwiSnSwH0mugCsvgPqjEJLEvPhaAJ16b9pR0qlJzF2msXF9VeKX36zOWvvsu9PWlMbe1PsIGw"
      }
    }
    "###);

    // Create the holder's blinded issuance request.
    let holder = HolderContext::generate_with_rng(&mut nostr_rng);
    let blind_msg = json!(holder.public_key());
    let (request, pending) = PendingIssuance::create_request_with_rng(
        &issuer_authority.issuer.issuance_key,
        issuer_authority.issuer.issuer_id_pubkey.clone(),
        credential_info.clone(),
        blind_msg,
        &mut pbrsa_rng,
    )
    .unwrap();

    insta::assert_json_snapshot!(request, @r###"
    {
      "version": 1,
      "blinded_message": "lVObVKDwBk70A0XkJSeXNMLe6lRmF1wX6Im2RwN1xsAliAQ5t8b7BIvcl1YHml5fepA1tYrVWrgKvD8KcEMl63qFnzNqgAA8OiyLihlITB0nInmKlJuZDtiVECfHM9H6jlr-2_apoUp4W4YRrytP58rYLy-13B7OVAmJgdNmIKTPQTiObMhgiFj837vd5xRf8bfagBJRsvzqAv06sVaa1wB7_ZI4heUoa4EMkH6FUN80t1ZAv4yaASyK_LIJ_sfuNUfmGvYBrafkTG-5_9bkYCz6bYmte03kFZB0Y6owjr-PvQriPY5b2wS1aZCn850R3WNOHy98HJO_krUPoNw46A"
    }
    "###);

    // Issue the blinded credential response from the trusted issuer.
    let response = issuer
        .issue_credential_with_rng(credential_info, &request, &mut pbrsa_rng)
        .unwrap();

    insta::assert_json_snapshot!(response, @r###"
    {
      "version": 1,
      "issuer_id": "edf91ee8ef705ad30cdbffffe86cd1fb08a6114178ed998f7a5ad52e25a67f97",
      "info": {
        "schema": "fedi-trust-score-v1.0",
        "trust_level": 7
      },
      "blind_signature": "O2YBb_kP0tCSPNbytQiKsNdfDQQ054RMnZcwmXxpSERC1lLZdsLPOY0V4N1kygVtIdy0cOrYPe22hM6x5kC3bPIEdDMLfHzuGuRSp-QfSY5rKHxpCPLvdAg31c4zVMF1V15sLjW0AfYebyg462LUqZXntt54TwsT_QTUOi9hgHT4N8tBuEbipAEhfQfF3MTOp024nwsvhoPKh6l4-iH7vWVgVNjh3y_bYPLbNKzXSHTJp5OjLMRkkb_qVGOl-zfohz9B7SaTPoSt4Xdwp5SnFY9jfqOlzYJ75v9mnshv4rjpwwlZgf6zH72itkCZzzjK34LpZD8eHAKocshAAccaMg"
    }
    "###);

    // Finalize the blinded response into the holder's credential.
    let mut credential = pending
        .finalize(&issuer_authority.issuer.issuance_key, &response)
        .unwrap();

    insta::assert_json_snapshot!(credential, @r###"
    {
      "version": 1,
      "credential": {
        "issuer_id_pubkey": "edf91ee8ef705ad30cdbffffe86cd1fb08a6114178ed998f7a5ad52e25a67f97",
        "info": {
          "schema": "fedi-trust-score-v1.0",
          "trust_level": 7
        },
        "blind_msg": "8ec0627df98259165e8f4cc88f57757bad9579c129d729bbd3bef47b0321cbf9"
      },
      "proof": {
        "signature": "jn5ZZhl_okr9S8jtf19fo7Ili71DYPiK5XRFg3MhpXBMnzerv6QWpTFZ3EoL7pHRlqFfZnQUbBEk3xco2tQHDzrrAJyqGQnHw25wpxn4rAZ_mTEj74tnelcIIiBdFXV6j51TRXFp7wbDo4jUYcOdpQ6PSvu0PljgHKI-OmKZRgQW_UgDQNUlvDu6hAiAQUrXaoGAk8vwOuzjm1Jt3z_mlKdWoUuXIiqaEFOrU3qc-g3LGpMB7PuW4mhBsiN74ah76K7MP2gkYsdVN4LXw-V2N-IpM-xWtSYVrhC2rilOwtQkf1tNuaxiV_q-Di-6xApem4dDKNL4rIrVFJYF9CodCQ"
      }
    }
    "###);

    // Revoke the finalized credential and snapshot the signed revocation.
    let signed_revocation = issuer
        .revoke_credential_with_rng(&credential, &mut nostr_rng)
        .unwrap();

    insta::assert_json_snapshot!(signed_revocation, @r###"
    {
      "version": 1,
      "revocation": {
        "credential_digest": "tetb3pX05--31jb9ZO8yoU5Wn2xSXm9YdB3tG9fVxUA"
      },
      "proof": {
        "issuer_id_pubkey": "edf91ee8ef705ad30cdbffffe86cd1fb08a6114178ed998f7a5ad52e25a67f97",
        "signature": "M7jsEWZOiuZFnAP8kpNQI6O5eLDSbPPDtS0P4eBKZyOLdvA6aLKFNE0IbY4_bTKtVxzdAwZpDRVAsMWLlBOn-g"
      }
    }
    "###);
    let other_identity_keys = nostr::Keys::generate_with_rng(&mut nostr_rng);
    let other_issuer = issuer_context_with_identity(other_identity_keys);
    let other_issuer_authority = other_issuer
        .issuer_authority_with_rng(vec![], &mut nostr_rng)
        .unwrap();
    let other_issuer_revocation = revocation_signed_by(&other_issuer, &credential, &mut nostr_rng);

    // Verify the same credential before and after trusting the issuer and revocation.
    let mut verifier = VerificationContext::new();
    let unknown_before_trust = verifier.verify_credential(&credential).unwrap_err();
    verifier.add_issuer_authority(&issuer_authority).unwrap();
    verifier
        .add_issuer_authority(&other_issuer_authority)
        .unwrap();
    let verified_before_revocation = verifier.verify_credential(&credential).is_ok();
    verifier.add_revocation(&other_issuer_revocation).unwrap();
    let verified_after_other_issuer_revocation = verifier.verify_credential(&credential).is_ok();
    verifier.add_revocation(&signed_revocation).unwrap();
    let revoked_after_revocation = verifier.verify_credential(&credential).unwrap_err();

    insta::assert_json_snapshot!(json!({
        "unknown_before_trust": unknown_before_trust.to_string(),
        "verified_before_revocation": verified_before_revocation,
        "verified_after_other_issuer_revocation": verified_after_other_issuer_revocation,
        "revoked_after_revocation": revoked_after_revocation.to_string(),
    }), @r###"
    {
      "revoked_after_revocation": "credential has been revoked",
      "unknown_before_trust": "unknown issuer",
      "verified_after_other_issuer_revocation": true,
      "verified_before_revocation": true
    }
    "###);

    // Importing persisted issuer secrets must preserve both identity and issuance keys.
    let imported = IssuerContext::import_secret_key(&issuer.export_secret_key().unwrap()).unwrap();
    let imported_authority = imported.issuer_authority(vec![]).unwrap();

    insta::assert_json_snapshot!(json!({
        "original_issuer_id": issuer_authority.issuer.issuer_id_pubkey,
        "imported_issuer_id": imported_authority.issuer.issuer_id_pubkey,
        "same_issuance_public_key": issuer_authority.issuer.issuance_key == imported_authority.issuer.issuance_key,
    }), @r###"
    {
      "imported_issuer_id": "edf91ee8ef705ad30cdbffffe86cd1fb08a6114178ed998f7a5ad52e25a67f97",
      "original_issuer_id": "edf91ee8ef705ad30cdbffffe86cd1fb08a6114178ed998f7a5ad52e25a67f97",
      "same_issuance_public_key": true
    }
    "###);

    // Tampering checks cover signed issuer metadata, credential payloads, and issuer mismatch.
    let mut tampered_authority = issuer_authority.clone();
    tampered_authority.issuer.revocation[0].location = "wss://evil.example.com".to_owned();

    credential.credential.blind_msg = json!("mallory-public-key");
    let mut verifier = VerificationContext::new();
    verifier.add_issuer_authority(&issuer_authority).unwrap();

    insta::assert_json_snapshot!(json!({
        "tampered_credential": verifier.verify_credential(&credential).unwrap_err().to_string(),
        "tampered_authority": tampered_authority.verify().unwrap_err().to_string(),
        "wrong_issuer_revoke": other_issuer.revoke_credential(&credential).unwrap_err().to_string(),
    }), @r###"
    {
      "tampered_authority": "verification failed",
      "tampered_credential": "blind RSA operation failed: Verification failed",
      "wrong_issuer_revoke": "issuer_id does not match"
    }
    "###);
}

#[test]
fn holder_context_authorizes_credential_use() {
    let mut rng = <NostrRng as nostr::secp256k1::rand::SeedableRng>::seed_from_u64(TEST_RNG_SEED);
    let holder = HolderContext::generate_with_rng(&mut rng);
    let subject = nostr::Keys::generate_with_rng(&mut rng);
    let (request, credential) =
        holder_authorization_request(subject.public_key(), holder.public_key());
    let expected_credential_digest = CredentialDigest(credential.credential.digest().unwrap());

    let authorization = holder
        .authorize_credential_use_with_rng_at_time(request, &credential, 1_717_000_000, &mut rng)
        .unwrap();

    assert_eq!(authorization.version, ProtocolV1);
    assert_eq!(
        authorization.authorization.holder_id_pubkey,
        HolderId(holder.public_key())
    );
    assert_eq!(
        authorization.authorization.subject_pubkey,
        SubjectPubkey(subject.public_key())
    );
    assert_eq!(
        authorization.authorization.credential_digest,
        expected_credential_digest
    );
    assert_eq!(
        authorization.digest().unwrap(),
        authorization.authorization.digest().unwrap()
    );

    let holder_public_key = authorization
        .authorization
        .holder_id_pubkey
        .0
        .xonly()
        .unwrap();
    nostr::SECP256K1
        .verify_schnorr(
            &authorization.proof.signature,
            &nostr::secp256k1::Message::from_digest(authorization.digest().unwrap().into()),
            &holder_public_key,
        )
        .unwrap();
}

#[test]
fn verification_context_verifies_credential_authorization() {
    let fixture = credential_authorization_fixture();

    fixture
        .authorization
        .verify()
        .expect("holder authorization signature verifies");
    fixture
        .verifier
        .verify_credential_authorization_at_time(
            &fixture.credential,
            &fixture.authorization,
            fixture.issued_at + 1,
        )
        .unwrap();
}

#[test]
fn verification_context_rejects_invalid_credential_authorizations() {
    let fixture = credential_authorization_fixture();
    let mut rng =
        <NostrRng as nostr::secp256k1::rand::SeedableRng>::seed_from_u64(TEST_RNG_SEED + 1);
    let other_holder = HolderContext::generate_with_rng(&mut rng);
    let different_credential = credential_for_authorization(
        IssuerId(nostr::Keys::generate_with_rng(&mut rng).public_key()),
        fixture.holder.public_key(),
    );
    let other_holder_credential = credential_for_authorization(
        fixture.credential.credential.issuer_id_pubkey.clone(),
        other_holder.public_key(),
    );
    let missing_ref_authorization = fixture
        .holder
        .authorize_credential_use_with_rng_at_time(
            HolderAuthorizationRequest {
                subject_pubkey: fixture.authorization.authorization.subject_pubkey.clone(),
            },
            &different_credential,
            fixture.issued_at,
            &mut rng,
        )
        .unwrap();
    let mut holder_mismatch_statement = fixture.authorization.authorization.clone();
    holder_mismatch_statement.holder_id_pubkey = HolderId(other_holder.public_key());
    let holder_mismatch_authorization = authorization_statement_signed_by_holder(
        &other_holder,
        holder_mismatch_statement,
        &mut rng,
    );
    let mut tampered_authorization = fixture.authorization.clone();
    tampered_authorization.authorization.issued_at = crate::Timestamp(fixture.issued_at + 2);

    insta::assert_json_snapshot!(json!({
        "signing_holder_mismatch": fixture.holder.authorize_credential_use_with_rng_at_time(
            HolderAuthorizationRequest {
                subject_pubkey: fixture.authorization.authorization.subject_pubkey.clone(),
            },
            &other_holder_credential,
            fixture.issued_at,
            &mut rng,
        ).unwrap_err().to_string(),
        "holder_mismatch": fixture.verifier.verify_credential_authorization_at_time(
            &fixture.credential,
            &holder_mismatch_authorization,
            fixture.issued_at + 1,
        ).unwrap_err().to_string(),
        "future_issued_at": fixture.verifier.verify_credential_authorization_at_time(
            &fixture.credential,
            &fixture.authorization,
            fixture.issued_at - 1,
        ).unwrap_err().to_string(),
        "credential_digest_mismatch": fixture.verifier.verify_credential_authorization_at_time(
            &fixture.credential,
            &missing_ref_authorization,
            fixture.issued_at + 1,
        ).unwrap_err().to_string(),
        "tampered_authorization": fixture.verifier.verify_credential_authorization_at_time(
            &fixture.credential,
            &tampered_authorization,
            fixture.issued_at + 1,
        ).unwrap_err().to_string(),
    }), @r###"
    {
      "credential_digest_mismatch": "credential digest is not authorized",
      "future_issued_at": "authorization is not yet valid",
      "holder_mismatch": "holder_id does not match",
      "signing_holder_mismatch": "holder_id does not match",
      "tampered_authorization": "verification failed"
    }
    "###);
}

#[test]
#[ignore = "slow RSA safe-prime key generation; run with --ignored --nocapture to print timing"]
fn issuer_context_generate_reports_rsa_keygen_timing() {
    let run_count = env_usize("RSA_KEYGEN_RUNS", 1);
    let concurrent = env_bool("RSA_KEYGEN_CONCURRENT") && run_count > 1;
    let wall_started = Instant::now();

    let timings = if concurrent {
        (1..=run_count)
            .map(|run| std::thread::spawn(move || generate_issuer_for_timing(run, run_count)))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    } else {
        (1..=run_count)
            .map(|run| generate_issuer_for_timing(run, run_count))
            .collect::<Vec<_>>()
    };

    report_keygen_stats(&timings, wall_started.elapsed(), concurrent);
}
