//! Multi-signer issuance and verification tests.

use blind_rsa_signatures::{reexports::rand::SeedableRng as _, Signature as PbrsaSignature};
use serde_json::{json, Value};

use crate::{
    Credential, CredentialDigest, CredentialProof, CredentialsError, HolderAuthorization,
    HolderAuthorizationRequest, HolderContext, IssuerAuthority, IssuerContext, IssuerId,
    IssuerSecretKeys, MultiSignerCredential, MultiSignerPendingIssuance, MultiSignerProof,
    PendingIssuance, ProtocolV1, SignedCredential, SubjectPubkey, VerificationContext,
};

type NostrRng = nostr::secp256k1::rand::rngs::StdRng;
type PbrsaRng = blind_rsa_signatures::reexports::rand::rngs::StdRng;

// Test-only PBRSA issuance keys, generated once so tests skip slow keygen.
// Each member needs its own key; never reuse these outside tests.
const ISSUANCE_SECRET_KEYS: [&str; 4] = [
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDAQ1EwvOUFvlSU0vvwrRFsZoFtswUS1kdp0zxpmSF1clbKtpuY2TXkhSsOXMtAy2Ci2tCQ1_bqviht3pYTuF2KkBFa_0lbNXf1-jVbjckvWhjVfQoTNUn9QzvUPQklSBEokEXgHjvhI4vASaCWStl7Os5FfZW6MJ7CPNuSLouuIoI9aWTplP2-PD4DC9kzP3sRBSugVvx6CgPjPCq9T1eQzy52Ed18bpY0IKgvBkKnnc2j2JuvDENRDX2KxLHjpymDJhrMC_pSTxSnUMOncozdw-HI7E1I7t59gWiXz0S8Uk5kom2NS2x4QUkFKjpxQwarupAObUhtnDaLjCrszybxAgMBAAECggEAMxqxng7XoWsx-E0MgrC-DN5CUPJgyt0CJnLrf_YgGqPFxiQ7v6kc1h0_kJXBwPtOOHuJLLb6_vKEtI-RvLQoyQf6VQG-cewIcu2K-Ub6zwdXyoduAiUMAbG5WXTP1YUOaoXOzP-8Ut-r6fSoJsrGfCbpZTc4cUEzMdYTVwvgPOyhJr66lD26wWMnJD7hk8qi54lhpWG2fkwR61eSKhO_sBLUYXPywxkGVLRfXVpXZxxr8EDMDsxeD03Y6rZOMAS3-g4xv8-dIGFjbIPH_VsZn8g8eRmtAaaVLoDGfphaOfP5JSYw76QLzj5Y0Slzf3wUaaK3dxbAQoUIKi_RaCb7sQKBgQDRcOQ9hqQTF0g5TovWw8nLwJyCPrbqcjDT6MuQYDWKzKzPeQ6fPcjbpCgme7YCUZZ8AT2n9yZaFWOjNxGyRKps-YcBI2nhmQWzuV_UcmayxtehJ0ee3PyukKs8aJieuBwb9xFzZ5-ekSiDbghmA-wSvHDXoLFf1HDZXhH3XpxgBwKBgQDrANa5p1wmzNcW4Lvh8qkFhE9eGTbKugpxw94I6Qj2RQImupVBySSt1v_pi2771R66foBvspnzaEf505BNppYZ9jh3zLS3jjhztkkK76MOilho0cFHF0328s3AgNI8LFQDYpVp-_rCDb6NwPPLAhEewyecL690xvE_NbUMlTATRwKBgQDCnaZYzZ3053ODXMtwe2ouXQKRvHj4Dbf1kaJmvB_EpEAIYjMGIcFc54Mvj1EngmzVOcnzJCONHccCSQ-2mTvMG2op0qB2s1yrDpxPqyZnBYIlC3zvz-U0yNV1QrRe-DGWgtTCag3WqIf-6OYA9bAOEPDCTV3E8IEUWudS96VTTQKBgQDYbNlT-XHAuf2MsEPX_ubykbuWaZowcc2UoFIn2pXKWBt3F3bGMzx4bP0aVLNNciTuk_os5EssA-nlhpXrLXQnTL8MdZYpRe1vg30ZeUCt73MkdaiOlEPVHh-nHfyANkLZKz13cfyqIoZPflgHqkuiDRC5oqDv5xfeotOuVucDmQKBgH_9bUklrSGmRvIKwPyuaP52vSOWginmXzjRKvOGIleg6RRQs4tlbsVluHeQx7bZQQ4b578NYyK78FWfX1AG1OrbscHN8vUrSTN_viPGn6gXpxL0KDaX8okd7zdixwwxqYD0juxmLlaRSTGTAwUF0f-EkPDuNdisG-gkbbsBRJat",
    "MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAHknj7o6hJ6vOGz2I70tvurG57Oe0y_iTwlxG3s-Ze3H0Ejqka6q4syC0YHROdUpcdFevyxswDSOdmTCwtzOL2FUm9BVxn_yyPZJzsbUtFhsZ5fhG0wu8g-hYO5XxEf8AIRSrYyobtYLVGHs27DN6ZL2wgBACD_JE2b84g20qHxxcM2ejoxEGVdks9vt26a3Xgr2aF4FH5R5Ms-n8Eej1M-Iaj6HCDTWE5qKKziS03NHXOOelJTHtpI7HLQHYk-gW-1fz3RTpX57wQ2M9jV7vyOaLfhXhI50zH9mnoNM-g9lXEbSDuhrECgTyY_LXKOPbRU59Ie-19HN8c8mydJgPB0CAwEAAQKCAQAO5IYOZlMXDoLpIfiSsKTfR0QEGGntYOxGRNkT9T-iUwWPcQYnamomqY4HXyi0wztyeSsW0udtjnWPPUGm0tGQLU5Z9bFI2RdK7xez6UGh_PFfAhTQ8JRgx32azr8Z-ig2G9OpjqrRNONShkMbILStlBeU4EojTRxNdJh1BtgPM9cq4HPgHyXJInAuCwjhRzJTSbwFjqtHh0rGhsj-ypnzQ0u8ARLaRSaCn6sM9788adScxSxXfsyZ7boI3QdEaOo9FCTfkLVK3PGyt6KUw7itmet90nTKWjDpss8_SF1qDrNqWh5xy8SqrQvB15CnfwkksuuR7YvBiY8dySfxFaAhAoGBAMBSIzmId7bvNhl5dNQWOxbZC-HBGabYZAMBQu-qaXPJ62BYguwTM9zbIp_l385TguhQnf9Y6tP0HB9nTdjgeKLq0lkxdiCC92EfA4K_ciLi4zBTNvYGfZzpLBpNBKkIWiKWFhTcH4cLEqM1Iv45NH3Gu3VctvYAR6YosOOcybf_AoGBAKFFFzV5JvQQ-jEfQaTKMOoSQ4ZhmdcbloMBcXlyJoa25IGomJxoDXhX_qAFlONvTfS-7Pj-fvKcRHz2kuQlK9VKzXam2c5Wtg6XjRiQh8j0HKTuJ1ZzJuAlfZnBGWQEXvG2Z83xiBbDdudXwXUSJouIlNwPB_So70SNicz4ZevjAoGAXjjfoRRG8o0HyDtFDZNGp872j0f3tVJWzVIU5S5sM5o9gxpaKibORenmcMhCeedYP1Ef1zZM9kKmdIw8C4EOGWNKYwBki1EeuapkIe6BkK3v-IEMcESFzhY-0TPikJ3S6xb1AotFtvepzeP-nOaR3P08YidmS-efMrzEzP7HpSkCgYB1Wbo2vg8bYNM-NXll-X84hMvAGHuCrN-MOtugvPDN7H5A3zcV8R2EKbvuI8Gg8hhu9ROpaD9mOVIZALAI9gd8cK8sHOO3Ix_dZGhWrK0yDHhfh7D2Vlq-lmlcHchlIE0aZFoK4SvfLKL0WsY6c1e7B0sTCpkGbnuVjcztav93cwKBgEZ-lEhUM3eGlL9fzMiDopAY6pX8syego-QwKgHWI7wl4QB6bopuxeeczPQKbn7R0LKpS7sqSJOV9JYvMML-JJSaBIgzEmvXVC9DtHwXIJtd4broPkqo1W3OkAYuPpPvq4qEKXMwBSdzkPbpeN2921ymIJhbKa90B6rN7rqMH52F",
    "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCLhMIhNBmLoRszbOGxe3zfzSlW7N8eAvOGLLlmkz4z9tsm4Fxa94M-jqIKFOJJtCT-D0WUldqpIjwRIfF1vahqkGdc5GT5r-5-COsbpM40w12zgzFjrAh9cYsIbTxrDDS_MH0ycmD9dE9gl7keyi4Ah_f8gTaJOISAEqwJ75KtFnQtOn4cXMjqZZSkYAJmoDR9ZXFcK5jyfm0wBY3Wle3d1YfCzMH8xkD8JzujZgqShZN0Dagc2q67VavCKtwMvDq5iSfBkt2QllGwhYf8VQe7apdeoBAFUW8PI4ZC6dUVk8HAGHHiZoeAx6B8irWVNnukPalP5EgtsTI41342XA3VAgMBAAECggEAWEOr4P-p7ZkFsVn_yp26GYgc0B5Y5Q6u68KdpFQgtRVF_elQ5EfUIx5vSvt9UW2DPauBtIe9ZuT-pUQZEwjiZFBo4-6mJwRzWA7iVoHD5sN2IxwrgcgTMvFDKRiacYquUAooGmMcExyjHxO9jMoRokpiy78fNl6oDLJDXqHO5GrtjGEVHqSxHQIwBwZtQixImtNTM2GzF0qMeYr9AFI-Xxgb-gmulxGRXndLLTNpu5QIUQkKWAUVuP1fBeOV9lg4kebLNZCVvIBcn5kshlkE1bzXqLJ0jaPdaUOwuiAaZobREwgNYwXKMuMXiwJnjfAkk7YWmM6hubJGzzvkzGk0nQKBgQCb1kgQ6TM6r8zY1niRIN4IBnidN8ntfblw4wDjq_voo_5zYMDbqxIpRLSY536nNEFK-1tLIa167k2ppvr-8X00I0bONosrVj5JbJl5qZ9uImRit3_TU5sFk36y8XYH128ZhW-O3LJXpDO_uCD4BVcKomxiMZOpZOUCm3earqSpPwKBgQDlMWiPTAjG21wQHyUhQonKLCC_7CncpfOPorq9kiVnq3KTxImlLH0q_9CTjdhEa_tQUzJp0UlJE-OVvID3ZECIZ5Jbo-PImPYBaXIVpiKzriSYEJRBBAcxQeSxvhS65P0TNYWSiAVyqLwlMTH__0yfHOHd4ZsmKfcgWSkodDYP6wKBgHxwnzmJzpPFgFGC6eISGdrUuAnrW77ej29ahgJH-q-qDO07TKXdNHJp38Dd0qBYNO9YSm1zZiFtG-0mXvWoBu_UX50ZpwYjJzfglam2To5Wvkyp9VPeRkMspZblA_h9CsWZbRzqlSsw_vXQZdtIAFqImv3KUvyIiesMFHUbkndnAoGAOfgFOjlA_wr8fhdijMcHktsWbXSOIgDXWb0O_mO4kkAK-tT6-4wFHJsXZjq6OJQXPHnOhnUo1BLzvSuwcuIocFfB7OvG8TW_AxxofpFGtauWFeAbn1Yle4_vCAXLuHmyiOlAn49H0XhcHgwTWWx5NMVZW4V0eHKkzsm-Xz0Fb4ECgYAQo7XoZl-jiULQUlyXh8RwbrZKRkFoVNZ8p-w_XNJiKMqsa_4eJVQzncBib0iZvCIUxqTfrCI98V8YW51WJvdvv0tLO6HC7gsFi2HxPvOrhWREToJBgyrVcX2oBcjdG2UL4EUyWOKV7NoYSdLNO206WlMlpwtV4wXmOfppVQI2iw",
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCLVKAtMb6BD5zoL-u-CQVsUlMLAkHTuAH2ljzjOQJ_BxNcMxNPfVQM2V584oj0AALSC9hzjACUKn14zOcltzuTUBh5A5APBJIqCFpEhpo3xAIOBDIH3OH2xtpVD99v4iZ4a78Lu19BLXW3hDDZWRnUDcYloHvbo6LJ2sdPAk8-tVHYs4tNPeI6hrsVwrrvf8hU7Y7ZPp6VlUx3mcqu02x4jXT1BH5zWgzs7J-8msZ8WHprAqoihJmt88MpZSTsFJOt5zPrABRA_4Fg50l9KJ8gf6CIhoOVVS12rS2X5H0sQdVlJDDD-bpFh-la1FWaIxn7oFuP2__yy8APJK6Y_lOdAgMBAAECggEATQhqztHz69NAAzeLdTPzpaIWe72xu2a-3yDNZSt979FvqMgsYwR91eTQUufEpHLlHFCkSa4cG88qNAHFwpp9-8KK5U1M9qCmV0rq7XwmA7MBF9LF_obm_9ONnv35oRg-ANJBfDEKRzTlIqOZhnG20AEVjnQeRp9AP64QB-TU_2vbNccjyaHkUCzc6gNguOZFrvLvp76V9rLctpYmpXm-jEiNdF_4wVt8w0qwflZc2UbA1qQ92tDvF97O0Vrf1A1RB13kxw_IS7OAGHSHsE8XFtVReQo2HSu_iL6IMLxG5LgUF_K0EvDF1MF-7AOCMdWTk9rl7IXmPy3H0eggL5aOGQKBgQDIKaNqhVh2QBKqKNMriGrNDZEKJyvnjHnjTWZJjXCHRpDjua6V1-M967_yAUVIZvT7qU5UX9wyLMbnUu6RNjaLOHj5BMJBf40e0VLPolPfxNtzWI5N0Sw-cu52C83YftdncybfHLtXxnPe2CUGOnx1Owe7kSj1A6i2pId4cf_ZCwKBgQCyMr3SWhAjZ306odhL3yQGutg2HJ1LK1pvuakoyjo2ujIUtVdexSzdDw3utcnuu8MzCUgCDwblD7kgSLzaZex3dkzWx2eyM_JZ4pdtoEiM16kl8zmumXV5EJ4G3b6dGLNoOOd8xIBwVVeHrknA6nSKmdyJgOI_Mdw8jnaXskH-9wKBgG60kNx-aeHlKC2SrNDb_23v_fMmnSLQ0C1GhrdRkhZPkh1Rel0H7Xg25o-b4kzcHMz_5AHIjwn1OAGDHc2UtXAkyMu5tRLy0ANmdK3AMzGFOHbAWNxzP0w-1uLVPoFqDgr6ZlpqErfGXBm5ZCjguitAfdNgws1Yu7xgnUihjIbnAoGAZ3qRwlosbvLExMyBFyX__Kx5q4qYSLNnM-PjeF1eyrL7LA1WLCFh-Qip9Ym5NpnwM23bU964CUJFJZs3l7eCRqj62-o1rEUAIfQ0LSPbnXYKso_4WgyhK-lbau9PplhWrloFCu3tC85zIsYx7AX6IRZR-8NNHpdspfmwokyQiGcCgYEArLaAyvyx0tGoKthD0STEP4fbPVf59i8NtZuYEnXg2OyblAqONf7v3nJLzhyq42ZmmbFsKCXW5cCYA7vtC1gWTucF6WqU2wxzzOui0c90dKN8vQDD-ObaO_KKWSuQ9ROYVHyqbYVYg83vkMLIVCwl4r4DblCreeHhwSm9hSyWJUU",
];

const ISSUED_AT: u64 = 1_717_000_000;

fn info() -> Value {
    json!({
        "schema": "example-membership-v1.0",
        "level": 2,
    })
}

struct Member {
    issuer: IssuerContext,
    authority: IssuerAuthority,
}

impl Member {
    fn id(&self) -> IssuerId {
        self.authority.issuer.issuer_id_pubkey.clone()
    }
}

fn member(index: usize, nostr_rng: &mut NostrRng) -> Member {
    let identity_keys = nostr::Keys::generate_with_rng(nostr_rng);
    let secret_keys: IssuerSecretKeys = serde_json::from_value(json!({
        "issuer_id_secret_key": identity_keys.secret_key().to_secret_hex(),
        "issuance_secret_key": ISSUANCE_SECRET_KEYS[index],
    }))
    .unwrap();
    let issuer = IssuerContext::import_secret_key(&secret_keys).unwrap();
    let authority = issuer.issuer_authority_with_rng(vec![], nostr_rng).unwrap();
    Member { issuer, authority }
}

struct Fixture {
    nostr_rng: NostrRng,
    pbrsa_rng: PbrsaRng,
    group_id: IssuerId,
    /// Three trusted members of the group.
    members: Vec<Member>,
    /// An issuer the verifier does not trust for the group.
    outsider: Member,
    holder: HolderContext,
}

fn fixture() -> Fixture {
    let mut nostr_rng =
        <NostrRng as nostr::secp256k1::rand::SeedableRng>::seed_from_u64(0x6d75_6c74_6953_6967);
    let pbrsa_rng = PbrsaRng::from_seed([7u8; 32]);
    // A fixed identifier with no known private key.
    let group_id = IssuerId(nostr::PublicKey::from_byte_array([0x47; 32]));
    let members = (0..3).map(|i| member(i, &mut nostr_rng)).collect();
    let outsider = member(3, &mut nostr_rng);
    let holder = HolderContext::generate_with_rng(&mut nostr_rng);

    Fixture {
        nostr_rng,
        pbrsa_rng,
        group_id,
        members,
        outsider,
        holder,
    }
}

impl Fixture {
    fn blind_msg(&self) -> Value {
        json!(self.holder.public_key())
    }

    fn member_authorities(&self) -> Vec<IssuerAuthority> {
        self.members
            .iter()
            .map(|member| member.authority.clone())
            .collect()
    }

    fn verifier(&self, threshold: usize) -> VerificationContext {
        let mut verifier = VerificationContext::new();
        verifier
            .add_multi_signer_group(self.group_id.clone(), &self.member_authorities(), threshold)
            .unwrap();
        verifier
    }

    fn sign_member(&mut self, index: usize) -> MultiSignerCredential {
        let blind_msg = self.blind_msg();
        sign(
            &self.members[index],
            &self.group_id,
            info(),
            blind_msg,
            &mut self.pbrsa_rng,
        )
    }

    fn sign_outsider(&mut self) -> MultiSignerCredential {
        let blind_msg = self.blind_msg();
        sign(
            &self.outsider,
            &self.group_id,
            info(),
            blind_msg,
            &mut self.pbrsa_rng,
        )
    }

    fn authorize(&mut self, credential: &MultiSignerCredential) -> HolderAuthorization {
        let subject = nostr::Keys::generate_with_rng(&mut self.nostr_rng);
        let credential = SignedCredential {
            version: ProtocolV1,
            credential: credential.credential.clone(),
            proof: CredentialProof {
                signature: PbrsaSignature(vec![]),
            },
        };
        self.holder
            .authorize_credential_use_with_rng_at_time(
                HolderAuthorizationRequest {
                    subject_pubkey: SubjectPubkey(subject.public_key()),
                },
                &credential,
                ISSUED_AT,
                &mut self.nostr_rng,
            )
            .unwrap()
    }
}

/// Run one member's issuance under `group_id` end to end.
fn sign(
    signer: &Member,
    group_id: &IssuerId,
    info: Value,
    blind_msg: Value,
    pbrsa_rng: &mut PbrsaRng,
) -> MultiSignerCredential {
    let (request, pending) = MultiSignerPendingIssuance::create_request_with_rng(
        &signer.authority.issuer.issuance_key,
        group_id.clone(),
        signer.id(),
        info.clone(),
        blind_msg,
        pbrsa_rng,
    )
    .unwrap();
    let response = signer
        .issuer
        .issue_multi_signer_credential_with_rng(group_id.clone(), info, &request, pbrsa_rng)
        .unwrap();
    assert_eq!(response.issuer_id, signer.id());
    assert_eq!(&response.group_id, group_id);

    pending
        .finalize(&signer.authority.issuer.issuance_key, &response)
        .unwrap()
}

fn combine(credentials: impl IntoIterator<Item = MultiSignerCredential>) -> MultiSignerCredential {
    let mut credentials = credentials.into_iter();
    let mut combined = credentials.next().unwrap();
    for credential in credentials {
        combined.merge(credential).unwrap();
    }
    combined
}

fn valid_members(
    verifier: &VerificationContext,
    credential: &MultiSignerCredential,
) -> Vec<IssuerId> {
    verifier
        .valid_multi_signer_members(credential)
        .unwrap()
        .into_iter()
        .collect()
}

fn sorted(mut ids: Vec<IssuerId>) -> Vec<IssuerId> {
    ids.sort();
    ids
}

fn assert_threshold_not_met(
    result: Result<(), CredentialsError>,
    expected_valid: usize,
    expected_threshold: usize,
) {
    match result {
        Err(CredentialsError::MultiSignerThresholdNotMet { valid, threshold }) => {
            assert_eq!((valid, threshold), (expected_valid, expected_threshold));
        }
        other => panic!("expected MultiSignerThresholdNotMet, got {other:?}"),
    }
}

#[test]
fn group_signature_is_not_the_members_single_issuer_credential() {
    let mut fixture = fixture();
    let group_credential = fixture.sign_member(0);
    let member = &fixture.members[0];
    let mut verifier = VerificationContext::new();
    verifier.add_issuer_authority(&member.authority).unwrap();

    // The member's group signature relabelled as the member's own credential.
    let as_member_credential = SignedCredential {
        version: ProtocolV1,
        credential: Credential {
            issuer_id_pubkey: member.id(),
            ..group_credential.credential.clone()
        },
        proof: CredentialProof {
            signature: group_credential.proofs[0].signature.clone(),
        },
    };
    assert!(matches!(
        verifier.verify_credential(&as_member_credential),
        Err(CredentialsError::BlindRsa(_))
    ));

    // Presented as-is through the single-issuer verifier, the group id is not a trusted issuer.
    let as_group_credential = SignedCredential {
        version: ProtocolV1,
        credential: group_credential.credential.clone(),
        proof: CredentialProof {
            signature: group_credential.proofs[0].signature.clone(),
        },
    };
    assert!(matches!(
        verifier.verify_credential(&as_group_credential),
        Err(CredentialsError::UnknownIssuer)
    ));
}

#[test]
fn single_issuer_signature_does_not_count_toward_the_group() {
    let mut fixture = fixture();
    let verifier = fixture.verifier(1);
    let blind_msg = fixture.blind_msg();
    let member = &fixture.members[0];

    // The member issues an ordinary single-issuer credential for the same info and holder.
    let (request, pending) = PendingIssuance::create_request_with_rng(
        &member.authority.issuer.issuance_key,
        member.id(),
        info(),
        blind_msg.clone(),
        &mut fixture.pbrsa_rng,
    )
    .unwrap();
    let response = member
        .issuer
        .issue_credential_with_rng(info(), &request, &mut fixture.pbrsa_rng)
        .unwrap();
    let single = pending
        .finalize(&member.authority.issuer.issuance_key, &response)
        .unwrap();

    // Its signature attached to the group credential, tagged with that member.
    let forged = MultiSignerCredential {
        version: ProtocolV1,
        credential: Credential {
            issuer_id_pubkey: fixture.group_id.clone(),
            info: info(),
            blind_msg,
        },
        proofs: vec![MultiSignerProof {
            issuer_id_pubkey: member.id(),
            signature: single.proof.signature.clone(),
        }],
    };
    assert!(valid_members(&verifier, &forged).is_empty());
    assert_threshold_not_met(verifier.verify_multi_signer_credential(&forged), 0, 1);

    // Wrapped unchanged, it names the member rather than a configured group.
    let wrapped = MultiSignerCredential {
        version: ProtocolV1,
        credential: single.credential.clone(),
        proofs: forged.proofs.clone(),
    };
    assert!(matches!(
        verifier.verify_multi_signer_credential(&wrapped),
        Err(CredentialsError::UnknownIssuer)
    ));
}

#[test]
fn threshold_counts_distinct_trusted_members_with_valid_signatures() {
    let mut fixture = fixture();
    let verifier = fixture.verifier(2);
    let ids: Vec<IssuerId> = fixture.members.iter().map(Member::id).collect();
    let by_0 = fixture.sign_member(0);
    let by_1 = fixture.sign_member(1);
    let by_2 = fixture.sign_member(2);

    // t - 1 distinct members: rejected.
    assert_eq!(valid_members(&verifier, &by_0), vec![ids[0].clone()]);
    assert_threshold_not_met(verifier.verify_multi_signer_credential(&by_0), 1, 2);

    // t distinct members: accepted, whichever two.
    let two = combine([by_0.clone(), by_2.clone()]);
    assert_eq!(
        valid_members(&verifier, &two),
        sorted(vec![ids[0].clone(), ids[2].clone()])
    );
    verifier.verify_multi_signer_credential(&two).unwrap();
    let all = combine([by_1.clone(), by_0.clone(), by_2.clone()]);
    assert_eq!(valid_members(&verifier, &all), sorted(ids.clone()));
    verifier.verify_multi_signer_credential(&all).unwrap();

    // The same member twice counts once: both an exact duplicate proof and a
    // second, independently blinded signature by the same member.
    let resigned_0 = fixture.sign_member(0);
    assert_ne!(resigned_0.proofs[0], by_0.proofs[0]);
    let mut same_member_twice = combine([by_0.clone(), resigned_0]);
    same_member_twice.proofs.push(by_0.proofs[0].clone());
    assert_eq!(same_member_twice.proofs.len(), 3);
    assert_eq!(
        valid_members(&verifier, &same_member_twice),
        vec![ids[0].clone()]
    );
    assert_threshold_not_met(
        verifier.verify_multi_signer_credential(&same_member_twice),
        1,
        2,
    );

    // An unknown member's signature verifies under its own key but is ignored.
    let by_outsider = fixture.sign_outsider();
    let mut outsider_check = VerificationContext::new();
    outsider_check
        .add_multi_signer_group(
            fixture.group_id.clone(),
            &[fixture.outsider.authority.clone()],
            1,
        )
        .unwrap();
    outsider_check
        .verify_multi_signer_credential(&by_outsider)
        .unwrap();
    let with_outsider = combine([by_0.clone(), by_outsider]);
    assert_eq!(
        valid_members(&verifier, &with_outsider),
        vec![ids[0].clone()]
    );
    assert_threshold_not_met(
        verifier.verify_multi_signer_credential(&with_outsider),
        1,
        2,
    );

    // An outsider's proof relabelled as a trusted member does not verify under that member's key.
    let mut relabelled = combine([by_0.clone(), fixture.sign_outsider()]);
    relabelled.proofs[1].issuer_id_pubkey = ids[1].clone();
    assert_eq!(valid_members(&verifier, &relabelled), vec![ids[0].clone()]);

    // A trusted member's proof relabelled as another member counts for neither extra member.
    let mut relabelled_member = by_0.clone();
    let mut copy = by_0.proofs[0].clone();
    copy.issuer_id_pubkey = ids[1].clone();
    relabelled_member.proofs.push(copy);
    assert_eq!(
        valid_members(&verifier, &relabelled_member),
        vec![ids[0].clone()]
    );
    assert_threshold_not_met(
        verifier.verify_multi_signer_credential(&relabelled_member),
        1,
        2,
    );

    // A tampered signature is not counted.
    let mut tampered = combine([by_0.clone(), by_1.clone()]);
    let last = tampered.proofs[1].signature.0.len() - 1;
    tampered.proofs[1].signature.0[last] ^= 1;
    assert_eq!(valid_members(&verifier, &tampered), vec![ids[0].clone()]);
    assert_threshold_not_met(verifier.verify_multi_signer_credential(&tampered), 1, 2);

    // Valid signatures over a tampered payload are not counted either.
    let mut tampered_payload = two.clone();
    tampered_payload.credential.info = json!({
        "schema": "example-membership-v1.0",
        "level": 3,
    });
    assert!(valid_members(&verifier, &tampered_payload).is_empty());
}

#[test]
fn unconfigured_group_is_unknown() {
    let mut fixture = fixture();
    let credential = combine([fixture.sign_member(0), fixture.sign_member(1)]);
    let mut verifier = VerificationContext::new();
    // Trusting the members as single issuers does not trust their group.
    for member in &fixture.members {
        verifier.add_issuer_authority(&member.authority).unwrap();
    }

    assert!(matches!(
        verifier.verify_multi_signer_credential(&credential),
        Err(CredentialsError::UnknownIssuer)
    ));
    assert!(matches!(
        verifier.valid_multi_signer_members(&credential),
        Err(CredentialsError::UnknownIssuer)
    ));
}

#[test]
fn group_configuration_is_validated() {
    let fixture = fixture();
    let authorities = fixture.member_authorities();
    let invalid = |result: Result<(), CredentialsError>| {
        matches!(result, Err(CredentialsError::InvalidMultiSignerGroup(_)))
    };
    let mut verifier = VerificationContext::new();

    assert!(invalid(verifier.add_multi_signer_group(
        fixture.group_id.clone(),
        &authorities,
        0
    )));
    assert!(invalid(verifier.add_multi_signer_group(
        fixture.group_id.clone(),
        &authorities,
        4
    )));
    verifier
        .add_multi_signer_group(fixture.group_id.clone(), &authorities, 3)
        .unwrap();
    // A member's own id cannot be the group id.
    assert!(invalid(verifier.add_multi_signer_group(
        authorities[0].issuer.issuer_id_pubkey.clone(),
        &authorities,
        1
    )));
    // Listing a member twice would let one signer count twice.
    assert!(invalid(verifier.add_multi_signer_group(
        fixture.group_id.clone(),
        &[authorities[0].clone(), authorities[0].clone()],
        1
    )));

    // Two identities sharing one issuance key would also let one signature count twice.
    let mut nostr_rng = <NostrRng as nostr::secp256k1::rand::SeedableRng>::seed_from_u64(1);
    let shared_key = member(0, &mut nostr_rng);
    assert_ne!(shared_key.id(), authorities[0].issuer.issuer_id_pubkey);
    assert!(invalid(verifier.add_multi_signer_group(
        fixture.group_id.clone(),
        &[authorities[0].clone(), shared_key.authority],
        1
    )));

    // A tampered member authority is rejected like any issuer authority.
    let mut tampered = authorities.clone();
    tampered[1]
        .issuer
        .revocation
        .push(crate::RevocationLocation {
            protocol: "nostr".to_owned(),
            location: "wss://relay.example.com".to_owned(),
        });
    assert!(matches!(
        verifier.add_multi_signer_group(fixture.group_id.clone(), &tampered, 2),
        Err(CredentialsError::VerificationFailed)
    ));
}

#[test]
fn issuer_and_holder_reject_own_id_as_group_id() {
    let mut fixture = fixture();
    let member = &fixture.members[0];
    let (request, _) = MultiSignerPendingIssuance::create_request_with_rng(
        &member.authority.issuer.issuance_key,
        fixture.group_id.clone(),
        member.id(),
        info(),
        fixture.blind_msg(),
        &mut fixture.pbrsa_rng,
    )
    .unwrap();

    assert!(matches!(
        member
            .issuer
            .issue_multi_signer_credential(member.id(), info(), &request),
        Err(CredentialsError::InvalidMultiSignerGroup(_))
    ));
    assert!(matches!(
        MultiSignerPendingIssuance::create_request(
            &member.authority.issuer.issuance_key,
            member.id(),
            member.id(),
            info(),
            fixture.blind_msg(),
        ),
        Err(CredentialsError::InvalidMultiSignerGroup(_))
    ));
}

#[test]
fn holder_finalize_checks_the_response() {
    let mut fixture = fixture();
    let blind_msg = fixture.blind_msg();
    let (member_0, member_1) = (&fixture.members[0], &fixture.members[1]);
    let (request, pending) = MultiSignerPendingIssuance::create_request_with_rng(
        &member_0.authority.issuer.issuance_key,
        fixture.group_id.clone(),
        member_0.id(),
        info(),
        blind_msg,
        &mut fixture.pbrsa_rng,
    )
    .unwrap();
    let pending =
        MultiSignerPendingIssuance::import_state(&pending.export_state().unwrap()).unwrap();

    let response = member_0
        .issuer
        .issue_multi_signer_credential(fixture.group_id.clone(), info(), &request)
        .unwrap();
    // A response naming another member or another group does not match the
    // pending state. (Another member cannot simply sign this request: it was
    // blinded for member 0's modulus.)
    let mut wrong_member = response.clone();
    wrong_member.issuer_id = member_1.id();
    let wrong_group = member_0
        .issuer
        .issue_multi_signer_credential(
            IssuerId(nostr::PublicKey::from_byte_array([0x48; 32])),
            info(),
            &request,
        )
        .unwrap();

    let reimport =
        || MultiSignerPendingIssuance::import_state(&pending.export_state().unwrap()).unwrap();
    assert!(matches!(
        reimport().finalize(&member_0.authority.issuer.issuance_key, &wrong_member),
        Err(CredentialsError::IssuerIdMismatch)
    ));
    assert!(matches!(
        reimport().finalize(&member_0.authority.issuer.issuance_key, &wrong_group),
        Err(CredentialsError::IssuerIdMismatch)
    ));
    // Finalizing under the wrong member key fails the built-in verification.
    assert!(reimport()
        .finalize(&member_1.authority.issuer.issuance_key, &response)
        .is_err());

    let credential = pending
        .finalize(&member_0.authority.issuer.issuance_key, &response)
        .unwrap();
    assert_eq!(credential.credential.issuer_id_pubkey, fixture.group_id);
    assert_eq!(credential.proofs.len(), 1);
    assert_eq!(credential.proofs[0].issuer_id_pubkey, member_0.id());

    // Wire shape: the ordinary credential plus member-tagged proofs.
    let wire = serde_json::to_value(&credential).unwrap();
    let mut keys: Vec<&str> = wire
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort();
    assert_eq!(keys, ["credential", "proofs", "version"]);
    assert_eq!(wire["version"], json!(1));
    assert_eq!(
        wire["credential"],
        serde_json::to_value(&credential.credential).unwrap()
    );
    assert_eq!(wire["proofs"][0]["issuer_id_pubkey"], json!(member_0.id()));
    let round_trip: MultiSignerCredential = serde_json::from_value(wire).unwrap();
    assert_eq!(round_trip, credential);
}

#[test]
fn holder_authorization_covers_the_multi_signer_credential() {
    let mut fixture = fixture();
    let verifier = fixture.verifier(2);
    let credential = combine([fixture.sign_member(0), fixture.sign_member(1)]);

    // The digest is that of the ordinary credential payload, built independently here.
    let payload = Credential {
        issuer_id_pubkey: fixture.group_id.clone(),
        info: info(),
        blind_msg: json!(fixture.holder.public_key()),
    };
    let subject = SubjectPubkey(nostr::PublicKey::from_byte_array([0x33; 32]));
    let authorization = fixture
        .holder
        .authorize_multi_signer_credential_use_at_time(
            HolderAuthorizationRequest {
                subject_pubkey: subject.clone(),
            },
            &credential,
            ISSUED_AT,
        )
        .unwrap();
    assert_eq!(
        authorization.authorization.credential_digest,
        CredentialDigest(payload.digest().unwrap())
    );
    // An authorization made over the plain credential payload is the same statement.
    let plain_authorization = fixture.authorize(&credential);
    assert_eq!(
        plain_authorization.authorization.credential_digest,
        authorization.authorization.credential_digest
    );

    verifier
        .verify_multi_signer_credential_authorization_at_time(
            &credential,
            &authorization,
            ISSUED_AT + 1,
        )
        .unwrap();
    verifier
        .verify_multi_signer_credential_authorization_at_time(
            &credential,
            &plain_authorization,
            ISSUED_AT + 1,
        )
        .unwrap();
    assert!(matches!(
        verifier.verify_multi_signer_credential_authorization_at_time(
            &credential,
            &authorization,
            ISSUED_AT - 1,
        ),
        Err(CredentialsError::AuthorizationNotYetValid)
    ));

    // Validly signed credentials that differ in info, group id or holder are not authorized.
    let signers = &fixture.members[..2];
    let rng = &mut fixture.pbrsa_rng;
    let blind_msg = json!(fixture.holder.public_key());
    let other_info = json!({ "schema": "example-membership-v1.0", "level": 3 });
    let other_info_credential = combine(signers.iter().map(|signer| {
        sign(
            signer,
            &fixture.group_id,
            other_info.clone(),
            blind_msg.clone(),
            rng,
        )
    }));
    verifier
        .verify_multi_signer_credential(&other_info_credential)
        .unwrap();
    assert!(matches!(
        verifier.verify_multi_signer_credential_authorization_at_time(
            &other_info_credential,
            &authorization,
            ISSUED_AT + 1,
        ),
        Err(CredentialsError::AuthorizationCredentialDigestMismatch)
    ));

    let other_group_id = IssuerId(nostr::PublicKey::from_byte_array([0x48; 32]));
    let mut other_group_verifier = verifier.clone();
    let signer_authorities: Vec<IssuerAuthority> = signers
        .iter()
        .map(|signer| signer.authority.clone())
        .collect();
    other_group_verifier
        .add_multi_signer_group(other_group_id.clone(), &signer_authorities, 2)
        .unwrap();
    let other_group_credential = combine(
        signers
            .iter()
            .map(|signer| sign(signer, &other_group_id, info(), blind_msg.clone(), rng)),
    );
    other_group_verifier
        .verify_multi_signer_credential(&other_group_credential)
        .unwrap();
    assert!(matches!(
        other_group_verifier.verify_multi_signer_credential_authorization_at_time(
            &other_group_credential,
            &authorization,
            ISSUED_AT + 1,
        ),
        Err(CredentialsError::AuthorizationCredentialDigestMismatch)
    ));

    let other_holder = HolderContext::generate_with_rng(&mut fixture.nostr_rng);
    let other_blind_msg = json!(other_holder.public_key());
    let other_holder_credential = combine(signers.iter().map(|signer| {
        sign(
            signer,
            &fixture.group_id,
            info(),
            other_blind_msg.clone(),
            rng,
        )
    }));
    verifier
        .verify_multi_signer_credential(&other_holder_credential)
        .unwrap();
    assert!(matches!(
        verifier.verify_multi_signer_credential_authorization_at_time(
            &other_holder_credential,
            &authorization,
            ISSUED_AT + 1,
        ),
        Err(CredentialsError::HolderIdMismatch)
    ));

    // The holder cannot authorize a credential bound to someone else.
    assert!(matches!(
        fixture
            .holder
            .authorize_multi_signer_credential_use_at_time(
                HolderAuthorizationRequest {
                    subject_pubkey: subject,
                },
                &other_holder_credential,
                ISSUED_AT,
            ),
        Err(CredentialsError::HolderIdMismatch)
    ));
}

#[test]
fn adding_a_member_signature_later_keeps_authorizations_valid() {
    let mut fixture = fixture();
    let mut credential = fixture.sign_member(0);
    let digest_before = credential.credential.digest().unwrap();
    let authorization = fixture
        .holder
        .authorize_multi_signer_credential_use_at_time(
            HolderAuthorizationRequest {
                subject_pubkey: SubjectPubkey(nostr::PublicKey::from_byte_array([0x33; 32])),
            },
            &credential,
            ISSUED_AT,
        )
        .unwrap();

    let verifier = fixture.verifier(2);
    assert_threshold_not_met(
        verifier.verify_multi_signer_credential_authorization_at_time(
            &credential,
            &authorization,
            ISSUED_AT + 1,
        ),
        1,
        2,
    );

    credential.merge(fixture.sign_member(2)).unwrap();
    assert_eq!(credential.proofs.len(), 2);
    assert_eq!(credential.credential.digest().unwrap(), digest_before);
    verifier
        .verify_multi_signer_credential_authorization_at_time(
            &credential,
            &authorization,
            ISSUED_AT + 1,
        )
        .unwrap();

    // Merging a finalization of a different credential is refused and changes nothing.
    let blind_msg = fixture.blind_msg();
    let other = sign(
        &fixture.members[1],
        &fixture.group_id,
        json!({ "level": 9 }),
        blind_msg,
        &mut fixture.pbrsa_rng,
    );
    assert!(matches!(
        credential.clone().merge(other),
        Err(CredentialsError::MultiSignerCredentialMismatch)
    ));
    // Merging the same proofs again adds nothing.
    let before = credential.clone();
    credential.merge(before.clone()).unwrap();
    assert_eq!(credential, before);
}

#[test]
fn one_issuer_with_two_keys_rotates_one_without_reissuing() {
    // One issuer keeps two keys as members of its group, threshold 1, and
    // signs every credential with both.
    let mut fixture = fixture();
    let blind_msg = fixture.blind_msg();
    let [key_a, key_b, key_c] = [0, 1, 2].map(|i| fixture.members[i].authority.clone());
    let credential = combine([0, 1].map(|i| {
        sign(
            &fixture.members[i],
            &fixture.group_id,
            info(),
            blind_msg.clone(),
            &mut fixture.pbrsa_rng,
        )
    }));
    let mut before_rotation = VerificationContext::new();
    before_rotation
        .add_multi_signer_group(fixture.group_id.clone(), &[key_a, key_b.clone()], 1)
        .unwrap();
    before_rotation
        .verify_multi_signer_credential(&credential)
        .unwrap();

    // Key A is retired and key C added; the credential still verifies through
    // key B without being reissued.
    let mut after_rotation = VerificationContext::new();
    after_rotation
        .add_multi_signer_group(fixture.group_id.clone(), &[key_b, key_c], 1)
        .unwrap();
    assert_eq!(
        valid_members(&after_rotation, &credential),
        vec![fixture.members[1].id()]
    );
    after_rotation
        .verify_multi_signer_credential(&credential)
        .unwrap();

    // A credential signed only by the retired key no longer verifies.
    let only_a = fixture.sign_member(0);
    assert_threshold_not_met(after_rotation.verify_multi_signer_credential(&only_a), 0, 1);
}
