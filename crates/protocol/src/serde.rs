use nostr::secp256k1::schnorr::Signature;
use serde_with::{base64::Base64, base64::UrlSafe, formats::Unpadded};
use serde_with::{DeserializeAs, SerializeAs};
use sha2::{digest::Output, Sha256};

use crate::PbrsaPublicKey;

/// Unpadded URL-safe base64 encoding used for byte fields in JSON.
pub(crate) type Base64UrlUnpadded = Base64<UrlSafe, Unpadded>;

pub(crate) struct PbrsaPublicKeyBase64UrlUnpadded;
pub(crate) struct SchnorrSignatureBase64UrlUnpadded;
pub(crate) struct Sha256DigestBase64UrlUnpadded;

impl SerializeAs<PbrsaPublicKey> for PbrsaPublicKeyBase64UrlUnpadded {
    fn serialize_as<S>(source: &PbrsaPublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ::serde::Serializer,
    {
        let der = source.to_der().map_err(::serde::ser::Error::custom)?;
        Base64UrlUnpadded::serialize_as(&der, serializer)
    }
}

impl<'de> DeserializeAs<'de, PbrsaPublicKey> for PbrsaPublicKeyBase64UrlUnpadded {
    fn deserialize_as<D>(deserializer: D) -> Result<PbrsaPublicKey, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        let der: Vec<u8> = Base64UrlUnpadded::deserialize_as(deserializer)?;
        PbrsaPublicKey::from_der(&der).map_err(::serde::de::Error::custom)
    }
}

impl SerializeAs<Signature> for SchnorrSignatureBase64UrlUnpadded {
    fn serialize_as<S>(source: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ::serde::Serializer,
    {
        Base64UrlUnpadded::serialize_as(&source.serialize(), serializer)
    }
}

impl<'de> DeserializeAs<'de, Signature> for SchnorrSignatureBase64UrlUnpadded {
    fn deserialize_as<D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Base64UrlUnpadded::deserialize_as(deserializer)?;
        Signature::from_slice(&bytes).map_err(::serde::de::Error::custom)
    }
}

impl SerializeAs<Output<Sha256>> for Sha256DigestBase64UrlUnpadded {
    fn serialize_as<S>(source: &Output<Sha256>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ::serde::Serializer,
    {
        Base64UrlUnpadded::serialize_as(&source.to_vec(), serializer)
    }
}

impl<'de> DeserializeAs<'de, Output<Sha256>> for Sha256DigestBase64UrlUnpadded {
    fn deserialize_as<D>(deserializer: D) -> Result<Output<Sha256>, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Base64UrlUnpadded::deserialize_as(deserializer)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| ::serde::de::Error::invalid_length(bytes.len(), &"32"))?;
        Ok(bytes.into())
    }
}
