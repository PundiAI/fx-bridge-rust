use crate::address::Address;
use crate::proto_ext::MessageExt;
use cosmos_sdk_proto::cosmos;
use ecdsa::elliptic_curve::sec1::ToEncodedPoint;
use eyre::Result;
use prost_types;
use prost_types::Any;
use ripemd160::Ripemd160;
use sha2::{Digest, Sha256};
use std::convert::TryFrom;

const ED25519_TYPE_URL: &str = "/cosmos.crypto.ed25519.PubKey";

const SECP256K1_TYPE_URL: &str = "/cosmos.crypto.secp256k1.PubKey";

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PublicKey(tendermint::PublicKey);

impl PublicKey {
    pub fn to_address(&self) -> Address {
        let sha256 = Sha256::digest(&self.0.as_bytes());
        let ripemd160 = Ripemd160::digest(&sha256);
        let mut bytes: [u8; 20] = Default::default();
        bytes.copy_from_slice(&ripemd160[..]);
        Address::from_bytes(bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    pub fn to_any(&self) -> Result<Any> {
        match self.0 {
            tendermint::PublicKey::Ed25519(_) => {
                let pub_key = cosmos::crypto::secp256k1::PubKey { key: self.to_bytes() };

                Ok(Any {
                    type_url: ED25519_TYPE_URL.to_owned(),
                    value: pub_key.to_bytes()?,
                })
            }
            tendermint::PublicKey::Secp256k1(_) => {
                let pub_key = cosmos::crypto::secp256k1::PubKey { key: self.to_bytes() };

                Ok(Any {
                    type_url: SECP256K1_TYPE_URL.to_owned(),
                    value: pub_key.to_bytes()?,
                })
            }
            _ => Err(eyre::Error::msg("invalid public type")),
        }
    }
}

impl From<k256::ecdsa::VerifyingKey> for PublicKey {
    fn from(vk: k256::ecdsa::VerifyingKey) -> PublicKey {
        PublicKey::from(&vk)
    }
}

impl From<&k256::ecdsa::VerifyingKey> for PublicKey {
    fn from(vk: &k256::ecdsa::VerifyingKey) -> PublicKey {
        PublicKey(vk.to_encoded_point(true).into())
    }
}

impl TryFrom<&Any> for PublicKey {
    type Error = eyre::Error;

    fn try_from(any: &Any) -> Result<Self> {
        match any.type_url.as_str() {
            SECP256K1_TYPE_URL => tendermint::PublicKey::from_raw_secp256k1(&any.value)
                .map(Into::into)
                .ok_or_else(|| eyre::Error::msg("cryptographic error")),
            other => Err(eyre::Error::msg(format!("invalid type URL for public key: {}", other))),
        }
    }
}

impl From<tendermint::PublicKey> for PublicKey {
    fn from(pk: tendermint::PublicKey) -> PublicKey {
        PublicKey(pk)
    }
}

impl From<PublicKey> for tendermint::PublicKey {
    fn from(pk: PublicKey) -> tendermint::PublicKey {
        pk.0
    }
}
