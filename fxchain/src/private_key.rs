use crate::public_key::PublicKey;
use bip39::Mnemonic;
use core::convert::TryFrom;
use eyre::Result;
use k256::ecdsa::Signature;
use k256::ecdsa::VerifyingKey;
use num_bigint::BigUint;
use rand_core::OsRng;
use secp256k1::constants::CURVE_ORDER;
use secp256k1::Secp256k1;
use secp256k1::{PublicKey as PublicKeyEC, SecretKey};
use sha2::{Digest, Sha256, Sha512};
use std::str::FromStr;

pub struct PrivateKey {
    inner: Box<dyn Secp256k1Signer>,
}

impl PrivateKey {
    pub fn random() -> Self {
        Self {
            inner: Box::new(k256::ecdsa::SigningKey::random(&mut OsRng)),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let signing_key = k256::ecdsa::SigningKey::from_bytes(bytes)?;
        Ok(Self { inner: Box::new(signing_key) })
    }

    pub fn from_secsret(secret: &[u8]) -> Result<PrivateKey> {
        let sec_hash = Sha256::digest(secret);

        let mut i = BigUint::from_bytes_be(&sec_hash);

        // Parameters of the curve as explained in https://en.bitcoin.it/wiki/Secp256k1
        let mut n = BigUint::from_bytes_be(&CURVE_ORDER);
        n -= 1u64;

        i %= n;
        i += 1u64;

        let mut result: [u8; 32] = Default::default();
        let mut i_bytes = i.to_bytes_be();
        // key has leading or trailing zero that's not displayed
        // by default since this is a big int library missing a defined
        // integer width.
        while i_bytes.len() < 32 {
            i_bytes.push(0);
        }
        result.copy_from_slice(&i_bytes);
        PrivateKey::from_bytes(result.as_ref())
    }

    pub fn from_phrase(phrase: &str, passphrase: &str) -> Result<PrivateKey> {
        if phrase.is_empty() {
            return Err(eyre::Error::msg("phrase can't be empty"));
        }
        PrivateKey::from_hd_wallet_path("m/44'/118'/0'/0/0", phrase, passphrase)
    }

    pub fn from_hd_wallet_path(path: &str, phrase: &str, passphrase: &str) -> Result<PrivateKey> {
        if !path.starts_with('m') || path.contains('\\') {
            return Err(eyre::Error::msg("invalid path spec"));
        }
        let mut iterator = path.split('/');
        // discard the m
        let _ = iterator.next();

        let key_import = Mnemonic::from_str(phrase).unwrap();
        let seed_bytes = key_import.to_seed(passphrase);
        let (master_secret_key, master_chain_code) = master_key_from_seed(&seed_bytes);
        let mut secret_key = master_secret_key;
        let mut chain_code = master_chain_code;

        for mut val in iterator {
            let mut hardened = false;
            if val.contains('\'') {
                hardened = true;
                val = val.trim_matches('\'');
            }
            if let Ok(parsed_int) = val.parse() {
                let (s, c) = get_child_key(secret_key, chain_code, parsed_int, hardened);
                secret_key = s;
                chain_code = c;
            } else {
                return Err(eyre::Error::msg("phrase can't be empty"));
            }
        }
        PrivateKey::from_bytes(secret_key.as_ref())
    }

    pub fn public_key(&self) -> PublicKey {
        self.inner.verifying_key().into()
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature> {
        Ok(self.inner.try_sign(msg)?)
    }
}

impl FromStr for PrivateKey {
    type Err = eyre::Error;

    fn from_str(s: &str) -> Result<Self> {
        match hex::decode(s) {
            Ok(bytes) => {
                if bytes.len() == 32 {
                    let mut inner: [u8; 32] = [0; 32];
                    inner.copy_from_slice(&bytes[0..32]);
                    PrivateKey::from_bytes(inner.as_ref())
                } else {
                    Err(eyre::Error::msg("hex private key len must be 32"))
                }
            }
            Err(e) => Err(eyre::Error::msg(format!("{}", e))),
        }
    }
}

impl From<Box<dyn Secp256k1Signer>> for PrivateKey {
    fn from(signer: Box<dyn Secp256k1Signer>) -> Self {
        Self { inner: signer }
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = eyre::Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::from_bytes(bytes)
    }
}

pub trait Secp256k1Signer: ecdsa::signature::Signer<Signature> {
    fn verifying_key(&self) -> VerifyingKey;
}

impl<T> Secp256k1Signer for T
where
    T: ecdsa::signature::Signer<Signature>,
    k256::ecdsa::VerifyingKey: for<'a> From<&'a T>,
{
    fn verifying_key(&self) -> VerifyingKey {
        self.into()
    }
}

fn master_key_from_seed(seed_bytes: &[u8]) -> ([u8; 32], [u8; 32]) {
    use hmac::crypto_mac::Mac;
    use hmac::crypto_mac::NewMac;
    use hmac::Hmac;
    type HmacSha512 = Hmac<Sha512>;

    let mut hasher = HmacSha512::new_varkey(b"Bitcoin seed").unwrap();
    hasher.update(&seed_bytes);
    let hash = hasher.finalize().into_bytes();
    let mut master_secret_key: [u8; 32] = [0; 32];
    let mut master_chain_code: [u8; 32] = [0; 32];
    master_secret_key.copy_from_slice(&hash[0..32]);
    master_chain_code.copy_from_slice(&hash[32..64]);

    // key check
    let _ = SecretKey::from_slice(&master_secret_key).unwrap();

    (master_secret_key, master_chain_code)
}

fn get_child_key(k_parent: [u8; 32], c_parent: [u8; 32], i: u32, hardened: bool) -> ([u8; 32], [u8; 32]) {
    use hmac::crypto_mac::Mac;
    use hmac::crypto_mac::NewMac;
    use hmac::Hmac;
    type HmacSha512 = Hmac<Sha512>;

    let i = if hardened { 2u32.pow(31) + i } else { i };
    let mut hasher = HmacSha512::new_varkey(&c_parent).unwrap();
    if hardened {
        hasher.update(&[0u8]);
        hasher.update(&k_parent);
    } else {
        let scep = Secp256k1::new();
        let private_key = SecretKey::from_slice(&k_parent).unwrap();
        let public_key = PublicKeyEC::from_secret_key(&scep, &private_key);
        hasher.update(&public_key.serialize());
    }
    hasher.update(&i.to_be_bytes());

    let l_param = hasher.finalize().into_bytes();

    let mut parse_i_l = SecretKey::from_slice(&l_param[0..32]).unwrap();
    parse_i_l.add_assign(&k_parent).unwrap();
    let child_key = parse_i_l;

    let mut child_key_res: [u8; 32] = [0; 32];
    child_key_res.copy_from_slice(child_key.as_ref());
    let mut chain_code_res: [u8; 32] = [0; 32];
    chain_code_res.copy_from_slice(&l_param[32..64]);
    (child_key_res, chain_code_res)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FX_MNEMONIC: &str = "";
    const HEX_PRIVATE_KEY: &str = "";
    const ACC_ADDRESS: &str = "fx1zgpzdf2uqla7hkx85wnn4p2r3duwqzd8xst6v2";

    #[test]
    fn test_private_key_from_str() {
        let private_key = PrivateKey::from_str(HEX_PRIVATE_KEY).unwrap();
        let address = private_key.public_key().to_address().to_string();
        assert_eq!(ACC_ADDRESS, address)
    }

    #[test]
    fn test_private_key_from_mnemonic() {
        let private_key = PrivateKey::from_phrase(FX_MNEMONIC, "").unwrap();
        let address = private_key.public_key().to_address().to_string();
        assert_eq!(ACC_ADDRESS, address)
    }

    #[test]
    fn test_many_key_generation() {
        for _ in 0..1000 {
            let private_key = PrivateKey::random();
            let _address = private_key.public_key().to_address();
        }
    }
}
