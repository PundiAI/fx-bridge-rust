use std::ops::Deref;
use std::str::FromStr;

use secp256k1::{Error, Message, PublicKey, Secp256k1, SecretKey};
use secp256k1::recovery::{RecoverableSignature, RecoveryId};
use sha3::{Digest, Keccak256};
use web3::signing::{RecoveryError, SigningError};
use web3::types::{Address, H256, H520};

pub trait Key {
    /// Sign given message and include chain-id replay protection.
    ///
    /// When a chain ID is provided, the `Signature`'s V-value will have chain relay
    /// protection added (as per EIP-155). Otherwise, the V-value will be in
    /// 'Electrum' notation.
    fn sign(&self, message: &[u8], chain_id: Option<u64>) -> Result<Signature, SigningError>;

    /// Get public address that this key represents.
    fn address(&self) -> Address;
}

#[derive(Debug, Clone)]
pub struct PrivateKey(SecretKey);

impl PrivateKey {
    pub fn new(key: SecretKey) -> Self {
        Self(key)
    }

    pub fn from_slice(slice: &[u8]) -> Result<PrivateKey, Error> {
        Ok(PrivateKey(SecretKey::from_slice(slice)?))
    }

    pub fn to_bytes(&self) -> &[u8; 32] {
        self.0.as_ref()
    }

    pub fn to_public_key(&self) -> PublicKey {
        PublicKey::from_secret_key(&Secp256k1::signing_only(), self)
    }

    pub fn sign_hash(&self, data: &[u8]) -> Result<Signature, SigningError> {
        self.sign(data, None)
    }

    pub fn sign_msg(&self, data: &[u8]) -> Result<Signature, SigningError> {
        let digest = Keccak256::digest(data);
        self.sign_hash(&digest)
    }

    pub fn sign_ethereum_msg(&self, data: &[u8]) -> Result<Signature, SigningError> {
        let digest = Keccak256::digest(data);
        debug!("msg data Keccak256 hash: {:x}", digest);
        let hash: [u8; 32] = digest.into();
        let message = ethereum_msg_hash(hash.into());
        self.sign_hash(message.as_ref())
    }
}

impl FromStr for PrivateKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let s = match s.strip_prefix("0x") {
            Some(s) => s,
            None => &s,
        };
        Ok(PrivateKey(SecretKey::from_str(s)?))
    }
}

impl From<[u8; 32]> for PrivateKey {
    fn from(val: [u8; 32]) -> PrivateKey {
        PrivateKey(SecretKey::from_slice(val.as_ref()).unwrap())
    }
}

impl From<SecretKey> for PrivateKey {
    fn from(key: SecretKey) -> Self {
        Self::new(key)
    }
}

impl Deref for PrivateKey {
    type Target = SecretKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Deref<Target=SecretKey>> Key for T {
    fn sign(&self, message: &[u8], chain_id: Option<u64>) -> Result<Signature, SigningError> {
        let message = Message::from_slice(&message).map_err(|_| SigningError::InvalidMessage)?;
        let (recovery_id, signature) = Secp256k1::signing_only()
            .sign_recoverable(&message, self)
            .serialize_compact();

        let standard_v = recovery_id.to_i32() as u64;
        let v = if let Some(chain_id) = chain_id {
            // When signing with a chain ID, add chain replay protection.
            standard_v + 35 + chain_id * 2
        } else {
            // Otherwise, convert to 'Electrum' notation.
            standard_v + 27
        };
        let r = H256::from_slice(&signature[..32]);
        let s = H256::from_slice(&signature[32..]);

        Ok(Signature { v, r, s })
    }

    fn address(&self) -> Address {
        let secp = Secp256k1::signing_only();
        public_key_address(&PublicKey::from_secret_key(&secp, self))
    }
}

/// A struct that represents the components of a secp256k1 signature.
#[derive(Debug, Default, Clone)]
pub struct Signature {
    /// V component in electrum format with chain-id replay protection.
    pub v: u64,
    /// R component of the signature.
    pub r: H256,
    /// S component of the signature.
    pub s: H256,
}

impl Signature {
    pub fn new(v: u64, r: H256, s: H256) -> Self {
        Signature { v, r, s }
    }

    pub fn chain_id(&self) -> Option<u64> {
        if self.r == H256::zero() && self.s == H256::zero() {
            Some(self.v.clone())
        } else if self.v == 27u64 || self.v == 28u64 {
            None
        } else {
            Some(((self.v.clone() - 1u64) / 2u64) - 17u64)
        }
    }

    pub fn to_hash(&self) -> H520 {
        self.to_bytes().into()
    }

    pub fn to_bytes(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        bytes[0..32].copy_from_slice(&self.r.clone().0);
        bytes[32..64].copy_from_slice(&self.s.clone().0);
        bytes[64] = self.v.to_le_bytes()[0];
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 65 {
            return Err(Error::InvalidSignature);
        }
        let r = H256::from_slice(&bytes[0..32]);
        let s = H256::from_slice(&bytes[32..64]);
        let v = bytes[64];
        Ok(Signature::new(v.into(), r, s))
    }

    pub fn recovery_id(&self) -> Option<i32> {
        match self.v {
            27 => Some(0),
            28 => Some(1),
            v if v >= 35 => Some(((v - 1) % 2) as _),
            _ => None,
        }
    }

    pub fn recover_ethereum_msg(&self, message: &[u8]) -> Result<Address, RecoveryError> {
        let digest = Keccak256::digest(message);
        debug!("msg data Keccak256 hash: {:x}", digest);
        let hash: [u8; 32] = digest.into();
        let hash = ethereum_msg_hash(hash.into());
        Ok(self.recover(hash.as_ref())?)
    }

    pub fn recover(&self, message: &[u8]) -> Result<Address, RecoveryError> {
        let recovery_id = self.recovery_id().ok_or(RecoveryError::InvalidSignature)?;
        let signature = {
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(self.r.as_bytes());
            sig[32..].copy_from_slice(self.s.as_bytes());
            sig
        };
        let address = recover(message, &signature, recovery_id)?;
        Ok(address)
    }
}

impl FromStr for Signature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let s = match s.strip_prefix("0x") {
            Some(s) => s,
            None => &s,
        };

        Ok(Signature::from_bytes(hex::decode(s).unwrap().as_slice())?)
    }
}

/// Gets the address of a public key.
///
/// The public address is defined as the low 20 bytes of the keccak hash of
/// the public key. Note that the public key returned from the `secp256k1`
/// crate is 65 bytes long, that is because it is prefixed by `0x04` to
/// indicate an uncompressed public key; this first byte is ignored when
/// computing the hash.
pub fn public_key_address(public_key: &PublicKey) -> Address {
    let public_key = public_key.serialize_uncompressed();
    debug_assert_eq!(public_key[0], 0x04);
    let hash = Keccak256::digest(&public_key[1..]);
    Address::from_slice(&hash[12..])
}

/// Recover a sender, given message and the signature.
///
/// Signature and `recovery_id` can be obtained from `types::Recovery` type.
pub fn recover(
    message: &[u8],
    signature: &[u8],
    recovery_id: i32,
) -> Result<Address, RecoveryError> {
    let message = Message::from_slice(message).map_err(|_| RecoveryError::InvalidMessage)?;
    let recovery_id =
        RecoveryId::from_i32(recovery_id).map_err(|_| RecoveryError::InvalidSignature)?;
    let signature = RecoverableSignature::from_compact(&signature, recovery_id)
        .map_err(|_| RecoveryError::InvalidSignature)?;
    let public_key = Secp256k1::verification_only()
        .recover(&message, &signature)
        .map_err(|_| RecoveryError::InvalidSignature)?;

    Ok(public_key_address(&public_key))
}

pub fn ethereum_msg_hash(data: H256) -> H256 {
    let salt_bytes = "\x19Ethereum Signed Message:\n32".as_bytes();
    let digest = Keccak256::digest(&[salt_bytes, data.as_ref()].concat());
    debug!("msg ethereum Keccak256 hash: {:x}", digest);
    let hash: [u8; 32] = digest.into();
    hash.into()
}
