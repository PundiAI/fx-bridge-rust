use bech32::{FromBase32, ToBase32};
use eyre::Result;
use serde::{Serialize, Serializer};
use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;
use std::str::FromStr;

pub const DEFAULT_BECH32_PREFIX: &str = "fx";

pub const VALIDATOR_ADDRESS_PREFIX: &str = "fxvaloper";

#[derive(Default, PartialEq, Eq, Copy, Clone, Deserialize, Hash)]
pub struct Address([u8; 20]);

impl Address {
    pub fn from_bytes(bytes: [u8; 20]) -> Address {
        Address(bytes)
    }

    pub fn from_bech32(s: String) -> Result<Address> {
        let (_hrp, data) = match bech32::decode(&s) {
            Ok(val) => val,
            Err(e) => return Err(eyre::Error::new(e)),
        };
        let vec: Vec<u8> = match FromBase32::from_base32(&data) {
            Ok(val) => val,
            Err(e) => return Err(eyre::Error::new(e)),
        };
        let mut addr = [0u8; 20];
        if vec.len() != 20 {
            return Err(eyre::Error::msg("decode hex address length must be 20"));
        }
        addr.copy_from_slice(&vec);
        Ok(Address(addr))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_bech32<T: Into<String>>(&self, hrp: T) -> Result<String> {
        let bech32 = bech32::encode(&hrp.into(), self.0.to_base32())?;
        Ok(bech32)
    }

    pub fn to_bytes32(&self) -> [u8; 32] {
        let mut bytes = self.as_bytes().to_vec();
        while bytes.len() < 32 {
            bytes.insert(0, 0u8);
        }
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&bytes);
        addr
    }

    pub fn to_valoper(&self) -> Result<String> {
        self.to_bech32(VALIDATOR_ADDRESS_PREFIX)
    }
}

impl FromStr for Address {
    type Err = eyre::Error;

    fn from_str(s: &str) -> Result<Self> {
        // interpret as bech32 if prefixed, hex otherwise
        if s.starts_with(DEFAULT_BECH32_PREFIX) {
            Address::from_bech32(s.to_string())
        } else {
            match hex::decode(s) {
                Ok(bytes) => {
                    if bytes.len() == 20 {
                        let mut inner = [0; 20];
                        inner.copy_from_slice(&bytes[0..20]);
                        Ok(Address(inner))
                    } else {
                        Err(eyre::Error::msg("decode hex address length must be 20"))
                    }
                }
                Err(e) => Err(eyre::Error::msg(format!("{}", e))),
            }
        }
    }
}

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Serialize address as a string with a default prefix for addresses
        let s = self
            .to_bech32(DEFAULT_BECH32_PREFIX)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&s)
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_bech32(DEFAULT_BECH32_PREFIX).unwrap())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_bech32(DEFAULT_BECH32_PREFIX).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_address_to_bech32() {
        let address = Address::default();
        assert_eq!(
            address.to_bech32(DEFAULT_BECH32_PREFIX).unwrap(),
            "fx1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfn322v"
        );
        let address2 =
            Address::from_bech32("fx1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfn322v".to_string()).unwrap();
        assert_eq!(address, address2);
    }

    #[test]
    fn test_bech32_to_address() {
        let address =
            Address::from_bech32("fx1zgpzdf2uqla7hkx85wnn4p2r3duwqzd8xst6v2".to_string()).unwrap();
        let address1 = Address::from_bytes(address.0);
        assert_eq!(address, address1)
    }
}
