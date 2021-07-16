use crypto::{digest::Digest, sha3::Sha3};
use web3::types::Address;

pub trait Checksum {
    fn to_hex_string(&self) -> String;
}

impl Checksum for Address {
    fn to_hex_string(&self) -> String {
        checksum(format!("{:?}", &self).as_str())
    }
}

pub fn checksum(address: &str) -> String {
    let address = address.trim_start_matches("0x").to_lowercase();

    let address_hash = {
        let mut hasher = Sha3::keccak256();
        hasher.input(address.as_bytes());
        hasher.result_str()
    };

    address.char_indices().fold(String::from("0x"), |mut acc, (index, address_char)| {
        let n = u16::from_str_radix(&address_hash[index..index + 1], 16).unwrap();
        if n > 7 {
            acc.push_str(&address_char.to_uppercase().to_string())
        } else {
            acc.push(address_char)
        }
        acc
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_address() {
        let addr = Address::from_str("0xAC9163b07D9306c2006d81e268Cac57eDfe1A0e9").unwrap();
        println!("{:x}", addr);
        println!("{:X}", addr);
        println!("{:?}", addr);
    }

    #[test]
    fn test_address_checksum() {
        assert_eq!(
            "0xAC9163b07D9306c2006d81e268Cac57eDfe1A0e9",
            Address::from_str("0xac9163b07d9306c2006d81e268cac57edfe1a0e9").unwrap().to_hex_string()
        )
    }
}
