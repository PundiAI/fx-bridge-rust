use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Debug;
use std::str::FromStr;

use eyre::Result;
use web3::ethabi::ethereum_types::H256;
use web3::types::Address as EthAddress;

use ethereum::private_key::Signature as EthSignature;
use fxchain::address::Address as FxAddress;

const TOTAL_GRAVITY_POWER: u64 = u32::MAX as u64;

const THRESHOLD_VOTE_POWER: f64 = 66f64;

fn gravity_power_to_percent(input: u64) -> f64 {
    (input as f64 / TOTAL_GRAVITY_POWER as f64) * 100f64
}

pub fn get_hash_map<T: Confirm + Clone>(input: &[T]) -> HashMap<EthAddress, T> {
    let mut out = HashMap::new();
    for i in input.iter() {
        out.insert(i.get_eth_address(), i.clone());
    }
    out
}

pub trait Confirm {
    fn get_eth_address(&self) -> EthAddress;
    fn get_signature(&self) -> EthSignature;
}

#[derive(Debug, Default, Clone)]
pub struct ValsetConfirmResponse {
    pub orchestrator: FxAddress,
    pub eth_address: EthAddress,
    pub nonce: u64,
    pub eth_signature: EthSignature,
}

impl ValsetConfirmResponse {
    pub fn from_proto(input: fxchain::x::gravity::MsgValsetConfirm) -> Result<Self> {
        Ok(ValsetConfirmResponse {
            orchestrator: FxAddress::from_str(input.orchestrator.as_str())?,
            eth_address: EthAddress::from_str(input.eth_address.as_str())?,
            nonce: input.nonce,
            eth_signature: EthSignature::from_str(input.signature.as_str())?,
        })
    }
}

impl Confirm for ValsetConfirmResponse {
    fn get_eth_address(&self) -> EthAddress {
        self.eth_address
    }
    fn get_signature(&self) -> EthSignature {
        self.eth_signature.clone()
    }
}

#[derive(Debug, Default, Clone)]
pub struct BatchConfirmResponse {
    pub nonce: u64,
    pub orchestrator: FxAddress,
    pub token_contract: EthAddress,
    pub ethereum_signer: EthAddress,
    pub eth_signature: EthSignature,
}

impl BatchConfirmResponse {
    pub fn from_proto(input: fxchain::x::gravity::MsgConfirmBatch) -> Result<Self> {
        Ok(BatchConfirmResponse {
            nonce: input.nonce,
            orchestrator: FxAddress::from_str(input.orchestrator.as_str())?,
            token_contract: EthAddress::from_str(input.token_contract.as_str())?,
            ethereum_signer: EthAddress::from_str(input.eth_signer.as_str())?,
            eth_signature: EthSignature::from_str(input.signature.as_str())?,
        })
    }
}

impl Confirm for BatchConfirmResponse {
    fn get_eth_address(&self) -> EthAddress {
        self.ethereum_signer
    }
    fn get_signature(&self) -> EthSignature {
        self.eth_signature.clone()
    }
}

#[derive(Debug, Clone)]
struct SignatureStatus {
    ordered_signatures: Vec<GravitySignature>,
    power_of_good_sigs: u64,
    power_of_nonvoters: u64,
    number_of_nonvoters: usize,
    power_of_invalid_signers: u64,
    number_of_invalid_signers: usize,
    num_validators: usize,
}

/// a list of validators, powers, and eth addresses at a given block height
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
pub struct ValsetMember {
    pub power: u64,
    pub eth_address: EthAddress,
}

impl Ord for ValsetMember {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.power != other.power {
            self.power.cmp(&other.power)
        } else {
            self.eth_address.cmp(&other.eth_address).reverse()
        }
    }
}

impl PartialOrd for ValsetMember {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for ValsetMember {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Address: {} Power: {}", self.eth_address, self.power)
    }
}

impl From<&fxchain::x::gravity::BridgeValidator> for ValsetMember {
    fn from(input: &fxchain::x::gravity::BridgeValidator) -> Self {
        ValsetMember {
            power: input.power,
            eth_address: EthAddress::from_str(input.eth_address.as_str()).unwrap(),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Valset {
    pub nonce: u64,
    pub members: Vec<ValsetMember>,
}

impl Valset {
    fn get_signature_status<T: Confirm + Clone + Debug>(&self, message: &[u8], signatures: &[T]) -> Result<SignatureStatus> {
        if signatures.is_empty() {
            return Err(eyre::Error::msg("No signatures!".to_string()));
        }

        let mut out = Vec::new();
        let signatures_hashmap: HashMap<EthAddress, T> = get_hash_map(signatures);
        let mut power_of_good_sigs = 0;
        let mut power_of_nonvoters = 0;
        let mut number_of_nonvoters = 0;
        let mut power_of_invalid_signers = 0;
        let mut number_of_invalid_signers = 0;
        for member in self.members.iter() {
            if let Some(sig) = signatures_hashmap.get(&member.eth_address) {
                assert_eq!(sig.get_eth_address(), member.eth_address);
                // assert!(sig.get_signature().is_valid());
                let recover_key = sig.get_signature().recover_ethereum_msg(message).unwrap();
                if recover_key == sig.get_eth_address() {
                    out.push(GravitySignature {
                        power: member.power,
                        eth_address: sig.get_eth_address(),
                        v: sig.get_signature().v.clone(),
                        r: sig.get_signature().r.clone(),
                        s: sig.get_signature().s.clone(),
                    });
                    power_of_good_sigs += member.power;
                } else {
                    out.push(GravitySignature {
                        power: member.power,
                        eth_address: member.eth_address,
                        v: 0u64,
                        r: H256::from([0u8; 32]),
                        s: H256::from([0u8; 32]),
                    });
                    power_of_invalid_signers += member.power;
                    number_of_invalid_signers += 1;
                }
            } else {
                out.push(GravitySignature {
                    power: member.power,
                    eth_address: member.eth_address,
                    v: 0u64,
                    r: H256::from([0u8; 32]),
                    s: H256::from([0u8; 32]),
                });
                power_of_nonvoters += member.power;
                number_of_nonvoters += 1;
            }
        }

        let num_validators = self.members.len();
        Ok(SignatureStatus {
            ordered_signatures: out,
            power_of_good_sigs,
            power_of_nonvoters,
            num_validators,
            number_of_nonvoters,
            power_of_invalid_signers,
            number_of_invalid_signers,
        })
    }

    pub fn order_signatures<T: Confirm + Clone + Debug>(&self, message: &[u8], signatures: &[T]) -> Result<Vec<GravitySignature>> {
        let status = self.get_signature_status(message, signatures)?;
        if gravity_power_to_percent(status.power_of_good_sigs) < THRESHOLD_VOTE_POWER {
            let err = format!(
                "has {}/{} or {:.2}% power voting! Can not execute on Ethereum!
                {}/{} validators have Ethereum keys set but have not voted representing {}/{} or {:.2}% of the power required
                {}/{} validators have Invalid signatures {}/{} or {:.2}% of the power required
                This valset probably just needs to accumulate signatures for a moment.",
                status.power_of_good_sigs,
                TOTAL_GRAVITY_POWER,
                gravity_power_to_percent(status.power_of_good_sigs),
                status.number_of_nonvoters,
                status.num_validators,
                status.power_of_nonvoters,
                TOTAL_GRAVITY_POWER,
                gravity_power_to_percent(status.power_of_nonvoters),
                status.number_of_invalid_signers,
                status.num_validators,
                status.power_of_invalid_signers,
                TOTAL_GRAVITY_POWER,
                gravity_power_to_percent(status.power_of_invalid_signers),
            );
            Err(eyre::Error::msg(err))
        } else {
            Ok(status.ordered_signatures)
        }
    }
}

impl From<ethereum::fx_bridge::ValsetUpdatedEvent> for Valset {
    fn from(input: ethereum::fx_bridge::ValsetUpdatedEvent) -> Self {
        let mut valset = Valset {
            nonce: input.valset_nonce.as_u64(),
            members: Vec::new(),
        };
        for i in 0..input.validators.len() {
            valset.members.push(ValsetMember {
                power: input.powers[i].as_u64(),
                eth_address: input.validators[i],
            })
        }
        valset
    }
}

impl From<fxchain::x::gravity::Valset> for Valset {
    fn from(input: fxchain::x::gravity::Valset) -> Self {
        Valset {
            nonce: input.nonce,
            members: input.members.iter().map(|i| i.into()).collect(),
        }
    }
}

/// A sortable struct of a validator and it's signatures
/// this can be used for either transaction batch or validator
/// set signatures
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GravitySignature {
    pub power: u64,
    pub eth_address: EthAddress,
    pub v: u64,
    pub r: H256,
    pub s: H256,
}

impl Ord for GravitySignature {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.power != other.power {
            self.power.cmp(&other.power)
        } else {
            self.eth_address.cmp(&other.eth_address).reverse()
        }
    }
}

impl PartialOrd for GravitySignature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
