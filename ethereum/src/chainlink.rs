use std::fmt::Debug;

use eyre::Result;
use web3::api::Eth;
use web3::contract::{Contract, Options};
use web3::ethabi::Contract as ContractABI;
use web3::transports::Http;
use web3::types::{Address, BlockId, BlockNumber, U256};

use crate::private_key::{Key, PrivateKey};

const CHAINLINK_AGGREGATORS_ABI: &str = r#"[{"inputs":[],"name":"latestRoundData","outputs":[{"internalType":"uint80","name":"roundId","type":"uint80"},{"internalType":"int256","name":"answer","type":"int256"},{"internalType":"uint256","name":"startedAt","type":"uint256"},{"internalType":"uint256","name":"updatedAt","type":"uint256"},{"internalType":"uint80","name":"answeredInRound","type":"uint80"}],"stateMutability":"view","type":"function"}]"#;

#[derive(Debug, Clone)]
pub struct ChainlinkAggregator {
    eth: Eth<Http>,
    contract: Contract<Http>,
    options: Options,
    private_key: Option<PrivateKey>,
    from: Address,
}

impl ChainlinkAggregator {
    pub fn new(
        private_key: Option<PrivateKey>,
        options: Option<Options>,
        eth: Eth<Http>,
        address: Address,
    ) -> Self {
        let abi: ContractABI = serde_json::from_str(CHAINLINK_AGGREGATORS_ABI)
            .expect("invalid chainlink aggregator abi");
        let contract = Contract::new(eth.clone(), address, abi);
        let options = if options.is_some() {
            options.unwrap()
        } else {
            Options::default()
        };
        let (private_key, from) = if private_key.is_some() {
            (private_key.clone(), private_key.unwrap().address())
        } else {
            (None, Address::default())
        };
        ChainlinkAggregator {
            eth,
            contract,
            options,
            private_key,
            from,
        }
    }
    pub async fn latest_round_data(&self) -> Result<(U256, U256, U256, U256, U256)> {
        let (round_id, answer, started_at, updated_at, answered_in_round) = self
            .contract
            .query(
                "latestRoundData",
                (),
                self.from,
                self.options.clone(),
                BlockId::Number(BlockNumber::Latest),
            )
            .await?;
        Ok((round_id, answer, started_at, updated_at, answered_in_round))
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    const ETH_RPC_URL: &str = "";

    #[tokio::test]
    async fn test_erc20_approve() {
        let transport = web3::transports::Http::new(ETH_RPC_URL).unwrap();
        let web3 = web3::Web3::new(transport);

        let aggregator_address =
            Address::from_str("0x9e904BD324dE7A314b4eC491a017Da47F9af2CeC").unwrap();
        let chainlink_aggregator =
            ChainlinkAggregator::new(None, None, web3.eth(), aggregator_address);
        let result = chainlink_aggregator.latest_round_data().await.unwrap();
        println!("{:?}", result);
    }
}
