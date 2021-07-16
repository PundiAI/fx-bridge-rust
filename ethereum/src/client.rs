use eyre::Result;
use web3::transports::Http;
use web3::types::{Address, U256, U64};
use web3::Web3;

use crate::address::Checksum;

pub async fn check_for_ether(web3: &Web3<Http>, account: Address, expect: U256) -> bool {
    let balance = web3.eth().balance(account, None).await.unwrap();
    debug!("Ethereum account {} balance {} ether", account.to_hex_string(), balance);
    if balance.is_zero() || balance.le(&expect) {
        return false;
    }
    return true;
}

pub async fn get_block_delay(web3: &Web3<Http>) -> Result<U64> {
    let res = web3.net().version().await?;
    let net_version: u64 = res.parse()?;
    match net_version {
        // Mainline Ethereum, Ethereum classic, or the Ropsten, Mordor testnets all POW Chains
        1 | 3 | 7 | 42 => Ok(6u8.into()),
        // Rinkeby, Goerli, Hardhat and Kotti respectively all non-pow chains
        4 | 5 | 6 | 15 | 31337 => Ok(0u8.into()),
        // assume the safe option (POW) where we don't know
        _ => Ok(6u8.into()),
    }
}

#[cfg(test)]
mod tests {
    use crate::client::check_for_ether;

    use super::*;

    const ETH_RPC_URL: &str = "http://localhost:8545";

    #[tokio::test]
    async fn test_check_for_ether() {
        env_logger::builder().filter_module("ethereum::client", log::LevelFilter::Trace).init();

        let transport = web3::transports::Http::new(ETH_RPC_URL).unwrap();
        let web3 = web3::Web3::new(transport);

        let mut accounts = web3.eth().accounts().await.unwrap();
        accounts.push("0xb4fA5979babd8Bb7e427157d0d353Cf205F43752".parse().unwrap());

        for account in accounts {
            check_for_ether(&web3, account, U256::from(10)).await;
        }
    }

    #[tokio::test]
    async fn test_get_block_delay() {
        let transport = web3::transports::Http::new(ETH_RPC_URL).unwrap();
        let web3 = web3::Web3::new(transport);

        let block_delay = get_block_delay(&web3).await.unwrap();
        println!("{}", block_delay);
    }

    #[tokio::test]
    async fn test_eth_gas_price() {
        let transport = web3::transports::Http::new("").unwrap();
        let web3 = web3::Web3::new(transport);
        let gas_price = web3.eth().gas_price().await.unwrap();
        println!("{}", gas_price);
    }
}
