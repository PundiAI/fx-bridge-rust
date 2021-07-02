use std::str::FromStr;

use eyre::Result;
use tokio::time::sleep;
use web3::transports::Http;
use web3::types::{Address as EthAddress, U256, U64};
use web3::types::H256;
use web3::Web3;

use ethereum::address::Checksum;
use ethereum::client::get_block_delay;
use ethereum::erc20::ERC20;
use ethereum::fx_bridge::{FxBridge, query_all_event};
use ethereum::private_key::{Key, PrivateKey as EthPrivateKey};
use fxchain::address::Address as FxAddress;

use crate::ETH_AVG_BLOCK_TIME;

pub async fn send_to_fx_loop(
    web3: &Web3<Http>,
    eth_private_key: &EthPrivateKey,
    bridge_addr: EthAddress,
    destination_str: String,
) {
    let result = FxAddress::from_str(destination_str.as_str());
    if result.is_err() {
        if destination_str.len() != 0 {
            panic!("{}", result.unwrap_err())
        }
        return;
    }
    let destination = result.unwrap();

    let eth_block_delay = get_block_delay(web3).await.unwrap();

    let fx_bridge = FxBridge::new(None, None, web3.eth(), bridge_addr);
    let erc20_addr = fx_bridge.fx_originated_token().await.unwrap();
    let amount = U256::from(10).pow(U256::from(18));

    info!("send to fx loop running ...");

    loop {
        sleep(ETH_AVG_BLOCK_TIME * 2).await;

        let result = web3.eth().block_number().await;
        if result.is_err() {
            error!(
                "Oracle fetch eth block number failed {:?}",
                result.unwrap_err()
            );
            continue;
        }
        let eth_latest_block = result.unwrap() - eth_block_delay;
        let eth_buf = (24 * 3600 / 6 / 15).into();
        let mut start_block = U64::from(0);
        if eth_latest_block > eth_buf {
            start_block = eth_latest_block - eth_buf;
        } else {
            info!("eth block {}, {}", start_block, eth_latest_block);
            continue;
        }
        let result =
            query_all_event(web3, bridge_addr, start_block, Some(eth_latest_block)).await;
        if result.is_err() {
            error!("query fx bridge contract all event failed {:?}", result.err());
            continue;
        }
        let (deposits_a, withdraws_a, fx_originated_token_a, valset_updated_a) = result.unwrap();
        if deposits_a.len() > 0 || withdraws_a.len() > 0 || fx_originated_token_a.len() > 0 || valset_updated_a.len() > 0 {
            info!("find event from {} to {}", start_block, eth_latest_block);
            continue;
        }

        let result = send_to_fx(web3, eth_private_key, erc20_addr, bridge_addr, destination, amount).await;
        match result {
            Ok(hash) => {
                info!("send to fx hash {}", hash)
            }
            Err(report) => {
                error!("send to fx error {}", report)
            }
        }
    }
}

pub async fn send_to_fx(
    web3: &Web3<Http>,
    eth_private_key: &EthPrivateKey,
    erc20_addr: EthAddress,
    bridge_addr: EthAddress,
    destination: FxAddress,
    amount: U256,
) -> Result<H256> {
    info!("Eth address {} send to fx address {} amount {}", eth_private_key.address().to_hex_string(), destination.to_string(), amount);

    let erc20 = ERC20::new(Some(eth_private_key.clone()), None, web3.eth(), erc20_addr);
    let allowance = erc20
        .allowance(eth_private_key.address(), bridge_addr)
        .await?;
    if allowance.le(&amount) {
        info!(
            "Account {} approve bridge {} erc20 {}",
            eth_private_key.address().to_hex_string(),
            bridge_addr.to_hex_string(),
            erc20_addr.to_hex_string()
        );
        let receipt = erc20.approve(bridge_addr, U256::max_value()).await?;
        info!(
            "Erc20 approve tx receipt {:?}, status {:?}",
            receipt.transaction_hash, receipt.status
        );
        if receipt.status.is_none() || receipt.status.unwrap() != 1.into() {
            error!("Erc20 approve tx failed {:?}", receipt);
            return Err(eyre::Error::msg("approve failed"));
        }
    }
    let fx_bridge = FxBridge::new(Some(eth_private_key.clone()), None, web3.eth(), bridge_addr);

    let target_ibc: [u8; 32] = [0; 32];
    let receipt = fx_bridge
        .send_to_fx(erc20_addr, destination.to_bytes32(), target_ibc, amount)
        .await?;
    info!(
        "Ethereum send assets to fx tx receipt {:?}, status {:?}",
        receipt.transaction_hash, receipt.status
    );
    Ok(receipt.transaction_hash)
}
