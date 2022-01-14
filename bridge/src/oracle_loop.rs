use std::collections::HashMap;
use std::ops::{Add, Sub};
use std::str::FromStr;

use async_recursion::async_recursion;
use cosmos_sdk_proto::cosmos::staking::v1beta1::BondStatus;
use eyre::Result;
use tokio::time::sleep;
use tonic::transport::Channel;
use web3::transports::Http;
use web3::types::{Address as EthAddress, U256, U64};
use web3::Web3;

use ethereum::address::Checksum;
use ethereum::fx_bridge;
use fxchain::address::Address as FxAddress;
use fxchain::builder::Builder;
use fxchain::grpc_client::{get_last_event_block_height_by_addr, get_last_event_nonce, get_orchestrator_validator_status};
use fxchain::proto_ext::MessageExt;
use fxchain::x::gravity::{BridgeValidator, MsgDepositClaim, MsgFxOriginatedTokenClaim, MsgValsetUpdatedClaim, MsgWithdrawClaim};

use crate::singer_loop::set_fx_key_balance_metrics;
use crate::{ETH_AVG_BLOCK_TIME, ETH_BLOCKS_TO_SEARCH, ETH_BLOCK_DELAY, ETH_EVENT_TO_SEARCH};

/// Periodically check for Ethereum FxBridge contract events and forward the monitored events to the Fx chain
pub async fn eth_oracle_bridge_loop(fx_builder: &Builder, grpc_channel: &Channel, web3: &Web3<Http>, bridge_addr: EthAddress, mut eth_last_block: U64) {
    loop {
        sleep(ETH_AVG_BLOCK_TIME).await;

        // check validator status is bonded
        let result = get_orchestrator_validator_status(&grpc_channel, fx_builder.address()).await;
        if result.is_err() {
            warn!("Get orchestrator validator status failed {:?}", result.unwrap_err().root_cause());
            continue;
        }
        let (status, eth_address_str) = result.unwrap();
        if status != BondStatus::Bonded as i32 {
            warn!("Get orchestrator validator status is not 'Bonded', {:?}", status);
            continue;
        }
        let eth_address = EthAddress::from_str(eth_address_str.as_str()).unwrap();

        let result = web3.eth().block_number().await;
        if result.is_err() {
            error!("Oracle fetch ethereum block number failed {:?}", result.unwrap_err());
            continue;
        }
        let mut eth_latest_block = result.unwrap();
        if eth_latest_block <= U64::from(ETH_BLOCK_DELAY) {
            warn!("Get eth latest block is invalid {}", eth_last_block);
            continue;
        }
        eth_latest_block = eth_latest_block.sub(U64::from(ETH_BLOCK_DELAY));

        if eth_last_block.is_zero() {
            let result = get_last_checked_block_height(web3, grpc_channel, fx_builder.address(), eth_address, bridge_addr, eth_latest_block).await;
            if result.is_err() {
                warn!("Oracle get last block height failed {:?}", result.unwrap_err().root_cause());
                continue;
            }

            eth_last_block = result.unwrap();
            info!("Oracle sync complete, Oracle now operational, last block {:?}", eth_last_block);
            continue;
        }
        prometheus::metrics::ETH_BRIDGE_ORACLE_SYNC_BLOCK_HEIGHT.set(eth_last_block.as_u64() as f64);
        if eth_last_block.ge(&eth_latest_block) {
            // Waiting for a new block
            continue;
        }

        let geight_interval = eth_latest_block.sub(eth_last_block);
        if geight_interval.gt(&(ETH_EVENT_TO_SEARCH.into())) {
            eth_latest_block = eth_last_block.add(ETH_EVENT_TO_SEARCH)
        }

        let result = eth_oracle_bridge(fx_builder, grpc_channel, web3, bridge_addr, eth_last_block, eth_latest_block).await;
        match result {
            Ok(latest_block) => {
                eth_last_block = latest_block;
                if latest_block > 2000.into() {
                    let _ = std::fs::write("config", (latest_block.sub(U64::from(2000))).to_string());
                }
            }
            Err(report) => {
                error!("Failed to ethereum oracle {:?}", report.root_cause());
            }
        }
    }
}

#[async_recursion(? Send)]
async fn eth_oracle_bridge(fx_builder: &Builder, grpc_channel: &Channel, web3: &Web3<Http>, bridge_addr: EthAddress, from_block: U64, mut to_block: U64) -> Result<U64> {
    let fx_address = fx_builder.address();

    let last_event_nonce = fxchain::grpc_client::get_last_event_nonce(grpc_channel, fx_address).await?;
    info!("Query last event nonce by fx address {}", last_event_nonce);

    info!("Query oracle bridge event from {} to {}", from_block, to_block);
    prometheus::metrics::ETH_BRIDGE_ORACLE_QUERY_LOG_BLOCK_HEIGHT_INTERVAL.set((to_block - from_block).as_u64() as f64);

    let (deposits, withdraws, fx_originated_token, valset_updated) = match fx_bridge::query_all_event(web3, bridge_addr, from_block, Some(to_block)).await {
        Ok(event_list) => event_list,
        Err(report) => {
            error!("Eth bridge oracle query all event error: {:?}", report.root_cause());

            let eth_block_buf = (to_block - from_block) / 2;
            if eth_block_buf > 1.into() {
                return eth_oracle_bridge(fx_builder, grpc_channel, web3, bridge_addr, from_block, from_block + eth_block_buf).await;
            }
            to_block = from_block;
            fx_bridge::query_all_event_san_block(web3, bridge_addr, from_block).await?
        }
    };
    let mut unordered_msgs = HashMap::new();

    for deposit in deposits {
        if deposit.event_nonce <= U256::from(last_event_nonce) {
            continue;
        }
        let claim = MsgDepositClaim {
            event_nonce: deposit.event_nonce.as_u64(),
            block_height: deposit.block_number.as_u64(),
            token_contract: deposit.erc20.to_hex_string(),
            amount: deposit.amount.to_string(),
            fx_receiver: FxAddress::from_bytes(deposit.destination).to_string(),
            target_ibc: deposit.target_ibc,
            eth_sender: deposit.sender.to_hex_string(),
            orchestrator: fx_address.to_string(),
        };
        debug!("deposit claim {:?}", claim);
        let msg = claim.to_any("/fx.gravity.v1.MsgDepositClaim");
        unordered_msgs.insert(deposit.event_nonce.clone(), msg);
    }
    for withdraw in withdraws {
        if withdraw.event_nonce <= U256::from(last_event_nonce) {
            continue;
        }
        let claim = MsgWithdrawClaim {
            event_nonce: withdraw.event_nonce.as_u64(),
            block_height: withdraw.block_number.as_u64(),
            token_contract: withdraw.erc20.to_hex_string(),
            batch_nonce: withdraw.batch_nonce.as_u64(),
            orchestrator: fx_address.to_string(),
        };
        debug!("withdraw claim {:?}", claim);
        let msg = claim.to_any("/fx.gravity.v1.MsgWithdrawClaim");
        unordered_msgs.insert(withdraw.event_nonce.clone(), msg);
    }
    for token in fx_originated_token {
        if token.event_nonce <= U256::from(last_event_nonce) {
            continue;
        }
        let claim = MsgFxOriginatedTokenClaim {
            event_nonce: token.event_nonce.as_u64(),
            block_height: token.block_number.as_u64(),
            token_contract: token.erc20.to_hex_string(),
            name: token.name,
            symbol: token.symbol,
            decimals: token.decimals.as_u64(),
            orchestrator: fx_address.to_string(),
        };
        debug!("fx originated token claim {:?}", claim);
        let msg = claim.to_any("/fx.gravity.v1.MsgFxOriginatedTokenClaim");
        unordered_msgs.insert(token.event_nonce.clone(), msg);
    }
    for valset in valset_updated {
        if valset.event_nonce <= U256::from(last_event_nonce) {
            continue;
        }
        let mut bridge_validator = Vec::new();
        for i in 0..valset.validators.len() {
            bridge_validator.push(BridgeValidator {
                power: valset.powers[i].as_u64(),
                eth_address: valset.validators[i].to_hex_string(),
            })
        }
        let claim = MsgValsetUpdatedClaim {
            event_nonce: valset.event_nonce.as_u64(),
            block_height: valset.block_number.as_u64(),
            valset_nonce: valset.valset_nonce.as_u64(),
            members: bridge_validator,
            orchestrator: fx_address.to_string(),
        };
        debug!("valset updated token claim {:?}", claim);
        let msg = claim.to_any("/fx.gravity.v1.MsgValsetUpdatedClaim");
        unordered_msgs.insert(valset.event_nonce.clone(), msg);
    }
    if unordered_msgs.len() <= 0 {
        info!("An Oracle event to be processed was not found(eth-fx) {}", to_block);
        return Ok(to_block + 1);
    }

    let mut keys = Vec::new();
    for (key, _) in unordered_msgs.iter() {
        keys.push(key.clone());
    }
    keys.sort();
    prometheus::metrics::ETH_BRIDGE_ORACLE_MSG_PENDING_LEN.set(unordered_msgs.len() as f64);
    info!("Oracle bridge originated token and deposit and withdraw len {}, {:?}", unordered_msgs.len(), keys);

    if keys[0] != (last_event_nonce + 1).into() {
        panic!("Oracle bridge event nonce out of the current state")
    }

    let mut msgs = Vec::new();
    for i in keys {
        msgs.push(unordered_msgs.remove_entry(&i).unwrap().1);
    }
    let mut cur_msg = Vec::new();
    for i in 0..msgs.len() {
        cur_msg.push(msgs[i].clone());
        if (i + 1) % fxchain::FX_MSG_MAX_NUMBER != 0 && (i + 1) != msgs.len() {
            continue;
        }
        let tx_resp = fxchain::grpc_client::send_tx(fx_builder, grpc_channel, cur_msg.clone()).await?;
        info!("Eth oracle bridge fx tx response code {}, tx hash {}", tx_resp.code, tx_resp.txhash);

        if tx_resp.code != 0 {
            error!("Send eth oracle bridge tx failed: {:?}", tx_resp.raw_log);

            return Ok(from_block);
        }
        info!("Oracle Claims processed, new nonce {}", last_event_nonce);

        set_fx_key_balance_metrics(fx_builder, grpc_channel).await;
        cur_msg.clear()
    }
    debug!("Oracle loop complete {}", to_block + 1);
    Ok(to_block + 1)
}

async fn get_last_checked_block_height(web3: &Web3<Http>, grpc_channel: &Channel, fx_address: FxAddress, eth_address: EthAddress, bridge_addr: EthAddress, eth_latest_block: U64) -> Result<U64> {
    let last_event_nonce: U256 = get_last_event_nonce(grpc_channel, fx_address).await?.into();

    if last_event_nonce != 0u8.into() {
        let last_event_block_height = get_last_event_block_height_by_addr(grpc_channel, fx_address).await?.into();
        let mut cache_block_height = U64::from(0);
        if std::path::Path::new("config").exists() {
            let mut res = std::fs::read_to_string("config").unwrap();
            if res.ends_with("\n") {
                let _ = res.split_off(res.len() - 1);
            }
            cache_block_height = U64::from_str_radix(res.as_str(), 10).unwrap();
        }
        if last_event_block_height > 0.into() && last_event_block_height > cache_block_height {
            return Ok(last_event_block_height);
        } else if cache_block_height > 0.into() {
            return Ok(cache_block_height);
        }
    }
    info!("Query fx chain last event nonce {}, address {:?}", last_event_nonce, fx_address.to_string());

    let mut current_block = eth_latest_block;
    let mut end_block = U64::from(0);
    if current_block > U64::from(20000) {
        end_block = current_block - U64::from(20000);
    }
    while current_block > end_block {
        let end_search = if current_block < U64::from(ETH_BLOCKS_TO_SEARCH) {
            0u8.into()
        } else {
            current_block - U64::from(ETH_BLOCKS_TO_SEARCH)
        };
        info!("Oracle is resyncing from {} to {}", end_search, current_block);

        let mut valset_updated = fx_bridge::query_valset_updated_event(web3, bridge_addr.clone(), end_search, Some(current_block)).await?;
        valset_updated.reverse();
        for event in valset_updated {
            for val in event.validators {
                if val == eth_address {
                    return Ok(event.block_number);
                }
            }
        }
        current_block = end_search;
    }
    return Err(eyre::Error::msg("No found last event block height"));
    // panic!("You have reached the end of block history without finding the FxBridge contract deploy event! You must have the wrong contract address!");
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use log::LevelFilter::Info;

    use ethereum::fx_bridge::query_all_event_san_block;
    use fxchain::address::Address as FxAddress;
    use fxchain::grpc_client::{get_account_info, get_chain_id, new_grpc_channel};
    use fxchain::private_key::PrivateKey;
    use fxchain::x::gravity::query_client::QueryClient as GravityQueryClient;
    use fxchain::x::gravity::QueryLastEventNonceByAddrRequest;

    use super::*;

    const FX_MNEMONIC: &str = "";
    const ETH_RPC_URL: &str = "http://localhost:8545";
    const FX_GRPC_URL: &str = "http://127.0.0.1:9090";
    const BRIDGE_ADDR: &str = "0x0412C7c846bb6b7DC462CF6B453f76D8440b2609";

    #[tokio::test]
    async fn query_event_nonce() {
        let grpc_channel = new_grpc_channel(FX_GRPC_URL).await.unwrap();
        let fx_address = FxAddress::from_str("fx1qllms2p25gec8fn4xvyak83g856xdltp4wc335").unwrap();
        let last_event_nonce = fxchain::grpc_client::get_last_event_nonce(&grpc_channel, fx_address).await.unwrap();
        println!("{}", last_event_nonce);

        let block_height = get_last_event_block_height_by_addr(&grpc_channel, fx_address).await.unwrap();
        println!("{}", block_height);
    }

    #[tokio::test]
    async fn test_eth_oracle_main_loop() {
        let transport = web3::transports::Http::new(ETH_RPC_URL).unwrap();
        let web3 = web3::Web3::new(transport);

        let private_key = PrivateKey::from_phrase(FX_MNEMONIC, "").unwrap();
        let acc_address = private_key.public_key().to_address().to_string();
        let grpc_channel = new_grpc_channel(FX_GRPC_URL).await.unwrap();
        let auth_account = get_account_info(&grpc_channel, acc_address).await.unwrap();
        let chain_id = get_chain_id(&grpc_channel).await.unwrap();
        let builder = Builder::new(chain_id, private_key, auth_account.account_number, "FX");

        let bridge_addr = EthAddress::from_str(BRIDGE_ADDR).unwrap();
        eth_oracle_bridge_loop(&builder, &grpc_channel, &web3, bridge_addr, U64::from(0)).await;
    }

    #[tokio::test]
    async fn test_last_event_nonce_by_addr() {
        let grpc_channel = new_grpc_channel(FX_GRPC_URL).await.unwrap();

        let mut gravity_query_client = GravityQueryClient::new(grpc_channel.clone());

        let response = gravity_query_client
            .last_event_nonce_by_addr(QueryLastEventNonceByAddrRequest {
                address: "fx16wvwsmpp4y4ttgzknyr6kqla877jud6u04lqey".to_string(),
            })
            .await
            .unwrap();
        println!("{}", response.into_inner().event_nonce);
    }

    #[async_recursion(? Send)]
    async fn test_eth_bridge_event(web3: &Web3<Http>, bridge_addr: EthAddress, from_block: U64, mut to_block: U64) -> Result<U64> {
        let (deposits, withdraws, fx_originated_token, valset_updated) = match fx_bridge::query_all_event(web3, bridge_addr, from_block, Some(to_block)).await {
            Ok(event_list) => event_list,
            Err(report) => {
                error!("Eth bridge oracle query all event error: {:?}", report.root_cause());
                let eth_block_buf = (to_block - from_block) / 2;
                if eth_block_buf > 1.into() {
                    info!("recursion {:?},{:?}", from_block, from_block + eth_block_buf);
                    return test_eth_bridge_event(web3, bridge_addr, from_block, from_block + eth_block_buf).await;
                }
                info!("san block: {:?}", to_block);
                to_block = from_block;
                query_all_event_san_block(web3, bridge_addr, from_block).await?
            }
        };
        println!("{}", deposits.len());
        println!("{}", withdraws.len());
        println!("{}", fx_originated_token.len());
        println!("{}", valset_updated.len());
        Ok(to_block + 1)
    }

    #[tokio::test]
    async fn test_file() {
        let _ = std::fs::write("config", U64::from(100).to_string());
        if std::path::Path::new("config").exists() {
            let mut res = std::fs::read_to_string("config").unwrap();
            if res.ends_with("\n") {
                let _ = res.split_off(res.len() - 1);
            }
            println!("{:?}", res);
            println!("{}", U64::from_str_radix(res.as_str(), 10).unwrap());
        }
        let _ = std::fs::remove_file("config");
    }

    #[tokio::test]
    async fn test_test_eth_bridge_event() {
        env_logger::builder().filter_module("bridge::oracle_loop", Info).init();

        let transport = web3::transports::Http::new(ETH_RPC_URL).unwrap();
        let web3 = web3::Web3::new(transport);
        let bridge_addr = EthAddress::from_str("0x57c62672F61f8FF14b61AE70C516C73aCF3374cA").unwrap();
        let res = test_eth_bridge_event(&web3, bridge_addr, 25250829.into(), 25250830.into()).await;
        println!("{:?}", res);
    }

    #[test]
    fn test_overflow() {
        let latest = U64::from_dec_str("25113218").unwrap();
        let last = U64::from_dec_str("25113219").unwrap();
        println!("{}", latest - last);
    }

    #[test]
    fn test_vec_splice() {
        let mut msgs = Vec::new();
        for i in 0..800 {
            msgs.push(i)
        }

        let mut cur_msg = Vec::new();
        for i in 0..msgs.len() {
            cur_msg.push(msgs[i]);
            if (i + 1) % 300 != 0 && (i + 1) != msgs.len() {
                continue;
            }
            println!("{}, {:?}", cur_msg.len(), cur_msg);
            cur_msg.clear()
        }
    }
}
