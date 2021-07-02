use std::collections::HashMap;
use std::ops::{Add, Sub};

use async_recursion::async_recursion;
use eyre::Result;
use tokio::time::sleep;
use tonic::transport::Channel;
use web3::transports::Http;
use web3::types::{Address as EthAddress, U256, U64};
use web3::Web3;

use ethereum::address::Checksum;
use ethereum::client::get_block_delay;
use ethereum::fx_bridge;
use ethereum::fx_bridge::{
    FxOriginatedTokenEvent, query_all_event_san_block, SendToFxEvent,
    TransactionBatchExecutedEvent, ValsetUpdatedEvent,
};
use fxchain::address::Address as FxAddress;
use fxchain::builder::Builder;
use fxchain::grpc_client::{get_last_event_block_height_by_addr, get_last_event_nonce};
use fxchain::proto_ext::MessageExt;
use fxchain::x::gravity::{
    BridgeValidator, MsgDepositClaim, MsgFxOriginatedTokenClaim, MsgValsetUpdatedClaim,
    MsgWithdrawClaim,
};
use prometheus::metrics;

use crate::{ETH_AVG_BLOCK_TIME, ETH_BLOCKS_TO_SEARCH, ETH_EVENT_TO_SEARCH};
use crate::singer_loop::set_fx_key_balance_metrics;

pub async fn eth_oracle_bridge_loop(
    fx_builder: &Builder,
    grpc_channel: &Channel,
    web3: &Web3<Http>,
    bridge_addr: EthAddress,
) {
    let mut eth_last_block = U64::from(0);
    let eth_block_delay = get_block_delay(web3).await.unwrap();

    loop {
        sleep(ETH_AVG_BLOCK_TIME).await;

        if eth_last_block.is_zero() {
            let result = get_last_checked_block_height(
                web3,
                grpc_channel,
                fx_builder.address(),
                bridge_addr,
                eth_block_delay,
            ).await;
            if result.is_err() {
                error!("Oracle check last block height failed {:?}", result.unwrap_err());
                continue;
            }

            eth_last_block = result.unwrap();
            info!("Oracle sync complete, Oracle now operational, last block {:?}", eth_last_block);
            continue;
        }
        metrics::ETH_BRIDGE_ORACLE_SYNC_BLOCK_HEIGHT.set(eth_last_block.as_u64() as f64);

        let result = web3.eth().block_number().await;
        if result.is_err() {
            error!("Oracle fetch eth block number failed {:?}", result.unwrap_err());
            continue;
        }
        let mut eth_latest_block = result.unwrap() - eth_block_delay;

        if eth_last_block.ge(&eth_latest_block) {
            continue;
        }

        if eth_latest_block.sub(eth_last_block).gt(&(ETH_EVENT_TO_SEARCH.into())) {
            eth_latest_block = eth_last_block.add(ETH_EVENT_TO_SEARCH)
        }

        let result = eth_oracle_bridge(
            fx_builder,
            grpc_channel,
            web3,
            bridge_addr,
            eth_last_block,
            eth_latest_block,
        ).await;

        match result {
            Ok(latest_block) => {
                eth_last_block = latest_block;
                let _ = std::fs::write("config", eth_last_block.to_string());
            }
            Err(report) => {
                error!("Failed to ethereum oracle {:?}", report);
            }
        }
    }
}

#[async_recursion(? Send)]
async fn eth_oracle_bridge(
    fx_builder: &Builder,
    grpc_channel: &Channel,
    web3: &Web3<Http>,
    bridge_addr: EthAddress,
    from_block: U64,
    mut to_block: U64,
) -> Result<U64> {
    let fx_address = fx_builder.address();

    let last_event_nonce = fxchain::grpc_client::get_last_event_nonce(grpc_channel, fx_address).await?;
    debug!("Query fx last event nonce {}", last_event_nonce);

    info!("Query oracle bridge event from {} to {}", from_block, to_block);

    metrics::ETH_BRIDGE_ORACLE_QUERY_LOG_BLOCK_HEIGHT_INTERVAL.set((to_block - from_block).as_u64() as f64);

    let deposits: Vec<SendToFxEvent>;
    let withdraws: Vec<TransactionBatchExecutedEvent>;
    let fx_originated_token: Vec<FxOriginatedTokenEvent>;
    let valset_updated: Vec<ValsetUpdatedEvent>;

    let event_result = fx_bridge::query_all_event(web3, bridge_addr, from_block, Some(to_block)).await;
    if event_result.is_err() {
        let err_info = event_result.unwrap_err();
        error!("Eth bridge oracle query all event error: {:?}", err_info);

        let eth_block_buf = (to_block - from_block) / 2;
        if eth_block_buf > 1.into() {
            return eth_oracle_bridge(
                fx_builder,
                grpc_channel,
                web3,
                bridge_addr,
                from_block,
                from_block + eth_block_buf,
            ).await;
        }
        to_block = from_block;
        let (deposits_a, withdraws_a, fx_originated_token_a, valset_updated_a) =
            query_all_event_san_block(web3, bridge_addr, from_block).await?;
        deposits = deposits_a;
        withdraws = withdraws_a;
        fx_originated_token = fx_originated_token_a;
        valset_updated = valset_updated_a;
    } else {
        let (deposits_a, withdraws_a, fx_originated_token_a, valset_updated_a) =
            event_result.unwrap();
        deposits = deposits_a;
        withdraws = withdraws_a;
        fx_originated_token = fx_originated_token_a;
        valset_updated = valset_updated_a;
    }

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
        trace!("deposit claim {:?}", claim);
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
        trace!("withdraw claim {:?}", claim);
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
        trace!("fx originated token claim {:?}", claim);
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
        trace!("valset updated token claim {:?}", claim);
        let msg = claim.to_any("/fx.gravity.v1.MsgValsetUpdatedClaim");
        unordered_msgs.insert(valset.event_nonce.clone(), msg);
    }
    if unordered_msgs.len() <= 0 {
        debug!(
            "An Oracle event to be processed was not found (eth-fx){}",
            to_block
        );
        return Ok(to_block + 1);
    }

    let mut keys = Vec::new();
    for (key, _) in unordered_msgs.iter() {
        keys.push(key.clone());
    }
    keys.sort();
    metrics::ETH_BRIDGE_ORACLE_MSG_PENDING_LEN.set(unordered_msgs.len() as f64);
    info!(
        "Oracle bridge originated token and deposit and withdraw len {}, {:?}",
        unordered_msgs.len(),
        keys
    );
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
        let tx_resp =
            fxchain::grpc_client::send_tx(fx_builder, grpc_channel, cur_msg.clone()).await?;
        info!(
            "Eth oracle bridge fx tx response code {}, tx hash {}",
            tx_resp.code, tx_resp.txhash
        );
        if tx_resp.code != 0 {
            error!("Send eth oracle bridge tx failed: {:?}", tx_resp.raw_log);
            return Ok(from_block);
        }
        info!("Oracle Claims processed, new nonce {}", last_event_nonce);

        set_fx_key_balance_metrics(fx_builder, grpc_channel).await;
        cur_msg.clear()
    }
    Ok(to_block + 1)
}

async fn get_last_checked_block_height(
    web3: &Web3<Http>,
    grpc_channel: &Channel,
    fx_address: FxAddress,
    bridge_addr: EthAddress,
    eth_block_delay: U64,
) -> Result<U64> {
    let mut last_event_nonce: U256 = get_last_event_nonce(grpc_channel, fx_address).await?.into();

    if last_event_nonce == 0u8.into() {
        last_event_nonce = 1u8.into();
    } else {
        if std::path::Path::new("config").exists() {
            let mut res = std::fs::read_to_string("config").unwrap();
            if res.ends_with("\n") {
                let _ = res.split_off(res.len() - 1);
            }
            return Ok(U64::from_str_radix(res.as_str(), 10).unwrap());
        }

        let last_event_block_height = get_last_event_block_height_by_addr(grpc_channel, fx_address).await?;
        if last_event_block_height > 0 {
            return Ok(last_event_block_height.into());
        }
    }
    info!("Query fx chain last event nonce {}, address {:?}", last_event_nonce, fx_address.to_string());

    let mut current_block = web3.eth().block_number().await?;
    current_block = current_block - eth_block_delay;

    while current_block.clone() > 0u8.into() {
        let end_search = if current_block.clone() < U64::from(ETH_BLOCKS_TO_SEARCH) {
            0u8.into()
        } else {
            current_block.clone() - U64::from(ETH_BLOCKS_TO_SEARCH)
        };
        info!(
            "Oracle is resyncing, looking back into the history to find our last event nonce {}, from {} to {}",
            last_event_nonce, end_search, current_block
        );


        let (deposits, withdraws, fx_originated_token, valset_updated) =
            fx_bridge::query_all_event(web3, bridge_addr.clone(), end_search, Some(current_block))
                .await?;

        for event in deposits {
            if event.event_nonce == last_event_nonce {
                return Ok(event.block_number);
            }
        }
        for event in withdraws {
            if event.event_nonce == last_event_nonce {
                return Ok(event.block_number);
            }
        }
        for event in fx_originated_token {
            if event.event_nonce == last_event_nonce {
                return Ok(event.block_number);
            }
        }
        for event in valset_updated {
            if event.valset_nonce == 0u8.into()
                && event.event_nonce == last_event_nonce
                && last_event_nonce == 1u8.into()
            {
                return Ok(event.block_number);
            } else if event.valset_nonce == 0u8.into() && last_event_nonce > 1u8.into() {
                panic!("Could not find the last event relayed by {}, Last Event nonce is {} but no event matching that could be found!", fx_address, last_event_nonce)
            }
        }

        current_block = end_search;
    }

    panic!("You have reached the end of block history without finding the FxBridge contract deploy event! You must have the wrong contract address!");
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use log::LevelFilter::Trace;

    use fxchain::grpc_client::{get_account_info, get_chain_id, new_grpc_channel};
    use fxchain::private_key::PrivateKey;
    use fxchain::x::gravity::query_client::QueryClient as GravityQueryClient;
    use fxchain::x::gravity::QueryLastEventNonceByAddrRequest;

    use super::*;

    const FX_MNEMONIC: &str = "";
    const ETH_RPC_URL: &str = "http://localhost:8545";
    const FX_GRPC_URL: &str = "http://127.0.0.1:9090";
    const BRIDGE_ADDR: &str = "";

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
        eth_oracle_bridge_loop(&builder, &grpc_channel, &web3, bridge_addr).await;
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
    async fn test_eth_bridge_event(
        web3: &Web3<Http>,
        bridge_addr: EthAddress,
        from_block: U64,
        mut to_block: U64,
    ) -> Result<U64> {
        let deposits: Vec<SendToFxEvent>;
        let withdraws: Vec<TransactionBatchExecutedEvent>;
        let fx_originated_token: Vec<FxOriginatedTokenEvent>;
        let valset_updated: Vec<ValsetUpdatedEvent>;

        let event_result =
            fx_bridge::query_all_event(web3, bridge_addr, from_block, Some(to_block)).await;
        if event_result.is_err() {
            error!(
                "Eth bridge oracle query all event error: {:?}",
                event_result
            );
            let eth_block_buf = (to_block - from_block) / 2;
            if eth_block_buf > 1.into() {
                trace!(
                    "recursion {:?},{:?}",
                    from_block,
                    from_block + eth_block_buf
                );
                return test_eth_bridge_event(
                    web3,
                    bridge_addr,
                    from_block,
                    from_block + eth_block_buf,
                )
                    .await;
            }
            trace!("san block: {:?}", to_block);
            to_block = from_block;
            let (deposits_a, withdraws_a, fx_originated_token_a, valset_updated_a) =
                query_all_event_san_block(web3, bridge_addr, from_block).await?;
            deposits = deposits_a;
            withdraws = withdraws_a;
            fx_originated_token = fx_originated_token_a;
            valset_updated = valset_updated_a;
        } else {
            let (deposits_a, withdraws_a, fx_originated_token_a, valset_updated_a) =
                event_result.unwrap();
            deposits = deposits_a;
            withdraws = withdraws_a;
            fx_originated_token = fx_originated_token_a;
            valset_updated = valset_updated_a;
        }
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
        env_logger::builder().filter_module("bridge::oracle_loop", Trace).init();

        let transport = web3::transports::Http::new(ETH_RPC_URL)
            .unwrap();
        let web3 = web3::Web3::new(transport);
        let bridge_addr =
            EthAddress::from_str("0x57c62672F61f8FF14b61AE70C516C73aCF3374cA").unwrap();
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
