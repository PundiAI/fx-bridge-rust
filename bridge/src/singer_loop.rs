use std::ops::Div;
use std::str::FromStr;

use cosmos_sdk_proto::cosmos::staking::v1beta1::BondStatus;
use eyre::Result;
use tokio::time::sleep;
use tonic::transport::Channel;
use web3::ethabi::{FixedBytes, Token, Uint};
use web3::types::{Address as EthAddress, U256};

use ethereum::address::Checksum;
use ethereum::private_key::{Key, PrivateKey as EthPrivateKey, PrivateKey};
use fxchain::builder::Builder;
use fxchain::grpc_client::get_orchestrator_validator_status;
use fxchain::proto_ext::MessageExt;
use fxchain::x::gravity::query_client::QueryClient as GravityQueryClient;
use fxchain::x::gravity::QueryLastPendingBatchRequestByAddrRequest;
use fxchain::x::gravity::QueryLastPendingValsetRequestByAddrRequest;
use fxchain::x::gravity::{MsgConfirmBatch, MsgValsetConfirm, OutgoingTxBatch, Valset};

use crate::FX_AVG_BLOCK_TIME;

pub async fn eth_signer_main_loop(fx_builder: &Builder, grpc_channel: &Channel, eth_private_key: &EthPrivateKey) {
    let gravity_id = fxchain::grpc_client::get_gravity_id(grpc_channel).await.unwrap();

    loop {
        sleep(FX_AVG_BLOCK_TIME).await;

        let result = get_orchestrator_validator_status(&grpc_channel, fx_builder.address()).await;
        if result.is_err() {
            warn!("Get orchestrator status failed {:?}", result.unwrap_err().root_cause());
            continue;
        }
        let (status, eth_address_str) = result.unwrap();
        if status != BondStatus::Bonded as i32 {
            warn!("Get orchestrator status is not 'Bonded', {:?}", status);
            continue;
        }
        if eth_address_str != eth_private_key.address().to_hex_string() {
            panic!("invalid eth private key, expect {}", eth_address_str)
        }

        let result = singer_last_pending_valset_request(fx_builder, grpc_channel, eth_private_key, &gravity_id).await;
        if result.is_err() {
            error!("singer last pending valset request error: {:?}", result.unwrap_err().root_cause());
            continue;
        }

        let result = singer_last_pending_batch_request(fx_builder, grpc_channel, eth_private_key, &gravity_id).await;
        if result.is_err() {
            error!("singer last pending batch request error: {:?}", result.unwrap_err().root_cause());
            continue;
        }

        set_fx_key_balance_metrics(fx_builder, grpc_channel).await;
    }
}

pub async fn set_fx_key_balance_metrics(fx_builder: &Builder, grpc_channel: &Channel) {
    let result = fxchain::grpc_client::get_balance(grpc_channel, fx_builder.address(), fx_builder.get_fee_denom()).await;
    match result {
        Ok(balance) => {
            let amount = U256::from_dec_str(balance.amount.as_str()).unwrap().div(U256::from(10).pow(U256::from(18)));
            prometheus::metrics::FX_KEY_BALANCE.set(amount.as_u64() as f64)
        }
        Err(report) => error!("Query fx account {} balance failed {}", fx_builder.address(), report.root_cause()),
    }
}

async fn singer_last_pending_valset_request(fx_builder: &Builder, grpc_channel: &Channel, eth_private_key: &PrivateKey, gravity_id: &String) -> Result<()> {
    let mut gravity_query_client = GravityQueryClient::new(grpc_channel.clone());
    let response = gravity_query_client
        .last_pending_valset_request_by_addr(QueryLastPendingValsetRequestByAddrRequest {
            address: fx_builder.address().to_string(),
        })
        .await?;
    let valsets = response.into_inner().valsets;
    if valsets.is_empty() {
        debug!("No validator sets to sign, node is caught up!");
        return Ok(());
    }
    let eth_address = eth_private_key.address().to_hex_string();
    info!(
        "Sending {} valset confirms starting with nonce {}, valset update singer {}",
        valsets.len(),
        valsets[0].nonce,
        eth_address
    );

    let mut messages = Vec::new();
    for valset in valsets.iter() {
        info!("Submitting signature for valset {}, {}", valset.nonce, valset.height);
        let message = encode_valset_confirm_hash(gravity_id.clone(), &valset);
        let eth_signature = eth_private_key.sign_ethereum_msg(message.as_slice()).unwrap();
        let confirm = MsgValsetConfirm {
            orchestrator: fx_builder.address().to_string(),
            eth_address: eth_private_key.address().to_hex_string(),
            nonce: valset.nonce,
            signature: format!("{:x}", eth_signature.to_hash()),
        };
        let msg = confirm.to_any("/fx.gravity.v1.MsgValsetConfirm");
        messages.push(msg);
    }

    let tx_resp = fxchain::grpc_client::send_tx(fx_builder, grpc_channel, messages).await?;
    info!("Valset confirm tx response code {}, tx hash {}", tx_resp.code, tx_resp.txhash);
    if tx_resp.code != 0 {
        error!("Send valset confirm tx failed: {:?}", tx_resp.raw_log);
    }
    prometheus::metrics::UPDATE_VALSET_SIGN.inc();
    return Ok(());
}

async fn singer_last_pending_batch_request(fx_builder: &Builder, grpc_channel: &Channel, eth_private_key: &PrivateKey, gravity_id: &String) -> Result<()> {
    let mut gravity_query_client = GravityQueryClient::new(grpc_channel.clone());
    let response = gravity_query_client
        .last_pending_batch_request_by_addr(QueryLastPendingBatchRequestByAddrRequest {
            address: fx_builder.address().to_string(),
        })
        .await?;
    let outgoing_tx_batch_opt = response.into_inner().batch;
    if outgoing_tx_batch_opt.is_none() {
        return Ok(());
    }
    let unsigned_batch = outgoing_tx_batch_opt.unwrap();
    info!(
        "Sending batch confirm for {} nonce {} with block {} in fees",
        unsigned_batch.token_contract, unsigned_batch.batch_nonce, unsigned_batch.block
    );

    let message = encode_tx_batch_confirm_hash(gravity_id.clone(), unsigned_batch.clone());
    let eth_signature = eth_private_key.sign_ethereum_msg(message.as_slice()).unwrap();
    info!("Sending batch update with address {}", eth_private_key.address().to_hex_string());

    let confirm = MsgConfirmBatch {
        token_contract: unsigned_batch.token_contract,
        orchestrator: fx_builder.address().to_string(),
        eth_signer: eth_private_key.address().to_hex_string(),
        nonce: unsigned_batch.batch_nonce,
        signature: format!("{:x}", eth_signature.to_hash()),
    };
    let msg = confirm.to_any("/fx.gravity.v1.MsgConfirmBatch");

    let tx_resp = fxchain::grpc_client::send_tx(fx_builder, grpc_channel, vec![msg]).await?;
    info!("batch confirm tx response {}, {}", tx_resp.code, tx_resp.txhash);
    if tx_resp.code != 0 {
        error!("Send batch confirm tx failed: {:?}", tx_resp.raw_log);
    }
    prometheus::metrics::SUBMIT_BATCH_SIGN.inc();
    Ok(())
}

pub fn encode_valset_confirm_hash(gravity_id: String, valset: &Valset) -> Vec<u8> {
    let mut powers = Vec::new();
    let mut addresses = Vec::new();
    for item in valset.members.iter() {
        powers.push(Token::Uint(Uint::from(item.power)));
        addresses.push(Token::Address(EthAddress::from_str(item.eth_address.as_str()).unwrap()))
    }
    web3::ethabi::encode(&[
        Token::FixedBytes(FixedBytes::from(gravity_id)),
        Token::FixedBytes(FixedBytes::from("checkpoint")),
        Token::Uint(Uint::from(valset.nonce)),
        Token::Array(addresses),
        Token::Array(powers),
    ])
}

pub fn encode_tx_batch_confirm_hash(gravity_id: String, batch: OutgoingTxBatch) -> Vec<u8> {
    let mut amounts = Vec::new();
    let mut fees = Vec::new();
    let mut destinations = Vec::new();
    for item in batch.transactions.iter() {
        amounts.push(Token::Uint(Uint::from_dec_str(item.erc20_token.as_ref().unwrap().amount.as_str()).unwrap()));
        destinations.push(Token::Address(EthAddress::from_str(item.dest_address.as_str()).unwrap()));
        fees.push(Token::Uint(Uint::from_dec_str(item.erc20_fee.as_ref().unwrap().amount.as_str()).unwrap()));
    }
    web3::ethabi::encode(&[
        Token::FixedBytes(FixedBytes::from(gravity_id)),
        Token::FixedBytes(FixedBytes::from("transactionBatch")),
        Token::Array(amounts),
        Token::Array(destinations),
        Token::Array(fees),
        Token::Uint(Uint::from(batch.batch_nonce)),
        Token::Address(EthAddress::from_str(batch.token_contract.as_str()).unwrap()),
        Token::Uint(Uint::from(batch.batch_timeout)),
        Token::Address(EthAddress::from_str(batch.fee_receive.as_str()).unwrap()),
    ])
}

#[cfg(test)]
mod tests {
    use log::LevelFilter::{Debug, Info};
    use web3::types::{H256, U256};

    use ethereum::private_key::{ethereum_msg_hash, Signature};
    use fxchain::grpc_client::{get_account_info, get_chain_id, new_grpc_channel};
    use fxchain::private_key::PrivateKey as FxPrivateKey;
    use fxchain::x::gravity::{QueryBatchRequestByNonceRequest, QueryParamsRequest};

    use super::*;

    const ETH_PRIVATE_KEY: &str = "";
    const FX_GRPC_URL: &str = "http://127.0.0.1:9090";
    const FX_MNEMONIC: &str = "";

    #[tokio::test]
    async fn test_valset_confirm_signature() {
        env_logger::builder().filter_level(Info).init();

        let fx_private_key = FxPrivateKey::from_phrase(FX_MNEMONIC, "").unwrap();
        let fx_address = fx_private_key.public_key().to_address().to_string();
        let grpc_channel = new_grpc_channel(FX_GRPC_URL).await.unwrap();
        let auth_account = get_account_info(&grpc_channel, fx_address.clone()).await.unwrap();
        let fx_chain_id = get_chain_id(&grpc_channel).await.unwrap();
        let fx_builder = Builder::new(fx_chain_id, fx_private_key, auth_account.account_number, "FX");

        let eth_private_key = EthPrivateKey::from_str(ETH_PRIVATE_KEY).unwrap();

        let grpc_channel = new_grpc_channel(FX_GRPC_URL).await.unwrap();

        let mut gravity_query_client = GravityQueryClient::new(grpc_channel.clone());
        let response = gravity_query_client.params(QueryParamsRequest {}).await.unwrap();

        let gravity_id = response.into_inner().params.unwrap().gravity_id;
        println!("gravity_id {}", gravity_id);

        let response = gravity_query_client
            .last_pending_valset_request_by_addr(QueryLastPendingValsetRequestByAddrRequest { address: fx_address })
            .await
            .unwrap();

        for valset in response.into_inner().valsets.iter() {
            // println!("{:?}", valset);
            let message = encode_valset_confirm_hash(gravity_id.clone(), valset);
            let eth_signature = eth_private_key.sign_ethereum_msg(message.as_slice()).unwrap();
            // println!("{:x}", eth_signature.to_hash());
            // let address = eth_signature.recover(message.as_slice()).unwrap();
            // println!("{:?}", address);
            let confirm = MsgValsetConfirm {
                orchestrator: fx_builder.address().to_string(),
                eth_address: eth_private_key.address().to_hex_string(),
                nonce: valset.nonce,
                signature: format!("{:x}", eth_signature.to_hash()),
            };
            let msg = confirm.to_any("/fx.gravity.v1.MsgValsetConfirm");

            let response = fxchain::grpc_client::send_tx(&fx_builder, &grpc_channel, vec![msg]).await.unwrap();
            println!("Valset confirm tx response code {}, tx hash {}", response.code, response.txhash)
        }
    }

    #[tokio::test]
    async fn test_tx_batch_confirm_signature() {
        env_logger::builder().filter_level(Debug).init();
        let eth_private_key = EthPrivateKey::from_str(ETH_PRIVATE_KEY).unwrap();

        let grpc_channel = new_grpc_channel(FX_GRPC_URL).await.unwrap();

        let mut gravity_query_client = GravityQueryClient::new(grpc_channel.clone());

        let response = gravity_query_client.params(QueryParamsRequest {}).await.unwrap();

        let gravity_id = response.into_inner().params.unwrap().gravity_id;
        println!("gravity_id {}", gravity_id);

        let response = gravity_query_client
            .last_pending_batch_request_by_addr(QueryLastPendingBatchRequestByAddrRequest {
                address: "fx16wvwsmpp4y4ttgzknyr6kqla877jud6u04lqey".to_string(),
            })
            .await
            .unwrap();

        let batch = response.into_inner().batch.unwrap();
        // println!("{:?}", batch);
        let message = encode_tx_batch_confirm_hash(gravity_id.clone(), batch.clone());
        let eth_signature = eth_private_key.sign_ethereum_msg(message.as_slice()).unwrap();
        println!("{:x}", eth_signature.to_hash());

        let response = gravity_query_client
            .batch_request_by_nonce(QueryBatchRequestByNonceRequest {
                nonce: batch.batch_nonce,
                contract_address: batch.token_contract,
            })
            .await
            .unwrap();

        let batch = response.into_inner().batch.unwrap();
        // println!("{:?}", batch);
        let message = encode_tx_batch_confirm_hash(gravity_id.clone(), batch.clone());
        let eth_signature = eth_private_key.sign_ethereum_msg(message.as_ref()).unwrap();
        println!("{:x}", eth_signature.to_hash());
    }

    #[test]
    fn test_u256() {
        assert_eq!(U256::from(100), U256::from_dec_str("100").unwrap());
        assert_eq!(U256::from(100), U256::from_str_radix("100", 10).unwrap());
        assert_eq!(U256::from(1), U256::from_str("1").unwrap());
        assert_eq!(U256::from(16), U256::from_str("10").unwrap());
        assert_eq!(U256::from(256), U256::from_str("100").unwrap());
    }

    #[test]
    fn test_eth_signature_recover() {
        let eth_signature_str = "4a212f94464410009949897743de457f592f8226602576f57eb97902857688cf2f3228aa34b9831eb6dfb10d6779186e390a5db39d9157bb7215b80a9d7d8e671b";
        let eth_signature = Signature::from_str(eth_signature_str).unwrap();

        let message_str = "fb8e876ac0d212abcea3ff8975f5ecbebd3c400747496e05e8ea5018d200b66e";
        let message = H256::from_str(message_str).unwrap();
        let message = ethereum_msg_hash(message);
        println!("{:?}", message);

        let address = eth_signature.recover(message.as_bytes()).unwrap();
        println!("{:?}", address); //0x7add5a739B2882B67e60d2e7d0c2E4A825131787
    }

    #[test]
    fn test_eth_private_key() {
        let eth_private_key_str = "7490923dfece4901e603a1a0429ad74327ca574d7033bba145b68dcd00aa7a5d";
        let private_key = EthPrivateKey::from_str(eth_private_key_str).unwrap();
        println!("{}", private_key.address().to_hex_string());
    }

    #[tokio::test]
    async fn test_set_fx_key_balance_metrics() {
        let fx_private_key = FxPrivateKey::from_phrase(FX_MNEMONIC, "").unwrap();
        let fx_address = fx_private_key.public_key().to_address().to_string();
        let grpc_channel = new_grpc_channel(FX_GRPC_URL).await.unwrap();
        let auth_account = get_account_info(&grpc_channel, fx_address.clone()).await.unwrap();
        let fx_chain_id = get_chain_id(&grpc_channel).await.unwrap();
        let fx_builder = Builder::new(fx_chain_id, fx_private_key, auth_account.account_number, "FX");
        set_fx_key_balance_metrics(&fx_builder, &grpc_channel).await
    }
}
