use std::ops::Mul;
use std::str::FromStr;

use tonic::transport::Channel;
use web3::ethabi::{FixedBytes, Token};
use web3::ethabi::Address as EthAddress;
use web3::transports::Http;
use web3::types::U256;
use web3::Web3;

use bridge::singer_loop::encode_tx_batch_confirm_hash;
use ethereum::address::Checksum;
use ethereum::client::check_for_ether;
use ethereum::fx_bridge::FxBridge;
use ethereum::private_key::{Key, PrivateKey as EthPrivateKey};
use fxchain::x::gravity::{QueryBatchConfirmsRequest, QueryOutgoingTxBatchesRequest};
use fxchain::x::gravity::OutgoingTxBatch;
use fxchain::x::gravity::query_client::QueryClient as GravityQueryClient;

use crate::valset::{BatchConfirmResponse, Valset};

pub async fn relay_batches(
    current_valset: Valset,
    eth_private_key: &EthPrivateKey,
    grpc_channel: &Channel,
    web3: &Web3<Http>,
    bridge_addr: EthAddress,
    gravity_id: &String,
) {
    let expect = U256::from(5).mul(U256::from(10).pow(U256::from(17)));
    let is_enough = check_for_ether(&web3, eth_private_key.address(), expect).await;
    if !is_enough {
        error!("There's not enough ether! expect {}", expect);
    }

    let mut gravity_query_client = GravityQueryClient::new(grpc_channel.clone());

    let result = gravity_query_client
        .outgoing_tx_batches(QueryOutgoingTxBatchesRequest {})
        .await;
    if result.is_err() {
        error!("Query outgoing tx batches failed {:?}", result.err());
        return;
    }
    let latest_tx_batches = result.unwrap().into_inner().batches;
    debug!("Latest tx batches len {:?}", latest_tx_batches.len());

    let mut oldest_tx_batch: Option<OutgoingTxBatch> = None;
    let mut oldest_signatures: Option<Vec<BatchConfirmResponse>> = None;
    for latest_tx_batch in latest_tx_batches.iter() {
        let result = gravity_query_client
            .batch_confirms(QueryBatchConfirmsRequest {
                nonce: latest_tx_batch.clone().batch_nonce,
                contract_address: latest_tx_batch.clone().token_contract,
            })
            .await;
        if result.is_err() {
            error!(
                "Query batch confirms from nonce {} and contract {} failed {:?}",
                latest_tx_batch.batch_nonce,
                latest_tx_batch.token_contract,
                result.err()
            );
            continue;
        }
        let confirms = result.unwrap().into_inner().confirms;
        info!(
            "Query batch confirms from nonce {} and contract {} len {}",
            latest_tx_batch.batch_nonce,
            latest_tx_batch.token_contract,
            confirms.len()
        );
        let mut batch_signatures: Vec<BatchConfirmResponse> = Vec::new();
        for confirm in confirms {
            let response = BatchConfirmResponse::from_proto(confirm).unwrap();
            batch_signatures.push(response);
        }
        let hash = encode_tx_batch_confirm_hash(gravity_id.clone(), latest_tx_batch.clone());
        if current_valset
            .order_signatures(hash.as_ref(), &batch_signatures)
            .is_ok()
        {
            oldest_tx_batch = Some(latest_tx_batch.clone());
            oldest_signatures = Some(batch_signatures);
        } else {
            warn!(
                "Batch {}/{} can not be submitted yet, waiting for more signatures",
                latest_tx_batch.token_contract, latest_tx_batch.batch_nonce
            );
        }
    }
    if oldest_tx_batch.is_none() {
        debug!("No signed completed batch withdrawal request was found");
        return;
    }

    let oldest_signed_batch = oldest_tx_batch.unwrap();
    let oldest_signatures = oldest_signatures.unwrap();

    let bridge_contract =
        FxBridge::new(Some(eth_private_key.clone()), None, web3.eth(), bridge_addr);

    let erc20_contract = oldest_signed_batch.clone().token_contract;
    let result = bridge_contract
        .last_batch_nonce(EthAddress::from_str(erc20_contract.as_str()).unwrap())
        .await;

    if result.is_err() {
        error!("Failed to get latest Ethereum batch with {:?}", result.err());
        return;
    }
    let latest_ethereum_batch = result.unwrap();

    let latest_fx_batch_nonce = U256::from(oldest_signed_batch.clone().batch_nonce);

    if latest_fx_batch_nonce > latest_ethereum_batch {
        info!(
            "We have detected latest batch {} but latest on Ethereum is {} to submit",
            latest_fx_batch_nonce, latest_ethereum_batch,
        );

        let mut current_validators = Vec::new();
        let mut current_powers = Vec::new();
        for member in current_valset.members.iter() {
            current_validators.push(Token::Address(member.eth_address));
            current_powers.push(Token::Uint(U256::from(member.power)));
        }

        let mut v = Vec::new();
        let mut r = Vec::new();
        let mut s = Vec::new();
        for member in current_valset.members.iter() {
            let mut found = false;
            for item in oldest_signatures.iter() {
                if item.ethereum_signer.to_hex_string() == member.eth_address.to_hex_string() {
                    v.push(Token::Uint(U256::from(
                        item.eth_signature.v.to_le_bytes()[0],
                    )));
                    r.push(Token::FixedBytes(FixedBytes::from(
                        item.eth_signature.r.as_bytes(),
                    )));
                    s.push(Token::FixedBytes(FixedBytes::from(
                        item.eth_signature.s.as_bytes(),
                    )));
                    found = true;
                    break;
                }
            }
            if !found {
                v.push(Token::Uint(U256::from(0)));
                r.push(Token::FixedBytes(vec![0].repeat(32)));
                s.push(Token::FixedBytes(vec![0].repeat(32)));
            }
        }

        let mut amounts = Vec::new();
        let mut destinations = Vec::new();
        let mut fees = Vec::new();
        for item in oldest_signed_batch.transactions.iter() {
            amounts.push(Token::Uint(
                U256::from_dec_str(item.erc20_token.as_ref().unwrap().amount.as_str()).unwrap(),
            ));
            fees.push(Token::Uint(
                U256::from_dec_str(item.erc20_fee.as_ref().unwrap().amount.as_str()).unwrap(),
            ));
            destinations.push(Token::Address(
                EthAddress::from_str(item.dest_address.as_str()).unwrap(),
            ))
        }

        info!(
            "Submit Batch token contract {}",
            oldest_signed_batch.token_contract
        );
        let result = bridge_contract
            .submit_batch(
                current_validators,
                current_powers,
                v,
                r,
                s,
                amounts,
                destinations,
                fees,
                [U256::from(current_valset.nonce), latest_fx_batch_nonce],
                EthAddress::from_str(oldest_signed_batch.token_contract.as_str()).unwrap(),
                U256::from(oldest_signed_batch.batch_timeout),
                EthAddress::from_str(oldest_signed_batch.fee_receive.as_str()).unwrap(),
            )
            .await;
        match result {
            Ok(receipt) => {
                info!("Submit eth batch tx hash {:?}", receipt.transaction_hash);
            }
            Err(report) => error!("Submit eth batch tx failed {}", report),
        }
    }
}
