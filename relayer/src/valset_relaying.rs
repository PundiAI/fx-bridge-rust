use std::ops::Mul;
use std::str::FromStr;

use tonic::transport::Channel;
use web3::ethabi::{FixedBytes, Token};
use web3::transports::Http;
use web3::types::{Address as EthAddress, U256};
use web3::Web3;

use bridge::singer_loop::encode_valset_confirm_hash;
use ethereum::address::Checksum;
use ethereum::client::check_for_ether;
use ethereum::fx_bridge::FxBridge;
use ethereum::private_key::{Key, PrivateKey as EthPrivateKey};
use fxchain::x::gravity::query_client::QueryClient as GravityQueryClient;
use fxchain::x::gravity::QueryLastValsetRequestsRequest;
use fxchain::x::gravity::{QueryValsetConfirmsByNonceRequest, QueryValsetRequestRequest};

use crate::valset::{Valset, ValsetConfirmResponse};

pub async fn relay_valsets(current_valset: Valset, eth_private_key: &EthPrivateKey, web3: &Web3<Http>, grpc_channel: &Channel, bridge_addr: EthAddress, gravity_id: &String) {
    let expect = U256::from(5).mul(U256::from(10).pow(U256::from(17)));
    let is_enough = check_for_ether(&web3, eth_private_key.address(), expect).await;
    if !is_enough {
        error!("There's not enough ether! expect {}", expect);
    }

    let mut gravity_query_client = GravityQueryClient::new(grpc_channel.clone());

    let result = gravity_query_client.last_valset_requests(QueryLastValsetRequestsRequest {}).await;
    if result.is_err() {
        error!("Failed to get last valsets from fx chain {:?}", result.err());
        return;
    }
    let last_valsets = result.unwrap().into_inner().valsets;
    if last_valsets.is_empty() {
        error!("The last valset on the fx chain is empty!!!");
        return;
    }

    let mut latest_nonce = last_valsets[0].nonce;
    if latest_nonce == current_valset.nonce {
        debug!("There is no valset update on the fx chain, {:?}", last_valsets.len());
        return;
    }
    if latest_nonce < current_valset.nonce {
        error!("Latest nonce less than current valset nonce, {:?} < {:?}", latest_nonce, current_valset);
        return;
    }

    info!("Found last valset update nonce {}, current valset nonce {}", latest_nonce, current_valset.nonce);

    let mut latest_confirmed = None;
    let mut latest_valset = None;
    while latest_nonce > 0 {
        let result = gravity_query_client.valset_request(QueryValsetRequestRequest { nonce: latest_nonce }).await;
        if result.is_err() {
            error!("Query valset request from nonce {} failed {:?}", latest_nonce, result.err());
            return;
        }
        if let Some(valset) = result.unwrap().into_inner().valset {
            info!("Query valset request from nonce {} success, height {}", valset.nonce, valset.height);
            let result = gravity_query_client.valset_confirms_by_nonce(QueryValsetConfirmsByNonceRequest { nonce: latest_nonce }).await;
            if result.is_err() {
                error!("Query valset confirm from nonce {} failed {:?}", latest_nonce, result.err());
                return;
            }
            let valset_confirms = result.unwrap().into_inner().confirms;
            if !valset_confirms.is_empty() {
                info!("Query valset confirm from nonce {} len {}", latest_nonce, valset_confirms.len());
                let mut confirms = Vec::new();
                for item in valset_confirms {
                    let response = ValsetConfirmResponse::from_proto(item).unwrap();
                    assert_eq!(valset.nonce, response.nonce);
                    confirms.push(response)
                }

                let message = encode_valset_confirm_hash(gravity_id.clone(), valset.clone());
                let result = current_valset.order_signatures(message.as_slice(), &confirms);
                if result.is_ok() {
                    latest_confirmed = Some(confirms);
                    latest_valset = Some(valset);
                    break;
                } else {
                    info!("Check valset confirm failed {:?}", result.err());
                }
            }
        }
        latest_nonce -= 1
    }

    if latest_confirmed.is_none() || latest_valset.is_none() {
        error!("We don't have a latest confirmed valset?");
        return;
    }

    let latest_fx_confirmed = latest_confirmed.unwrap();

    let latest_fx_valset = latest_valset.unwrap();

    if latest_fx_valset.nonce > current_valset.nonce {
        let mut new_validators = Vec::new();
        let mut new_powers = Vec::new();
        let new_valset_nonce = U256::from(latest_fx_valset.nonce);
        for item in latest_fx_valset.members {
            new_validators.push(Token::Address(EthAddress::from_str(item.eth_address.as_str()).unwrap()));
            new_powers.push(Token::Uint(U256::from(item.power)));
        }

        let mut current_validators = Vec::new();
        let mut current_powers = Vec::new();
        let current_valset_nonce = U256::from(current_valset.nonce);
        for item in current_valset.members.iter() {
            current_validators.push(Token::Address(item.eth_address));
            current_powers.push(Token::Uint(U256::from(item.power)));
        }

        let mut v = Vec::new();
        let mut r = Vec::new();
        let mut s = Vec::new();
        for member in current_valset.members {
            let mut found = false;
            for item in latest_fx_confirmed.iter() {
                if item.eth_address.to_hex_string() == member.eth_address.to_hex_string() {
                    v.push(Token::Uint(U256::from(item.eth_signature.v.to_le_bytes()[0])));
                    r.push(Token::FixedBytes(FixedBytes::from(item.eth_signature.r.as_bytes())));
                    s.push(Token::FixedBytes(FixedBytes::from(item.eth_signature.s.as_bytes())));
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

        let bridge_contract = FxBridge::new(Some(eth_private_key.clone()), None, web3.eth(), bridge_addr);
        let result = bridge_contract
            .update_valset(new_validators, new_powers, new_valset_nonce, current_validators, current_powers, current_valset_nonce, v, r, s)
            .await;
        match result {
            Ok(receipt) => {
                info!("Update eth valset tx hash {:?}", receipt.transaction_hash);
            }
            Err(report) => error!("Update eth valset tx failed {}", report),
        }
    }
}

#[cfg(test)]
mod tests {
    use log::LevelFilter::Debug;

    use fxchain::grpc_client::new_grpc_channel;
    use fxchain::x::gravity::QueryParamsRequest;

    use super::*;

    const FX_GRPC_URL: &str = "http://127.0.0.1:9090";

    #[tokio::test]
    async fn test_valset_confirm_signature() {
        env_logger::builder().filter_level(Debug).init();

        let grpc_channel = new_grpc_channel(FX_GRPC_URL).await.unwrap();

        let mut gravity_query_client = GravityQueryClient::new(grpc_channel.clone());

        let response = gravity_query_client.params(QueryParamsRequest {}).await.unwrap();

        let gravity_id = response.into_inner().params.unwrap().gravity_id;

        let response = gravity_query_client.last_valset_requests(QueryLastValsetRequestsRequest {}).await.unwrap();

        let latest_nonce = response.into_inner().valsets[0].nonce;

        let response = gravity_query_client.valset_request(QueryValsetRequestRequest { nonce: latest_nonce }).await.unwrap();

        for valset in response.into_inner().valset.iter() {
            let response = gravity_query_client.valset_confirms_by_nonce(QueryValsetConfirmsByNonceRequest { nonce: latest_nonce }).await.unwrap();

            let mut confirms = Vec::new();
            for item in response.into_inner().confirms.iter() {
                let response = ValsetConfirmResponse::from_proto(item.clone()).unwrap();
                // info!("msg valset confirm {:?}", item);
                info!("ValsetConfirmResponse {:?}", response);
                confirms.push(response)
            }
            // let hash = encode_valset_confirm_hash(gravity_id.clone(), valset.clone());
            // let result = valset.order_signatures(hash.as_bytes(), &confirms);
            // info!("signature result {:?}", result)
        }
    }
}
