use std::convert::TryFrom;
use std::ops::Mul;
use std::str::FromStr;

use cosmos_sdk_proto::cosmos::auth::v1beta1::query_client::QueryClient as AuthQueryClient;
use cosmos_sdk_proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountRequest};
use cosmos_sdk_proto::cosmos::bank::v1beta1::query_client::QueryClient as BankQueryClient;
use cosmos_sdk_proto::cosmos::bank::v1beta1::{QueryAllBalancesRequest, QueryBalanceRequest};
use cosmos_sdk_proto::cosmos::base::abci::v1beta1::GasInfo;
use cosmos_sdk_proto::cosmos::base::abci::v1beta1::TxResponse;
use cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::service_client::ServiceClient as TendermintClient;
use cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetLatestBlockRequest;
use cosmos_sdk_proto::cosmos::base::v1beta1::Coin;
use cosmos_sdk_proto::cosmos::staking::v1beta1::query_client::QueryClient as StakingQueryClient;
use cosmos_sdk_proto::cosmos::staking::v1beta1::QueryValidatorRequest;
use cosmos_sdk_proto::cosmos::tx::v1beta1::service_client::ServiceClient as TxClient;
use cosmos_sdk_proto::cosmos::tx::v1beta1::{BroadcastMode, Tx, TxRaw};
use cosmos_sdk_proto::cosmos::tx::v1beta1::{BroadcastTxRequest, Fee, SimulateRequest};
use eyre::{Error, Result};
use num_bigint::BigInt;
use prost_types::Any;
use tendermint::block;
use tendermint::chain;
use tonic::transport::channel::Channel;
use tonic::transport::{ClientTlsConfig, Endpoint};
use url::Url;

use crate::address::Address as FxAddress;
use crate::builder::Builder;
use crate::proto_ext::{unpack_any, MessageExt};
use crate::x::gravity::query_client::QueryClient as GravityQueryClient;
use crate::x::gravity::{QueryDelegateKeyByOrchestratorRequest, QueryLastEventBlockHeightByAddrRequest, QueryLastEventNonceByAddrRequest, QueryLastObservedEthBlockHeightRequest, QueryParamsRequest};
use crate::x::other::query_client::QueryClient as OtherQueryClient;
use crate::x::other::GasPriceRequest;
use crate::{DEFAULT_GAS_LIMIT, DEFAULT_TX_TIMEOUT_HEIGHT, FX_MSG_MAX_NUMBER, get_gas_price_multiplier, GAS_LIMIT_MULTIPLIER_PRO};

/* ============================== gRPC ============================== */

pub async fn send_tx(builder: &Builder, grpc_channel: &Channel, msgs: Vec<Any>) -> Result<TxResponse> {
    let sequence = builder.get_next_sequence(grpc_channel).await?;

    let mut fee = Fee {
        amount: vec![],
        gas_limit: DEFAULT_GAS_LIMIT,
        payer: Default::default(),
        granter: Default::default(),
    };
    let gas_price = get_gas_price_by_denom(grpc_channel, builder.get_fee_denom()).await?;
    fee.amount = vec![Coin {
        denom: gas_price.denom.clone(),
        amount: BigInt::from_str(gas_price.amount.as_str()).unwrap().mul(fee.gas_limit).to_string(),
    }];

    let timeout_height = block::Height::from(DEFAULT_TX_TIMEOUT_HEIGHT);

    let tx = builder.sign_tx(sequence, msgs.clone(), fee.clone(), timeout_height)?;

    let gas_info = estimating_gas_usage(grpc_channel, tx.clone()).await?;
    debug!("Fx chain tx estimating gas used {}, wanted {}", gas_info.gas_used, gas_info.gas_wanted);

    if msgs.len() >= FX_MSG_MAX_NUMBER {
        fee.gas_limit = (gas_info.gas_used * ((GAS_LIMIT_MULTIPLIER_PRO * 10f64) as u64)) / 10;
    } else {
        fee.gas_limit = (gas_info.gas_used * ((get_gas_price_multiplier() * 10f64) as u64)) / 10;
    }
    fee.amount = vec![Coin {
        denom: gas_price.denom,
        amount: BigInt::from_str(gas_price.amount.as_str()).unwrap().mul(fee.gas_limit).to_string(),
    }];
    debug!("Send fx chain tx gas limit {}, amount {:?}", fee.gas_limit, fee.amount);

    let tx = builder.sign_tx(sequence, msgs, fee, timeout_height)?;

    let tx_raw = TxRaw {
        body_bytes: tx.body.unwrap().to_bytes()?,
        auth_info_bytes: tx.auth_info.unwrap().to_bytes()?,
        signatures: tx.signatures,
    };

    let tx_bytes = tx_raw.to_bytes()?;

    let mut tx_client = TxClient::new(grpc_channel.clone());
    let response = tx_client
        .broadcast_tx(BroadcastTxRequest {
            tx_bytes,
            mode: BroadcastMode::Block as i32,
        })
        .await?;
    let tx_response = response.into_inner().tx_response.unwrap();
    Ok(tx_response)
}

pub async fn new_grpc_channel(grpc_url: &str) -> Result<Channel> {
    let url = Url::parse(grpc_url)?;
    if url.scheme() != "http" && url.scheme() != "https" && url.scheme() != "tcp" {
        return Err(Error::msg(format!("Your url {} has an invalid scheme, please chose http or https", grpc_url)));
    }
    let dst = grpc_url.trim_end_matches('/').to_string();
    let mut endpoint = Endpoint::new(dst)?;
    if url.scheme() == "https" {
        let mut tls_config = ClientTlsConfig::new();
        tls_config = tls_config.domain_name(url.domain().unwrap());
        endpoint = endpoint.tls_config(tls_config)?;
    }
    Ok(endpoint.connect().await?)
}

pub async fn get_account_info(grpc_channel: &Channel, address: String) -> Result<BaseAccount> {
    let mut auth_query_client = AuthQueryClient::new(grpc_channel.clone());

    let response = auth_query_client.account(QueryAccountRequest { address }).await?;
    let account = response.into_inner().account.unwrap();
    let auth_account = unpack_any(account, BaseAccount::default())?;
    Ok(auth_account)
}

pub async fn estimating_gas_usage(grpc_channel: &Channel, tx: Tx) -> Result<GasInfo> {
    let mut tx_client = TxClient::new(grpc_channel.clone());
    let response = tx_client.simulate(SimulateRequest { tx: Some(tx) }).await?;
    let gas_info = response.into_inner().gas_info.unwrap();
    Ok(gas_info)
}

pub async fn get_gas_price(grpc_channel: &Channel) -> Result<Vec<Coin>> {
    let mut other_query_client = OtherQueryClient::new(grpc_channel.clone());
    let response = other_query_client.gas_price(GasPriceRequest {}).await?;
    Ok(response.into_inner().gas_prices)
}

pub async fn get_gas_price_by_denom(grpc_channel: &Channel, denom: String) -> Result<Coin> {
    let gas_prices = get_gas_price(grpc_channel).await?;
    let price = gas_prices.iter().find(|&a| a.denom.eq(&denom));
    if price.is_some() {
        Ok(price.unwrap().clone())
    } else {
        error!("no found gas price by denom: {}", denom);
        Ok(Coin { denom, amount: "0".to_string() })
    }
}

pub async fn check_for_fee_denom(grpc_channel: &Channel, account: FxAddress, fee_denom: &str) {
    let mut bank_query_client = BankQueryClient::new(grpc_channel.clone());
    let response = bank_query_client
        .balance(QueryBalanceRequest {
            address: account.to_string(),
            denom: fee_denom.to_string(),
        })
        .await
        .unwrap();
    let balance = response.into_inner().balance.unwrap();
    let amount = BigInt::from_str(balance.amount.as_str()).unwrap();
    // amount > 1 * 10^18
    if amount.gt(&BigInt::from_str("1000000000000000000").unwrap()) {
        debug!("account {}, balance {}{}", account, balance.amount, fee_denom);
        return;
    }
    panic!("You have specified that fees should be paid in {} but account {} has no balance of that token!", fee_denom, account);
}

pub async fn get_latest_block_height(grpc_channel: &Channel) -> Result<u64> {
    let mut tendermint_client = TendermintClient::new(grpc_channel.clone());
    let result = tendermint_client.get_latest_block(GetLatestBlockRequest {}).await?;
    let response = result.into_inner();
    if let Some(block) = &response.block {
        if block.header.is_some() {
            let height = block.header.as_ref().unwrap().height;
            return Ok(u64::try_from(height).unwrap());
        }
    }
    error!("grpc get latest block failed: {:?}", response);
    Err(Error::msg("grpc get latest block height failed"))
}

pub async fn get_chain_id(grpc_channel: &Channel) -> Result<chain::Id> {
    let mut tendermint_client = TendermintClient::new(grpc_channel.clone());
    let result = tendermint_client.get_latest_block(GetLatestBlockRequest {}).await?;
    let response = result.into_inner();
    if let Some(block) = response.clone().block {
        if block.header.is_some() {
            let chain_id = block.header.unwrap().chain_id;
            return Ok(chain::Id::try_from(chain_id).unwrap());
        }
    }
    error!("grpc get latest block failed: {:?}", response);
    Err(Error::msg("grpc get latest block height failed"))
}

pub async fn get_all_balances(grpc_channel: &Channel, fx_address: FxAddress) -> Result<Vec<Coin>> {
    let mut bank_query_client = BankQueryClient::new(grpc_channel.clone());
    let result = bank_query_client
        .all_balances(QueryAllBalancesRequest {
            address: fx_address.to_string(),
            pagination: None,
        })
        .await?;
    Ok(result.into_inner().balances)
}

pub async fn get_balance(grpc_channel: &Channel, fx_address: FxAddress, denom: String) -> Result<Coin> {
    let mut bank_query_client = BankQueryClient::new(grpc_channel.clone());
    let result = bank_query_client
        .balance(QueryBalanceRequest {
            address: fx_address.to_string(),
            denom: denom.clone(),
        })
        .await?;
    if let Some(balance) = result.into_inner().balance {
        Ok(balance)
    } else {
        Err(Error::msg(format!("no found balance by {}", denom)))
    }
}

/* ===== gravity ===== */

pub async fn get_gravity_id(grpc_channel: &Channel) -> Result<String> {
    let mut gravity_query_client = GravityQueryClient::new(grpc_channel.clone());
    let result = gravity_query_client.params(QueryParamsRequest {}).await?;
    Ok(result.into_inner().params.unwrap().gravity_id)
}

pub async fn get_last_event_nonce(grpc_channel: &Channel, fx_address: FxAddress) -> Result<u64> {
    let mut gravity_query_client = GravityQueryClient::new(grpc_channel.clone());
    let result = gravity_query_client
        .last_event_nonce_by_addr(QueryLastEventNonceByAddrRequest { address: fx_address.to_string() })
        .await?;
    Ok(result.into_inner().event_nonce)
}

pub async fn get_last_event_block_height_by_addr(grpc_channel: &Channel, fx_address: FxAddress) -> Result<u64> {
    let mut gravity_query_client = GravityQueryClient::new(grpc_channel.clone());
    let result = gravity_query_client
        .last_event_block_height_by_addr(QueryLastEventBlockHeightByAddrRequest { address: fx_address.to_string() })
        .await?;
    Ok(result.into_inner().block_height)
}

pub async fn get_last_eth_block_height(grpc_channel: &Channel) -> Result<u64> {
    let mut gravity_query_client = GravityQueryClient::new(grpc_channel.clone());
    let result = gravity_query_client.last_observed_eth_block_height(QueryLastObservedEthBlockHeightRequest {}).await?;
    Ok(result.into_inner().block_height)
}

pub async fn get_orchestrator_validator(grpc_channel: &Channel, fx_address: FxAddress) -> Result<String> {
    let mut gravity_query_client = GravityQueryClient::new(grpc_channel.clone());
    let result = gravity_query_client
        .get_delegate_key_by_orchestrator(QueryDelegateKeyByOrchestratorRequest {
            orchestrator_address: fx_address.to_string(),
        })
        .await?;
    Ok(result.into_inner().validator_address)
}

pub async fn get_orchestrator_validator_status(grpc_channel: &Channel, fx_address: FxAddress) -> Result<(i32, String)> {
    let mut gravity_query_client = GravityQueryClient::new(grpc_channel.clone());
    let result = gravity_query_client
        .get_delegate_key_by_orchestrator(QueryDelegateKeyByOrchestratorRequest {
            orchestrator_address: fx_address.to_string(),
        })
        .await?;
    let orchestrator = result.into_inner();
    let mut staking_query_client = StakingQueryClient::new(grpc_channel.clone());
    let result = staking_query_client
        .validator(QueryValidatorRequest {
            validator_addr: orchestrator.validator_address,
        })
        .await?;
    let val = result.into_inner().validator;
    if val.is_none() {
        return Err(eyre::Error::msg("no found validator"));
    }
    return Ok((val.unwrap().status, orchestrator.eth_address));
}

#[cfg(test)]
mod tests {
    use std::ops::Div;

    use crate::grpc_client::{get_account_info, new_grpc_channel};
    use crate::private_key::PrivateKey;
    use crate::x::gravity::MsgSetOrchestratorAddress;

    use super::*;

    const FX_MNEMONIC: &str = "";
    const FX_GRPC_URL: &str = "http://127.0.0.1:9090";

    #[tokio::test]
    async fn test_update_gravity_delegate_addresses() {
        let fx_private_key = PrivateKey::from_phrase(FX_MNEMONIC, "").unwrap();
        let fx_address = fx_private_key.public_key().to_address().to_string();
        let grpc_channel = new_grpc_channel(FX_GRPC_URL).await.unwrap();
        let auth_account = get_account_info(&grpc_channel, fx_address).await.unwrap();
        let fx_chain_id = get_chain_id(&grpc_channel).await.unwrap();
        let fx_builder = Builder::new(fx_chain_id, fx_private_key, auth_account.account_number, "FX");

        let msg = MsgSetOrchestratorAddress {
            validator: fx_builder.address().to_valoper().unwrap(),
            orchestrator: String::from("fx1zgpzdf2uqla7hkx85wnn4p2r3duwqzd8xst6v2"),
            eth_address: String::from("0xeAD9C93b79Ae7C1591b1FB5323BD777E86e150d4"),
        };
        let message = msg.to_any("/fx.gravity.v1.MsgSetOrchestratorAddress");

        let tx_response = send_tx(&fx_builder, &grpc_channel, vec![message]).await.unwrap();
        // println!("{:#?}", tx_response)
        println!("code: {}, info: {}, tx hash: {}", tx_response.code, tx_response.info, tx_response.txhash)
    }

    #[tokio::test]
    async fn test_get_account_info() {
        let private_key = PrivateKey::from_phrase(FX_MNEMONIC, "").unwrap();
        let fx_address = private_key.public_key().to_address().to_string();
        let grpc_channel = new_grpc_channel(FX_GRPC_URL).await.unwrap();
        let auth_account = get_account_info(&grpc_channel, fx_address).await.unwrap();
        assert_eq!(0u64, auth_account.account_number);
        // println!("account info: {:?}", auth_account);
        println!("account info: {}, number: {}, sequence: {}", auth_account.address, auth_account.account_number, auth_account.sequence);
    }

    #[tokio::test]
    async fn test_new_grpc_channel() {
        let grpc_channel = new_grpc_channel(FX_GRPC_URL).await.unwrap();
        assert_eq!("Channel", format!("{:?}", grpc_channel));
    }

    #[tokio::test]
    async fn test_check_for_fee_denom() {
        env_logger::builder().filter_module("fxchain::client", log::LevelFilter::Trace).init();
        let grpc_channel = new_grpc_channel("tcp://127.0.0.1:9090").await.unwrap();
        let private_key = PrivateKey::from_phrase(FX_MNEMONIC, "").unwrap();
        let fx_address = private_key.public_key().to_address();
        check_for_fee_denom(&grpc_channel, fx_address, "FX").await;
    }

    #[tokio::test]
    async fn test_get_chain_id() {
        let grpc_channel = new_grpc_channel(FX_GRPC_URL).await.unwrap();
        let chain_id = get_chain_id(&grpc_channel).await.unwrap();
        println!("{}", chain_id);
        assert_eq!(chain_id.to_string(), "fxcore".to_string())
    }

    #[tokio::test]
    async fn test_get_last_event_nonce() {
        let grpc_channel = new_grpc_channel("tcp://127.0.0.1:9090").await.unwrap();

        let private_key = PrivateKey::from_phrase(FX_MNEMONIC, "").unwrap();
        let fx_address = private_key.public_key().to_address();

        let result = get_last_event_nonce(&grpc_channel, fx_address).await;
        match result {
            Ok(nonce) => println!("{}", nonce),
            Err(e) => println!("{}", e),
        };
    }

    #[tokio::test]
    async fn test_get_gas_price_by_denom() {
        let grpc_channel = new_grpc_channel("tcp://127.0.0.1:9090").await.unwrap();
        let gas_price = get_gas_price_by_denom(&grpc_channel, "FX".to_string()).await.unwrap();
        println!("{}, {}", gas_price.amount, gas_price.denom);
        println!("{}", BigInt::from_str(gas_price.amount.as_str()).unwrap().div(BigInt::from(10).pow(18)));
        println!("{}", BigInt::from_str(gas_price.amount.as_str()).unwrap().to_string());
        println!("{}", BigInt::from_str(gas_price.amount.as_str()).unwrap().mul(DEFAULT_GAS_LIMIT).to_string())
    }
}
