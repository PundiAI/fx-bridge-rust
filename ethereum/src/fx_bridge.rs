use std::fmt::Debug;
use std::time;

use eyre::Result;
use sha3::{Digest, Keccak256};
use web3::api::{Eth, Namespace};
use web3::contract::{Contract, Options};
use web3::contract::tokens::Tokenize;
use web3::ethabi::{Contract as ContractABI, Token};
use web3::ethabi::Hash;
use web3::signing::Key;
use web3::transports::Http;
use web3::types::{Address, BlockId, BlockNumber, Bytes, CallRequest, TransactionParameters, U256, U64};
use web3::types::{FilterBuilder, Log, TransactionReceipt};
use web3::Web3;

use crate::confirm_tx::send_raw_transaction_with_confirmation;
use crate::gas_price::get_max_gas_price;
use crate::private_key::PrivateKey;
use crate::TX_CONFIRMATIONS_BLOCK_NUMBER;

const FX_BRIDGE_ABI: &str = r#"[{"inputs":[{"internalType":"bytes32","name":"_fxBridgeId","type":"bytes32"},{"internalType":"uint256","name":"_powerThreshold","type":"uint256"},{"internalType":"address[]","name":"_validators","type":"address[]"},{"internalType":"uint256[]","name":"_powers","type":"uint256[]"}],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"_tokenContract","type":"address"},{"indexed":false,"internalType":"string","name":"_name","type":"string"},{"indexed":false,"internalType":"string","name":"_symbol","type":"string"},{"indexed":false,"internalType":"uint8","name":"_decimals","type":"uint8"},{"indexed":false,"internalType":"uint256","name":"_eventNonce","type":"uint256"}],"name":"FxOriginatedTokenEvent","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"_tokenContract","type":"address"},{"indexed":true,"internalType":"address","name":"_sender","type":"address"},{"indexed":true,"internalType":"bytes32","name":"_destination","type":"bytes32"},{"indexed":false,"internalType":"bytes32","name":"_targetIBC","type":"bytes32"},{"indexed":false,"internalType":"uint256","name":"_amount","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"_eventNonce","type":"uint256"}],"name":"SendToFxEvent","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint256","name":"_batchNonce","type":"uint256"},{"indexed":true,"internalType":"address","name":"_token","type":"address"},{"indexed":false,"internalType":"uint256","name":"_eventNonce","type":"uint256"}],"name":"TransactionBatchExecutedEvent","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint256","name":"_newValsetNonce","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"_eventNonce","type":"uint256"},{"indexed":false,"internalType":"address[]","name":"_validators","type":"address[]"},{"indexed":false,"internalType":"uint256[]","name":"_powers","type":"uint256[]"}],"name":"ValsetUpdatedEvent","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"_tokenContract","type":"address"},{"indexed":false,"internalType":"address","name":"_newOwner","type":"address"}],"name":"transferOwnerEvent","type":"event"},{"inputs":[{"internalType":"address","name":"_tokenAddr","type":"address"}],"name":"addBridgeToken","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"bridgeTokens","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_tokenAddr","type":"address"}],"name":"checkAssetStatus","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address[]","name":"_currentValidators","type":"address[]"},{"internalType":"uint256[]","name":"_currentPowers","type":"uint256[]"},{"internalType":"uint8[]","name":"_v","type":"uint8[]"},{"internalType":"bytes32[]","name":"_r","type":"bytes32[]"},{"internalType":"bytes32[]","name":"_s","type":"bytes32[]"},{"internalType":"bytes32","name":"_theHash","type":"bytes32"},{"internalType":"uint256","name":"_powerThreshold","type":"uint256"}],"name":"checkValidatorSignatures","outputs":[],"stateMutability":"pure","type":"function"},{"inputs":[{"internalType":"address","name":"_tokenAddr","type":"address"}],"name":"delBridgeToken","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"getBridgeTokenList","outputs":[{"components":[{"internalType":"address","name":"addr","type":"address"},{"internalType":"string","name":"name","type":"string"},{"internalType":"string","name":"symbol","type":"string"},{"internalType":"uint8","name":"decimals","type":"uint8"}],"internalType":"struct FxBridge.BridgeToken[]","name":"","type":"tuple[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_erc20Address","type":"address"}],"name":"lastBatchNonce","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address[]","name":"_validators","type":"address[]"},{"internalType":"uint256[]","name":"_powers","type":"uint256[]"},{"internalType":"uint256","name":"_valsetNonce","type":"uint256"},{"internalType":"bytes32","name":"_fxBridgeId","type":"bytes32"}],"name":"makeCheckpoint","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"pure","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_tokenContract","type":"address"},{"internalType":"bytes32","name":"_destination","type":"bytes32"},{"internalType":"bytes32","name":"_targetIBC","type":"bytes32"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"sendToFx","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_tokenAddr","type":"address"}],"name":"setFxOriginatedToken","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"state_fxBridgeId","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"state_fxOriginatedToken","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"state_lastBatchNonces","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"state_lastEventNonce","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"state_lastValsetCheckpoint","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"state_lastValsetNonce","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"state_powerThreshold","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address[]","name":"_currentValidators","type":"address[]"},{"internalType":"uint256[]","name":"_currentPowers","type":"uint256[]"},{"internalType":"uint8[]","name":"_v","type":"uint8[]"},{"internalType":"bytes32[]","name":"_r","type":"bytes32[]"},{"internalType":"bytes32[]","name":"_s","type":"bytes32[]"},{"internalType":"uint256[]","name":"_amounts","type":"uint256[]"},{"internalType":"address[]","name":"_destinations","type":"address[]"},{"internalType":"uint256[]","name":"_fees","type":"uint256[]"},{"internalType":"uint256[2]","name":"_nonceArray","type":"uint256[2]"},{"internalType":"address","name":"_tokenContract","type":"address"},{"internalType":"uint256","name":"_batchTimeout","type":"uint256"},{"internalType":"address","name":"_feeReceive","type":"address"}],"name":"submitBatch","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_token","type":"address"},{"internalType":"address","name":"_newOwner","type":"address"}],"name":"transferOwner","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address[]","name":"_newValidators","type":"address[]"},{"internalType":"uint256[]","name":"_newPowers","type":"uint256[]"},{"internalType":"uint256","name":"_newValsetNonce","type":"uint256"},{"internalType":"address[]","name":"_currentValidators","type":"address[]"},{"internalType":"uint256[]","name":"_currentPowers","type":"uint256[]"},{"internalType":"uint256","name":"_currentValsetNonce","type":"uint256"},{"internalType":"uint8[]","name":"_v","type":"uint8[]"},{"internalType":"bytes32[]","name":"_r","type":"bytes32[]"},{"internalType":"bytes32[]","name":"_s","type":"bytes32[]"}],"name":"updateValset","outputs":[],"stateMutability":"nonpayable","type":"function"}]"#;

#[derive(Debug, Clone)]
pub struct FxBridge {
    eth: Eth<Http>,
    contract: Contract<Http>,
    options: Options,
    private_key: Option<PrivateKey>,
    from: Address,
}

impl FxBridge {
    pub fn new(private_key: Option<PrivateKey>, options: Option<Options>, eth: Eth<Http>, address: Address) -> Self {
        let abi: ContractABI = serde_json::from_str(FX_BRIDGE_ABI).expect("invalid FxBridge abi");
        let contract = Contract::new(eth.clone(), address, abi);
        let options = if options.is_some() { options.unwrap() } else { Options::default() };
        let (private_key, from) = if private_key.is_some() {
            (private_key.clone(), private_key.unwrap().address())
        } else {
            (None, Address::default())
        };
        FxBridge {
            eth,
            contract,
            options,
            private_key,
            from,
        }
    }
    ///"Calls the contract's `state_fxOriginatedToken` () function"
    pub async fn fx_originated_token(&self) -> Result<Address> {
        let result = self
            .contract
            .query("state_fxOriginatedToken", (), self.from, self.options.clone(), BlockId::Number(BlockNumber::Latest))
            .await?;
        Ok(result)
    }
    ///"Calls the contract's `bridgeTokens` (0x70e5a898) function"
    pub async fn bridge_tokens(&self, index: U256) -> Result<Address> {
        let result = self
            .contract
            .query("bridgeTokens", index, self.from, self.options.clone(), BlockId::Number(BlockNumber::Latest))
            .await?;
        Ok(result)
    }
    ///"Calls the contract's `checkAssetStatus` () function"
    pub async fn check_asset_status(&self, token_addr: Address) -> Result<bool> {
        let result = self
            .contract
            .query("checkAssetStatus", token_addr, self.from, self.options.clone(), BlockId::Number(BlockNumber::Latest))
            .await?;
        Ok(result)
    }
    ///"Calls the contract's `lastBatchNonce` (0x011b2174) function"
    pub async fn last_batch_nonce(&self, erc20_address: Address) -> Result<U256> {
        let result = self
            .contract
            .query("lastBatchNonce", erc20_address, self.from, self.options.clone(), BlockId::Number(BlockNumber::Latest))
            .await?;
        Ok(result)
    }
    ///"Calls the contract's `makeCheckpoint` (0x71cbf381) function"
    pub async fn make_checkpoint(&self, validators: Vec<Address>, powers: Vec<U256>, valset_nonce: U256, fx_bridge_id: [u8; 32]) -> Result<[u8; 32]> {
        let result = self
            .contract
            .query(
                "makeCheckpoint",
                (validators, powers, valset_nonce, fx_bridge_id),
                self.from,
                self.options.clone(),
                BlockId::Number(BlockNumber::Latest),
            )
            .await?;
        Ok(result)
    }
    ///"Calls the contract's `owner` (0x8da5cb5b) function"
    pub async fn owner(&self) -> Result<Address> {
        let result = self.contract.query("owner", (), self.from, self.options.clone(), BlockId::Number(BlockNumber::Latest)).await?;
        Ok(result)
    }
    ///"Calls the contract's `state_fxBridgeId` (0xf92367fd) function"
    pub async fn state_fx_bridge_id(&self) -> Result<[u8; 32]> {
        let result = self
            .contract
            .query("state_fxBridgeId", (), self.from, self.options.clone(), BlockId::Number(BlockNumber::Latest))
            .await?;
        Ok(result)
    }
    ///"Calls the contract's `state_invalidationMapping` (0x7dfb6f86) function"
    pub async fn state_invalidation_mapping(&self, bytes: [u8; 32]) -> Result<U256> {
        let result = self
            .contract
            .query("state_invalidationMapping", bytes, self.from, self.options.clone(), BlockId::Number(BlockNumber::Latest))
            .await?;
        Ok(result)
    }
    ///"Calls the contract's `state_lastBatchNonces` (0xdf97174b) function"
    pub async fn state_last_batch_nonces(&self, address: Address) -> Result<U256> {
        let result = self
            .contract
            .query("state_lastBatchNonces", address, self.from, self.options.clone(), BlockId::Number(BlockNumber::Latest))
            .await?;
        Ok(result)
    }
    /// "Calls the contract's `state_lastEventNonce` (0x73b20547) function"
    pub async fn state_last_event_nonce(&self) -> Result<U256> {
        let result = self
            .contract
            .query("state_lastEventNonce", (), self.from, self.options.clone(), BlockId::Number(BlockNumber::Latest))
            .await?;
        Ok(result)
    }
    ///"Calls the contract's `state_lastValsetCheckpoint` (0xf2b53307) function"
    pub async fn state_last_valset_checkpoint(&self) -> Result<[u8; 32]> {
        let result = self
            .contract
            .query("state_lastValsetCheckpoint", (), self.from, self.options.clone(), BlockId::Number(BlockNumber::Latest))
            .await?;
        Ok(result)
    }
    /// "Calls the contract's `state_lastValsetNonce` (0xb56561fe) function"
    pub async fn state_last_valset_nonce(&self) -> Result<U256> {
        let result = self
            .contract
            .query("state_lastValsetNonce", (), self.from, self.options.clone(), BlockId::Number(BlockNumber::Latest))
            .await?;
        Ok(result)
    }
    /// "Calls the contract's `state_powerThreshold` (0xe5a2b5d2) function"
    pub async fn state_power_threshold(&self) -> Result<U256> {
        let result = self
            .contract
            .query("state_powerThreshold", (), self.from, self.options.clone(), BlockId::Number(BlockNumber::Latest))
            .await?;
        Ok(result)
    }
    ///"Calls the contract's `checkValidatorSignatures` (0xea10bb20) function"
    pub async fn check_validator_signatures(
        &self,
        current_validators: Vec<Address>,
        current_powers: Vec<U256>,
        v: Vec<u8>,
        r: Vec<[u8; 32]>,
        s: Vec<[u8; 32]>,
        the_hash: [u8; 32],
        power_threshold: U256,
    ) -> Result<Vec<u8>> {
        let result = self
            .contract
            .query(
                "checkValidatorSignatures",
                (current_validators, current_powers, v, r, s, the_hash, power_threshold),
                self.from,
                self.options.clone(),
                BlockId::Number(BlockNumber::Latest),
            )
            .await?;
        Ok(result)
    }
    ///"Calls the contract's `sendToFx` (0xd593c5bf) function"
    pub async fn send_to_fx(&self, token_contract: Address, destination: [u8; 32], target_ibc: [u8; 32], amount: U256) -> Result<TransactionReceipt> {
        let transaction_receipt = self
            .signed_call_with_confirmations("sendToFx", (token_contract, destination, target_ibc, amount), TX_CONFIRMATIONS_BLOCK_NUMBER)
            .await?;
        Ok(transaction_receipt)
    }
    ///"Calls the contract's `submitBatch` function"
    pub async fn submit_batch(
        &self,
        current_validators: Vec<Token>,
        current_powers: Vec<Token>,
        v: Vec<Token>,
        r: Vec<Token>,
        s: Vec<Token>,
        amounts: Vec<Token>,
        destinations: Vec<Token>,
        fees: Vec<Token>,
        nonce_array: [U256; 2],
        token_contract: Address,
        batch_timeout: U256,
        fee_receive: Address,
    ) -> Result<TransactionReceipt> {
        let transaction_receipt = self
            .signed_call_with_confirmations(
                "submitBatch",
                (
                    current_validators,
                    current_powers,
                    v,
                    r,
                    s,
                    amounts,
                    destinations,
                    fees,
                    nonce_array,
                    token_contract,
                    batch_timeout,
                    fee_receive,
                ),
                TX_CONFIRMATIONS_BLOCK_NUMBER,
            )
            .await?;
        Ok(transaction_receipt)
    }
    ///"Calls the contract's `updateValset` (0xe3cb9f62) function"
    pub async fn update_valset(
        &self,
        new_validators: Vec<Token>,
        new_powers: Vec<Token>,
        new_valset_nonce: U256,
        current_validators: Vec<Token>,
        current_powers: Vec<Token>,
        current_valset_nonce: U256,
        v: Vec<Token>,
        r: Vec<Token>,
        s: Vec<Token>,
    ) -> Result<TransactionReceipt> {
        let transaction_receipt = self
            .signed_call_with_confirmations(
                "updateValset",
                (new_validators, new_powers, new_valset_nonce, current_validators, current_powers, current_valset_nonce, v, r, s),
                TX_CONFIRMATIONS_BLOCK_NUMBER,
            )
            .await?;
        Ok(transaction_receipt)
    }

    pub async fn signed_call_with_confirmations(&self, func: &str, params: impl Tokenize, confirmations: usize) -> Result<TransactionReceipt> {
        if self.private_key.is_none() {
            return Err(eyre::Error::msg("no private key to authorize the transaction with"));
        }
        info!("signed_call_with_confirmations: {}", func);
        let poll_interval = time::Duration::from_secs(10);
        let fn_data = self
            .contract
            .abi()
            .function(func)
            .and_then(|function| function.encode_input(&params.into_tokens()))
            .map_err(|err| web3::Error::Decoder(format!("{:?}", err)))?;

        let accounts = web3::api::Accounts::new(self.eth.transport().clone());
        let mut tx = TransactionParameters {
            to: Some(self.contract.address()),
            data: Bytes(fn_data),
            ..Default::default()
        };
        tx.nonce = Some(self.options.nonce.unwrap_or(self.eth.transaction_count(self.from, Some(BlockNumber::Latest)).await?));
        tx.value = self.options.value.unwrap_or(U256::from(0));
        let block = self.eth.block(BlockId::Number(BlockNumber::Latest)).await?.ok_or(eyre::Error::msg("invalid block"))?;
        let gas_price = self.eth.gas_price().await?;
        let max_gas_price = get_max_gas_price();
        if gas_price > max_gas_price {
            return Err(eyre::Error::msg(format!("gas price {} > mas gas price {}", gas_price, max_gas_price)));
        }
        if block.base_fee_per_gas.is_some() && self.options.gas_price.is_none() {
            // tx.max_priority_fee_per_gas = Some(self.options.max_priority_fee_per_gas.unwrap_or(self.eth.gas_price().await? - block.base_fee_per_gas.unwrap()));
            tx.max_priority_fee_per_gas = Some(self.options.max_priority_fee_per_gas.unwrap_or( U256::from(10).pow(U256::from(8)) * 12));
            // tx.max_fee_per_gas = Some(self.options.max_fee_per_gas.unwrap_or(block.base_fee_per_gas.unwrap() * 2 + tx.max_priority_fee_per_gas.unwrap()));
            tx.max_fee_per_gas = Some(self.options.max_fee_per_gas.unwrap_or(gas_price + U256::from(10).pow(U256::from(9)) * 10));
            if tx.max_fee_per_gas.cmp(&tx.max_priority_fee_per_gas).is_le() {
                return Err(eyre::Error::msg(format!(
                    "maxFeePerGas ({:?}) < maxPriorityFeePerGas ({:?})",
                    tx.max_fee_per_gas, tx.max_priority_fee_per_gas
                )));
            }
            tx.transaction_type = Some(U64::from(2));
        } else {
            if self.options.max_fee_per_gas.is_some() || self.options.max_priority_fee_per_gas.is_some() {
                return Err(eyre::Error::msg("maxFeePerGas or maxPriorityFeePerGas specified but london is not active yet"));
            }
            tx.gas_price = Some(self.options.gas_price.unwrap_or(gas_price));
            tx.transaction_type = Some(U64::from(1));
        }
        tx.gas = self.options.gas.unwrap_or(self.estimate_gas(&tx).await?);

        let key = self.private_key.clone().unwrap();
        let signed = accounts.sign_transaction(tx.clone(), key).await?;
        let receipt = send_raw_transaction_with_confirmation(self.eth.transport().clone(), signed.raw_transaction, poll_interval, confirmations).await?;
        return Ok(receipt);
    }

    pub async fn estimate_gas(&self, tx: &TransactionParameters) -> Result<U256> {
        self.eth
            .estimate_gas(
                CallRequest {
                    from: Some(self.from),
                    to: tx.to,
                    gas: None,
                    gas_price: tx.gas_price,
                    value: Some(tx.value),
                    data: Some(tx.data.clone()),
                    transaction_type: tx.transaction_type,
                    access_list: tx.access_list.clone(),
                    max_fee_per_gas: tx.max_fee_per_gas,
                    max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
                },
                None,
            )
            .await
            .map_err(Into::into)
    }
}

pub async fn query_all_event_san_block(
    web3: &Web3<Http>,
    bridge_addr: Address,
    block_height: U64,
) -> Result<(Vec<SendToFxEvent>, Vec<TransactionBatchExecutedEvent>, Vec<FxOriginatedTokenEvent>, Vec<ValsetUpdatedEvent>)> {
    let mut deposits = Vec::new();
    let mut withdraws = Vec::new();
    let mut fx_originated_token = Vec::new();
    let mut valset_updated = Vec::new();

    let block_id = web3::types::BlockId::from(block_height);
    let block_txs = web3.eth().block_with_txs(block_id).await?;
    if block_txs.is_some() {
        let block = block_txs.unwrap();
        for tx in block.transactions {
            let tx_receipt = web3.eth().transaction_receipt(tx.hash).await?;
            if tx_receipt.is_none() {
                continue;
            }
            for log in tx_receipt.unwrap().logs {
                if log.address != bridge_addr {
                    continue;
                }
                for topic in &log.topics {
                    if topic.eq(&SendToFxEvent::signature()) {
                        deposits.push(SendToFxEvent::from_log(&log)?)
                    } else if topic.eq(&TransactionBatchExecutedEvent::signature()) {
                        withdraws.push(TransactionBatchExecutedEvent::from_log(&log)?)
                    } else if topic.eq(&FxOriginatedTokenEvent::signature()) {
                        fx_originated_token.push(FxOriginatedTokenEvent::from_log(&log)?)
                    } else if topic.eq(&ValsetUpdatedEvent::signature()) {
                        valset_updated.push(ValsetUpdatedEvent::from_log(&log)?)
                    }
                }
            }
        }
    }
    Ok((deposits, withdraws, fx_originated_token, valset_updated))
}

pub async fn query_all_event(
    web3: &Web3<Http>,
    bridge_addr: Address,
    from_block: U64,
    to_block: Option<U64>,
) -> Result<(Vec<SendToFxEvent>, Vec<TransactionBatchExecutedEvent>, Vec<FxOriginatedTokenEvent>, Vec<ValsetUpdatedEvent>)> {
    let to_block = if to_block.is_some() { BlockNumber::Number(to_block.unwrap()) } else { BlockNumber::Latest };
    let filter_builder = FilterBuilder::default()
        .address(vec![bridge_addr])
        .from_block(BlockNumber::Number(from_block))
        .to_block(to_block)
        .topics(
            Option::from(vec![
                SendToFxEvent::signature(),
                TransactionBatchExecutedEvent::signature(),
                FxOriginatedTokenEvent::signature(),
                ValsetUpdatedEvent::signature(),
            ]),
            None,
            None,
            None,
        );
    let logs = web3.eth().logs(filter_builder.build()).await?;
    let mut deposits = Vec::new();
    let mut withdraws = Vec::new();
    let mut fx_originated_token = Vec::new();
    let mut valset_updated = Vec::new();
    prometheus::metrics::ETH_BRIDGE_ORACLE_EVENT_PENDING_LEN.set(logs.len() as f64);
    for log in logs {
        for topic in &log.topics {
            if topic.eq(&SendToFxEvent::signature()) {
                deposits.push(SendToFxEvent::from_log(&log)?)
            } else if topic.eq(&TransactionBatchExecutedEvent::signature()) {
                withdraws.push(TransactionBatchExecutedEvent::from_log(&log)?)
            } else if topic.eq(&FxOriginatedTokenEvent::signature()) {
                fx_originated_token.push(FxOriginatedTokenEvent::from_log(&log)?)
            } else if topic.eq(&ValsetUpdatedEvent::signature()) {
                valset_updated.push(ValsetUpdatedEvent::from_log(&log)?)
            }
        }
    }
    Ok((deposits, withdraws, fx_originated_token, valset_updated))
}

pub async fn query_valset_updated_event(web3: &Web3<Http>, bridge_addr: Address, from_block: U64, to_block: Option<U64>) -> Result<Vec<ValsetUpdatedEvent>> {
    let to_block = if to_block.is_some() { BlockNumber::Number(to_block.unwrap()) } else { BlockNumber::Latest };
    let filter_builder = FilterBuilder::default()
        .address(vec![bridge_addr])
        .from_block(BlockNumber::Number(from_block))
        .to_block(to_block)
        .topics(Option::from(vec![ValsetUpdatedEvent::signature()]), None, None, None);
    let logs = web3.eth().logs(filter_builder.build()).await?;
    let mut valset_updated = Vec::new();
    for log in logs {
        for topic in &log.topics {
            if topic.eq(&ValsetUpdatedEvent::signature()) {
                valset_updated.push(ValsetUpdatedEvent::from_log(&log).unwrap())
            }
        }
    }
    Ok(valset_updated)
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
pub struct FxOriginatedTokenEvent {
    pub erc20: Address,
    pub name: String,
    pub symbol: String,
    pub decimals: U256,
    pub event_nonce: U256,
    pub block_number: U64,
}

impl FxOriginatedTokenEvent {
    pub fn signature() -> Hash {
        Hash::from_slice(Keccak256::digest("FxOriginatedTokenEvent(address,string,string,uint8,uint256)".as_bytes()).as_slice())
    }

    pub fn from_log(input: &Log) -> Result<FxOriginatedTokenEvent> {
        if input.topics.len() != 2 {
            return Err(eyre::Error::msg("Invalid log topics"));
        }
        if let Some(erc20_data) = input.topics.get(1) {
            let erc20 = Address::from_slice(&erc20_data[12..32]);

            let index_start = 2 * 32;
            let index_end = index_start + 32;
            let decimals = U256::from(&input.data.0[index_start..index_end]);

            let index_start = index_end;
            let index_end = index_start + 32;
            let event_nonce = U256::from(&input.data.0[index_start..index_end]);

            let index_start = index_end;
            let index_end = index_start + 32;
            let name_len = U256::from(&input.data.0[index_start..index_end]).as_usize();
            let index_start = index_end;
            let index_end = index_start + name_len;
            let name = String::from_utf8(input.data.0[index_start..index_end].to_vec()).unwrap();

            let index_start = ((index_end + 31) / 32) * 32;
            let index_end = index_start + 32;
            let symbol_len = U256::from(&input.data.0[index_start..index_end]).as_usize();
            let index_start = index_end;
            let index_end = index_start + symbol_len;
            let symbol = String::from_utf8(input.data.0[index_start..index_end].to_vec()).unwrap();

            let block_number = if let Some(bn) = input.block_number.clone() {
                bn
            } else {
                return Err(eyre::Error::msg("Log does not have block number, we only search logs already in blocks?"));
            };
            Ok(FxOriginatedTokenEvent {
                erc20,
                name,
                symbol,
                decimals,
                event_nonce,
                block_number,
            })
        } else {
            Err(eyre::Error::msg("Topics parsing failed"))
        }
    }
    pub fn from_logs(input: &[Log]) -> Result<Vec<FxOriginatedTokenEvent>> {
        let mut res = Vec::new();
        for item in input {
            res.push(FxOriginatedTokenEvent::from_log(item)?);
        }
        Ok(res)
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
pub struct ValsetUpdatedEvent {
    pub valset_nonce: U256,
    pub event_nonce: U256,
    pub powers: Vec<U256>,
    pub validators: Vec<Address>,
    pub block_number: U64,
}

impl ValsetUpdatedEvent {
    pub fn signature() -> Hash {
        Hash::from_slice(Keccak256::digest("ValsetUpdatedEvent(uint256,uint256,address[],uint256[])".as_bytes()).as_slice())
    }

    pub fn from_log(input: &Log) -> Result<ValsetUpdatedEvent> {
        if input.topics.len() != 2 {
            return Err(eyre::Error::msg("Invalid log topics"));
        }
        if input.topics.get(1).is_none() {
            return Err(eyre::Error::msg("Too few topics".to_string()));
        }

        let valset_nonce = U256::from(input.topics[1].as_bytes());

        let index_start = 0;
        let index_end = index_start + 32;
        let event_nonce = U256::from(&input.data.0[index_start..index_end]);

        let index_start = 3 * 32;
        let index_end = index_start + 32;
        let validators_offset = index_start + 32;
        let validators_len = U256::from(&input.data.0[index_start..index_end]).as_usize();

        let mut validators = Vec::new();
        for i in 0..validators_len {
            let address_start = (i * 32) + validators_offset;
            let address_end = address_start + 32;
            let validator = Address::from_slice(&input.data.0[address_start + 12..address_end]);
            validators.push(validator);
        }

        let index_start = (4 + validators_len) * 32;
        let index_end = index_start + 32;
        let powers_offset = index_start + 32;
        let powers_len = U256::from(&input.data.0[index_start..index_end]).as_usize();

        let mut powers = Vec::new();
        for i in 0..powers_len {
            let power_start = (i * 32) + powers_offset;
            let power_end = power_start + 32;
            let power = U256::from(&input.data.0[power_start..power_end]);
            powers.push(power);
        }

        let block_number = if let Some(bn) = input.block_number.clone() {
            bn
        } else {
            return Err(eyre::Error::msg("Log does not have block number, we only search logs already in blocks?"));
        };

        Ok(ValsetUpdatedEvent {
            valset_nonce,
            event_nonce,
            validators,
            powers,
            block_number,
        })
    }
    pub fn from_logs(input: &[Log]) -> Result<Vec<ValsetUpdatedEvent>> {
        let mut res = Vec::new();
        for item in input {
            res.push(ValsetUpdatedEvent::from_log(item)?);
        }
        Ok(res)
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
pub struct SendToFxEvent {
    pub erc20: Address,
    pub sender: Address,
    pub destination: [u8; 20],
    pub target_ibc: String,
    pub amount: U256,
    pub event_nonce: U256,
    pub block_number: U64,
}

impl SendToFxEvent {
    pub fn signature() -> Hash {
        Hash::from_slice(Keccak256::digest("SendToFxEvent(address,address,bytes32,bytes32,uint256,uint256)".as_bytes()).as_slice())
    }

    pub fn from_log(input: &Log) -> Result<SendToFxEvent> {
        if input.topics.len() != 4 {
            return Err(eyre::Error::msg("Invalid log topics"));
        }

        if let (Some(erc20_data), Some(sender_data), Some(destination_data)) = (input.topics.get(1), input.topics.get(2), input.topics.get(3)) {
            let erc20 = Address::from_slice(&erc20_data[12..32]);
            let sender = Address::from_slice(&sender_data[12..32]);

            let mut destination: [u8; 20] = [0; 20];
            destination.copy_from_slice(&destination_data[12..32]);

            let index_start = 0;
            let index_end = index_start + 32;

            let target_ibc_bytes = input.data.0[index_start..index_end].to_vec();
            let mut length = target_ibc_bytes.len() - 1;
            while length > 0 && target_ibc_bytes[length - 1] == 0 {
                length = length - 1
            }
            let target_ibc = hex::encode(target_ibc_bytes.split_at(length).0.to_vec());

            let index_start = index_end;
            let index_end = index_start + 32;
            let amount = U256::from(&input.data.0[index_start..index_end]);

            let index_start = index_end;
            let index_end = index_start + 32;
            let event_nonce = U256::from(&input.data.0[index_start..index_end]);

            let block_number = if let Some(bn) = input.block_number.clone() {
                bn
            } else {
                return Err(eyre::Error::msg("Log does not have block number, we only search logs already in blocks?"));
            };

            Ok(SendToFxEvent {
                erc20,
                sender,
                destination,
                target_ibc,
                amount,
                event_nonce,
                block_number,
            })
        } else {
            Err(eyre::Error::msg("Topics parsing failed"))
        }
    }

    pub fn from_logs(input: &[Log]) -> Result<Vec<SendToFxEvent>> {
        let mut res = Vec::new();
        for item in input {
            res.push(SendToFxEvent::from_log(item)?);
        }
        Ok(res)
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
pub struct TransactionBatchExecutedEvent {
    pub batch_nonce: U256,
    pub erc20: Address,
    pub event_nonce: U256,
    pub block_number: U64,
}

impl TransactionBatchExecutedEvent {
    pub fn signature() -> Hash {
        Hash::from_slice(Keccak256::digest("TransactionBatchExecutedEvent(uint256,address,uint256)".as_bytes()).as_slice())
    }

    pub fn from_log(input: &Log) -> Result<TransactionBatchExecutedEvent> {
        if input.topics.len() != 3 {
            return Err(eyre::Error::msg("Invalid log topics"));
        }
        if let (Some(batch_nonce_data), Some(erc20_data)) = (input.topics.get(1), input.topics.get(2)) {
            let batch_nonce = U256::from(batch_nonce_data.as_bytes());
            let erc20 = Address::from_slice(&erc20_data[12..32]);
            let event_nonce = U256::from(input.data.0.as_slice());
            let block_number = if let Some(bn) = input.block_number.clone() {
                bn
            } else {
                return Err(eyre::Error::msg("Log does not have block number, we only search logs already in blocks?"));
            };
            Ok(TransactionBatchExecutedEvent {
                batch_nonce,
                erc20,
                event_nonce,
                block_number,
            })
        } else {
            Err(eyre::Error::msg("Topics parsing failed"))
        }
    }

    pub fn from_logs(input: &[Log]) -> Result<Vec<TransactionBatchExecutedEvent>> {
        let mut res = Vec::new();
        for item in input {
            res.push(TransactionBatchExecutedEvent::from_log(item)?);
        }
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hex::FromHex;
    use secp256k1::SecretKey;
    use web3::ethabi::FixedBytes;

    use super::*;

    const ETH_RPC_URL: &str = "http://localhost:8545";
    const ETH_PRIVATE_KEY: &str = "";
    const BRIDGE_ADDR: &str = "0x0412C7c846bb6b7DC462CF6B453f76D8440b2609";

    #[test]
    fn test_fx_bridge_new() {
        let transport = web3::transports::Http::new(ETH_RPC_URL).unwrap();
        let web3 = web3::Web3::new(transport);

        let bridge_addr = Address::from_str(BRIDGE_ADDR).unwrap();

        let secret_key = SecretKey::from_str(ETH_PRIVATE_KEY).unwrap();

        let private_key = PrivateKey::new(secret_key);

        let fx_bridge = FxBridge::new(Some(private_key), Option::default(), web3.eth(), bridge_addr);
        println!("{:?}", fx_bridge);
    }

    #[tokio::test]
    async fn test_state_last_valset_nonce() {
        let transport = web3::transports::Http::new(ETH_RPC_URL).unwrap();
        let web3 = web3::Web3::new(transport);

        let bridge_addr = Address::from_str(BRIDGE_ADDR).unwrap();

        let secret_key = SecretKey::from_str(ETH_PRIVATE_KEY).unwrap();

        let private_key = PrivateKey::new(secret_key);

        let fx_bridge = FxBridge::new(Some(private_key), Option::default(), web3.eth(), bridge_addr);

        let last_valset_nonce = fx_bridge.state_last_valset_nonce().await.unwrap();
        println!("{:?}", last_valset_nonce);
    }

    #[tokio::test]
    async fn test_state_fx_bridge_id() {
        let transport = web3::transports::Http::new(ETH_RPC_URL).unwrap();
        let web3 = web3::Web3::new(transport);

        let bridge_addr = Address::from_str(BRIDGE_ADDR).unwrap();

        let secret_key = SecretKey::from_str(ETH_PRIVATE_KEY).unwrap();

        let private_key = PrivateKey::new(secret_key);

        let fx_bridge = FxBridge::new(Some(private_key), Option::default(), web3.eth(), bridge_addr);

        let fx_bridge_id = fx_bridge.state_fx_bridge_id().await.unwrap();
        println!("{:?}", fx_bridge_id);
        println!("{:?}", String::from_utf8(fx_bridge_id.into()).unwrap());
        println!("{:?}", Token::FixedBytes(FixedBytes::from(fx_bridge_id.to_vec())));
    }

    /*=============== Event Test ===============*/

    #[tokio::test]
    async fn test_query_fx_bridge_all_event() {
        let transport = web3::transports::Http::new(
            "http://127.0.0.1:8545",
        )
            .unwrap();
        let web3 = web3::Web3::new(transport);

        let bridge_addr = Address::from_str("0x57c62672F61f8FF14b61AE70C516C73aCF3374cA").unwrap();
        let result = query_all_event(&web3, bridge_addr, 25250855.into(), Some(25250855.into())).await;
        if result.is_err() {
            println!("{:?}", result.unwrap_err().root_cause());
        } else {
            let (deposits, withdraws, originated_token, valset_updated) = result.unwrap();
            println!(
                "{:?}, {:?}, {:?}, {:?}, {:?}",
                deposits.len(),
                withdraws.len(),
                originated_token.len(),
                valset_updated.len(),
                deposits.len() + withdraws.len() + originated_token.len() + valset_updated.len()
            );
        }
    }

    #[tokio::test]
    async fn test_query_all_event_san_block() {
        let transport = web3::transports::Http::new(
            "http://127.0.0.1:8545",
        )
            .unwrap();
        let web3 = web3::Web3::new(transport);

        let bridge_addr = Address::from_str("0x57c62672F61f8FF14b61AE70C516C73aCF3374cA").unwrap();
        let result = query_all_event_san_block(&web3, bridge_addr, 25250829.into()).await;
        if result.is_err() {
            println!("{:?}", result.unwrap_err().root_cause());
        } else {
            let (deposits, withdraws, originated_token, valset_updated) = result.unwrap();
            println!(
                "{:?}, {:?}, {:?}, {:?}, {:?}",
                deposits.len(),
                withdraws.len(),
                originated_token.len(),
                valset_updated.len(),
                deposits.len() + withdraws.len() + originated_token.len() + valset_updated.len()
            );
        }
    }

    #[test]
    fn test_fx_originated_token_event() {
        let res: Log = serde_json::from_str(
            r#"
  {
    "transactionIndex": "0x0",
    "blockNumber": "0x4",
    "transactionHash": "0x8aaa14e598aa0977585660fbbf9fbff48ada3d13471e5b1e155bd7e5104792cb",
    "address": "0x8858eeB3DfffA017D4BCE9801D340D36Cf895CCf",
    "topics": [
      "0xfbaa7af285fff024998c9265afef33fb4e87f832f053151022580ea67fde8417",
      "0x000000000000000000000000e0d11fe9721c610d99ab46fd19594b478ee8abfb"
    ],
    "data": "0x000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000f46756e6374696f6e5820436861696e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000024658000000000000000000000000000000000000000000000000000000000000",
    "logIndex": "0x0",
    "blockHash": "0x1ca83275bd39cd3b58236b7ca38ca1263dac1c547e28faa7ee84b4622cd2c285"
  }
"#).unwrap();
        // println!("{:x}", FxOriginatedTokenEvent::signature());
        assert_eq!(res.topics.first().unwrap(), &FxOriginatedTokenEvent::signature());
        let event = FxOriginatedTokenEvent::from_log(&res).unwrap();
        assert_eq!(event.erc20, Address::from_str("0xe0d11fe9721c610d99ab46fd19594b478ee8abfb").unwrap());
        assert_eq!(event.name, "FunctionX Chain".to_string());
        assert_eq!(event.symbol, "FX".to_string());
        assert_eq!(event.decimals, U256::from(18));
        assert_eq!(event.event_nonce, U256::from(1));
        assert_eq!(event.block_number, U64::from(4));
    }

    #[test]
    fn test_valset_update_event() {
        let res: Log = serde_json::from_str(
            r#"
  {
    "transactionIndex": "0x1",
    "blockNumber": "0x12",
    "transactionHash": "0xc2f25d84183fcb3c7bfe3e80e529e0b9f9ad5beb13e734810fff420a7e1e460f",
    "address": "0xEC8Ec2A30c3E9Fb0cE7031ac4A52DbdFAD57a0D2",
    "topics": [
      "0xb119f1f36224601586b5037da909ecf37e83864dddea5d32ad4e32ac1d97e62b",
      "0x0000000000000000000000000000000000000000000000000000000000000000"
    ],
    "data": "0x0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000b4fA5979babd8Bb7e427157d0d353Cf205F4375200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000002710",
    "logIndex": "0x1",
    "blockHash": "0xe390492be21e4c23aac9f08c422b90b78a1987691255f3a5bc8ff4398958a73b"
  }
"#).unwrap();
        assert_eq!(res.topics.first().unwrap(), &ValsetUpdatedEvent::signature());
        let event = ValsetUpdatedEvent::from_log(&res).unwrap();
        assert_eq!(event.valset_nonce, 0.into());
        assert_eq!(event.event_nonce, 2.into());
        assert_eq!(event.validators[0], Address::from_str("0xb4fA5979babd8Bb7e427157d0d353Cf205F43752").unwrap());
        assert_eq!(event.powers[0], U256::from(10000));
        assert_eq!(event.block_number, U64::from(18));
    }

    #[test]
    fn test_send_to_fx_event() {
        let res: Log = serde_json::from_str(
            r#"
  {
    "transactionIndex": "0x0",
    "blockNumber": "0x11",
    "transactionHash": "0x2610f3e9f4ddbf8cfa2743987d45e456e4692378f752a1c6d519f545ba435788",
    "address": "0x8B5B7a6055E54a36fF574bbE40cf2eA68d5554b3",
    "topics": [
      "0x034c5b22dd525a50d0a6b15549df0a6ac83b833a6c3da57ea16890832c72507c",
      "0x000000000000000000000000d6c850aebfdc46d7f4c207e445cc0d6b0919bdbe",
      "0x000000000000000000000000b4fA5979babd8Bb7e427157d0d353Cf205F43752",
      "0x0000000000000000000000000000000000000000000000000000000000000001"
    ],
    "data": "0x7061792f7472616e736665722f6368616e6e656c2d300000000000000000000000000000000000000000000000000000000000000000000000000000000003e80000000000000000000000000000000000000000000000000000000000000002",
    "logIndex": "0x2",
    "blockHash": "0xb7fbe05d17d064e248ae6a92075e5817be136719b88b0dde64b49e240e779252"
  }
"#,
        )
            .unwrap();
        assert_eq!(res.topics.first().unwrap(), &SendToFxEvent::signature());
        let event = SendToFxEvent::from_log(&res).unwrap();
        assert_eq!(event.erc20, Address::from_str("0xd6c850aebfdc46d7f4c207e445cc0d6b0919bdbe").unwrap());
        assert_eq!(event.sender, Address::from_str("0xb4fA5979babd8Bb7e427157d0d353Cf205F43752").unwrap());
        assert_eq!(event.destination, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(event.target_ibc, hex::encode("pay/transfer/channel-0"));
        assert_eq!(event.block_number, U64::from(17));
        assert_eq!(event.amount, U256::from(1000));
        assert_eq!(event.event_nonce, U256::from(2));
    }

    #[test]
    fn test_send_to_fx_event2() {
        let res: Log = serde_json::from_str(
            r#"
  {
    "transactionIndex": "0x0",
    "blockNumber": "0x11",
    "transactionHash": "0x2610f3e9f4ddbf8cfa2743987d45e456e4692378f752a1c6d519f545ba435788",
    "address": "0x8B5B7a6055E54a36fF574bbE40cf2eA68d5554b3",
    "topics": [
      "0x034c5b22dd525a50d0a6b15549df0a6ac83b833a6c3da57ea16890832c72507c",
      "0x000000000000000000000000d6c850aebfdc46d7f4c207e445cc0d6b0919bdbe",
      "0x000000000000000000000000b4fA5979babd8Bb7e427157d0d353Cf205F43752",
      "0x0000000000000000000000000000000000000000000000000000000000000001"
    ],
    "data": "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003e80000000000000000000000000000000000000000000000000000000000000002",
    "logIndex": "0x2",
    "blockHash": "0xb7fbe05d17d064e248ae6a92075e5817be136719b88b0dde64b49e240e779252"
  }
"#,
        )
            .unwrap();
        assert_eq!(res.topics.first().unwrap(), &SendToFxEvent::signature());
        let event = SendToFxEvent::from_log(&res).unwrap();
        assert_eq!(event.erc20, Address::from_str("0xd6c850aebfdc46d7f4c207e445cc0d6b0919bdbe").unwrap());
        assert_eq!(event.sender, Address::from_str("0xb4fA5979babd8Bb7e427157d0d353Cf205F43752").unwrap());
        assert_eq!(event.destination, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(event.target_ibc, "".to_string());
        assert_eq!(event.block_number, U64::from(17));
        assert_eq!(event.amount, U256::from(1000));
        assert_eq!(event.event_nonce, U256::from(2));
    }

    #[test]
    fn test_transaction_batch_executed_event() {
        let res: Log = serde_json::from_str(
            r#"
  {
    "transactionIndex": "0x0",
    "blockNumber": "0x12",
    "transactionHash": "0x925cfc06238c20f93e4c9f8798164d3dbfde81273b21c9f52d6752981e5408b3",
    "address": "0x1A1FEe7EeD918BD762173e4dc5EfDB8a78C924A8",
    "topics": [
      "0x02c7e81975f8edb86e2a0c038b7b86a49c744236abf0f6177ff5afc6986ab708",
      "0x0000000000000000000000000000000000000000000000000000000000000001",
      "0x000000000000000000000000038b86d9d8fafdd0a02ebd1a476432877b0107c8"
    ],
    "data": "0x0000000000000000000000000000000000000000000000000000000000000002",
    "logIndex": "0x2",
    "blockHash": "0x09518b53d3b6981ea218e72772df54159dd0f299b988cca33bdfba81c0537ed2"
  }
"#,
        )
            .unwrap();
        assert_eq!(res.topics.first().unwrap(), &TransactionBatchExecutedEvent::signature());
        let event = TransactionBatchExecutedEvent::from_log(&res).unwrap();

        assert_eq!(event.erc20, Address::from_str("0x038b86d9d8fafdd0a02ebd1a476432877b0107c8").unwrap());
        assert_eq!(event.batch_nonce, U256::from(1));
        assert_eq!(event.event_nonce, U256::from(2));
        assert_eq!(event.block_number, U64::from(18))
    }

    #[test]
    fn test_vue_to_string() {
        let data = FixedBytes::from_hex("000000000000000000000000120226a55c07fbebd8c7a3a73a85438b78e009a7").unwrap();
        println!("{:?}", data);
        println!("{:?}", String::from_utf8(data.clone()));
        unsafe {
            println!("{}", String::from_utf8_unchecked(data));
        }
    }
}
