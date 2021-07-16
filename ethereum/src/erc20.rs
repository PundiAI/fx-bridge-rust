use std::fmt::Debug;

use eyre::Result;
use sha3::{Digest, Keccak256};
use web3::api::Eth;
use web3::contract::tokens::{Detokenize, Tokenizable};
use web3::contract::{Contract, Options};
use web3::ethabi::{Contract as ContractABI, Hash, Token};
use web3::transports::Http;
use web3::types::{Address, BlockId, BlockNumber, TransactionReceipt, U256};

use crate::private_key::{Key, PrivateKey};
use crate::TX_CONFIRMATIONS_BLOCK_NUMBER;

const ERC20_ABI: &str = r#"[{"inputs":[{"internalType":"string","name":"name","type":"string"},{"internalType":"string","name":"symbol","type":"string"}],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"spender","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Transfer","type":"event"},{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"subtractedValue","type":"uint256"}],"name":"decreaseAllowance","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"addedValue","type":"uint256"}],"name":"increaseAllowance","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"recipient","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"transfer","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"sender","type":"address"},{"internalType":"address","name":"recipient","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"transferFrom","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"}]"#;

#[derive(Debug, Clone)]
pub struct ERC20 {
    eth: Eth<Http>,
    contract: Contract<Http>,
    options: Options,
    private_key: Option<PrivateKey>,
    from: Address,
}

impl ERC20 {
    pub fn new(private_key: Option<PrivateKey>, options: Option<Options>, eth: Eth<Http>, address: Address) -> Self {
        let abi: ContractABI = serde_json::from_str(ERC20_ABI).expect("invalid ERC20 abi");
        let contract = Contract::new(eth.clone(), address, abi);
        let options = if options.is_some() { options.unwrap() } else { Options::default() };
        let (private_key, from) = if private_key.is_some() {
            (private_key.clone(), private_key.unwrap().address())
        } else {
            (None, Address::default())
        };
        ERC20 {
            eth,
            contract,
            options,
            private_key,
            from,
        }
    }
    ///"Calls the contract's `balanceOf` (0x70a08231) function"
    pub async fn balance_of(&self, account: Address) -> Result<U256> {
        let result = self.contract.query("balanceOf", account, self.from, self.options.clone(), BlockId::Number(BlockNumber::Latest)).await?;
        Ok(result)
    }
    ///"Calls the contract's `decimals` (0x313ce567) function"
    pub async fn decimals(&self) -> Result<u8> {
        let result = self.contract.query("decimals", (), self.from, self.options.clone(), BlockId::Number(BlockNumber::Latest)).await?;
        Ok(result)
    }
    ///"Calls the contract's `name` (0x06fdde03) function"
    pub async fn name(&self) -> Result<String> {
        let result = self.contract.query("name", (), self.from, self.options.clone(), BlockId::Number(BlockNumber::Latest)).await?;
        Ok(result)
    }
    ///"Calls the contract's `symbol` (0x95d89b41) function"
    pub async fn symbol(&self) -> Result<String> {
        let result = self.contract.query("symbol", (), self.from, self.options.clone(), BlockId::Number(BlockNumber::Latest)).await?;
        Ok(result)
    }
    ///"Calls the contract's `totalSupply` (0x18160ddd) function"
    pub async fn total_supply(&self) -> Result<U256> {
        let result = self.contract.query("totalSupply", (), self.from, self.options.clone(), BlockId::Number(BlockNumber::Latest)).await?;
        Ok(result)
    }
    ///"Calls the contract's `allowance` (0xdd62ed3e) function"
    pub async fn allowance(&self, owner: Address, spender: Address) -> Result<U256> {
        let result = self
            .contract
            .query("allowance", (owner, spender), self.from, self.options.clone(), BlockId::Number(BlockNumber::Latest))
            .await?;
        Ok(result)
    }
    ///"Calls the contract's `approve` (0x095ea7b3) function"
    pub async fn approve(&self, spender: Address, amount: U256) -> Result<TransactionReceipt> {
        if self.private_key.is_none() {
            return Err(eyre::Error::msg("no private key to authorize the transaction with"));
        }
        let mut options = self.options.clone();
        options.nonce = Option::from(if let Some(nonce) = self.options.nonce {
            nonce
        } else {
            self.eth.transaction_count(self.from, Some(BlockNumber::Latest)).await?
        });
        options.gas_price = if let Some(gas_price) = self.options.gas_price {
            Some(gas_price)
        } else {
            let gas_price = self.eth.gas_price().await?;
            Some(gas_price)
        };
        options.gas = if let Some(gas) = self.options.gas {
            Some(gas)
        } else {
            let gas = self.contract.estimate_gas("approve", (spender, amount), self.from.clone(), options.clone()).await?;
            Some(gas)
        };

        let transaction_receipt = self
            .contract
            .signed_call_with_confirmations("approve", (spender, amount), options.clone(), TX_CONFIRMATIONS_BLOCK_NUMBER, self.private_key.clone().unwrap())
            .await?;
        Ok(transaction_receipt)
    }
    // ///"Calls the contract's `decreaseAllowance` (0xa457c2d7) function"
    // pub async fn decrease_allowance(
    //     &self,
    //     spender: Address,
    //     subtracted_value: U256,
    // ) -> Result<bool> {
    // }
    // ///"Calls the contract's `increaseAllowance` (0x39509351) function"
    // pub async fn increase_allowance(&self, spender: Address, added_value: U256) -> Result<bool> {}
    ///"Calls the contract's `transfer` (0xa9059cbb) function"
    pub async fn transfer(&self, recipient: Address, amount: U256) -> Result<TransactionReceipt> {
        if self.private_key.is_none() {
            return Err(eyre::Error::msg("no private key to authorize the transaction with"));
        }
        let mut options = self.options.clone();
        options.nonce = Option::from(if let Some(nonce) = self.options.nonce {
            nonce
        } else {
            self.eth.transaction_count(self.from, Some(BlockNumber::Latest)).await?
        });
        options.gas_price = if let Some(gas_price) = self.options.gas_price {
            Some(gas_price)
        } else {
            let gas_price = self.eth.gas_price().await?;
            Some(gas_price)
        };
        options.gas = if let Some(gas) = self.options.gas {
            Some(gas)
        } else {
            let gas = self.contract.estimate_gas("transfer", (recipient, amount), self.from.clone(), options.clone()).await?;
            Some(gas)
        };

        let transaction_receipt = self
            .contract
            .signed_call_with_confirmations("transfer", (recipient, amount), options.clone(), TX_CONFIRMATIONS_BLOCK_NUMBER, self.private_key.clone().unwrap())
            .await?;
        Ok(transaction_receipt)
    }
    // ///"Calls the contract's `transferFrom` (0x23b872dd) function"
    // pub async fn transfer_from(
    //     &self,
    //     sender: Address,
    //     recipient: Address,
    //     amount: U256,
    // ) -> Result<bool> {
    // }
    // ///"Gets the contract's `Approval` event"]
    // pub async fn approval_filter(&self) -> Event<M, ApprovalFilter> {}
    // ///"Gets the contract's `Transfer` event"]
    // pub async fn transfer_filter(&self) -> Event<M, TransferFilter> {}
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ApprovalEvent {
    pub owner: Address,
    pub spender: Address,
    pub value: U256,
}

impl ApprovalEvent {
    pub fn signature() -> Hash {
        Hash::from_slice(Keccak256::digest(ApprovalEvent::abi_signature().as_bytes()).as_slice())
    }
    pub const fn abi_signature() -> &'static str {
        "Approval(address,address,uint256)"
    }
}

impl Detokenize for ApprovalEvent {
    fn from_tokens(tokens: Vec<Token>) -> web3::contract::Result<Self> {
        if tokens.len() != 3 {
            return Err(web3::contract::Error::InvalidOutputType(format!("Expected {} tokens, got {}: {:?}", 3, tokens.len(), tokens)));
        }
        #[allow(unused_mut)]
        let mut tokens = tokens.into_iter();
        let owner = Tokenizable::from_token(tokens.next().unwrap())?;
        let spender = Tokenizable::from_token(tokens.next().unwrap())?;
        let value = Tokenizable::from_token(tokens.next().unwrap())?;
        Ok(ApprovalEvent { owner, spender, value })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TransferEvent {
    pub from: Address,
    pub to: Address,
    pub value: U256,
}

impl TransferEvent {
    pub fn signature() -> Hash {
        Hash::from_slice(Keccak256::digest(TransferEvent::abi_signature().as_bytes()).as_slice())
    }
    pub const fn abi_signature() -> &'static str {
        "Transfer(address,address,uint256)"
    }
}

impl Detokenize for TransferEvent {
    fn from_tokens(tokens: Vec<Token>) -> web3::contract::Result<Self> {
        if tokens.len() != 3 {
            return Err(web3::contract::Error::InvalidOutputType(format!("Expected {} tokens, got {}: {:?}", 3, tokens.len(), tokens)));
        }
        #[allow(unused_mut)]
        let mut tokens = tokens.into_iter();
        let from = Tokenizable::from_token(tokens.next().unwrap())?;
        let to = Tokenizable::from_token(tokens.next().unwrap())?;
        let value = Tokenizable::from_token(tokens.next().unwrap())?;
        Ok(TransferEvent { from, to, value })
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use secp256k1::SecretKey;

    use super::*;

    const ETH_RPC_URL: &str = "http://localhost:8545";
    const ETH_PRIVATE_KEY: &str = "";
    const BRIDGE_ADDR: &str = "0x0412C7c846bb6b7DC462CF6B453f76D8440b2609";
    const ERC20_TOKEN: &str = "0x30dA8589BFa1E509A319489E014d384b87815D89";

    #[tokio::test]
    async fn test_erc20_approve() {
        let transport = web3::transports::Http::new(ETH_RPC_URL).unwrap();
        let web3 = web3::Web3::new(transport);

        let erc20_addr = Address::from_str(ERC20_TOKEN).unwrap();

        let secret_key = SecretKey::from_str(ETH_PRIVATE_KEY).unwrap();

        let private_key = PrivateKey::new(secret_key);

        let erc20 = ERC20::new(Some(private_key), None, web3.eth(), erc20_addr);

        let bridge_addr = Address::from_str(BRIDGE_ADDR).unwrap();

        let tx = erc20.approve(bridge_addr, U256::from(100)).await;
        println!("{:?}", tx);
    }

    #[tokio::test]
    async fn test_erc20_balance() {
        let transport = web3::transports::Http::new(ETH_RPC_URL).unwrap();
        let web3 = web3::Web3::new(transport);

        let erc20_addr = Address::from_str("0x30dA8589BFa1E509A319489E014d384b87815D89").unwrap();

        let erc20 = ERC20::new(None, None, web3.eth(), erc20_addr);

        let balance = erc20.balance_of(Address::from_str("0xBf660843528035a5A4921534E156a27e64B231fE").unwrap()).await.unwrap();
        println!("{}", balance);
    }
}
