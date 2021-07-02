use cosmos_sdk_proto::cosmos::tx::signing::v1beta1::SignMode;
use cosmos_sdk_proto::cosmos::tx::v1beta1::{Fee, mode_info, ModeInfo};
use cosmos_sdk_proto::cosmos::tx::v1beta1::{AuthInfo, SignDoc, SignerInfo, Tx, TxBody};
use eyre::Result;
use prost_types::Any;
use tendermint::{block, chain};
use tonic::transport::Channel;

use crate::address::Address;
use crate::grpc_client::{get_account_info, get_chain_id};
use crate::private_key::PrivateKey;
use crate::proto_ext::MessageExt;

/// Protocol Buffer-encoded transaction builder
pub struct Builder {
    chain_id: chain::Id,
    private_key: PrivateKey,
    account_number: u64,
    fees_denom: String,
    memo: String,
}

impl Builder {
    /// Create a new transaction builder
    pub fn new(
        chain_id: impl Into<chain::Id>,
        private_key: PrivateKey,
        account_number: u64,
        fees_denom: &str,
    ) -> Self {
        Builder {
            chain_id: chain_id.into(),
            private_key,
            account_number,
            fees_denom: fees_denom.to_string(),
            memo: Default::default(),
        }
    }

    pub async fn from_net(
        grpc_channel: &Channel,
        fx_private_key: PrivateKey,
        fees_denom: &str,
    ) -> eyre::Result<Self> {
        let fx_address = fx_private_key.public_key().to_address().to_string();
        let fx_account = get_account_info(&grpc_channel, fx_address).await?;
        info!("Fx chain account address {}, account number {}", fx_account.address, fx_account.account_number);

        let chain_id = get_chain_id(&grpc_channel).await?;
        info!("Fx chain id {}, use fee denom {}", chain_id, fees_denom);
        Ok(Builder::new(
            chain_id,
            fx_private_key,
            fx_account.account_number,
            fees_denom,
        ))
    }

    pub fn with_memo(&mut self, memo: String) -> &mut Builder {
        self.memo = memo;
        self
    }

    pub fn get_fee_denom(&self) -> String {
        self.fees_denom.clone()
    }

    /// Borrow this transaction builder's chain ID
    pub fn chain_id(&self) -> &chain::Id {
        &self.chain_id
    }

    pub fn address(&self) -> Address {
        self.private_key.public_key().to_address()
    }

    /// Get latest account sequence
    pub async fn get_next_sequence(&self, grpc_channel: &Channel) -> Result<u64> {
        let address = self.private_key.public_key().to_address().to_string();
        let account_info = get_account_info(grpc_channel, address).await?;
        Ok(account_info.sequence)
    }

    /// Build and sign a transaction containing the given messages
    pub fn sign_tx(
        &self,
        sequence: u64,
        messages: Vec<Any>,
        fee: Fee,
        timeout_height: block::Height,
    ) -> Result<Tx> {
        let body = TxBody {
            messages,
            memo: self.memo.clone(),
            timeout_height: timeout_height.into(),
            extension_options: Default::default(),
            non_critical_extension_options: Default::default(),
        };
        let body_bytes = body.to_bytes()?;

        let pk = self.private_key.public_key();
        let pk_any = pk.to_any()?;

        let single = mode_info::Single {
            mode: SignMode::Direct as i32,
        };
        let mode = ModeInfo {
            sum: Some(mode_info::Sum::Single(single)),
        };
        let signer_info = SignerInfo {
            public_key: Some(pk_any),
            mode_info: Some(mode),
            sequence,
        };

        let auth_info = AuthInfo {
            signer_infos: vec![signer_info],
            fee: Some(fee),
        };
        let auth_info_bytes = auth_info.to_bytes()?;

        let sign_doc = SignDoc {
            body_bytes,
            auth_info_bytes,
            chain_id: self.chain_id.to_string(),
            account_number: self.account_number,
        };
        let sign_doc_bytes = sign_doc.to_bytes()?;
        let signed = self.private_key.sign(&sign_doc_bytes)?;

        Ok(Tx {
            body: Some(body),
            auth_info: Some(auth_info),
            signatures: vec![signed.as_ref().to_vec()],
        })
    }
}
