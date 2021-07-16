use std::time::{Duration, Instant};

use futures::{Future, StreamExt};
use web3::{
    api::{Eth, EthFilter, Namespace},
    error,
    types::{Bytes, TransactionReceipt, TransactionRequest, H256, U64},
    Transport,
};

use crate::TX_CONFIRMATIONS_TIMEOUT;

pub trait ConfirmationCheck {
    type Check: Future<Output = error::Result<Option<U64>>>;

    fn check(&self) -> Self::Check;
}

impl<F, T> ConfirmationCheck for F
where
    F: Fn() -> T,
    T: Future<Output = error::Result<Option<U64>>>,
{
    type Check = T;

    fn check(&self) -> Self::Check {
        (*self)()
    }
}

pub async fn wait_for_confirmations<T, V, F>(eth: Eth<T>, eth_filter: EthFilter<T>, poll_interval: Duration, confirmations: usize, check: V) -> error::Result<()>
where
    T: Transport,
    V: ConfirmationCheck<Check = F>,
    F: Future<Output = error::Result<Option<U64>>>,
{
    let filter = eth_filter.create_blocks_filter().await?;
    let filter_stream = filter.stream(poll_interval).skip(confirmations);
    futures::pin_mut!(filter_stream);

    let start_loop = Instant::now();
    loop {
        let _ = filter_stream.next().await;
        if let Some(confirmation_block_number) = check.check().await? {
            let block_number = eth.block_number().await?;
            if confirmation_block_number.low_u64() + confirmations as u64 <= block_number.low_u64() {
                return Ok(());
            }
        } else {
            if Instant::now() - start_loop > TX_CONFIRMATIONS_TIMEOUT {
                return Err(error::Error::Transport("tx confirm timeout".to_string()));
            }
        }
    }
}

async fn transaction_receipt_block_number_check<T: Transport>(eth: &Eth<T>, hash: H256) -> error::Result<Option<U64>> {
    let receipt = eth.transaction_receipt(hash).await?;
    Ok(receipt.and_then(|receipt| receipt.block_number))
}

async fn send_transaction_with_confirmation_<T: Transport>(hash: H256, transport: T, poll_interval: Duration, confirmations: usize) -> error::Result<TransactionReceipt> {
    let eth = Eth::new(transport.clone());
    if confirmations > 0 {
        let confirmation_check = || transaction_receipt_block_number_check(&eth, hash);
        let eth_filter = EthFilter::new(transport.clone());
        let eth = eth.clone();
        wait_for_confirmations(eth, eth_filter, poll_interval, confirmations, confirmation_check).await?;
    }
    let receipt = eth.transaction_receipt(hash).await?;
    if receipt.is_none() {
        Err(error::Error::InvalidResponse("receipt can't be null after wait for confirmations".to_string()))
    } else {
        Ok(receipt.unwrap())
    }
}

#[allow(dead_code)]
pub async fn send_transaction_with_confirmation<T>(transport: T, tx: TransactionRequest, poll_interval: Duration, confirmations: usize) -> error::Result<TransactionReceipt>
where
    T: Transport,
{
    let hash = Eth::new(&transport).send_transaction(tx).await?;
    send_transaction_with_confirmation_(hash, transport, poll_interval, confirmations).await
}

pub async fn send_raw_transaction_with_confirmation<T>(transport: T, tx: Bytes, poll_interval: Duration, confirmations: usize) -> error::Result<TransactionReceipt>
where
    T: Transport,
{
    let hash = Eth::new(&transport).send_raw_transaction(tx).await?;
    send_transaction_with_confirmation_(hash, transport, poll_interval, confirmations).await
}

#[cfg(test)]
mod tests {}
