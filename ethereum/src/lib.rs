#[macro_use]
extern crate log;
extern crate serde;

use std::time::Duration;

pub mod address;
pub mod chainlink;
pub mod client;
pub mod erc20;
pub mod fx_bridge;
pub mod private_key;
mod confirm_tx;

const TX_CONFIRMATIONS_BLOCK_NUMBER: usize = 1;

const TX_CONFIRMATIONS_TIMEOUT: Duration = Duration::from_secs(10 * 15);
