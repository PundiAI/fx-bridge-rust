#[macro_use]
extern crate log;
extern crate serde;
extern crate serde_derive;
extern crate serde_json;

use std::time::Duration;

pub mod address;
mod confirm_tx;
pub mod erc20;
pub mod fx_bridge;
pub mod gas_price;
pub mod private_key;

const TX_CONFIRMATIONS_BLOCK_NUMBER: usize = 1;

const TX_CONFIRMATIONS_TIMEOUT: Duration = Duration::from_secs(10 * 15);
