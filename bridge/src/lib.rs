#[macro_use]
extern crate log;

use std::time::Duration;

pub mod oracle_loop;
pub mod singer_loop;

/// Average block time in Ethereum
const ETH_AVG_BLOCK_TIME: Duration = Duration::from_secs(30);

/// Average block output time of FxChain
const FX_AVG_BLOCK_TIME: Duration = Duration::from_secs(6);

/// Ethereum block search interval
const ETH_BLOCKS_TO_SEARCH: u64 = 5_000u64;

/// Ethereum event search interval
const ETH_EVENT_TO_SEARCH: u64 = 3000u64;

/// Ethereum event delay processing block height
const ETH_BLOCK_DELAY: u64 = 12u64;
