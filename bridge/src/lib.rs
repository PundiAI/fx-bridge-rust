#[macro_use]
extern crate log;

use std::time::Duration;

pub mod oracle_loop;
pub mod singer_loop;
pub mod send_to_fx;

const ETH_AVG_BLOCK_TIME: Duration = Duration::from_secs(30);

const FX_AVG_BLOCK_TIME: Duration = Duration::from_secs(6);

const ETH_BLOCKS_TO_SEARCH: u64 = 5_000u64;

const ETH_EVENT_TO_SEARCH: u64 = 2000u64;
