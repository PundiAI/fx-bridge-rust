#[macro_use]
extern crate log;

use std::time::Duration;

mod batch_relaying;
mod find_latest_valset;
pub mod relayer_loop;
mod valset;
mod valset_relaying;

const ETH_BLOCKS_TO_SEARCH: u64 = 5_000u64;

const RELAYER_LOOP_TIME: Duration = Duration::from_secs(30);
