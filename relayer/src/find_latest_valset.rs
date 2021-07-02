use eyre::Result;
use tonic::transport::Channel;
use web3::transports::Http;
use web3::types::Address as EthAddress;
use web3::types::U64;
use web3::Web3;

use ethereum::fx_bridge;
use ethereum::fx_bridge::FxBridge;
use fxchain::x::gravity::query_client::QueryClient as GravityQueryClient;
use fxchain::x::gravity::QueryValsetRequestRequest;

use crate::valset::Valset;
use crate::ETH_BLOCKS_TO_SEARCH;

pub async fn find_latest_valset(
    grpc_channel: &Channel,
    web3: &Web3<Http>,
    bridge_addr: EthAddress,
) -> Result<Valset> {
    let eth_latest_block = web3.eth().block_number().await?;
    let mut current_block = eth_latest_block.clone();

    let bridge_contract = FxBridge::new(None, None, web3.eth(), bridge_addr);
    let latest_eth_valset_nonce = bridge_contract.state_last_valset_nonce().await?;

    trace!(
        "Query bridge contract state last valset nonce {}",
        latest_eth_valset_nonce
    );

    let mut gravity_query_client = GravityQueryClient::new(grpc_channel.clone());
    let valset_request_result = gravity_query_client
        .valset_request(QueryValsetRequestRequest {
            nonce: latest_eth_valset_nonce.as_u64(),
        })
        .await?;
    let fx_valset = match valset_request_result.into_inner().valset {
        Some(v) => Some(v),
        None => None,
    };
    trace!(
        "Query valset request from nonce {}, {:?}",
        latest_eth_valset_nonce,
        fx_valset
    );

    while current_block.clone() > 0u8.into() {
        let end_search = if current_block.clone() < U64::from(ETH_BLOCKS_TO_SEARCH) {
            0u8.into()
        } else {
            current_block.clone() - U64::from(ETH_BLOCKS_TO_SEARCH)
        };
        trace!(
            "Find the last Valset Update, from {} to {}",
            end_search,
            current_block
        );
        let mut eth_latest_valset = fx_bridge::query_valset_updated_event(
            web3,
            bridge_addr,
            end_search,
            Some(current_block),
        )
        .await?;
        // by default the lowest found valset goes first, we want the highest.
        eth_latest_valset.reverse();
        trace!(
            "Found eth latest valset number of {:?}",
            eth_latest_valset.len()
        );

        for event in eth_latest_valset {
            let eth_valset = Valset::from(event);
            return Ok(eth_valset);
        }
        current_block = end_search;
    }

    panic!("Could not find the last validator set for contract {}, probably not a valid Bridge contract!", bridge_addr)
}
