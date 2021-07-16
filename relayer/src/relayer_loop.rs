use tokio::time::sleep;
use tonic::transport::Channel;
use web3::transports::Http;
use web3::types::Address as EthAddress;
use web3::Web3;

use ethereum::fx_bridge::FxBridge;
use ethereum::private_key::PrivateKey as EthPrivateKey;
use fxchain::x::gravity::query_client::QueryClient as GravityQueryClient;
use fxchain::x::gravity::QueryParamsRequest;

use crate::batch_relaying::relay_batches;
use crate::find_latest_valset::find_latest_valset;
use crate::valset_relaying::relay_valsets;
use crate::RELAYER_LOOP_TIME;

pub async fn relayer_main_loop(grpc_channel: &Channel, web3: &Web3<Http>, bridge_addr: EthAddress, eth_private_key_valset: &EthPrivateKey, eth_private_key_batch: &EthPrivateKey) {
    let mut gravity_query_client = GravityQueryClient::new(grpc_channel.clone());
    let response = gravity_query_client.params(QueryParamsRequest {}).await.unwrap();
    let gravity_id = response.into_inner().params.unwrap().gravity_id;
    info!("Relayer main loop query gravity id {}", gravity_id);

    let bridge_contract = FxBridge::new(None, None, web3.eth(), bridge_addr);
    let response = bridge_contract.state_fx_bridge_id().await.unwrap();
    let mut length = response.len() - 1;
    while length > 0 && response[length - 1] == 0 {
        length = length - 1
    }
    let eth_gravity_id = String::from_utf8(response.split_at(length).0.to_vec()).unwrap();
    if eth_gravity_id != gravity_id {
        panic!("The bridge ID on the two chains do not match")
    }
    loop {
        let result = find_latest_valset(grpc_channel, web3, bridge_addr).await;
        match result {
            Ok(current_valset) => {
                relay_valsets(current_valset.clone(), eth_private_key_valset, &web3, &grpc_channel, bridge_addr, &gravity_id).await;

                relay_batches(current_valset, eth_private_key_batch, &grpc_channel, &web3, bridge_addr, &gravity_id).await;
            }
            Err(report) => error!("The query for current valset failed {:?}", report),
        }

        sleep(RELAYER_LOOP_TIME).await;
    }
}
