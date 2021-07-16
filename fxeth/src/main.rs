#[macro_use]
extern crate log;

use std::str::FromStr;
use std::time::Duration;

use clap::{AppSettings, Clap};
use env_logger::Env;
use futures::future;
use tokio::time::sleep;
use tonic::transport::Channel;
use web3::transports::Http;
use web3::types::Address as EthAddress;
use web3::Web3;

use bridge::oracle_loop::eth_oracle_bridge_loop;
use bridge::singer_loop::eth_signer_main_loop;
use ethereum::address::Checksum;
use ethereum::private_key::{Key, PrivateKey as EthPrivateKey};
use fxchain::builder::Builder;
use fxchain::grpc_client::new_grpc_channel;
use fxchain::private_key::PrivateKey as FxPrivateKey;
use relayer::relayer_loop::relayer_main_loop;

/// F(x) Core chain and Ethereum chain orchestrator
#[derive(Clap, Debug)]
#[clap(author, version)]
#[clap(setting = AppSettings::ColoredHelp)]
struct Opts {
    ///set log level
    #[clap(short, long, env = "RUST_LOG", default_value = "debug")]
    log_level: String,
    ///config file path
    #[clap(short, long, default_value = "config.toml")]
    config_file: String,
    #[clap(subcommand)]
    sub_cmd: SubCmd,
}

#[derive(Clap, Debug)]
pub enum SubCmd {
    ///responsible for event on signature the F(x) Chain and the Ethereum
    #[clap(name = "bridge")]
    #[clap(setting = AppSettings::ColoredHelp)]
    BridgeCmd(Bridge),
    ///responsible for relaying data from the F(x) Chain to the Ethereum
    #[clap(name = "relayer")]
    #[clap(setting = AppSettings::ColoredHelp)]
    RelayerCmd(Relayer),
}

#[derive(Clap, Debug)]
pub struct Bridge {
    /// F(x) Chain validator private key
    #[clap(long)]
    fx_chain_key: String,
    /// F(x) Chain gRPC address
    #[clap(long, default_value = "http://127.0.0.1:9090")]
    fx_chain_grpc: String,
    /// F(x) Chain validator Ethereum private key
    #[clap(long)]
    ethereum_key: String,
    /// Ethereum RPC address
    #[clap(long, default_value = "http://127.0.0.1:9090")]
    ethereum_rpc: String,
    /// F(x) Chain Bridge contract address
    #[clap(long)]
    bridge_addr: String,
    /// F(x) Chain send transactions fee
    #[clap(long, default_value = "FX")]
    fees: String,
    // ///notice address
    // #[clap(long)]
    // notice_url: String,
}

#[derive(Clap, Debug)]
pub struct Relayer {
    /// F(x) Chain gRPC address
    #[clap(long, default_value = "http://127.0.0.1:9090")]
    fx_chain_grpc: String,
    /// Ethereum send submit batch tx private key
    #[clap(long)]
    ethereum_batch_key: String,
    /// Ethereum send valset update tx private key
    #[clap(long)]
    ethereum_valset_key: String,
    /// Ethereum RPC address
    #[clap(long, default_value = "http://127.0.0.1:9090")]
    ethereum_rpc: String,
    /// F(x) Chain Bridge contract address
    #[clap(long)]
    bridge_addr: String,
    // /// Eth gas station address
    // #[clap(long)]
    // eth_gas_station_url: String,
    // ///notice address
    // #[clap(long)]
    // notice_url: String,
}

#[tokio::main]
async fn main() {
    let opts: Opts = Opts::parse();
    env_logger::Builder::from_env(Env::default().default_filter_or(opts.log_level.clone())).init();
    debug!("Command args {:?}", opts);

    match opts.sub_cmd {
        SubCmd::BridgeCmd(cmd) => {
            let transport = web3::transports::Http::new(cmd.ethereum_rpc.as_str()).unwrap();
            let web3 = web3::Web3::new(transport);
            let ethereum_key_str = cmd.ethereum_key.as_str();
            let eth_private_key = EthPrivateKey::from_str(ethereum_key_str).unwrap();
            info!("Ethereum account address {}", eth_private_key.address().to_hex_string());

            let bridge_addr = EthAddress::from_str(cmd.bridge_addr.as_str()).unwrap();

            let grpc_channel = new_grpc_channel(cmd.fx_chain_grpc.as_str()).await.unwrap();

            with_sync_block(&grpc_channel, &web3).await;

            let fx_chain_key_str = cmd.fx_chain_key.as_str();
            let fx_private_key = FxPrivateKey::from_phrase(fx_chain_key_str, "").unwrap();

            let fx_builder = Builder::from_net(&grpc_channel, fx_private_key, cmd.fees.as_str()).await.unwrap();

            let future1 = eth_oracle_bridge_loop(&fx_builder, &grpc_channel, &web3, bridge_addr);
            let future2 = eth_signer_main_loop(&fx_builder, &grpc_channel, eth_private_key);
            let future3 = prometheus::start(9899);
            future::join3(future1, future2, future3).await;
        }
        SubCmd::RelayerCmd(cmd) => {
            let transport = web3::transports::Http::new(cmd.ethereum_rpc.as_str()).unwrap();
            let web3 = web3::Web3::new(transport);

            let ethereum_key_batch_str = cmd.ethereum_batch_key.as_str();
            let eth_private_key_batch = EthPrivateKey::from_str(ethereum_key_batch_str).unwrap();
            info!("Send ethereum batch tx account address {}", eth_private_key_batch.address().to_hex_string());

            let ethereum_key_valset_str = cmd.ethereum_valset_key.as_str();
            let eth_private_key_valset = EthPrivateKey::from_str(ethereum_key_valset_str).unwrap();
            info!("Send ethereum valset tx account address {}", eth_private_key_valset.address().to_hex_string());

            let bridge_addr = EthAddress::from_str(cmd.bridge_addr.as_str()).unwrap();

            let grpc_channel = new_grpc_channel(cmd.fx_chain_grpc.as_str()).await.unwrap();

            with_sync_block(&grpc_channel, &web3).await;

            let future1 = relayer_main_loop(&grpc_channel, &web3, bridge_addr, &eth_private_key_valset, &eth_private_key_batch);
            let future2 = prometheus::start(9898);
            future::join(future1, future2).await;
        }
    }
}

pub async fn with_sync_block(grpc_channel: &Channel, web3: &Web3<Http>) {
    const RETRY_TIME: Duration = Duration::from_secs(5);
    loop {
        let eth_latest_block_number = web3.eth().block_number().await;

        let fx_latest_block_height = fxchain::grpc_client::get_latest_block_height(grpc_channel).await;

        match (eth_latest_block_number, fx_latest_block_height) {
            (Ok(eth_latest_block_number), Ok(fx_latest_block_height)) => {
                trace!("Latest Eth block {} Latest FxChain block {}", eth_latest_block_number, fx_latest_block_height,);
                return;
            }
            (Ok(_), Err(_)) => {
                warn!("Could not contact Fx grpc, trying again");
                sleep(RETRY_TIME).await;
                continue;
            }
            (Err(_), Ok(_)) => {
                warn!("Could not contact Eth node, trying again");
                sleep(RETRY_TIME).await;
                continue;
            }
            (Err(_), Err(_)) => {
                error!("Could not reach Ethereum or FxChain rpc!");
                sleep(RETRY_TIME).await;
                continue;
            }
        }
    }
}
