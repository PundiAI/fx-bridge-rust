use lazy_static::lazy_static;
use prometheus::{Counter, Gauge};

lazy_static! {
    pub static ref ETH_BRIDGE_ORACLE_SYNC_BLOCK_HEIGHT: Gauge =
        register_gauge!(opts!("eth_bridge_oracle_sync_block_height", "eth_bridge_oracle_sync_block_height")).unwrap();
    pub static ref ETH_BRIDGE_ORACLE_QUERY_LOG_BLOCK_HEIGHT_INTERVAL: Gauge =
        register_gauge!(opts!("eth_bridge_oracle_query_log_block_interval", "eth_bridge_oracle_query_log_block_interval")).unwrap();
    pub static ref ETH_BRIDGE_ORACLE_EVENT_PENDING_LEN: Gauge =
        register_gauge!(opts!("eth_bridge_oracle_event_pending_len", "eth_bridge_oracle_event_pending_len")).unwrap();
    pub static ref ETH_BRIDGE_ORACLE_MSG_PENDING_LEN: Gauge =
        register_gauge!(opts!("eth_bridge_oracle_msg_pending_len", "eth_bridge_oracle_msg_pending_len")).unwrap();

    pub static ref SUBMIT_BATCH_SIGN: Counter =
        register_counter!(opts!("submit_batch_sign", "submit_batch_sign")).unwrap();
    pub static ref UPDATE_VALSET_SIGN: Counter =
        register_counter!(opts!("update_valset_sign", "update_valset_sign")).unwrap();
    pub static ref FX_KEY_BALANCE: Gauge =
        register_gauge!(opts!("fx_key_balance", "fx_key_balance")).unwrap();
}
