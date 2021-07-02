#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

pub mod x {
    pub mod gravity {
        include!("prost/fx.gravity.v1.rs");
    }

    pub mod other {
        include!("prost/fx.other.rs");
    }
}

pub mod address;
pub mod builder;
pub mod grpc_client;
pub mod private_key;
pub mod proto_ext;
pub mod public_key;

pub const DEFAULT_GAS_LIMIT: u64 = 500_000u64;

const GAS_LIMIT_MULTIPLIER: u64 = 2u64;

const GAS_LIMIT_MULTIPLIER_PRO: u64 = 3u64;

pub const FX_MSG_MAX_NUMBER: usize = 100;

pub const DEFAULT_TX_TIMEOUT_HEIGHT: u32 = 0u32;
