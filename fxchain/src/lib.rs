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

const GAS_LIMIT_MULTIPLIER: f64 = 1.5f64;

const GAS_LIMIT_MULTIPLIER_PRO: f64 = 2.5f64;

pub const FX_MSG_MAX_NUMBER: usize = 100;

pub const DEFAULT_TX_TIMEOUT_HEIGHT: u32 = 0u32;

pub fn get_gas_price_multiplier() -> f64 {
    return match std::env::var("FX_GAS_LIMIT_MULTIPLIER") {
        Ok(gas_price) => {
            gas_price.parse().unwrap_or(GAS_LIMIT_MULTIPLIER)
        }
        _ => {
            GAS_LIMIT_MULTIPLIER
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_gas_price_multiplier() {
        env_logger::builder().filter_level(log::LevelFilter::Debug).init();
        std::env::set_var("FX_GAS_LIMIT_MULTIPLIER", "1.2");

        let gas_price = get_gas_price_multiplier();
        println!("{}", gas_price);
    }
}
