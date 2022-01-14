use web3::types::U256;

pub fn get_max_gas_price() -> U256 {
    return match std::env::var("ETH_MAX_GAS_PRICE") {
        Ok(gas_price) => {
            U256::from_dec_str(gas_price.as_str()).unwrap() * U256::from(10).pow(U256::from(9))
        }
        _ => {
            U256::from(10).pow(U256::from(9)) * 200 // 200 gwei
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_gas_price() {
        env_logger::builder().filter_level(log::LevelFilter::Debug).init();
        std::env::set_var("ETH_MAX_GAS_PRICE", "300");

        let gas_price = get_max_gas_price();
        println!("{}", gas_price);
    }
}
