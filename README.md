# f(x)Core Chain - Ethereum

### Use

```shell script
make install
```

```
$ fxeth bridge --help
responsible for event on signature the f(x)Core and the Ethereum

USAGE:
    fxeth bridge [OPTIONS] --fx-chain-key <FX_CHAIN_KEY> --ethereum-key <ETHEREUM_KEY> --bridge-addr <BRIDGE_ADDR>

OPTIONS:
        --bridge-addr <BRIDGE_ADDR>
            f(x)Core Bridge contract address

        --eth-block-number <ETH_BLOCK_NUMBER>
            Ethereum start block number [default: 0]

        --ethereum-key <ETHEREUM_KEY>
            f(x)Core validator Ethereum private key

        --ethereum-pwd <ETHEREUM_PWD>
            f(x)Core validator Ethereum private key password [default: /root/eth.password]

        --ethereum-rpc <ETHEREUM_RPC>
            Ethereum RPC address [default: http://127.0.0.1:9090]

        --fees <FEES>
            f(x)Core send transactions fee [default: FX]

        --fx-chain-grpc <FX_CHAIN_GRPC>
            f(x)Core gRPC address [default: http://127.0.0.1:9090]

        --fx-chain-key <FX_CHAIN_KEY>
            f(x)Core validator private key

        --fx-chain-pwd <FX_CHAIN_PWD>
            f(x)Core validator private key password [default: /root/fx.password]

    -h, --help
            Print help information
```
