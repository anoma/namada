# 1) Environment setup
<!--  - *NOTE*: if you don't want to build namada you can download the binaries from [HERE](https://github.com/anoma/namada/releases/tag/v0.8.1). -->
- Export the following variables:
    ```bash
    export NAMADA_TAG=v0.13.0
    export TM_HASH=v0.1.4-abciplus
    ```

## Installing Namada
- Clone namada repository and build binaries
    ```bash
    git clone https://github.com/anoma/namada && cd namada && git checkout $NAMADA_TAG
    ```
- Build binaries
    - `make build-release`
        - There may be some additional requirements you may have to install (linux):
            ```bash
            sudo apt-get update -y
            sudo apt-get install build-essential make pkg-config libssl-dev libclang-dev -y
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
            ```

## Installing Tendermint
- Install the heliaxdev/tendermint fork
    ```bash
    git clone https://github.com/heliaxdev/tendermint && cd tendermint && git checkout $TM_HASH
    make build
    ```
    The above requires that golang is correctly installed with the correct $PATH setup
    - In linux, this can be resolved by
    - `sudo snap install go --channel=1.18/stable --classic`
- Copy both the namada and tendermint binaries to somewhere on $PATH (or uselol the relative paths) 
    - This step may or may not be necessary
    - namada binaries can be found in `/target/release`
    - tendermint is in `build/tendermint`

## Check ports
- Open ports on your machine:
    - 26656
    - 26657
    - To check if ports are open you can setup a simple server and curl the port from another host
        - Inside the namada folder, run 
        ``` bash
        { printf 'HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n' "$(wc -c < namada)"; cat namada; } | nc -l $PORT`
        ```
        - From another host run one of the two commands:
            - `nmap $IP -p$PORT`
            - `curl $IP:$PORT >/dev/null`

## Verifying your installation
- Make sure you are using the correct tendermint version
    - `tendermint version` should output `0.1.4-abciplus`
- Make sure you are using the correct Namada version
    - `namada --version` should output `Namada v0.13.0`
