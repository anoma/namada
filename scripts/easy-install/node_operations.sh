#!/bin/bash

while true; do
    clear
    echo "===================== Node Operations Menu ======================="
    echo "                                                                  "
    echo "1. Install Node"
    echo "2. Uninstall Node"
    echo "3. Restart Node"
    echo "4. Return to Main Menu"
    echo "=================================================================="
    read -p "Enter your choice: " node_choice

    case $node_choice in
        1)
            installNode() {
                echo "======================== Node Installation ==============================="

                # User set Moniker
                read -p "Do you want to launch a validator? (yes/no): " choice
                
                if [ "$choice" == "yes" ]; then
                    read -p "Set Validator Moniker: " input_moniker
                    if [ -z "$input_moniker" ]; then
                        echo "Moniker cannot be empty!"
                        exit 1
                    fi
                    MONIKER="$input_moniker"
                    echo "Moniker set to: $MONIKER"
                else
                    echo "You chose to install a node without a validator."
     
                fi

                # User set Wallet
                read -p "Set wallet name: " input_wallet_name
                if [ -z "$input_wallet_name" ]; then
                    echo "Wallet name cannot be empty!"
                    return
                fi
                WALLET_NAME=$input_wallet_name
                echo "Wallet name set to: $WALLET_NAME"

                # User set CHAIN_ID
                echo "Would you like to use the default Chain ID 'public-testnet-12.fedec12f3428'? (y/n)"
                read choice

                if [[ $choice == "y" || $choice == "Y" ]]; then
                    CHAIN_ID="public-testnet-12.fedec12f3428"
                else
                    echo "Please enter the name of Chain ID:"
                    read CHAIN_ID
                fi

                echo "Selected network: $CHAIN_ID"

                # Set var in profile
                if [ -n "$MONIKER" ]; then
                sed -i "/MONIKER=/d" "$HOME/.bash_profile"
                echo "MONIKER variable removed from .bash_profile"
                fi
                sed -i "/CHAIN_ID=/d" $HOME/.bash_profile
                sed -i "/WALLET_NAME=/d" $HOME/.bash_profile
                if [ -n "$MONIKER" ]; then
                echo "export MONIKER=$MONIKER" >> "$HOME/.bash_profile"
                fi
                echo "export CHAIN_ID=$CHAIN_ID" >> $HOME/.bash_profile
                echo "export WALLET_NAME=$WALLET_NAME" >> $HOME/.bash_profile

                # Res profile
                source $HOME/.bash_profile

                # Start installing
                echo "Starting installation..."

                # Install dependencies
                echo "Installing main dependencies..."
                sudo apt update &>/dev/null
                sudo apt upgrade -y &>/dev/null
                sudo apt install curl tar wget clang pkg-config git make libssl-dev libclang-dev libclang-12-dev jq build-essential bsdmainutils ncdu gcc git-core chrony liblz4-tool uidmap dbus-user-session protobuf-compiler unzip -y &>/dev/null


                # Go
                if ! [ -x "$(command -v go)" ]; then
                    echo "Installing Go..."
                    ver="1.19.4"
                    wget "https://golang.org/dl/go$ver.linux-amd64.tar.gz" &>/dev/null
                    sudo rm -rf /usr/local/go
                    sudo tar -C /usr/local -xzf "go$ver.linux-amd64.tar.gz" &>/dev/null
                    rm "go$ver.linux-amd64.tar.gz"
                    echo "export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin" >> ~/.bash_profile
                    source ~/.bash_profile
                    echo " "
                    echo "Installed Go version: $(go version)"
                    echo " "
                fi

                # Set var
                echo "Configuring environment variables..."
                sed -i '/public-testnet/d' "$HOME/.bash_profile"
                sed -i '/NAMADA_TAG/d' "$HOME/.bash_profile"
                sed -i '/WALLET_ADDRESS/d' "$HOME/.bash_profile"
                sed -i '/CBFT/d' "$HOME/.bash_profile"
                echo "export NAMADA_TAG=$(curl -s https://api.github.com/repos/anoma/namada/releases/latest | jq -r .tag_name)" >> ~/.bash_profile
                echo "export BASE_DIR=$HOME/.local/share/namada" >> ~/.bash_profile

                echo "Downloading and installing Namada..."
                NAMADA_TAG=$(curl -s https://api.github.com/repos/anoma/namada/releases/latest | jq -r .tag_name)
                NAMADA_URL="https://github.com/anoma/namada/releases/download/$NAMADA_TAG/namada-$NAMADA_TAG-Linux-x86_64.tar.gz"
                curl -L -o namada.tar.gz $NAMADA_URL
                tar -xzf namada.tar.gz --strip-components=1 -C /usr/local/bin/ namada-$NAMADA_TAG-Linux-x86_64/namada
                tar -xzf namada.tar.gz --strip-components=1 -C /usr/local/bin/ namada-$NAMADA_TAG-Linux-x86_64/namadac
                tar -xzf namada.tar.gz --strip-components=1 -C /usr/local/bin/ namada-$NAMADA_TAG-Linux-x86_64/namadan
                tar -xzf namada.tar.gz --strip-components=1 -C /usr/local/bin/ namada-$NAMADA_TAG-Linux-x86_64/namadaw
                rm namada.tar.gz
                echo "Namada $NAMADA_TAG installed successfully!"

                # Download and install Cometbft
                CBFT_TAG=$(curl -s https://api.github.com/repos/cometbft/cometbft/releases/latest | jq -r .tag_name)
                CBFT_URL="https://github.com/cometbft/cometbft/releases/download/$CBFT_TAG/cometbft_${CBFT_TAG#v}_linux_amd64.tar.gz"
                curl -L -o cometbft.tar.gz $CBFT_URL
                tar -xzf cometbft.tar.gz -C /usr/local/bin/ cometbft
                rm cometbft.tar.gz
                echo "Cometbft $CBFT_TAG installed successfully!"

                # Check and set dir
                if [ ! -d "/usr/local/bin" ]; then
                    sudo mkdir -p /usr/local/bin
                fi

                # Check ver
                cometbft_version=$(cometbft version)
                namada_version=$(namada --version)
                echo "Installed cometbft version: $cometbft_version"
                echo "Installed namada version: $namada_version"
                # Set service
                if [ ! -f "/etc/systemd/system/namadad.service" ]; then
                    echo "Creating service file..."
                    sudo tee /etc/systemd/system/namadad.service > /dev/null <<EOF
                [Unit]
                Description=namada
                After=network-online.target
                [Service]
                User=$USER
                WorkingDirectory=$HOME/.local/share/namada
                Environment=TM_LOG_LEVEL=p2p:none,pex:error
                Environment=NAMADA_CMT_STDOUT=true
                ExecStart=/usr/local/bin/namada node ledger run 
                StandardOutput=syslog
                StandardError=syslog
                Restart=always
                RestartSec=10
                LimitNOFILE=65535
                [Install]
                WantedBy=multi-user.target
                EOF

                    sudo systemctl daemon-reload &>/dev/null
                    sudo systemctl enable namadad &>/dev/null

                    echo "Service file successfully created and enabled!"
                else
                    echo "Service file namadad.service already exists. Proceeding to the next step."
                fi

                # Join in network
                echo "Joining the network..."
                namada client utils join-network --chain-id $CHAIN_ID

                # Start namadad
                echo "Starting namadad service..."
                sudo systemctl start namadad

                # Check status
                sed -i '/export SERVICE_STATUS=/d' $HOME/.bash_profile
                SERVICE_STATUS=$(sudo systemctl is-active namadad.service)
                echo "export SERVICE_STATUS=$SERVICE_STATUS" >> $HOME/.bash_profile

                if [[ "$SERVICE_STATUS" == "active" ]]; then
                    echo "Service status: Active"
                else
                    echo "Service status: Inactive"
                fi

                # Must get info for cont
                while [[ "$SERVICE_STATUS" != "active" ]]; do
                    sleep 5
                    SERVICE_STATUS=$(sudo systemctl is-active namadad.service)
                done

                # Sync check
                sed -i '/export SYNC_STATUS=/d' $HOME/.bash_profile
                SYNC_STATUS=$(curl -s localhost:26657/status | jq -r '.result.sync_info.catching_up')
                echo "export SYNC_STATUS=$SYNC_STATUS" >> $HOME/.bash_profile

                # Must get info for cont
                while [[ "$SYNC_STATUS" != "true" ]]; do
                    sleep 5
                    SYNC_STATUS=$(curl -s localhost:26657/status | jq -r '.result.sync_info.catching_up')
                done
                # Check color info
                if [[ "$SYNC_STATUS" == "true" ]]; then
                    echo -e "Sync status: \e[31mIn progress\e[0m"  # RED
                else
                    echo -e "Sync status: \e[32mSynced\e[0m"  # GREEN
                fi

                # Check block
                sed -i '/export NODE_BLOCK_HEIGHT=/d' $HOME/.bash_profile
                NODE_BLOCK_HEIGHT=$(curl -s localhost:26657/status | jq -r '.result.sync_info.latest_block_height')
                echo "export NODE_BLOCK_HEIGHT=$NODE_BLOCK_HEIGHT" >> $HOME/.bash_profile
                echo "Block height: $NODE_BLOCK_HEIGHT"

                namada wallet address gen --alias $WALLET_NAME --unsafe-dont-encrypt

                echo "Installation completed successfully!"
                echo " "
                echo "PLEASE NOTE!"
                echo "You can proceed with further actions after the node is fully synchronized."
                echo "Synchronization status you can check in the Node Status Check menu"
                echo "To successfully initialize your validator, you first need to request tokens to your wallet and then delegate those tokens to your validator"
            }

            installNode
            read -p "Press any key to continue..."
            ;;
        2)
            uninstallNode() {
                echo "======================== Node Uninstallation =============================="

                # Stop and disable service
                sudo systemctl stop namadad &>/dev/null
                sudo systemctl disable namadad &>/dev/null
                sudo rm -rf $HOME/.local/share/namada

                # Delete service
                sudo rm -f /etc/systemd/system/namadad.service

                # Delete directory
                rm -rf ~/namada &>/dev/null
                rm -rf ~/cometbft &>/dev/null

                # Unset variables from bash profile
                if [[ -e $HOME/.bash_profile ]]; then
                    sed -i '/MONIKER=/d' $HOME/.bash_profile &>/dev/null
                    sed -i '/CHAIN_ID=/d' $HOME/.bash_profile &>/dev/null
                    sed -i '/NAMADA_TAG=/d' $HOME/.bash_profile &>/dev/null
                    sed -i '/CBFT=/d' $HOME/.bash_profile &>/dev/null
                    sed -i '/WALLET_NAME=/d' $HOME/.bash_profile &>/dev/null
                    sed -i '/SERVICE_STATUS=/d' $HOME/.bash_profile &>/dev/null
                    sed -i '/NODE_BLOCK_HEIGHT=/d' $HOME/.bash_profile &>/dev/null
                    sed -i '/VALIDATOR_BOND=/d' $HOME/.bash_profile &>/dev/null
                    sed -i '/WALLET_BALANCE=/d' $HOME/.bash_profile &>/dev/null
                    sed -i '/WALLET_ADDRES=/d' $HOME/.bash_profile &>/dev/null
                    sed -i '/VALIDATOR_ADDRES=/d' $HOME/.bash_profile &>/dev/null
                    sed -i '/SYNC_STATUS=/d' $HOME/.bash_profile &>/dev/null
                fi

                # Unset variables from session
                unset MONIKER
                unset CHAIN_ID
                unset NAMADA_TAG
                unset WALLET_NAME
                unset CBFT
                unset SERVICE_STATUS
                unset NODE_BLOCK_HEIGHT
                unset VALIDATOR_BOND
                unset WALLET_BALANCE
                unset WALLET_ADDRES
                unset VALIDATOR_ADDRES
                unset SYNC_STATUS

                if [[ -e "/usr/local/bin/cometbft" || -e "/usr/local/bin/namada" || -e "/usr/local/bin/namadaWc" || -e "/usr/local/bin/namadan" || -e "/usr/local/bin/namadaw" ]]; then
                    sudo rm -f /usr/local/bin/cometbft
                    sudo rm -f /usr/local/bin/namada
                    sudo rm -f /usr/local/bin/namadac
                    sudo rm -f /usr/local/bin/namadan
                    sudo rm -f /usr/local/bin/namadaw

                    if [[ $? -eq 0 ]]; then
                        echo "Uninstallation completed successfully!"
                    else
                        echo "There was an error during the uninstallation process!"
                    fi
                else
                    echo "Node is not installed!"
                fi
            }

            uninstallNode
            read -p "Press any key to continue..."
            ;;
        3)
            restart_node() {
                echo "Restarting Node..."
                sudo systemctl restart namadad
                echo "Node successfully restarted"
            }

            restart_node
            read -p "Press any key to continue..."
            ;;
        4)
            echo "Returning to Main Menu..."
            break
            ;;
        *)
            echo "Invalid choice, please select from the given options."
            ;;
    esac
done
