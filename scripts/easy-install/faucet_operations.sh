#!/bin/bash

request_tokens() {

    # Check Sync Status
    if [[ "$SYNC_STATUS" == "true" ]]; then
        echo ""
        echo "Your node is synchronizing. You won't be able to execute token requests until your node finishes synchronization"
        echo "After synchronization is complete, you will be able to interact with commands to request tokens"
        echo ""
        read -p "Press any key to continue..."
        return
    fi

    if [[ -z "$WALLET_ADDRESS" ]]; then
        WALLET_ADDRESS=$(namadac balance --owner $WALLET_NAME --token NAM | grep "No nam balance found" | awk '{print $NF}')
        if [[ ! -z "$WALLET_ADDRESS" ]]; then
            sed -i '/export WALLET_ADDRESS=/d' $HOME/.bash_profile
            echo "export WALLET_ADDRESS=\"$WALLET_ADDRESS\"" >> $HOME/.bash_profile
            source $HOME/.bash_profile
        fi
    fi

    while true; do
        echo "1. Request Tokens to Wallet Address ($WALLET_ADDRESS)"
        
        if [[ ! -z "$VALIDATOR_ADDRESS" ]]; then
            echo "2. Request Tokens to Validator Address ($VALIDATOR_ADDRESS)"
        fi
        
        echo "3. Return to Main Menu"
        
        read -p "Enter your choice: " faucet_choice
        
        case $faucet_choice in
            1)
                echo "Requesting Tokens to Wallet Address ($WALLET_ADDRESS)..."
                namadac transfer --token NAM --amount 1000 --source faucet --target $WALLET_NAME --signing-keys $WALLET_NAME
                echo "Tokens requested successfully!"
                read -p "Press any key to continue..."
                ;;
            2)
                if [[ ! -z "$VALIDATOR_ADDRESS" ]]; then
                    echo "Requesting Tokens to Validator Address ($VALIDATOR_ADDRESS)..."
                    namadac transfer --token NAM --amount 1000 --source faucet --target $MONIKER --signing-keys $WALLET_NAME
                    echo "Tokens requested successfully!"
                    read -p "Press any key to continue..."
                else
                    echo "Validator address is not set."
                    read -p "Press any key to continue..."
                fi
                ;;
            3)
                break
                ;;
            *)
                echo "Invalid choice!"
                read -p "Press any key to continue..."
                ;;
        esac
    done
}

request_tokens
