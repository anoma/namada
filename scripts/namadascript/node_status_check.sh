#!/bin/bash

while true; do
    clear
    echo "===================== Node Status Check Menu ======================"
    echo "                                                                  "
    echo "1. View Logs"
    echo "2. Error Journal"
    echo "3. Service Status"
    echo "4. Return to Main Menu"
    echo "=================================================================="
    read -p "Enter your choice: " status_choice

    case $status_choice in
        1)
            echo "Viewing Logs..."
            view_logs() {
                sudo journalctl -u namadad --no-pager -n 100 --output cat
            }
            view_logs
            read -p "Press any key to continue..."
            ;;
        2)
            echo "Viewing Error Journal..."
            view_error_journal() {
                echo "Parsing in progress..."
                
                logs=$(sudo journalctl -u namadad --no-pager | grep -E "error|warning" | tail -n 100)
            
                if [[ -n "$logs" ]]; then
                    echo "$logs"
                else
                    echo "No error or warning logs found."
                fi
            }
            view_error_journal
            read -p "Press any key to continue..."
            ;;
        3)
            view_service_status() {
                echo "Viewing Service Status..."
            
                if grep -q '^export SERVICE_STATUS=' $HOME/.bash_profile; then
                    sed -i '/export SERVICE_STATUS=/d' $HOME/.bash_profile
                fi
                SERVICE_STATUS=$(sudo systemctl is-active namadad.service)
                echo "export SERVICE_STATUS=$SERVICE_STATUS" >> $HOME/.bash_profile
            
                if grep -q '^export SYNC_STATUS=' $HOME/.bash_profile; then
                    sed -i '/export SYNC_STATUS=/d' $HOME/.bash_profile
                fi
                SYNC_STATUS=$(curl -s localhost:26657/status | jq -r '.result.sync_info.catching_up')
                echo "export SYNC_STATUS=$SYNC_STATUS" >> $HOME/.bash_profile
            
                if grep -q '^export NODE_BLOCK_HEIGHT=' $HOME/.bash_profile; then
                    sed -i '/export NODE_BLOCK_HEIGHT=/d' $HOME/.bash_profile
                fi
                NODE_BLOCK_HEIGHT=$(curl -s localhost:26657/status | jq -r '.result.sync_info.latest_block_height')
                echo "export NODE_BLOCK_HEIGHT=$NODE_BLOCK_HEIGHT" >> $HOME/.bash_profile
            
                if [[ ! -z "$MONIKER" ]]; then
                    print_variable "Validator moniker" "$MONIKER"
                    
                    if [[ ! -z "$VALIDATOR_ADDRESS" ]]; then
                        print_variable "Address" "$VALIDATOR_ADDRESS"
                    fi
                    
                    if [[ ! -z "$WALLET_NAME" ]]; then
                        print_variable "Wallet name" "$WALLET_NAME"
                    fi
                    
                    if [[ ! -z "$WALLET_ADDRESS" ]]; then
                        print_variable "Wallet address" "$WALLET_ADDRESS"
                        
                        if [[ "$SYNC_STATUS" == "false" ]]; then
                            if [[ ! -z "$WALLET_BALANCE" ]]; then
                                echo "Wallet balance:      $WALLET_BALANCE NAM"
                            else
                                echo "Wallet balance:      NOT SET"
                            fi
                        fi
                    fi
                    
                    if [[ ! -z "$VALIDATOR_BOND" ]]; then
                        print_variable "Validator bond" "$VALIDATOR_BOND"
                    fi
                    
                    print_variable "Node block height" "$NODE_BLOCK_HEIGHT"
                    
                    if [[ "$SYNC_STATUS" == "true" ]]; then
                        echo -e "Sync status:         \e[31mIn progress\e[0m"  # RED
                    else
                        echo -e "Sync status:         \e[32mSynced\e[0m"  # GREEN
                    fi
                    
                    if [[ "$SERVICE_STATUS" == "active" ]]; then
                        echo -e "Service status:      \e[32mACTIVE\e[0m"  # GREEN
                    else
                        echo -e "Service status:      \e[31mNOT ACTIVE\e[0m"  # RED
                    fi
                    
                    echo "                                                                         "
                fi
            }

            view_service_status
            read -p "Press any key to continue..."
            ;;
        4)
            echo "Returning to Main Menu..."
            break
            ;;
        *)
            echo "Invalid choice, please select from the given options."
            read -p "Press any key to continue..."
            ;;
    esac
done
