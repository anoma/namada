#!/bin/bash

while true; do
    clear
    echo "===================== Validator Operations Menu ======================"
    echo "                                                                      "
    echo "1. Check Balance"
    echo "2. Init validator"
    echo "3. Check Staking Status"
    echo "4. Delegate from Balance"
    echo "5. Return to Main Menu"
    echo "====================================================================="
    read -p "Enter your choice: " validator_choice

    case $validator_choice in
        1)
            echo "Checking Balance..."
            if [[ "$SYNC_STATUS" == "true" ]]; then
                echo "Node synchronization is in progress. Balance check is not possible."
            else
                echo "Checking Balance..."
                check_balance() {
                    balance_output=$(namada client balance --owner $WALLET_NAME --token NAM)
                    WALLET_BALANCE=$(echo $balance_output | awk '{print $2}')
                    echo "Wallet balance: $WALLET_BALANCE NAM"
                }
                check_balance
            fi
            read -p "Press any key to continue..."
            ;;
        2)
            if [[ "$SYNC_STATUS" == "true" ]]; then
                echo "Node synchronization is in progress. Validator initialization is not possible."
            else
                init_validator() {
                    echo "Initing validator..."
                    
                    # Run the command to init the validator
                    init_result=$(namada client init-validator \
                        --alias $MONIKER \
                        --account-keys $WALLET_NAME \
                        --signing-keys $WALLET_NAME \
                        --commission-rate 0.05 \
                        --max-commission-rate-change 0.01)
                    
                    # Extract the validator address from the VPs result
                    VALIDATOR_ADDRES=$(echo $init_result | grep -oE "atest1[0-9a-z]+" | tail -1)
                    
                    if [[ ! -z "$VALIDATOR_ADDRESS" ]]; then
                        # Save the validator address to VALIDATOR_ADDRESS variable
                        sed -i '/export VALIDATOR_ADDRESS=/d' $HOME/.bash_profile
                        echo "export VALIDATOR_ADDRESS=\"$VALIDATOR_ADDRESS\"" >> $HOME/.bash_profile
                        echo "Validator address initialized: $VALIDATOR_ADDRESS"
                    else
                        echo "Failed to retrieve validator address. Initialization unsuccessful."
                    fi
                }
                init_validator
            fi
            read -p "Press any key to continue..."
            ;;
        3)
            if [[ "$SYNC_STATUS" == "true" ]]; then
                echo "Node synchronization is in progress. Staking status check is not possible."
            else
                check_staking_status() {
                    echo "Checking Staking Status..."
                    staking_output_moniker=$(namada client bonds --owner $MONIKER)
                    staking_output_wallet=$(namada client bonds --owner $WALLET_NAME)
                    LAST_COMMITTED_EPOCH=$(echo "$staking_output_moniker" | awk '/Last committed epoch:/ {print $4}')
                    VALIDATOR_BOND_MONIKER=$(echo "$staking_output_moniker" | awk '/All bonds total:/ {print $4}')
                    VALIDATOR_BOND_WALLET=$(echo "$staking_output_wallet" | awk '/All bonds total:/ {print $4}')
                    VALIDATOR_BOND=$(echo "$VALIDATOR_BOND_MONIKER + $VALIDATOR_BOND_WALLET" | bc)
                    
                    if [[ ! -z "$VALIDATOR_BOND" ]]; then
                        echo "Last committed epoch: $LAST_COMMITTED_EPOCH"
                        echo "All bonds total: $VALIDATOR_BOND"
                    else
                        echo "Staking status information is not available"
                    fi
                }
                check_staking_status
            fi
            read -p "Press any key to continue..."
            ;;
        4)
            echo "Delegating from Balance..."
            if [[ "$SYNC_STATUS" == "true" ]]; then
                echo "Node synchronization is in progress. Delegation is not possible."
            else
                echo "Delegating from Balance..."
                delegate_tokens() {
                    if [[ ! -z "$MONIKER" ]]; then
                        echo "1. Delegating from Wallet Address"
                        echo "2. Delegating from Validator Address"
                        read -p "Enter your choice: " delegation_choice
                        
                        if [[ $delegation_choice == "1" ]]; then
                            print_variable "Wallet address" "$WALLET_ADDRESS"
                            print_variable "Wallet balance" "${WALLET_BALANCE:-NOT AVAILABLE}"
                            
                            if [[ "$SYNC_STATUS" == "false" ]]; then
                                read -p "Enter the amount to delegate: " DELEGATION_AMOUNT
                                
                                if [[ $DELEGATION_AMOUNT =~ ^[0-9.]+$ ]]; then
                                    namada client bond \
                                        --source $WALLET_NAME \
                                        --validator $MONIKER \
                                        --amount $DELEGATION_AMOUNT \
                                        --signing-keys $WALLET_NAME
                                else
                                    echo "Invalid input. Delegation amount must be a positive number."
                                fi
                            else
                                echo "Node synchronization is in progress. Delegation is not possible."
                            fi
                        elif [[ $delegation_choice == "2" ]]; then
                            if [[ ! -z "$VALIDATOR_ADDRESS" ]]; then
                                print_variable "Validator address" "$VALIDATOR_ADDRESS"
                                print_variable "Validator balance" "${VALIDATOR_BALANCE:-NOT AVAILABLE}"
                                
                                if [[ "$SYNC_STATUS" == "false" ]]; then
                                    read -p "Enter the amount to delegate: " DELEGATION_AMOUNT
                                    
                                    if [[ $DELEGATION_AMOUNT =~ ^[0-9.]+$ ]]; then
                                        namada client bond \
                                            --validator $MONIKER \
                                            --amount $DELEGATION_AMOUNT
                                    else
                                        echo "Invalid input. Delegation amount must be a positive number."
                                    fi
                                else
                                    echo "Node synchronization is in progress. Delegation is not possible."
                                fi
                            else
                                echo "Validator address is not set. Delegation is not possible."
                            fi
                        else
                            echo "Invalid choice!"
                        fi
                    else
                        echo "Validator information is not available. Delegation is not possible."
                    fi
                }
                delegate_tokens
            fi
            read -p "Press any key to continue..."
            ;;
        5)
            echo "Returning to Main Menu..."
            break
            ;;
        *)
            echo "Invalid choice, please select from the given options."
            read -p "Press any key to continue..."
            ;;
    esac
done
