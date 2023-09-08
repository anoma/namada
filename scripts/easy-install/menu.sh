#!/bin/bash
clear

if [[ ! -f "$HOME/.bash_profile" ]]; then
    touch "$HOME/.bash_profile"
fi

if [ -f "$HOME/.bash_profile" ]; then
    source $HOME/.bash_profile
fi

max_label_width=20

print_variable() {
    local label=$1
    local value=$2
    printf "%-${max_label_width}s %s\n" "$label:" "$value"
}

RED="\033[1;31m"
GREEN="\033[1;32m"
RESET="\033[0m"

print_colored_variable() {
    local label=$1
    local value=$2

    if [[ "$value" == "NOT SET" ]]; then
        printf "%-20s %b%s%b\n" "$label:" $RED "$value" $RESET
    else
        printf "%-20s %b%s%b\n" "$label:" $GREEN "$value" $RESET
    fi
}

clear_logo() {
    clear

    cat << "EOF"
___      ___       _     ___       ___      _     ________        _      
`MM\     `M'      dM.    `MMb     dMM'     dM.    `MMMMMMMb.     dM.     
 MMM\     M      ,MMb     MMM.   ,PMM     ,MMb     MM    `Mb    ,MMb     
 M\MM\    M      d'YM.    M`Mb   d'MM     d'YM.    MM     MM    d'YM.    
 M \MM\   M     ,P `Mb    M YM. ,P MM    ,P `Mb    MM     MM   ,P `Mb    
 M  \MM\  M     d'  YM.   M `Mb d' MM    d'  YM.   MM     MM   d'  YM.   
 M   \MM\ M    ,P   `Mb   M  YM.P  MM   ,P   `Mb   MM     MM  ,P   `Mb   
 M    \MM\M    d'    YM.  M  `Mb'  MM   d'    YM.  MM     MM  d'    YM.  
 M     \MMM   ,MMMMMMMMb  M   YP   MM  ,MMMMMMMMb  MM     MM ,MMMMMMMMb  
 M      \MM   d'      YM. M   `'   MM  d'      YM. MM    .M9 d'      YM. 
_M_      \M _dM_     _dMM_M_      _MM_dM_     _dMM_MMMMMMM9_dM_     _dMM_

Smart script for NAMADA node
Developed by [NODERS]TEAM

EOF
}

display_information() {
    # UPDATE SERVICE_STATUS
    if grep -q '^export SERVICE_STATUS=' $HOME/.bash_profile; then
        sed -i '/export SERVICE_STATUS=/d' $HOME/.bash_profile
    fi
    SERVICE_STATUS=$(sudo systemctl is-active namadad.service)
    echo "export SERVICE_STATUS=$SERVICE_STATUS" >> $HOME/.bash_profile

    # UPDATE SYNC_STATUS
    if grep -q '^export SYNC_STATUS=' $HOME/.bash_profile; then
        sed -i '/export SYNC_STATUS=/d' $HOME/.bash_profile
    fi
    SYNC_STATUS=$(curl -s localhost:26657/status | jq -r '.result.sync_info.catching_up')
    echo "export SYNC_STATUS=$SYNC_STATUS" >> $HOME/.bash_profile

    # UPDATE NODE_BLOCK_HEIGHT
    if grep -q '^export NODE_BLOCK_HEIGHT=' $HOME/.bash_profile; then
        sed -i '/export NODE_BLOCK_HEIGHT=/d' $HOME/.bash_profile
    fi
    NODE_BLOCK_HEIGHT=$(curl -s localhost:26657/status | jq -r '.result.sync_info.latest_block_height')
    echo "export NODE_BLOCK_HEIGHT=$NODE_BLOCK_HEIGHT" >> $HOME/.bash_profile

    # Display status and balances
    if [[ ! -z "$MONIKER" ]]; then
        print_colored_variable "Validator moniker" "$MONIKER"
        
        if [[ ! -z "$VALIDATOR_ADDRESS" ]]; then
            print_colored_variable "Validator address" "$VALIDATOR_ADDRESS"
            
            balance_output_validator=$(namada client balance --owner $MONIKER --token NAM)
            VALIDATOR_BALANCE=$(echo $balance_output_validator | awk '{print $2}')

            if [[ $VALIDATOR_BALANCE =~ ^[0-9.]+$ ]]; then
                if (( $(echo "$VALIDATOR_BALANCE > 0" | bc -l) )); then
                    echo "Validator balance:   $VALIDATOR_BALANCE NAM"
                else
                    echo "Validator balance:   0 NAM"
                fi
            else
                echo "Validator balance:   0 NAM"
            fi
        fi
        
        echo ""

        if [[ ! -z "$WALLET_NAME" ]]; then
            print_colored_variable "Wallet name" "$WALLET_NAME"
        fi
        
        if [[ ! -z "$WALLET_ADDRESS" ]]; then
            print_colored_variable "Wallet address" "$WALLET_ADDRESS"

            if [[ "$SYNC_STATUS" == "false" ]]; then
                balance_output_wallet=$(namada client balance --owner $WALLET_NAME --token NAM)
                WALLET_BALANCE=$(echo $balance_output_wallet | awk '{print $2}')

                if [[ $WALLET_BALANCE =~ ^[0-9.]+$ ]]; then
                    echo "Wallet balance:      $WALLET_BALANCE NAM"
                else
                    echo "Wallet balance:      0 NAM"
                fi
            fi
        fi
        
        if [[ ! -z "$VALIDATOR_BOND" ]]; then
            print_colored_variable "Validator bond" "$VALIDATOR_BOND"
        fi
        
        echo ""
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

clear_logo
display_information

#!/bin/bash

while true; do
    echo "                                                                         "
    echo "================== Namada Node Installation Menu ========================"
    echo "                                                                         "
    echo "1. Node (Install, Uninstall, Restart)"
    echo "2. Node Status Check (Logs, Error Journal, Service Status)"
    echo "3. Validator (Check Balance, Init validator, Check Staking, Delegate (From wallet and validator address)"
    echo "4. Faucet (Request Tokens)"
    echo "5. User Cli (Docs link)"
    echo "6. Exit"
    echo "                                                                         "
    echo "========================================================================="
    read -p "Please enter the number corresponding to your choice: " main_choice

    case $main_choice in
        1)
            # Node (Install, Uninstall, Restart)
            source ./node_operations.sh
            clear_logo
            display_information
            ;;
        2)
            # Node Status Check (Logs, Error Journal, Service Status)
            source ./node_status_check.sh
            clear_logo
            display_information
            ;;
        3)
            # Validator (Check Balance, Init validator, Check Staking, Delegate)
            source ./validator_operations.sh
            clear_logo
            display_information
            ;;
        4)
            # Faucet (Request Tokens)
            source ./faucet_operations.sh
            clear_logo
            display_information
            ;;
        5)
            # User Cli (Docs link)
            echo "If you want to learn more about interacting with Namada through the CLI, you can visit the official documentation page for Namada at:"
            echo -e "\e[5m\e[34mhttps://docs.namada.net/users\e[0m"

            read -p "Press any key to continue..."
            clear_logo
            display_information
            ;;
        6)
            echo "Exiting the menu."
            sleep 2
            clear
            break
            ;;
        *)
            echo "Invalid choice, please select from the given options."
            ;;
    esac
done
