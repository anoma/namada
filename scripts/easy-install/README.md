![NAMADA](https://github.com/nodersteam/picture/blob/main/1_TRTbBismx0_kdvoGZz8-8g.gif?raw=true)

# NAMADA Node Installation Menu

This is a smart script developed by the [NODERS]TEAM to simplify the management and monitoring of the NAMADA node.

## Features

### 1. **Monitoring**
The script automatically fetches and showcases:
- **Validator Details**: Moniker, address, and balance.
- **Wallet Information**: Name, address, and balance.
- **Node Block Height**: Current block height.
- **Synchronization Status**: Displays if the node is still syncing or if it's already synchronized.
- **Service Status**: Indicates if the service is active or not.

### 2. **Main Management Menu**
- **Node Management**: Options to install, uninstall, or restart the node.
- **Node Status Check**: Features for checking the node logs, error journal, and service status.
- **Validator Management**: Tools to check the validator's balance, initialize the validator, inspect staking, and facilitate delegation from the wallet or validator's address.
- **Token Request**: A function to request tokens.
- **Exit**: Option to close the script.

## Getting Started
<pre>
sudo apt-get update
sudo apt-get install subversion
svn export https://github.com/anoma/namada/trunk/scripts/easy-install
</pre>

## Usage
To start the script, navigate to the directory containing the script and run:

<pre>
cd namadascript
. menu.sh
</pre>

![image](https://github.com/nodersteam/noderslabs/assets/94483941/6cdd90c7-eedc-46d4-8d54-97a455ed9b19)

## Initial installation

1. Node installation. Set wallet and validator name. (Point 1) 
2. Be sure to wait for complete synchronization
3. Validator initialization (Point 3)
4. After full synchronization, you will have the functionality of requesting tokens from faucet (Point 4)
5. Requesting tokens to the wallet address
6. Perform a primary bond from the wallet address (Point 3)
7. After that, you will see the full functionality of the script (Displaying information about the node and validator, bond tokens from the address of the wallet or validator)

## Support
For any issues or support, please contact [NODERS]TEAM.
