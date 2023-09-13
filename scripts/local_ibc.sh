
# Get the absolute path of the directory this script is in
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $SCRIPT_DIR
cd ../
NAMADA_DIR=$(pwd)
NAMADA_BIN_DIR=$NAMADA_DIR/target/debug/


cd $NAMADA_DIR

NAMADAW=$NAMADA_BIN_DIR/namadaw
NAMADAC=$NAMADA_BIN_DIR/namadac
NAMADA=$NAMADA_BIN_DIR/namada

mkdir -p base_dir_temp_1
mkdir -p base_dir_temp_2

. $SCRIPT_DIR/build_network.sh $NAMADA_BIN_DIR $NAMADA_DIR/base_dir_temp_1 > /dev/null 2>&1

. $SCRIPT_DIR/build_network.sh $NAMADA_BIN_DIR $NAMADA_DIR/base_dir_temp_2 > /dev/null 2>&1

# Grab the respective chain ids
CHAIN_ID_A=$(cat $NAMADA_DIR/base_dir_temp_1/global-config.toml | grep chain_id | cut -d'=' -f2 | tr -d ' ' | tr -d '"')
CHAIN_ID_B=$(cat $NAMADA_DIR/base_dir_temp_2/global-config.toml | grep chain_id | cut -d'=' -f2 | tr -d ' ' | tr -d '"')

echo "Chain id a is: $CHAIN_ID_A"
echo "Chain id b is: $CHAIN_ID_B"

# Generate the relayer keys
$NAMADAW --base-dir $NAMADA_DIR/base_dir_temp_1 key gen --alias relayer --unsafe-dont-encrypt > /dev/null 2>&1
$NAMADAW --base-dir $NAMADA_DIR/base_dir_temp_2 key gen --alias relayer --unsafe-dont-encrypt > /dev/null 2>&1

# Copy chain id directories to namada_wallet
cd $NAMADA_DIR
mkdir -p namada_wallet

BASE_DIR_A=$NAMADA_DIR/base_dir_temp_1
BASE_DIR_B=$NAMADA_DIR/base_dir_temp_2

cp -r $BASE_DIR_A/$CHAIN_ID_A $NAMADA_DIR/namada_wallet/
cp -r $BASE_DIR_B/$CHAIN_ID_B $NAMADA_DIR/namada_wallet/

# Make the hermes config
mkdir hermes_config
touch hermes_config/config.toml

python3 $SCRIPT_DIR/make_hermes_config.py $CHAIN_ID_A $CHAIN_ID_B

# Check that hermes config was made
if [ ! -f $NAMADA_DIR/hermes_config/config.toml ]; then
    echo "Hermes config was not generated successfully"
    exit 1
fi

# Start chain b temporarily
echo "starting chain B temporarily"
$NAMADA --base-dir $BASE_DIR_B ledger run > /dev/null 2>&1 &
pid=$!
sleep 5
kill ${pid}



# Replace the default port number for instance B

cat $BASE_DIR_B/${CHAIN_ID_B}/config.toml \
  | sed \
  -e "s/127.0.0.1:26657/127.0.0.1:27657/g" \
  -e "s/127.0.0.1:26658/127.0.0.1:27658/g" \
  -e "s/0.0.0.0:26656/0.0.0.0:27656/g" \
  -e "s/127.0.0.1:26661/127.0.0.1:27661/g" \
  > tmp.toml
mv tmp.toml ${BASE_DIR_B}/${CHAIN_ID_B}/config.toml
cat ${BASE_DIR_B}/${CHAIN_ID_B}/cometbft/config/config.toml \
  | sed \
  -e "s/127.0.0.1:26658/127.0.0.1:27658/g" \
  -e "s/127.0.0.1:26657/127.0.0.1:27657/g" \
  -e "s/0.0.0.0:26656/0.0.0.0:27656/g" \
  -e "s/127.0.0.1:26661/127.0.0.1:27661/g" \
  > tmp.toml
mv tmp.toml ${BASE_DIR_B}/${CHAIN_ID_B}/cometbft/config/config.toml


# Start the chains
echo "start chain A by running the following command:"
echo "$NAMADA --base-dir $NAMADA_DIR/base_dir_temp_1 ledger run"
echo "start chain B by running the following command:"
echo "$NAMADA --base-dir $NAMADA_DIR/base_dir_temp_2 ledger run"

echo "Clean up by running the following commands:"
echo "rm -rf $NAMADA_DIR/base_dir_temp* & rm -rf $NAMADA_DIR/hermes_config & rm -rf $NAMADA_DIR/namada_wallet"


