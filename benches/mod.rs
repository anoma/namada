//! Benchmarks module based on criterion.
//!
//! Measurements are taken on the elapsed wall-time.
//!
//! The benchmarks only focus on sucessfull transactions and vps: in case of
//! failure, the bench function shall panic to avoid timing incomplete execution
//! paths.
//!
//! In addition, this module also contains benchmarks for
//! [`WrapperTx`][`namada::core::types::transaction::wrapper::WrapperTx`]
//! validation and [`host_env`][`namada::vm::host_env`] exposed functions that
//! define the gas constants of [`gas`][`namada::core::ledger::gas`].
//!
//! For more realistic results these benchmarks should be run on all the
//! combination of supported OS/architecture.

use std::ops::{Deref, DerefMut};

use borsh::BorshSerialize;
use masp_primitives::zip32::ExtendedFullViewingKey;
use namada::core::ledger::ibc::actions;
use namada::core::types::address::{self, Address};
use namada::core::types::key::common::SecretKey;
use namada::core::types::storage::Key;
use namada::core::types::token::{Amount, Transfer};
use namada::ibc::applications::ics20_fungible_token_transfer::msgs::transfer::MsgTransfer;
use namada::ibc::clients::ics07_tendermint::client_state::{
    AllowUpdate, ClientState,
};
use namada::ibc::clients::ics07_tendermint::consensus_state::ConsensusState;
use namada::ibc::core::ics02_client::client_consensus::AnyConsensusState;
use namada::ibc::core::ics02_client::client_state::AnyClientState;
use namada::ibc::core::ics02_client::client_type::ClientType;
use namada::ibc::core::ics02_client::trust_threshold::TrustThreshold;
use namada::ibc::core::ics03_connection::connection::{
    ConnectionEnd, Counterparty, State as ConnectionState,
};
use namada::ibc::core::ics03_connection::version::Version;
use namada::ibc::core::ics04_channel::channel::{
    ChannelEnd, Counterparty as ChannelCounterparty, Order, State,
};
use namada::ibc::core::ics04_channel::Version as ChannelVersion;
use namada::ibc::core::ics23_commitment::commitment::CommitmentRoot;
use namada::ibc::core::ics23_commitment::specs::ProofSpecs;
use namada::ibc::core::ics24_host::identifier::{
    ChainId as IbcChainId, ChannelId, ClientId, ConnectionId, PortId,
};
use namada::ibc::core::ics24_host::path::{ChannelEndsPath, ConnectionsPath};
use namada::ibc::core::ics24_host::Path as IbcPath;
use namada::ibc::signer::Signer;
use namada::ibc::timestamp::Timestamp as IbcTimestamp;
use namada::ibc::tx_msg::Msg;
use namada::ibc::Height as IbcHeight;
use namada::ibc_proto::cosmos::base::v1beta1::Coin;
use namada::ledger::gas::TxGasMeter;
use namada::ledger::queries::{
    Client, EncodedResponseQuery, RequestCtx, RequestQuery, Router, RPC,
};
use namada::proof_of_stake;
use namada::proto::Tx;
use namada::tendermint::Hash;
use namada::tendermint_proto::Protobuf;
use namada::types::address::InternalAddress;
use namada::types::chain::ChainId;
use namada::types::masp::{
    ExtendedViewingKey, PaymentAddress, TransferSource, TransferTarget,
};
use namada::types::storage::{BlockHeight, KeySeg, TxIndex};
use namada::types::time::DateTimeUtc;
use namada::types::transaction::governance::{InitProposalData, ProposalType};
use namada::types::transaction::pos::Bond;
use namada::types::transaction::GasLimit;
use namada::vm::wasm::run;
use namada_apps::cli::args::{Tx as TxArgs, TxTransfer};
use namada_apps::cli::context::FromContext;
use namada_apps::cli::Context;
use namada_apps::client::tx;
use namada_apps::config::TendermintMode;
use namada_apps::facade::tendermint_config::net::Address as TendermintAddress;
use namada_apps::facade::tendermint_proto::abci::RequestInitChain;
use namada_apps::facade::tendermint_proto::google::protobuf::Timestamp;
use namada_apps::node::ledger::shell::Shell;
use namada_apps::wallet::defaults;
use namada_apps::{config, wasm_loader};
use namada_test_utils::tx_data::TxWriteData;
use rand_core::OsRng;
use tempfile::TempDir;

pub const WASM_DIR: &str = "../wasm";
pub const TX_BOND_WASM: &str = "tx_bond.wasm";
pub const TX_TRANSFER_WASM: &str = "tx_transfer.wasm";
pub const TX_UPDATE_VP_WASM: &str = "tx_update_vp.wasm";
pub const TX_VOTE_PROPOSAL_WASM: &str = "tx_vote_proposal.wasm";
pub const TX_UNBOND_WASM: &str = "tx_unbond.wasm";
pub const TX_INIT_PROPOSAL_WASM: &str = "tx_init_proposal.wasm";
pub const TX_REVEAL_PK_WASM: &str = "tx_reveal_pk.wasm";
pub const TX_CHANGE_VALIDATOR_COMMISSION_WASM: &str =
    "tx_change_validator_commission.wasm";
pub const TX_IBC_WASM: &str = "tx_ibc.wasm";

pub const ALBERT_PAYMENT_ADDRESS: &str = "albert_payment";
pub const ALBERT_SPENDING_KEY: &str = "albert_spending";
pub const BERTHA_PAYMENT_ADDRESS: &str = "bertha_payment";
const BERTHA_SPENDING_KEY: &str = "bertha_spending";

pub struct BenchShell {
    pub inner: Shell,
    /// NOTE: Temporary directory should be dropped last since Shell need to
    /// flush data on drop
    tempdir: TempDir,
}

impl Deref for BenchShell {
    type Target = Shell;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for BenchShell {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Default for BenchShell {
    fn default() -> Self {
        let (sender, _) = tokio::sync::mpsc::unbounded_channel();
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().canonicalize().unwrap();

        let mut shell = Shell::new(
            config::Ledger::new(
                path,
                Default::default(),
                TendermintMode::Validator,
            ),
            WASM_DIR.into(),
            sender,
            None,
            50 * 1024 * 1024, // 50 kiB
            50 * 1024 * 1024, // 50 kiB
            address::nam(),
        );

        shell
            .init_chain(
                RequestInitChain {
                    time: Some(Timestamp {
                        seconds: 0,
                        nanos: 0,
                    }),
                    chain_id: ChainId::default().to_string(),
                    ..Default::default()
                },
                1,
            )
            .unwrap();

        // Bond from Albert to validator
        let bond = Bond {
            validator: defaults::validator_address(),
            amount: Amount::whole(1000),
            source: Some(defaults::albert_address()),
        };
        let signed_tx =
            generate_tx(TX_BOND_WASM, bond, &defaults::albert_keypair());

        let mut bench_shell = BenchShell {
            inner: shell,
            tempdir,
        };

        bench_shell.execute_tx(&signed_tx);
        bench_shell.wl_storage.commit_tx();

        // Initialize governance proposal
        let signed_tx = generate_tx(
            TX_INIT_PROPOSAL_WASM,
            InitProposalData {
                id: None,
                content: vec![],
                author: defaults::albert_address(),
                r#type: ProposalType::Default(None),
                voting_start_epoch: 12.into(),
                voting_end_epoch: 15.into(),
                grace_epoch: 18.into(),
            },
            &defaults::albert_keypair(),
        );

        bench_shell.execute_tx(&signed_tx);
        bench_shell.wl_storage.commit_tx();
        bench_shell.commit();

        // Advance epoch for pos benches
        for _ in 0..=12 {
            bench_shell.advance_epoch();
        }

        bench_shell
    }
}

impl BenchShell {
    pub fn execute_tx(&mut self, tx: &Tx) {
        run::tx(
            &self.inner.wl_storage.storage,
            &mut self.inner.wl_storage.write_log,
            &mut TxGasMeter::new(u64::MAX),
            &TxIndex(0),
            &tx.code,
            tx.data.as_ref().unwrap(),
            &mut self.inner.vp_wasm_cache,
            &mut self.inner.tx_wasm_cache,
        )
        .unwrap();
    }

    pub fn advance_epoch(&mut self) {
        let pipeline_len =
            proof_of_stake::read_pos_params(&self.inner.wl_storage)
                .unwrap()
                .pipeline_len;

        self.wl_storage.storage.block.epoch =
            self.wl_storage.storage.block.epoch.next();
        let current_epoch = self.wl_storage.storage.block.epoch;

        proof_of_stake::copy_validator_sets_and_positions(
            &mut self.wl_storage,
            current_epoch,
            current_epoch + pipeline_len,
            &proof_of_stake::consensus_validator_set_handle(),
            &proof_of_stake::below_capacity_validator_set_handle(),
        )
        .unwrap();
    }

    pub fn init_ibc_channel(&mut self) {
        // Set connection open
        let client_id = ClientId::new(ClientType::Tendermint, 1).unwrap();
        let connection = ConnectionEnd::new(
            ConnectionState::Open,
            client_id.clone(),
            Counterparty::new(
                client_id,
                Some(ConnectionId::new(1)),
                actions::commitment_prefix(),
            ),
            vec![Version::default()],
            std::time::Duration::new(100, 0),
        );

        let addr_key =
            Key::from(Address::Internal(InternalAddress::Ibc).to_db_key());

        let path = IbcPath::Connections(ConnectionsPath(ConnectionId::new(1)));
        let connection_key =
            addr_key.join(&Key::parse(path.to_string()).unwrap());

        self.wl_storage
            .storage
            .write(&connection_key, connection.encode_vec().unwrap())
            .unwrap();

        // Set port
        let path = Key::parse(
            IbcPath::Ports(namada::ibc::core::ics24_host::path::PortsPath(
                PortId::transfer(),
            ))
            .to_string(),
        )
        .unwrap();
        let port_key = addr_key.join(&path);

        let index_key = addr_key
            .join(&Key::from("capabilities/index".to_string().to_db_key()));
        self.wl_storage
            .storage
            .write(&index_key, 1u64.to_be_bytes())
            .unwrap();
        self.wl_storage
            .storage
            .write(&port_key, 1u64.to_be_bytes())
            .unwrap();
        let cap_key =
            addr_key.join(&Key::from("capabilities/1".to_string().to_db_key()));
        self.wl_storage
            .storage
            .write(&cap_key, PortId::transfer().as_bytes())
            .unwrap();

        // Set Channel open
        let counterparty = ChannelCounterparty::new(
            PortId::transfer(),
            Some(ChannelId::new(5)),
        );
        let channel = ChannelEnd::new(
            State::Open,
            Order::Unordered,
            counterparty,
            vec![ConnectionId::new(1)],
            ChannelVersion::ics20(),
        );
        let path = IbcPath::ChannelEnds(ChannelEndsPath(
            PortId::transfer(),
            ChannelId::new(5),
        ));
        let channel_key = addr_key.join(&Key::parse(path.to_string()).unwrap());
        self.wl_storage
            .storage
            .write(&channel_key, channel.encode_vec().unwrap())
            .unwrap();

        // Set client state
        let client_id = ClientId::new(ClientType::Tendermint, 1).unwrap();
        let client_state_key = addr_key.join(&Key::from(
            IbcPath::ClientState(
                namada::ibc::core::ics24_host::path::ClientStatePath(
                    client_id.clone(),
                ),
            )
            .to_string()
            .to_db_key(),
        ));
        let client_state = ClientState::new(
            IbcChainId::from(ChainId::default().to_string()),
            TrustThreshold::ONE_THIRD,
            std::time::Duration::new(1, 0),
            std::time::Duration::new(2, 0),
            std::time::Duration::new(1, 0),
            IbcHeight::new(0, 1),
            ProofSpecs::cosmos(),
            vec![],
            AllowUpdate {
                after_expiry: true,
                after_misbehaviour: true,
            },
        )
        .unwrap();
        let bytes = AnyClientState::Tendermint(client_state)
            .encode_vec()
            .expect("encoding failed");
        self.wl_storage
            .storage
            .write(&client_state_key, bytes)
            .expect("write failed");

        // Set consensus state
        let now: namada::tendermint::Time =
            DateTimeUtc::now().try_into().unwrap();
        let consensus_key = addr_key.join(&Key::from(
            IbcPath::ClientConsensusState(
                namada::ibc::core::ics24_host::path::ClientConsensusStatePath {
                    client_id,
                    epoch: 0,
                    height: 1,
                },
            )
            .to_string()
            .to_db_key(),
        ));

        let consensus_state = ConsensusState {
            timestamp: now,
            root: CommitmentRoot::from_bytes(&[]),
            next_validators_hash: Hash::Sha256([0u8; 32]),
        };

        let bytes = AnyConsensusState::Tendermint(consensus_state)
            .encode_vec()
            .unwrap();
        self.wl_storage
            .storage
            .write(&consensus_key, bytes)
            .unwrap();
    }
}

pub fn generate_tx(
    wasm_code_path: &str,
    data: impl BorshSerialize,
    signer: &SecretKey,
) -> Tx {
    let tx = Tx::new(
        wasm_loader::read_wasm_or_exit(WASM_DIR, wasm_code_path),
        Some(data.try_to_vec().unwrap()),
        ChainId::default(),
        None,
    );

    tx.sign(signer)
}

pub fn generate_foreign_key_tx(signer: &SecretKey) -> Tx {
    let wasm_code = std::fs::read("../wasm_for_tests/tx_write.wasm").unwrap();

    let tx = Tx::new(
        wasm_code,
        Some(
            TxWriteData {
                key: Key::from("bench_foreing_key".to_string().to_db_key()),
                value: vec![0; 64],
            }
            .try_to_vec()
            .unwrap(),
        ),
        ChainId::default(),
        None,
    );

    tx.sign(signer)
}

pub fn generate_ibc_transfer_tx() -> Tx {
    let token = Some(Coin {
        denom: address::nam().to_string(),
        amount: Amount::whole(1000).to_string(),
    });

    let timeout_height = IbcHeight::new(0, 100);

    let now: namada::tendermint::Time = DateTimeUtc::now().try_into().unwrap();
    let now: IbcTimestamp = now.into();
    let timeout_timestamp = (now + std::time::Duration::new(3600, 0)).unwrap();

    let msg = MsgTransfer {
        source_port: PortId::transfer(),
        source_channel: ChannelId::new(5),
        token,
        sender: Signer::new(defaults::albert_address()),
        receiver: Signer::new(defaults::bertha_address()),
        timeout_height,
        timeout_timestamp,
    };
    let any_msg = msg.to_any();
    let mut data = vec![];
    prost::Message::encode(&any_msg, &mut data).unwrap();

    // Don't use execute_tx to avoid serializing the data again with borsh
    Tx::new(
        wasm_loader::read_wasm_or_exit(WASM_DIR, TX_IBC_WASM),
        Some(data),
        ChainId::default(),
        None,
    )
    .sign(&defaults::albert_keypair())
}

pub struct BenchShieldedCtx {
    pub ctx: Context,
    pub shell: BenchShell,
}

#[async_trait::async_trait(?Send)]
impl Client for BenchShell {
    type Error = std::io::Error;

    async fn request(
        &self,
        path: String,
        data: Option<Vec<u8>>,
        height: Option<BlockHeight>,
        prove: bool,
    ) -> Result<EncodedResponseQuery, Self::Error> {
        let data = data.unwrap_or_default();
        let height = height.unwrap_or_default();

        let request = RequestQuery {
            data,
            path,
            height,
            prove,
        };

        let ctx = RequestCtx {
            wl_storage: &self.wl_storage,
            event_log: self.event_log(),
            vp_wasm_cache: self.vp_wasm_cache.read_only(),
            tx_wasm_cache: self.tx_wasm_cache.read_only(),
            storage_read_past_height_limit: None,
        };

        RPC.handle(ctx, &request)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::NotFound))
    }
}

impl Default for BenchShieldedCtx {
    fn default() -> Self {
        let mut shell = BenchShell::default();

        let mut ctx = Context::new(namada_apps::cli::args::Global {
            chain_id: None,
            base_dir: shell.tempdir.as_ref().canonicalize().unwrap(),
            wasm_dir: None,
            mode: None,
        })
        .unwrap();

        // Generate spending key for Albert and Bertha
        ctx.wallet
            .gen_spending_key(ALBERT_SPENDING_KEY.to_string(), true);
        ctx.wallet
            .gen_spending_key(BERTHA_SPENDING_KEY.to_string(), true);
        ctx.wallet.save().unwrap();

        // Generate payment addresses for both Albert and Bertha
        for (alias, viewing_alias) in [
            (ALBERT_PAYMENT_ADDRESS, ALBERT_SPENDING_KEY),
            (BERTHA_PAYMENT_ADDRESS, BERTHA_SPENDING_KEY),
        ]
        .map(|(p, s)| (p.to_owned(), s.to_owned()))
        {
            let viewing_key: FromContext<ExtendedViewingKey> = FromContext::new(
                ctx.wallet
                    .find_viewing_key(viewing_alias)
                    .unwrap()
                    .to_string(),
            );
            let viewing_key =
                ExtendedFullViewingKey::from(ctx.get_cached(&viewing_key))
                    .fvk
                    .vk;
            let (div, _g_d) = tx::find_valid_diversifier(&mut OsRng);
            let payment_addr = viewing_key.to_payment_address(div).unwrap();
            let _ = ctx
                .wallet
                .insert_payment_addr(
                    alias,
                    PaymentAddress::from(payment_addr).pinned(false),
                )
                .unwrap();
        }

        ctx.wallet.save().unwrap();
        namada::ledger::storage::update_allowed_conversions(
            &mut shell.wl_storage,
        )
        .unwrap();

        Self { ctx, shell }
    }
}

impl BenchShieldedCtx {
    pub fn generate_masp_tx(
        &mut self,
        amount: Amount,
        source: TransferSource,
        target: TransferTarget,
    ) -> Tx {
        let mock_args = TxArgs {
            dry_run: false,
            dump_tx: false,
            force: false,
            broadcast_only: false,
            ledger_address: TendermintAddress::Tcp {
                peer_id: None,
                host: "bench-host".to_string(),
                port: 1,
            },
            initialized_account_alias: None,
            fee_amount: Amount::whole(0),
            fee_token: FromContext::new(address::nam().to_string()),
            gas_limit: GasLimit::from(u64::MAX),
            expiration: None,
            signing_key: Some(FromContext::new(
                defaults::albert_keypair().to_string(),
            )),
            signer: None,
        };

        let args = TxTransfer {
            tx: mock_args,
            source: FromContext::new(source.to_string()),
            target: FromContext::new(target.to_string()),
            token: FromContext::new(address::nam().to_string()),
            sub_prefix: None,
            amount,
        };

        let async_runtime = tokio::runtime::Runtime::new().unwrap();
        let spending_key = self
            .ctx
            .wallet
            .find_spending_key(ALBERT_SPENDING_KEY)
            .unwrap();
        async_runtime.block_on(self.ctx.shielded.fetch(
            &self.shell,
            &[spending_key.into()],
            &[],
        ));
        let shielded = async_runtime
            .block_on(tx::gen_shielded_transfer(
                &mut self.ctx,
                &self.shell,
                &args,
            ))
            .unwrap()
            .map(|x| x.0);

        generate_tx(
            TX_TRANSFER_WASM,
            Transfer {
                source: source.effective_address(),
                target: target.effective_address(),
                token: address::nam(),
                sub_prefix: None,
                amount,
                key: None,
                shielded,
            },
            &defaults::albert_keypair(),
        )
    }
}
