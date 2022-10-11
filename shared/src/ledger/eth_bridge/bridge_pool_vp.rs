//! Validity predicate for the Ethereum bridge pool
//!
//! This pool holds user initiated transfers of value from
//! Namada to Ethereum. It is to act like a mempool: users
//! add in their desired transfers and their chosen amount
//! of NAM to cover Ethereum side gas fees. These transfers
//! can be relayed in batches along with Merkle proofs.
//!
//! This VP checks that additions to the pool are handled
//! correctly. This means that the appropriate data is
//! added to the pool and gas fees are submitted appropriately.
use std::collections::BTreeSet;

use borsh::BorshDeserialize;
use eyre::eyre;

use crate::ledger::eth_bridge::storage::bridge_pool::{
    get_pending_key, is_bridge_pool_key, BRIDGE_POOL_ADDRESS,
};
use crate::ledger::eth_bridge::storage::wrapped_erc20s;
use crate::ledger::eth_bridge::vp::check_balance_changes;
use crate::ledger::native_vp::{Ctx, NativeVp, StorageReader};
use crate::ledger::storage::traits::StorageHasher;
use crate::ledger::storage::{DBIter, DB};
use crate::proto::SignedTxData;
use crate::types::address::{xan, Address, InternalAddress};
use crate::types::eth_bridge_pool::PendingTransfer;
use crate::types::keccak::encode::Encode;
use crate::types::storage::{Key, KeySeg};
use crate::types::token::{balance_key, Amount};
use crate::vm::WasmCacheAccess;

#[derive(thiserror::Error, Debug)]
#[error(transparent)]
/// Generic error that may be returned by the validity predicate
pub struct Error(#[from] eyre::Error);

/// A positive or negative amount
enum SignedAmount {
    Positive(Amount),
    Negative(Amount),
}

/// Validity predicate for the Ethereum bridge
pub struct BridgePoolVp<'ctx, D, H, CA>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'ctx, D, H, CA>,
}

impl<'a, D, H, CA> BridgePoolVp<'a, D, H, CA>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    /// Get the change in the balance of an account
    /// associated with an address
    fn account_balance_delta(&self, address: &Address) -> Option<SignedAmount> {
        let account_key = balance_key(&xan(), address);
        let before: Amount = (&self.ctx)
            .read_pre_value(&account_key)
            .unwrap_or_else(|error| {
                tracing::warn!(?error, %account_key, "reading pre value");
                None
            })?;
        let after: Amount = (&self.ctx)
            .read_post_value(&account_key)
            .unwrap_or_else(|error| {
                tracing::warn!(?error, %account_key, "reading post value");
                None
            })?;
        if before > after {
            Some(SignedAmount::Negative(before - after))
        } else {
            Some(SignedAmount::Positive(after - before))
        }
    }
}

/// Check if a delta matches the delta given by a transfer
fn check_delta(delta: &(Address, Amount), transfer: &PendingTransfer) -> bool {
    delta.0 == transfer.transfer.sender && delta.1 == transfer.transfer.amount
}

impl<'a, D, H, CA> NativeVp for BridgePoolVp<'a, D, H, CA>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    const ADDR: InternalAddress = InternalAddress::EthBridgePool;

    fn validate_tx(
        &self,
        tx_data: &[u8],
        keys_changed: &BTreeSet<Key>,
        _verifiers: &BTreeSet<Address>,
    ) -> Result<bool, Error> {
        tracing::debug!(
            tx_data_len = tx_data.len(),
            keys_changed_len = keys_changed.len(),
            verifiers_len = _verifiers.len(),
            "Ethereum Bridge Pool VP triggered",
        );
        let signed: SignedTxData = BorshDeserialize::try_from_slice(tx_data)
            .map_err(|e| Error(e.into()))?;

        let transfer: PendingTransfer = match signed.data {
            Some(data) => BorshDeserialize::try_from_slice(data.as_slice())
                .map_err(|e| Error(e.into()))?,
            None => {
                tracing::debug!(
                    "Rejecting transaction as there was no signed data"
                );
                return Ok(false);
            }
        };

        let pending_key = get_pending_key(&transfer);
        // check that transfer is not already in the pool
        match (&self.ctx).read_pre_value::<PendingTransfer>(&pending_key) {
            Ok(Some(_)) => {
                tracing::debug!(
                    "Rejecting transaction as the transfer is already in the \
                     Ethereum bridge pool."
                );
                return Ok(false);
            }
            Err(e) => {
                return Err(eyre!(
                    "Could not read the storage key associated with the \
                     transfer: {:?}",
                    e
                )
                .into());
            }
            _ => {}
        }
        for key in keys_changed.iter().filter(|k| is_bridge_pool_key(k)) {
            if *key != pending_key {
                tracing::debug!(
                    "Rejecting transaction as it is attempting to change an \
                     incorrect key in the Ethereum bridge pool: {}.\n \
                     Expected key: {}",
                    key,
                    pending_key
                );
                return Ok(false);
            }
        }
        let pending: PendingTransfer =
            (&self.ctx).read_post_value(&pending_key)?.ok_or(eyre!(
                "Rejecting transaction as the transfer wasn't added to the \
                 pool of pending transfers"
            ))?;
        if pending != transfer {
            tracing::debug!(
                "An incorrect transfer was added to the Ethereum bridge pool: \
                 {:?}.\n Expected: {:?}",
                transfer,
                pending
            );
            return Ok(false);
        }

        // check that gas fees were put into escrow

        // check that the correct amount was deducted from the fee payer
        if let Some(SignedAmount::Negative(amount)) =
            self.account_balance_delta(&transfer.gas_fee.payer)
        {
            if amount != transfer.gas_fee.amount {
                return Ok(false);
            }
        } else {
            tracing::debug!("The gas fee payers account was not debited.");
            return Ok(false);
        }
        // check that the correct amount was credited to escrow
        if let Some(SignedAmount::Positive(amount)) =
            self.account_balance_delta(&BRIDGE_POOL_ADDRESS)
        {
            if amount != transfer.gas_fee.amount {
                return Ok(false);
            }
        } else {
            tracing::debug!(
                "The Ethereum bridge pool's gas escrow was not credited."
            );
            return Ok(false);
        }
        tracing::info!(
            "The Ethereum bridge pool VP accepted the transfer {:?}.",
            transfer
        );

        // check that the assets to be transferred were escrowed
        let asset_key = wrapped_erc20s::Keys::from(&transfer.transfer.asset);
        let owner_key = asset_key.balance(&transfer.transfer.sender);
        let escrow_key = asset_key.balance(&BRIDGE_POOL_ADDRESS);
        if keys_changed.contains(&owner_key)
            && keys_changed.contains(&escrow_key)
        {
            match check_balance_changes(
                &self.ctx,
                (&escrow_key).try_into().expect("This should not fail"),
                (&owner_key).try_into().expect("This should not fail"),
            ) {
                Ok(Some(delta)) if check_delta(&delta, &transfer) => {}
                other => {
                    tracing::debug!(
                        "The assets of the transfer were not properly \
                         escrowed into the Ethereum bridge pool: {:?}",
                        other
                    );
                    return Ok(false);
                }
            }
        } else {
            tracing::debug!(
                "The assets of the transfer were not properly escrowed into \
                 the Ethereum bridge pool."
            );
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod test_bridge_pool_vp {
    use std::env::temp_dir;

    use borsh::{BorshDeserialize, BorshSerialize};

    use super::*;
    use crate::ledger::eth_bridge::storage::bridge_pool::get_signed_root_key;
    use crate::ledger::gas::VpGasMeter;
    use crate::ledger::storage::mockdb::MockDB;
    use crate::ledger::storage::traits::Sha256Hasher;
    use crate::ledger::storage::write_log::WriteLog;
    use crate::ledger::storage::Storage;
    use crate::proto::Tx;
    use crate::types::chain::ChainId;
    use crate::types::eth_bridge_pool::{GasFee, TransferToEthereum};
    use crate::types::ethereum_events::EthAddress;
    use crate::types::hash::Hash;
    use crate::types::key::{common, ed25519, SecretKey, SigScheme};
    use crate::vm::wasm::VpCache;
    use crate::vm::WasmCacheRwAccess;

    /// The amount of NAM Bertha has
    const ASSET: EthAddress = EthAddress([0; 20]);
    const BERTHA_WEALTH: u64 = 1_000_000;
    const BERTHA_TOKENS: u64 = 10_000;
    const ESCROWED_AMOUNT: u64 = 1_000;
    const ESCROWED_TOKENS: u64 = 1_000;
    const GAS_FEE: u64 = 100;
    const TOKENS: u64 = 100;

    /// A set of balances for an address
    struct Balance {
        owner: Address,
        balance: Amount,
        token: Amount,
    }

    impl Balance {
        fn new(address: Address) -> Self {
            Self {
                owner: address,
                balance: 0.into(),
                token: 0.into(),
            }
        }
    }

    /// An established user address for testing & development
    fn bertha_address() -> Address {
        Address::decode("atest1v4ehgw36xvcyyvejgvenxs34g3zygv3jxqunjd6rxyeyys3sxy6rwvfkx4qnj33hg9qnvse4lsfctw")
            .expect("The token address decoding shouldn't fail")
    }

    fn bertha_keypair() -> common::SecretKey {
        // generated from
        // [`namada::types::key::ed25519::gen_keypair`]
        let bytes = [
            240, 3, 224, 69, 201, 148, 60, 53, 112, 79, 80, 107, 101, 127, 186,
            6, 176, 162, 113, 224, 62, 8, 183, 187, 124, 234, 244, 251, 92, 36,
            119, 243,
        ];
        let ed_sk = ed25519::SecretKey::try_from_slice(&bytes).unwrap();
        ed_sk.try_to_sk().unwrap()
    }

    /// The bridge pool at the beginning of all tests
    fn initial_pool() -> PendingTransfer {
        PendingTransfer {
            transfer: TransferToEthereum {
                asset: ASSET,
                sender: bertha_address(),
                recipient: EthAddress([0; 20]),
                amount: 0.into(),
                nonce: 0u64.into(),
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            },
        }
    }

    /// Create a writelog representing storage before a transfer is added to the
    /// pool.
    fn new_writelog() -> WriteLog {
        let mut writelog = WriteLog::default();
        // setup the initial bridge pool storage
        writelog
            .write(&get_signed_root_key(), Hash([0; 32]).try_to_vec().unwrap())
            .expect("Test failed");
        let transfer = initial_pool();
        writelog
            .write(&get_pending_key(&transfer), transfer.try_to_vec().unwrap())
            .expect("Test failed");
        // set up a user with a balance
        update_balances(
            &mut writelog,
            Balance::new(bertha_address()),
            SignedAmount::Positive(BERTHA_WEALTH.into()),
            SignedAmount::Positive(BERTHA_TOKENS.into()),
        );
        // set up the initial balances of the bridge pool
        update_balances(
            &mut writelog,
            Balance::new(BRIDGE_POOL_ADDRESS),
            SignedAmount::Positive(ESCROWED_AMOUNT.into()),
            SignedAmount::Positive(ESCROWED_TOKENS.into()),
        );
        writelog.commit_tx();
        writelog
    }

    /// Update gas and token balances of an address and
    /// return the keys changed
    fn update_balances(
        write_log: &mut WriteLog,
        balance: Balance,
        gas_delta: SignedAmount,
        token_delta: SignedAmount,
    ) -> BTreeSet<Key> {
        // get the balance keys
        let token_key =
            wrapped_erc20s::Keys::from(&ASSET).balance(&balance.owner);
        let account_key = balance_key(&xan(), &balance.owner);

        // update the balance of xan
        let new_balance = match gas_delta {
            SignedAmount::Positive(amount) => balance.balance + amount,
            SignedAmount::Negative(amount) => balance.balance - amount,
        }
        .try_to_vec()
        .expect("Test failed");

        // update the balance of tokens
        let new_token_balance = match token_delta {
            SignedAmount::Positive(amount) => balance.token + amount,
            SignedAmount::Negative(amount) => balance.token - amount,
        }
        .try_to_vec()
        .expect("Test failed");

        // write the changes to the log
        write_log
            .write(&account_key, new_balance)
            .expect("Test failed");
        write_log
            .write(&token_key, new_token_balance)
            .expect("Test failed");

        // return the keys changed
        [account_key, token_key].into()
    }

    /// Setup a ctx for running native vps
    fn setup_ctx<'a>(
        tx: &'a Tx,
        storage: &'a Storage<MockDB, Sha256Hasher>,
        write_log: &'a WriteLog,
        keys_changed: &'a BTreeSet<Key>,
        verifiers: &'a BTreeSet<Address>,
    ) -> Ctx<'a, MockDB, Sha256Hasher, WasmCacheRwAccess> {
        Ctx::new(
            &BRIDGE_POOL_ADDRESS,
            storage,
            write_log,
            tx,
            VpGasMeter::new(0u64),
            keys_changed,
            verifiers,
            VpCache::new(temp_dir(), 100usize),
        )
    }

    enum Expect {
        True,
        False,
        Error,
    }

    /// Helper function that tests various ways gas can be escrowed,
    /// either correctly or incorrectly, is handled appropriately
    fn assert_bridge_pool<F>(
        payer_gas_delta: SignedAmount,
        gas_escrow_delta: SignedAmount,
        payer_delta: SignedAmount,
        escrow_delta: SignedAmount,
        insert_transfer: F,
        expect: Expect,
    ) where
        F: FnOnce(PendingTransfer, &mut WriteLog) -> BTreeSet<Key>,
    {
        // setup
        let mut write_log = new_writelog();
        let storage = Storage::<MockDB, Sha256Hasher>::open(
            std::path::Path::new(""),
            ChainId::default(),
            None,
        );
        let tx = Tx::new(vec![], None);

        // the transfer to be added to the pool
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: ASSET,
                sender: bertha_address(),
                recipient: EthAddress([1; 20]),
                amount: TOKENS.into(),
                nonce: 1u64.into(),
            },
            gas_fee: GasFee {
                amount: GAS_FEE.into(),
                payer: bertha_address(),
            },
        };
        // add transfer to pool
        let mut keys_changed =
            insert_transfer(transfer.clone(), &mut write_log);

        // change Bertha's balances
        let mut new_keys_changed = update_balances(
            &mut write_log,
            Balance {
                owner: bertha_address(),
                balance: BERTHA_WEALTH.into(),
                token: BERTHA_TOKENS.into(),
            },
            payer_gas_delta,
            payer_delta,
        );
        keys_changed.append(&mut new_keys_changed);

        // change the bridge pool balances
        let mut new_keys_changed = update_balances(
            &mut write_log,
            Balance {
                owner: BRIDGE_POOL_ADDRESS,
                balance: ESCROWED_AMOUNT.into(),
                token: ESCROWED_TOKENS.into(),
            },
            gas_escrow_delta,
            escrow_delta,
        );
        keys_changed.append(&mut new_keys_changed);
        let verifiers = BTreeSet::default();
        // create the data to be given to the vp
        let vp = BridgePoolVp {
            ctx: setup_ctx(
                &tx,
                &storage,
                &write_log,
                &keys_changed,
                &verifiers,
            ),
        };

        let to_sign = transfer.try_to_vec().expect("Test failed");
        let sig = common::SigScheme::sign(&bertha_keypair(), &to_sign);
        let signed = SignedTxData {
            data: Some(to_sign),
            sig,
        }
        .try_to_vec()
        .expect("Test failed");

        let res = vp.validate_tx(&signed, &keys_changed, &verifiers);
        match expect {
            Expect::True => assert!(res.expect("Test failed")),
            Expect::False => assert!(!res.expect("Test failed")),
            Expect::Error => assert!(res.is_err()),
        }
    }

    /// Test adding a transfer to the pool and escrowing gas passes vp
    #[test]
    fn test_happy_flow() {
        assert_bridge_pool(
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Negative(TOKENS.into()),
            SignedAmount::Positive(TOKENS.into()),
            |transfer, log| {
                log.write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
                BTreeSet::from([get_pending_key(&transfer)])
            },
            Expect::True,
        );
    }

    /// Test that if the balance for the gas payer
    /// was not correctly adjusted, reject
    #[test]
    fn test_incorrect_gas_withdrawn() {
        assert_bridge_pool(
            SignedAmount::Negative(10.into()),
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Negative(TOKENS.into()),
            SignedAmount::Positive(TOKENS.into()),
            |transfer, log| {
                log.write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
                BTreeSet::from([get_pending_key(&transfer)])
            },
            Expect::False,
        );
    }

    /// Test that if the gas payer's balance
    /// does not decrease, we reject the tx
    #[test]
    fn test_payer_balance_must_decrease() {
        assert_bridge_pool(
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Negative(TOKENS.into()),
            SignedAmount::Positive(TOKENS.into()),
            |transfer, log| {
                log.write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
                BTreeSet::from([get_pending_key(&transfer)])
            },
            Expect::False,
        );
    }

    /// Test that if the gas amount escrowed is incorrect,
    /// the tx is rejected
    #[test]
    fn test_incorrect_gas_deposited() {
        assert_bridge_pool(
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Positive(10.into()),
            SignedAmount::Negative(TOKENS.into()),
            SignedAmount::Positive(TOKENS.into()),
            |transfer, log| {
                log.write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
                BTreeSet::from([get_pending_key(&transfer)])
            },
            Expect::False,
        );
    }

    /// Test that if the number of tokens debited
    /// from one account does not equal the amount
    /// credited the other, the tx is rejected
    #[test]
    fn test_incorrect_token_deltas() {
        assert_bridge_pool(
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Negative(TOKENS.into()),
            SignedAmount::Positive(10.into()),
            |transfer, log| {
                log.write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
                BTreeSet::from([get_pending_key(&transfer)])
            },
            Expect::False,
        );
    }

    /// Test that if the number of tokens transferred
    /// is incorrect, the tx is rejected
    #[test]
    fn test_incorrect_tokens_escrowed() {
        assert_bridge_pool(
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Negative(10.into()),
            SignedAmount::Positive(10.into()),
            |transfer, log| {
                log.write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
                BTreeSet::from([get_pending_key(&transfer)])
            },
            Expect::False,
        );
    }

    /// Test that the amount of gas escrowed increases,
    /// otherwise the tx is rejected.
    #[test]
    fn test_escrowed_gas_must_increase() {
        assert_bridge_pool(
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Negative(TOKENS.into()),
            SignedAmount::Positive(TOKENS.into()),
            |transfer, log| {
                log.write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
                BTreeSet::from([get_pending_key(&transfer)])
            },
            Expect::False,
        );
    }

    /// Test that the amount of tokens escrowed in the
    /// bridge pool is positive.
    #[test]
    fn test_escrowed_tokens_must_increase() {
        assert_bridge_pool(
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Positive(TOKENS.into()),
            SignedAmount::Negative(TOKENS.into()),
            |transfer, log| {
                log.write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
                BTreeSet::from([get_pending_key(&transfer)])
            },
            Expect::False,
        );
    }

    /// Test that if the transfer was not added to the
    /// pool, the vp rejects
    #[test]
    fn test_not_adding_transfer_rejected() {
        assert_bridge_pool(
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Negative(TOKENS.into()),
            SignedAmount::Positive(TOKENS.into()),
            |transfer, _| BTreeSet::from([get_pending_key(&transfer)]),
            Expect::Error,
        );
    }

    /// Test that if the wrong transaction was added
    /// to the pool, it is rejected.
    #[test]
    fn test_add_wrong_transfer() {
        assert_bridge_pool(
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Negative(TOKENS.into()),
            SignedAmount::Positive(TOKENS.into()),
            |transfer, log| {
                let t = PendingTransfer {
                    transfer: TransferToEthereum {
                        asset: EthAddress([0; 20]),
                        sender: bertha_address(),
                        recipient: EthAddress([1; 20]),
                        amount: 100.into(),
                        nonce: 10u64.into(),
                    },
                    gas_fee: GasFee {
                        amount: GAS_FEE.into(),
                        payer: bertha_address(),
                    },
                };
                log.write(&get_pending_key(&transfer), t.try_to_vec().unwrap())
                    .unwrap();
                BTreeSet::from([get_pending_key(&transfer)])
            },
            Expect::False,
        );
    }

    /// Test that if the wrong transaction was added
    /// to the pool, it is rejected.
    #[test]
    fn test_add_wrong_key() {
        assert_bridge_pool(
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Negative(TOKENS.into()),
            SignedAmount::Positive(TOKENS.into()),
            |transfer, log| {
                let t = PendingTransfer {
                    transfer: TransferToEthereum {
                        asset: EthAddress([0; 20]),
                        sender: bertha_address(),
                        recipient: EthAddress([1; 20]),
                        amount: 100.into(),
                        nonce: 10u64.into(),
                    },
                    gas_fee: GasFee {
                        amount: GAS_FEE.into(),
                        payer: bertha_address(),
                    },
                };
                log.write(&get_pending_key(&t), transfer.try_to_vec().unwrap())
                    .unwrap();
                BTreeSet::from([get_pending_key(&transfer)])
            },
            Expect::Error,
        );
    }

    /// Test that no tx may alter the storage containing
    /// the signed merkle root.
    #[test]
    fn test_signed_merkle_root_changes_rejected() {
        assert_bridge_pool(
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Negative(TOKENS.into()),
            SignedAmount::Positive(TOKENS.into()),
            |transfer, log| {
                log.write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
                BTreeSet::from([
                    get_pending_key(&transfer),
                    get_signed_root_key(),
                ])
            },
            Expect::False,
        );
    }

    /// Test that adding a transfer to the pool
    /// that is already in the pool fails.
    #[test]
    fn test_adding_transfer_twice_fails() {
        // setup
        let mut write_log = new_writelog();
        let storage = Storage::<MockDB, Sha256Hasher>::open(
            std::path::Path::new(""),
            ChainId::default(),
            None,
        );
        let tx = Tx::new(vec![], None);

        // the transfer to be added to the pool
        let transfer = initial_pool();

        // add transfer to pool
        let mut keys_changed = {
            write_log
                .write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
            BTreeSet::from([get_pending_key(&transfer)])
        };

        // update Bertha's balances
        let mut new_keys_changed = update_balances(
            &mut write_log,
            Balance {
                owner: bertha_address(),
                balance: BERTHA_WEALTH.into(),
                token: BERTHA_TOKENS.into(),
            },
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Negative(TOKENS.into()),
        );
        keys_changed.append(&mut new_keys_changed);

        // update the bridge pool balances
        let mut new_keys_changed = update_balances(
            &mut write_log,
            Balance {
                owner: BRIDGE_POOL_ADDRESS,
                balance: ESCROWED_AMOUNT.into(),
                token: ESCROWED_TOKENS.into(),
            },
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Positive(TOKENS.into()),
        );
        keys_changed.append(&mut new_keys_changed);
        let verifiers = BTreeSet::default();

        // create the data to be given to the vp
        let vp = BridgePoolVp {
            ctx: setup_ctx(
                &tx,
                &storage,
                &write_log,
                &keys_changed,
                &verifiers,
            ),
        };

        let to_sign = transfer.try_to_vec().expect("Test failed");
        let sig = common::SigScheme::sign(&bertha_keypair(), &to_sign);
        let signed = SignedTxData {
            data: Some(to_sign),
            sig,
        }
        .try_to_vec()
        .expect("Test failed");

        let res = vp.validate_tx(&signed, &keys_changed, &verifiers);
        assert!(!res.expect("Test failed"));
    }

    /// Test that a transfer added to the pool with zero gas fees
    /// is rejected.
    #[test]
    fn test_zero_gas_fees_rejected() {
        // setup
        let mut write_log = new_writelog();
        let storage = Storage::<MockDB, Sha256Hasher>::open(
            std::path::Path::new(""),
            ChainId::default(),
            None,
        );
        let tx = Tx::new(vec![], None);

        // the transfer to be added to the pool
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: ASSET,
                sender: bertha_address(),
                recipient: EthAddress([1; 20]),
                amount: 0.into(),
                nonce: 1u64.into(),
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            },
        };

        // add transfer to pool
        let mut keys_changed = {
            write_log
                .write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
            BTreeSet::from([get_pending_key(&transfer)])
        };
        // We escrow 0 tokens
        keys_changed.insert(
            wrapped_erc20s::Keys::from(&ASSET).balance(&bertha_address()),
        );
        keys_changed.insert(
            wrapped_erc20s::Keys::from(&ASSET).balance(&BRIDGE_POOL_ADDRESS),
        );

        // inform the vp that the merkle root changed
        let keys_changed = BTreeSet::default();
        let verifiers = BTreeSet::default();

        // create the data to be given to the vp
        let vp = BridgePoolVp {
            ctx: setup_ctx(
                &tx,
                &storage,
                &write_log,
                &keys_changed,
                &verifiers,
            ),
        };

        let to_sign = transfer.try_to_vec().expect("Test failed");
        let sig = common::SigScheme::sign(&bertha_keypair(), &to_sign);
        let signed = SignedTxData {
            data: Some(to_sign),
            sig,
        }
        .try_to_vec()
        .expect("Test failed");

        let res = vp
            .validate_tx(&signed, &keys_changed, &verifiers)
            .expect("Test failed");
        assert!(!res);
    }
}
