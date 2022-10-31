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

use borsh::{BorshDeserialize, BorshSerialize};
use eyre::eyre;

use crate::ledger::eth_bridge::storage::bridge_pool::{
    get_pending_key, is_bridge_pool_key, BRIDGE_POOL_ADDRESS,
};
use crate::ledger::native_vp::{Ctx, NativeVp, StorageReader};
use crate::ledger::storage::traits::StorageHasher;
use crate::ledger::storage::{DBIter, Storage, DB};
use crate::proto::SignedTxData;
use crate::types::address::{xan, Address, InternalAddress};
use crate::types::eth_bridge_pool::PendingTransfer;
use crate::types::storage::Key;
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

/// Initialize the storage owned by the Bridge Pool VP.
///
/// This means that the amount of escrowed gas fees is
/// initialized to 0.
pub fn init_storage<D, H>(storage: &mut Storage<D, H>)
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    let escrow_key = balance_key(&xan(), &BRIDGE_POOL_ADDRESS);
    storage
        .write(
            &escrow_key,
            Amount::default()
                .try_to_vec()
                .expect("Serializing an amount shouldn't fail."),
        )
        .expect(
            "Initializing the escrow balance of the Bridge pool VP shouldn't \
             fail.",
        );
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
        for key in keys_changed.iter().filter(|k| is_bridge_pool_key(k)) {
            if *key != pending_key {
                tracing::debug!(
                    "Rejecting transaction as it is attempting to change an \
                     incorrect key in the pending transaction pool: {}.\n \
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
                 pending transfers"
            ))?;
        if pending != transfer {
            tracing::debug!(
                "An incorrect transfer was added to the pool: {:?}.\n \
                 Expected: {:?}",
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
            tracing::debug!("The bridge pools escrow was not credited.");
            return Ok(false);
        }
        tracing::info!(
            "The Ethereum bridge pool VP accepted the transfer {:?}.",
            transfer
        );

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
    const BERTHA_WEALTH: u64 = 1_000_000;
    const ESCROWED_AMOUNT: u64 = 1_000;
    const GAS_FEE: u64 = 100;

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
                asset: EthAddress([0; 20]),
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

    /// Create a new storage
    fn new_writelog() -> WriteLog {
        let mut writelog = WriteLog::default();
        // setup the bridge pool storage
        writelog
            .write(&get_signed_root_key(), Hash([0; 32]).try_to_vec().unwrap())
            .unwrap();
        let transfer = initial_pool();
        writelog
            .write(&get_pending_key(&transfer), transfer.try_to_vec().unwrap())
            .unwrap();
        let escrow_key = balance_key(&xan(), &BRIDGE_POOL_ADDRESS);
        let amount: Amount = ESCROWED_AMOUNT.into();
        writelog
            .write(&escrow_key, amount.try_to_vec().unwrap())
            .unwrap();

        // setup a user with a balance
        let bertha_account_key = balance_key(&xan(), &bertha_address());
        let bertha_wealth: Amount = BERTHA_WEALTH.into();
        writelog
            .write(&bertha_account_key, bertha_wealth.try_to_vec().unwrap())
            .unwrap();
        writelog.commit_tx();
        writelog
    }

    /// Setup a ctx for running native vps
    fn setup_ctx<'a>(
        tx: &'a Tx,
        storage: &'a Storage<MockDB, Sha256Hasher>,
        write_log: &'a WriteLog,
    ) -> Ctx<'a, MockDB, Sha256Hasher, WasmCacheRwAccess> {
        Ctx::new(
            storage,
            write_log,
            tx,
            VpGasMeter::new(0u64),
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
                asset: EthAddress([0; 20]),
                recipient: EthAddress([1; 20]),
                amount: 100.into(),
                nonce: 1u64.into(),
            },
            gas_fee: GasFee {
                amount: GAS_FEE.into(),
                payer: bertha_address(),
            },
        };
        // change the payers account
        let bertha_account_key = balance_key(&xan(), &bertha_address());
        let new_bertha_balance = match payer_delta {
            SignedAmount::Positive(amount) => {
                Amount::from(BERTHA_WEALTH) + amount
            }
            SignedAmount::Negative(amount) => {
                Amount::from(BERTHA_WEALTH) - amount
            }
        }
        .try_to_vec()
        .expect("Test failed");
        write_log
            .write(&bertha_account_key, new_bertha_balance)
            .expect("Test failed");
        // change the escrow account
        let escrow = balance_key(&xan(), &BRIDGE_POOL_ADDRESS);
        let new_escrow_balance = match escrow_delta {
            SignedAmount::Positive(amount) => {
                Amount::from(ESCROWED_AMOUNT) + amount
            }
            SignedAmount::Negative(amount) => {
                Amount::from(ESCROWED_AMOUNT) - amount
            }
        }
        .try_to_vec()
        .expect("Test failed");
        write_log
            .write(&escrow, new_escrow_balance)
            .expect("Test failed");

        // add transfer to pool
        let keys_changed = insert_transfer(transfer.clone(), &mut write_log);

        // create the data to be given to the vp
        let vp = BridgePoolVp {
            ctx: setup_ctx(&tx, &storage, &write_log),
        };

        let to_sign = transfer.try_to_vec().expect("Test failed");
        let sig = common::SigScheme::sign(&bertha_keypair(), &to_sign);
        let signed = SignedTxData {
            data: Some(to_sign),
            sig,
        }
        .try_to_vec()
        .expect("Test failed");

        let verifiers = BTreeSet::default();
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
            |transfer, log| {
                let t = PendingTransfer {
                    transfer: TransferToEthereum {
                        asset: EthAddress([0; 20]),
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
            |transfer, log| {
                let t = PendingTransfer {
                    transfer: TransferToEthereum {
                        asset: EthAddress([0; 20]),
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
                asset: EthAddress([0; 20]),
                recipient: EthAddress([1; 20]),
                amount: 100.into(),
                nonce: 1u64.into(),
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            },
        };

        write_log
            .write(
                &get_pending_key(&transfer),
                transfer.try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        // create the data to be given to the vp
        let vp = BridgePoolVp {
            ctx: setup_ctx(&tx, &storage, &write_log),
        };
        // inform the vp that the merkle root changed
        let keys_changed = BTreeSet::default();
        let verifiers = BTreeSet::default();

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
