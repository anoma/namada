//! Tx actions are used to indicate from tx to VPs the type of actions that have
//! been applied by the tx to simplify validation (We can check that the
//! storage changes are valid based on the action, rather than trying to derive
//! the action from storage changes). When used, the kind is expected to written
//! to under temporary storage (discarded after tx execution and validation).

use std::fmt;

use namada_core::address::Address;
use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::hash::Hash;
use namada_core::storage::KeySeg;
use namada_core::{address, storage};

pub use crate::data::pos::{
    Bond, ClaimRewards, Redelegation, Unbond, Withdraw,
};

/// Actions applied from txs.
pub type Actions = Vec<Action>;

/// An action applied from a tx.
#[allow(missing_docs)]
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub enum Action {
    Pos(PosAction),
    Gov(GovAction),
    Pgf(PgfAction),
    Masp(MaspAction),
}

/// PoS tx actions.
#[allow(missing_docs)]
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub enum PosAction {
    BecomeValidator(Address),
    DeactivateValidator(Address),
    ReactivateValidator(Address),
    Unjail(Address),
    Bond(Bond),
    Unbond(Unbond),
    Withdraw(Withdraw),
    Redelegation(Redelegation),
    ClaimRewards(ClaimRewards),
    CommissionChange(Address),
    MetadataChange(Address),
    ConsensusKeyChange(Address),
}

/// Gov tx actions.
#[allow(missing_docs)]
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub enum GovAction {
    InitProposal { author: Address },
    VoteProposal { id: u64, voter: Address },
}

/// PGF tx actions.
#[allow(missing_docs)]
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub enum PgfAction {
    ResignSteward(Address),
    UpdateStewardCommission(Address),
}

/// MASP tx action.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct MaspAction {
    pub masp_section_ref: Hash,
}

/// Read actions from temporary storage
pub trait Read {
    /// Storage access errors
    type Err: fmt::Debug;

    /// Read a temporary key-val
    fn read_temp<T: BorshDeserialize>(
        &self,
        key: &storage::Key,
    ) -> Result<Option<T>, Self::Err>;

    /// Read all the actions applied by a tx
    fn read_actions(&self) -> Result<Actions, Self::Err> {
        let key = storage_key();
        let actions = self.read_temp(&key)?;
        let actions: Actions = actions.unwrap_or_default();
        Ok(actions)
    }
}

/// Write actions to temporary storage
pub trait Write: Read {
    /// Write a temporary key-val
    fn write_temp<T: BorshSerialize>(
        &mut self,
        key: &storage::Key,
        val: T,
    ) -> Result<(), Self::Err>;

    /// Push an action applied in a tx.
    fn push_action(&mut self, action: Action) -> Result<(), Self::Err> {
        let key = storage_key();
        let actions = self.read_temp(&key)?;
        let mut actions: Actions = actions.unwrap_or_default();
        actions.push(action);
        self.write_temp(&key, actions)?;
        Ok(())
    }
}

const TX_ACTIONS_KEY: &str = "tx_actions";

fn storage_key() -> storage::Key {
    storage::Key::from(address::TEMP_STORAGE.to_db_key())
        .push(&TX_ACTIONS_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Helper function to get the optional masp section reference from the [`Actions`]. If more than one [`MaspAction`] has been found we return the first one
pub fn get_masp_section_ref<T: Read>(
    reader: &T,
) -> Result<Option<Hash>, <T as Read>::Err> {
    Ok(reader.read_actions()?.into_iter().find_map(|action| {
        // In case of multiple masp actions we get the first one
        if let Action::Masp(MaspAction { masp_section_ref }) = action {
            Some(masp_section_ref)
        } else {
            None
        }
    }))
}
