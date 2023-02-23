//! IBC lower-level functions for transactions.

pub use namada_core::ledger::ibc::actions::{Error, IbcActions, Result};
use namada_core::ledger::storage_api::{StorageRead, StorageWrite};
use namada_core::ledger::tx_env::TxEnv;
pub use namada_core::types::ibc::IbcEvent;
use namada_core::types::storage::{BlockHeight, Key};
use namada_core::types::time::Rfc3339String;
use namada_core::types::token::Amount;

use crate::token::transfer_with_keys;
use crate::Ctx;

impl IbcStorageContext for Ctx {
    type Error = crate::Error;

    fn read(
        &self,
        key: &Key,
    ) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
        let data = self.read_bytes(key)?;
        Ok(data)
    }

    fn write(
        &mut self,
        key: &Key,
        data: impl AsRef<[u8]>,
    ) -> std::result::Result<(), Self::Error> {
        self.write_bytes(key, data)?;
        Ok(())
    }

    fn delete(&mut self, key: &Key) -> std::result::Result<(), Self::Error> {
        self.delete(key)?;
        Ok(())
    }

    fn emit_ibc_event(
        &mut self,
        event: IbcEvent,
    ) -> std::result::Result<(), Self::Error> {
        <Ctx as TxEnv>::emit_ibc_event(self, &event)?;
        Ok(())
    }

    fn transfer_token(
        &mut self,
        src: &Key,
        dest: &Key,
        amount: Amount,
    ) -> std::result::Result<(), Self::Error> {
        transfer_with_keys(self, src, dest, amount)?;
        Ok(())
    }

    fn get_height(&self) -> std::result::Result<BlockHeight, Self::Error> {
        let val = self.get_block_height()?;
        Ok(val)
    }

    fn get_header_time(
        &self,
    ) -> std::result::Result<Rfc3339String, Self::Error> {
        let val = self.get_block_time()?;
        Ok(val)
    }
}

pub fn ibc_actions(ctx: &mut Ctx) -> IbcActions<Ctx> {
    IbcActions::new(ctx)
}
