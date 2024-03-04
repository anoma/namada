use core::fmt::Formatter;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use borsh::schema::BorshSchemaContainer;
use borsh_ext::BorshSerializeExt;
use data_encoding::HEXUPPER;
use namada_core::storage::Key;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Visitor;

pub trait DBUpdateVisitor {
    fn read(&self, key: &Key) -> Option<Vec<u8>>;
    fn write(&mut self, key: &Key, value: impl AsRef<[u8]>);
    fn delete(&mut self, key: &Key);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DbUpdateType {
    Add{key: Key, value: Vec<u8>},
    Delete(Key),
}

impl DbUpdateType {
    #[allow(dead_code)]
    fn update<DB: DBUpdateVisitor>(&self, db: &mut DB) -> eyre::Result<()>{
        match self {
            Self::Add{key, value} => {
                db.write(key, &value);
            }
            Self::Delete(key) =>{
                db.delete(key);
            }
        }
        Ok(())
    }
}
