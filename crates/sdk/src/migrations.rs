use core::fmt::{Formatter, Write};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use borsh::schema::BorshSchemaContainer;
use borsh_ext::BorshSerializeExt;
use borsh_serde_adapter::deserialize_adapter::deserialize_from_schema;
use data_encoding::HEXUPPER;
use namada_core::types::storage::Key;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Visitor;

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
/// A DB serialized value and schema.
pub struct DbSerializedValue {
    /// The schema of the type
    container: BorshSchemaContainer,
    /// The serialized bytes
    data: Vec<u8>,
}

impl DbSerializedValue {
    pub fn new<T>(data: T) -> Self
    where
        T: BorshSerialize + BorshDeserialize + BorshSchema
    {
        Self {
            container: BorshSchemaContainer::for_type::<T>(),
            data: data.serialize_to_vec(),
        }
    }

    /// Check if the schema can deserialize the data. If so, outputs
    /// a json representation of the data.
    ///
    /// NB: If custom Borsh serializations or schemas are implemented for
    /// a type, this validation may not pass. This works best for types
    /// where the serialization and schema are derived.
    pub fn validate(&self) -> std::io::Result<serde_json::Value> {
        deserialize_from_schema(&mut self.data.as_slice(), &self.container)
    }

    /// If the value under a key should have the same type as the existing value,
    /// check that the contained schema also deserializes the old data.
    pub fn is_same_type(&self, other: &mut &[u8]) -> bool {
        deserialize_from_schema(other, &self.container).is_ok()

    }
}

impl serde::Serialize for DbSerializedValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let bytes = self.serialize_to_vec();
        serializer.serialize_str(&HEXUPPER.encode(&bytes))
    }
}

struct DbValueVisitor;

impl<'de> Visitor<'de> for DbValueVisitor {
    type Value = DbSerializedValue;

    fn expecting(&self, formatter: &mut Formatter) -> core::fmt::Result {
        formatter.write_str("Hex encoded bytes of a DbSerializeValue struct.")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where E: serde::de::Error
    {
        let bytes = HEXUPPER.decode(v.as_bytes())
            .map_err(|e| E::custom(format!("Could not parse {} as hex with error: {}", v, e)))?;
        Self::Value::try_from_slice(&bytes).map_err(|e| E::custom(e.to_string()))
    }
}

impl<'de> serde::Deserialize<'de> for DbSerializedValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        deserializer.deserialize_any(DbValueVisitor { })
    }
}

pub trait DBUpdateVisitor {
    fn read(&self, key: &Key) -> Option<Vec<u8>>;
    fn write(&mut self, key: &Key, value: impl AsRef<u8>);
    fn delete(&mut self, key: &Key);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DbUpdateType {
    Add{key: Key, value: DbSerializedValue, fixed_type: bool},
    Delete(Key),
}

impl DbUpdateType {
    fn update<DB: DBUpdateVisitor>(&self, db: &mut DB) -> eyre::Result<()>{
        match self {
            Self::Add{key, value, fixed_type} => {
                let json_value = value
                    .validate()
                    .map_err(|e| eyre::eyre!(
                        "The updated DB value could not be deserialized with the provided schema due to: {}",
                        e,
                    ))?;
                if let Some(val) = db.read(&key) {
                    if *fixed_type && !value.is_same_type(&mut val.as_slice()) {
                        eyre::eyre!("The value under the key <{}> does not have the same type as {}", key, json_value)?;
                    }
                }
                db.write(key, &value.data);
            }
            Self::Delete(key) => db.delete(&key),
        }
        Ok(())
    }
}