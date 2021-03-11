use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use libp2p::identity::ed25519::Keypair;

#[derive(Serialize, Deserialize, Debug)]
pub struct Bookkeeper {
    pub address: String,
    #[serde(with = "keypair_serde")]
    pub key: Keypair,
}

// XXX TODO this is needed because libp2p does not export ed255519 serde feature
// maybe a MR for libp2p to export theses functions ?
#[cfg(feature = "dev")]
mod keypair_serde {
    use libp2p::identity::ed25519::Keypair;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_bytes::{ByteBuf as SerdeByteBuf, Bytes as SerdeBytes};

    pub fn serialize<S>(
        value: &Keypair,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = &value.encode()[..];
        SerdeBytes::new(bytes).serialize(serializer)
    }
    pub fn deserialize<'d, D>(deserializer: D) -> Result<Keypair, D::Error>
    where
        D: Deserializer<'d>,
    {
        let mut bytes = <SerdeByteBuf>::deserialize(deserializer)?;

        Keypair::decode(bytes.as_mut()).map_err(Error::custom)
    }
}

impl Bookkeeper {
    // Generates a new orderbook
    #[allow(dead_code)]
    pub fn new() -> Self {
        let key = Keypair::generate();
        let mut hasher = Sha256::new();
        hasher.update(key.public().encode());
        let address = format!("{:.40X}", hasher.finalize());
        Bookkeeper { address, key }
    }
}
