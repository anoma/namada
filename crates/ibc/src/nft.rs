use borsh::{BorshDeserialize, BorshSerialize};
use ibc::apps::nft_transfer::context::{NftClassContext, NftContext};
use ibc::apps::nft_transfer::types::{
    ClassData, ClassId, ClassUri, PrefixedClassId, TokenData, TokenId, TokenUri,
};
use ibc::core::host::types::error::DecodingError;

/// NFT class
#[derive(Clone, Debug)]
pub struct NftClass {
    /// NFT class ID
    pub class_id: PrefixedClassId,
    /// NFT class URI
    pub class_uri: Option<ClassUri>,
    /// NFT class data
    pub class_data: Option<ClassData>,
}

impl BorshSerialize for NftClass {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.class_id.to_string(), writer)?;
        match &self.class_uri {
            Some(uri) => {
                BorshSerialize::serialize(&true, writer)?;
                BorshSerialize::serialize(&uri.to_string(), writer)?;
            }
            None => BorshSerialize::serialize(&false, writer)?,
        }
        match &self.class_data {
            Some(data) => {
                BorshSerialize::serialize(&true, writer)?;
                BorshSerialize::serialize(&data.to_string(), writer)
            }
            None => BorshSerialize::serialize(&false, writer),
        }
    }
}

impl BorshDeserialize for NftClass {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        let class_id: String = BorshDeserialize::deserialize_reader(reader)?;
        let class_id = class_id.parse().map_err(|e: DecodingError| {
            Error::new(ErrorKind::InvalidData, e.to_string())
        })?;

        let is_uri: bool = BorshDeserialize::deserialize_reader(reader)?;
        let class_uri = if is_uri {
            let uri_str: String = BorshDeserialize::deserialize_reader(reader)?;
            Some(uri_str.parse().map_err(|e: DecodingError| {
                Error::new(ErrorKind::InvalidData, e.to_string())
            })?)
        } else {
            None
        };

        let is_data: bool = BorshDeserialize::deserialize_reader(reader)?;
        let class_data = if is_data {
            let data_str: String =
                BorshDeserialize::deserialize_reader(reader)?;
            Some(data_str.parse().map_err(|e: DecodingError| {
                Error::new(ErrorKind::InvalidData, e.to_string())
            })?)
        } else {
            None
        };

        Ok(Self {
            class_id,
            class_uri,
            class_data,
        })
    }
}

impl NftClassContext for NftClass {
    fn get_id(&self) -> &ClassId {
        &self.class_id.base_class_id
    }

    fn get_uri(&self) -> Option<&ClassUri> {
        self.class_uri.as_ref()
    }

    fn get_data(&self) -> Option<&ClassData> {
        self.class_data.as_ref()
    }
}

/// NFT metadata
#[derive(Clone, Debug)]
pub struct NftMetadata {
    /// NFT class ID
    pub class_id: PrefixedClassId,
    /// NFT ID
    pub token_id: TokenId,
    /// NFT URI
    pub token_uri: Option<TokenUri>,
    /// NFT data
    pub token_data: Option<TokenData>,
}

impl BorshSerialize for NftMetadata {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.class_id.to_string(), writer)?;
        BorshSerialize::serialize(&self.token_id.to_string(), writer)?;
        match &self.token_uri {
            Some(uri) => {
                BorshSerialize::serialize(&true, writer)?;
                BorshSerialize::serialize(&uri.to_string(), writer)?;
            }
            None => BorshSerialize::serialize(&false, writer)?,
        }
        match &self.token_data {
            Some(data) => {
                BorshSerialize::serialize(&true, writer)?;
                BorshSerialize::serialize(&data.to_string(), writer)
            }
            None => BorshSerialize::serialize(&false, writer),
        }
    }
}

impl BorshDeserialize for NftMetadata {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        let class_id: String = BorshDeserialize::deserialize_reader(reader)?;
        let class_id = class_id.parse().map_err(|e: DecodingError| {
            Error::new(ErrorKind::InvalidData, e.to_string())
        })?;

        let token_id: String = BorshDeserialize::deserialize_reader(reader)?;
        let token_id = token_id.parse().map_err(|e: DecodingError| {
            Error::new(ErrorKind::InvalidData, e.to_string())
        })?;

        let is_uri: bool = BorshDeserialize::deserialize_reader(reader)?;
        let token_uri = if is_uri {
            let uri_str: String = BorshDeserialize::deserialize_reader(reader)?;
            Some(uri_str.parse().map_err(|e: DecodingError| {
                Error::new(ErrorKind::InvalidData, e.to_string())
            })?)
        } else {
            None
        };

        let is_data: bool = BorshDeserialize::deserialize_reader(reader)?;
        let token_data = if is_data {
            let data_str: String =
                BorshDeserialize::deserialize_reader(reader)?;
            Some(data_str.parse().map_err(|e: DecodingError| {
                Error::new(ErrorKind::InvalidData, e.to_string())
            })?)
        } else {
            None
        };

        Ok(Self {
            class_id,
            token_id,
            token_uri,
            token_data,
        })
    }
}

impl NftContext for NftMetadata {
    fn get_class_id(&self) -> &ClassId {
        &self.class_id.base_class_id
    }

    fn get_id(&self) -> &TokenId {
        &self.token_id
    }

    fn get_uri(&self) -> Option<&TokenUri> {
        self.token_uri.as_ref()
    }

    fn get_data(&self) -> Option<&TokenData> {
        self.token_data.as_ref()
    }
}
