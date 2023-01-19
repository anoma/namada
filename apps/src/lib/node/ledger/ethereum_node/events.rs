pub mod signatures {
    pub const TRANSFER_TO_NAMADA_SIG: &str =
        "TransferToNamada(uint256,(address,uint256,string)[],uint256)";
    pub const TRANSFER_TO_ETHEREUM_SIG: &str =
        "TransferToErc(uint256,(address,address,uint256,string,uint256)[])";
    pub const VALIDATOR_SET_UPDATE_SIG: &str =
        "ValidatorSetUpdate(uint256,bytes32,bytes32)";
    pub const NEW_CONTRACT_SIG: &str = "NewContract(string,address)";
    pub const UPGRADED_CONTRACT_SIG: &str = "UpgradedContract(string,address)";
    pub const UPDATE_BRIDGE_WHITELIST_SIG: &str =
        "UpdateBridgeWhiteList(uint256,address[],uint256[])";
    pub const SIGNATURES: [&str; 6] = [
        TRANSFER_TO_NAMADA_SIG,
        TRANSFER_TO_ETHEREUM_SIG,
        VALIDATOR_SET_UPDATE_SIG,
        NEW_CONTRACT_SIG,
        UPGRADED_CONTRACT_SIG,
        UPDATE_BRIDGE_WHITELIST_SIG,
    ];

    /// Used to determine which smart contract address
    /// a signature belongs to
    pub enum SigType {
        Bridge,
        Governance,
    }

    impl From<&str> for SigType {
        fn from(sig: &str) -> Self {
            match sig {
                TRANSFER_TO_NAMADA_SIG | TRANSFER_TO_ETHEREUM_SIG => {
                    SigType::Bridge
                }
                _ => SigType::Governance,
            }
        }
    }
}

pub mod eth_events {
    use std::convert::TryInto;
    use std::fmt::Debug;
    use std::str::FromStr;

    use ethabi::decode;
    #[cfg(test)]
    use ethabi::encode;
    use ethabi::param_type::ParamType;
    use ethabi::token::Token;
    use namada::types::address::Address;
    use namada::types::ethereum_events::{
        EthAddress, EthereumEvent, TokenWhitelist, TransferToEthereum,
        TransferToNamada, Uint,
    };
    use namada::types::keccak::KeccakHash;
    use namada::types::token::Amount;
    use num256::Uint256;
    use thiserror::Error;

    pub use super::signatures;

    #[derive(Error, Debug)]
    pub enum Error {
        #[error("Could not decode Ethereum event: {0}")]
        Decode(String),
    }

    pub type Result<T> = std::result::Result<T, Error>;

    #[derive(Clone, Debug, PartialEq)]
    /// An event waiting for a certain number of confirmations
    /// before being sent to the ledger
    pub(in super::super) struct PendingEvent {
        /// number of confirmations to consider this event finalized
        confirmations: Uint256,
        /// the block height from which this event originated
        block_height: Uint256,
        /// the event itself
        pub event: EthereumEvent,
    }

    /// Event emitted with the validator set changes
    #[derive(Clone, Debug, PartialEq)]
    pub struct ValidatorSetUpdate {
        /// A monotonically increasing nonce
        nonce: Uint,
        /// Hash of the validators in the bridge contract
        bridge_validator_hash: KeccakHash,
        /// Hash of the validators in the governance contract
        governance_validator_hash: KeccakHash,
    }

    /// Event indicating a new smart contract has been
    /// deployed or upgraded on Ethereum
    #[derive(Clone, Debug, PartialEq)]
    pub(in super::super) struct ChangedContract {
        /// Name of the contract
        pub name: String,
        /// Address of the contract on Ethereum
        pub address: EthAddress,
    }

    /// Event for whitelisting new tokens and their
    /// rate limits
    #[derive(Clone, Debug, PartialEq)]
    struct UpdateBridgeWhitelist {
        /// A monotonically increasing nonce
        nonce: Uint,
        /// Tokens to be allowed to be transferred across the bridge
        whitelist: Vec<TokenWhitelist>,
    }

    impl PendingEvent {
        /// Decodes bytes into an [`EthereumEvent`] based on the signature.
        /// This is is turned into a [`PendingEvent`] along with the block
        /// height passed in here.
        ///
        /// If the event contains a confirmations field,
        /// this is passed to the corresponding [`PendingEvent`] field,
        /// otherwise a default is used.
        pub fn decode(
            signature: &str,
            block_height: Uint256,
            data: &[u8],
            min_confirmations: Uint256,
        ) -> Result<Self> {
            match signature {
                signatures::TRANSFER_TO_NAMADA_SIG => {
                    RawTransfersToNamada::decode(data).map(|txs| PendingEvent {
                        confirmations: min_confirmations
                            .max(txs.confirmations.into()),
                        block_height,
                        event: EthereumEvent::TransfersToNamada {
                            nonce: txs.nonce,
                            transfers: txs.transfers,
                        },
                    })
                }
                signatures::TRANSFER_TO_ETHEREUM_SIG => {
                    RawTransfersToEthereum::decode(data).map(|txs| {
                        PendingEvent {
                            confirmations: min_confirmations,
                            block_height,
                            event: EthereumEvent::TransfersToEthereum {
                                nonce: txs.nonce,
                                transfers: txs.transfers,
                            },
                        }
                    })
                }
                signatures::VALIDATOR_SET_UPDATE_SIG => {
                    ValidatorSetUpdate::decode(data).map(
                        |ValidatorSetUpdate {
                             nonce,
                             bridge_validator_hash,
                             governance_validator_hash,
                         }| PendingEvent {
                            confirmations: min_confirmations,
                            block_height,
                            event: EthereumEvent::ValidatorSetUpdate {
                                nonce,
                                bridge_validator_hash,
                                governance_validator_hash,
                            },
                        },
                    )
                }
                signatures::NEW_CONTRACT_SIG => ChangedContract::decode(data)
                    .map(|ChangedContract { name, address }| PendingEvent {
                        confirmations: min_confirmations,
                        block_height,
                        event: EthereumEvent::NewContract { name, address },
                    }),
                signatures::UPGRADED_CONTRACT_SIG => ChangedContract::decode(
                    data,
                )
                .map(|ChangedContract { name, address }| PendingEvent {
                    confirmations: min_confirmations,
                    block_height,
                    event: EthereumEvent::UpgradedContract { name, address },
                }),
                signatures::UPDATE_BRIDGE_WHITELIST_SIG => {
                    UpdateBridgeWhitelist::decode(data).map(
                        |UpdateBridgeWhitelist { nonce, whitelist }| {
                            PendingEvent {
                                confirmations: min_confirmations,
                                block_height,
                                event: EthereumEvent::UpdateBridgeWhitelist {
                                    nonce,
                                    whitelist,
                                },
                            }
                        },
                    )
                }
                _ => unreachable!(),
            }
        }

        /// Check if the minimum number of confirmations has been
        /// reached at the input block height.
        pub fn is_confirmed(&self, height: &Uint256) -> bool {
            self.confirmations <= height.clone() - self.block_height.clone()
        }
    }

    /// A batch of [`TransferToNamada`] from an Ethereum event
    #[derive(Clone, Debug, PartialEq)]
    pub(super) struct RawTransfersToNamada {
        /// A list of transfers
        pub transfers: Vec<TransferToNamada>,
        /// A monotonically increasing nonce
        #[allow(dead_code)]
        pub nonce: Uint,
        /// The number of confirmations needed to consider this batch
        /// finalized
        pub confirmations: u32,
    }

    /// A batch of [`TransferToNamada`] from an Ethereum event
    #[derive(Clone, Debug, PartialEq)]
    pub(in super::super) struct RawTransfersToEthereum {
        /// A list of transfers
        pub transfers: Vec<TransferToEthereum>,
        /// A monotonically increasing nonce
        #[allow(dead_code)]
        pub nonce: Uint,
    }

    impl RawTransfersToNamada {
        /// Parse ABI serialized data from an Ethereum event into
        /// an instance of [`RawTransfersToNamada`]
        fn decode(data: &[u8]) -> Result<Self> {
            let [nonce, transfers, confs]: [Token; 3] = decode(
                &[
                    ParamType::Uint(256),
                    ParamType::Array(Box::new(ParamType::Tuple(vec![
                        ParamType::Address,
                        ParamType::Uint(256),
                        ParamType::String,
                    ]))),
                    ParamType::Uint(256),
                ],
                data,
            )
            .map_err(|err| Error::Decode(format!("{:#?}", err)))?
            .try_into()
            .map_err(|error| {
                Error::Decode(format!(
                    "TransferToNamada signature should contain three types: \
                     {:?}",
                    error
                ))
            })?;

            Ok(Self {
                transfers: transfers.parse_transfer_to_namada_array()?,
                nonce: nonce.parse_uint256()?,
                confirmations: confs.parse_u32()?,
            })
        }

        /// Serialize an instance [`RawTransfersToNamada`] using Ethereum's
        /// ABI serialization scheme.
        #[cfg(test)]
        fn encode(self) -> Vec<u8> {
            let RawTransfersToNamada {
                transfers,
                nonce,
                confirmations,
            } = self;

            let transfers = transfers
                .into_iter()
                .map(
                    |TransferToNamada {
                         asset,
                         receiver,
                         amount,
                     }| {
                        Token::Tuple(vec![
                            Token::Address(asset.0.into()),
                            Token::Uint(u64::from(amount).into()),
                            Token::String(receiver.to_string()),
                        ])
                    },
                )
                .collect();

            encode(&[
                Token::Uint(nonce.into()),
                Token::Array(transfers),
                Token::Uint(confirmations.into()),
            ])
        }
    }

    impl RawTransfersToEthereum {
        /// Parse ABI serialized data from an Ethereum event into
        /// an instance of [`RawTransfersToEthereum`]
        fn decode(data: &[u8]) -> Result<Self> {
            let [nonce, transfers]: [Token; 2] = decode(
                &[
                    ParamType::Uint(256),
                    ParamType::Array(Box::new(ParamType::Tuple(vec![
                        ParamType::Address,
                        ParamType::Address,
                        ParamType::Uint(256),
                        ParamType::String,
                        ParamType::Uint(256),
                    ]))),
                ],
                data,
            )
            .map_err(|err| Error::Decode(format!("{:?}", err)))?
            .try_into()
            .map_err(|_| {
                Error::Decode(
                    "TransferToERC signature should contain five types"
                        .to_string(),
                )
            })?;

            let transfers = transfers.parse_transfer_to_eth_array()?;
            Ok(Self {
                transfers,
                nonce: nonce.parse_uint256()?,
            })
        }

        /// Serialize an instance [`RawTransfersToNamada`] using Ethereum's
        /// ABI serialization scheme.
        #[cfg(test)]
        pub fn encode(self) -> Vec<u8> {
            let RawTransfersToEthereum { transfers, nonce } = self;

            let transfers = transfers
                .into_iter()
                .map(
                    |TransferToEthereum {
                         amount,
                         asset,
                         receiver,
                         gas_amount,
                         gas_payer,
                     }| {
                        Token::Tuple(vec![
                            Token::Address(asset.0.into()),
                            Token::Address(receiver.0.into()),
                            Token::Uint(u64::from(amount).into()),
                            Token::String(gas_payer.to_string()),
                            Token::Uint(u64::from(gas_amount).into()),
                        ])
                    },
                )
                .collect();
            encode(&[Token::Uint(nonce.into()), Token::Array(transfers)])
        }
    }

    impl ValidatorSetUpdate {
        /// Parse ABI serialized data from an Ethereum event into
        /// an instance of [`ValidatorSetUpdate`]
        fn decode(data: &[u8]) -> Result<Self> {
            let [nonce, bridge_validator_hash, goverance_validator_hash]: [Token;
                3] = decode(
                &[
                    ParamType::Uint(256),
                    ParamType::FixedBytes(32),
                    ParamType::FixedBytes(32),
                ],
                data,
            )
                .map_err(|err| Error::Decode(format!("{:?}", err)))?
                .try_into()
                .map_err(|_| {
                    Error::Decode(
                        "ValidatorSetUpdate signature should contain three types"
                            .into(),
                    )
                })?;

            Ok(Self {
                nonce: nonce.parse_uint256()?,
                bridge_validator_hash: bridge_validator_hash.parse_keccak()?,
                governance_validator_hash: goverance_validator_hash
                    .parse_keccak()?,
            })
        }

        /// Serialize an instance [`ValidatorSetUpdate`] using Ethereum's
        /// ABI serialization scheme.
        #[cfg(test)]
        fn encode(self) -> Vec<u8> {
            let ValidatorSetUpdate {
                nonce,
                bridge_validator_hash,
                governance_validator_hash,
            } = self;

            encode(&[
                Token::Uint(nonce.into()),
                Token::FixedBytes(bridge_validator_hash.0.into()),
                Token::FixedBytes(governance_validator_hash.0.into()),
            ])
        }
    }

    impl ChangedContract {
        /// Parse ABI serialized data from an Ethereum event into
        /// an instance of [`ChangedContract`]
        fn decode(data: &[u8]) -> Result<Self> {
            let [name, address]: [Token; 2] =
                decode(&[ParamType::String, ParamType::Address], data)
                    .map_err(|err| Error::Decode(format!("{:?}", err)))?
                    .try_into()
                    .map_err(|_| {
                        Error::Decode(
                            "ContractUpdate signature should contain two types"
                                .into(),
                        )
                    })?;

            Ok(Self {
                name: name.parse_string()?,
                address: address.parse_eth_address()?,
            })
        }

        /// Serialize an instance [`ChangedContract`] using Ethereum's
        /// ABI serialization scheme.
        #[cfg(test)]
        pub fn encode(self) -> Vec<u8> {
            let ChangedContract { name, address } = self;
            encode(&[Token::String(name), Token::Address(address.0.into())])
        }
    }

    impl UpdateBridgeWhitelist {
        /// Parse ABI serialized data from an Ethereum event into
        /// an instance of [`UpdateBridgeWhitelist`]
        fn decode(data: &[u8]) -> Result<Self> {
            let [nonce, tokens, caps]: [Token; 3] = decode(
                &[
                    ParamType::Uint(256),
                    ParamType::Array(Box::new(ParamType::Address)),
                    ParamType::Array(Box::new(ParamType::Uint(256))),
                ],
                data,
            )
            .map_err(|err| Error::Decode(format!("{:?}", err)))?
            .try_into()
            .map_err(|_| {
                Error::Decode(
                    "UpdatedBridgeWhitelist signature should contain three \
                     types"
                        .into(),
                )
            })?;

            let tokens = tokens.parse_eth_address_array()?;
            let caps = caps.parse_amount_array()?;
            if tokens.len() != caps.len() {
                Err(Error::Decode(
                    "UpdatedBridgeWhitelist received different number of \
                     token address and token caps"
                        .into(),
                ))
            } else {
                Ok(Self {
                    nonce: nonce.parse_uint256()?,
                    whitelist: tokens
                        .into_iter()
                        .zip(caps.into_iter())
                        .map(|(token, cap)| TokenWhitelist { token, cap })
                        .collect(),
                })
            }
        }

        /// Serialize an instance [`UpdateBridgeWhitelist`] using Ethereum's
        /// ABI serialization scheme.
        #[cfg(test)]
        fn encode(self) -> Vec<u8> {
            let UpdateBridgeWhitelist { nonce, whitelist } = self;

            let (tokens, caps): (Vec<Token>, Vec<Token>) = whitelist
                .into_iter()
                .map(|TokenWhitelist { token, cap }| {
                    (
                        Token::Address(token.0.into()),
                        Token::Uint(u64::from(cap).into()),
                    )
                })
                .unzip();
            encode(&[
                Token::Uint(nonce.into()),
                Token::Array(tokens),
                Token::Array(caps),
            ])
        }
    }

    /// Trait to add parsing methods to `Token`, which is a
    /// foreign type
    trait Parse {
        fn parse_eth_address(self) -> Result<EthAddress>;
        fn parse_address(self) -> Result<Address>;
        fn parse_amount(self) -> Result<Amount>;
        fn parse_u32(self) -> Result<u32>;
        fn parse_uint256(self) -> Result<Uint>;
        fn parse_bool(self) -> Result<bool>;
        fn parse_string(self) -> Result<String>;
        fn parse_keccak(self) -> Result<KeccakHash>;
        fn parse_amount_array(self) -> Result<Vec<Amount>>;
        fn parse_eth_address_array(self) -> Result<Vec<EthAddress>>;
        fn parse_address_array(self) -> Result<Vec<Address>>;
        fn parse_string_array(self) -> Result<Vec<String>>;
        fn parse_transfer_to_namada_array(
            self,
        ) -> Result<Vec<TransferToNamada>>;
        fn parse_transfer_to_namada(self) -> Result<TransferToNamada>;
        fn parse_transfer_to_eth_array(self)
        -> Result<Vec<TransferToEthereum>>;
        fn parse_transfer_to_eth(self) -> Result<TransferToEthereum>;
    }

    impl Parse for Token {
        fn parse_eth_address(self) -> Result<EthAddress> {
            if let Token::Address(addr) = self {
                Ok(EthAddress(addr.0))
            } else {
                Err(Error::Decode(format!(
                    "Expected type `Address`, got {:?}",
                    self
                )))
            }
        }

        fn parse_address(self) -> Result<Address> {
            if let Token::String(addr) = self {
                Address::from_str(&addr)
                    .map_err(|err| Error::Decode(format!("{:?}", err)))
            } else {
                Err(Error::Decode(format!(
                    "Expected type `String`, got {:?}",
                    self
                )))
            }
        }

        fn parse_amount(self) -> Result<Amount> {
            if let Token::Uint(amount) = self {
                Ok(Amount::from(amount.as_u64()))
            } else {
                Err(Error::Decode(format!(
                    "Expected type `Uint`, got {:?}",
                    self
                )))
            }
        }

        fn parse_u32(self) -> Result<u32> {
            if let Token::Uint(amount) = self {
                Ok(amount.as_u32())
            } else {
                Err(Error::Decode(format!(
                    "Expected type `Uint`, got {:?}",
                    self
                )))
            }
        }

        fn parse_uint256(self) -> Result<Uint> {
            if let Token::Uint(uint) = self {
                Ok(uint.into())
            } else {
                Err(Error::Decode(format!(
                    "Expected type `Uint`, got {:?}",
                    self
                )))
            }
        }

        fn parse_bool(self) -> Result<bool> {
            if let Token::Bool(b) = self {
                Ok(b)
            } else {
                Err(Error::Decode(format!(
                    "Expected type `bool`, got {:?}",
                    self
                )))
            }
        }

        fn parse_string(self) -> Result<String> {
            if let Token::String(string) = self {
                Ok(string)
            } else {
                Err(Error::Decode(format!(
                    "Expected type `String`, got {:?}",
                    self
                )))
            }
        }

        fn parse_keccak(self) -> Result<KeccakHash> {
            if let Token::FixedBytes(bytes) = self {
                let bytes = bytes.try_into().map_err(|_| {
                    Error::Decode("Expect 32 bytes for a Keccak hash".into())
                })?;
                Ok(KeccakHash(bytes))
            } else {
                Err(Error::Decode(format!(
                    "Expected type `FixedBytes`, got {:?}",
                    self
                )))
            }
        }

        fn parse_amount_array(self) -> Result<Vec<Amount>> {
            let array = if let Token::Array(array) = self {
                array
            } else {
                return Err(Error::Decode(format!(
                    "Expected type `Array`, got {:?}",
                    self
                )));
            };
            let mut amounts = vec![];
            for token in array.into_iter() {
                let amount = token.parse_amount()?;
                amounts.push(amount);
            }
            Ok(amounts)
        }

        fn parse_eth_address_array(self) -> Result<Vec<EthAddress>> {
            let array = if let Token::Array(array) = self {
                array
            } else {
                return Err(Error::Decode(format!(
                    "Expected type `Array`, got {:?}",
                    self
                )));
            };
            let mut addrs = vec![];
            for token in array.into_iter() {
                let addr = token.parse_eth_address()?;
                addrs.push(addr);
            }
            Ok(addrs)
        }

        fn parse_transfer_to_namada_array(
            self,
        ) -> Result<Vec<TransferToNamada>> {
            let array = if let Token::Array(array) = self {
                array
            } else {
                return Err(Error::Decode(format!(
                    "Expected type `Array`, got {:?}",
                    self
                )));
            };
            let mut transfers = vec![];
            for token in array.into_iter() {
                let transfer = token.parse_transfer_to_namada()?;
                transfers.push(transfer);
            }
            Ok(transfers)
        }

        fn parse_transfer_to_namada(self) -> Result<TransferToNamada> {
            if let Token::Tuple(mut items) = self {
                let asset = items.remove(0).parse_eth_address()?;
                let amount = items.remove(0).parse_amount()?;
                let receiver = items.remove(0).parse_address()?;
                Ok(TransferToNamada {
                    asset,
                    amount,
                    receiver,
                })
            } else {
                Err(Error::Decode(format!(
                    "Expected type `Tuple`, got {:?}",
                    self
                )))
            }
        }

        fn parse_transfer_to_eth_array(
            self,
        ) -> Result<Vec<TransferToEthereum>> {
            let array = if let Token::Array(array) = self {
                array
            } else {
                return Err(Error::Decode(format!(
                    "Expected type `Array`, got {:?}",
                    self
                )));
            };
            let mut transfers = vec![];
            for token in array.into_iter() {
                let transfer = token.parse_transfer_to_eth()?;
                transfers.push(transfer);
            }
            Ok(transfers)
        }

        fn parse_transfer_to_eth(self) -> Result<TransferToEthereum> {
            if let Token::Tuple(mut items) = self {
                let asset = items.remove(0).parse_eth_address()?;
                let receiver = items.remove(0).parse_eth_address()?;
                let amount = items.remove(0).parse_amount()?;
                let gas_payer = items.remove(0).parse_address()?;
                let gas_amount = items.remove(0).parse_amount()?;
                Ok(TransferToEthereum {
                    asset,
                    amount,
                    receiver,
                    gas_amount,
                    gas_payer,
                })
            } else {
                Err(Error::Decode(format!(
                    "Expected type `Tuple`, got {:?}",
                    self
                )))
            }
        }

        fn parse_address_array(self) -> Result<Vec<Address>> {
            let array = if let Token::Array(array) = self {
                array
            } else {
                return Err(Error::Decode(format!(
                    "Expected type `Array`, got {:?}",
                    self
                )));
            };
            let mut addrs = vec![];
            for token in array.into_iter() {
                let addr = token.parse_address()?;
                addrs.push(addr);
            }
            Ok(addrs)
        }

        fn parse_string_array(self) -> Result<Vec<String>> {
            let array = if let Token::Array(array) = self {
                array
            } else {
                return Err(Error::Decode(format!(
                    "Expected type `Array`, got {:?}",
                    self
                )));
            };
            let mut strings = vec![];
            for token in array.into_iter() {
                let string = token.parse_string()?;
                strings.push(string);
            }
            Ok(strings)
        }
    }

    #[cfg(test)]
    mod test_events {
        use assert_matches::assert_matches;

        use super::*;

        #[test]
        fn test_transfer_to_namada_decode() {
            let data: Vec<u8> = vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 95, 189, 178, 49, 86, 120, 175, 236, 179, 103, 240,
                50, 217, 63, 100, 47, 100, 24, 10, 163, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 84, 97, 116, 101, 115, 116, 49, 118, 52, 101, 104,
                103, 119, 51, 54, 120, 117, 117, 110, 119, 100, 54, 57, 56, 57,
                112, 114, 119, 100, 102, 107, 120, 113, 109, 110, 118, 115,
                102, 106, 120, 115, 54, 110, 118, 118, 54, 120, 120, 117, 99,
                114, 115, 51, 102, 51, 120, 99, 109, 110, 115, 51, 102, 99,
                120, 100, 122, 114, 118, 118, 122, 57, 120, 118, 101, 114, 122,
                118, 122, 114, 53, 54, 108, 101, 56, 102, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ];

            let raw = RawTransfersToNamada::decode(&data);

            let raw = raw.unwrap();
            assert_eq!(
                raw.transfers,
                vec![TransferToNamada {
                    amount: Amount::from(100),
                    asset: EthAddress::from_str("0x5FbDB2315678afecb367f032d93F642f64180aa3").unwrap(),
                    receiver: Address::decode("atest1v4ehgw36xuunwd6989prwdfkxqmnvsfjxs6nvv6xxucrs3f3xcmns3fcxdzrvvz9xverzvzr56le8f").unwrap(),
                }]
            )
        }

        /// Test that for Ethereum events for which a custom number of
        /// confirmations may be specified, if a value lower than the
        /// protocol-specified minimum confirmations is attempted to be used,
        /// then the protocol-specified minimum confirmations is used instead.
        #[test]
        fn test_min_confirmations_enforced() -> Result<()> {
            let arbitrary_block_height: Uint256 = 123u64.into();
            let min_confirmations: Uint256 = 100u64.into();
            let lower_than_min_confirmations = 5;

            let (sig, event) = (
                signatures::TRANSFER_TO_NAMADA_SIG,
                RawTransfersToNamada {
                    transfers: vec![],
                    nonce: 0.into(),
                    confirmations: lower_than_min_confirmations,
                },
            );
            let data = event.encode();
            let pending_event = PendingEvent::decode(
                sig,
                arbitrary_block_height,
                &data,
                min_confirmations.clone(),
            )?;

            assert_matches!(pending_event, PendingEvent { confirmations, .. } if confirmations == min_confirmations);

            Ok(())
        }

        /// Test that for Ethereum events for which a custom number of
        /// confirmations may be specified, the custom number is used if it is
        /// at least the protocol-specified minimum confirmations.
        #[test]
        fn test_custom_confirmations_used() {
            let arbitrary_block_height: Uint256 = 123u64.into();
            let min_confirmations: Uint256 = 100u64.into();
            let higher_than_min_confirmations = 200;

            let (sig, event) = (
                signatures::TRANSFER_TO_NAMADA_SIG,
                RawTransfersToNamada {
                    transfers: vec![],
                    nonce: 0.into(),
                    confirmations: higher_than_min_confirmations,
                },
            );
            let data = event.encode();
            let pending_event = PendingEvent::decode(
                sig,
                arbitrary_block_height,
                &data,
                min_confirmations,
            )
            .unwrap();

            assert_matches!(pending_event, PendingEvent { confirmations, .. } if confirmations == higher_than_min_confirmations.into());
        }

        /// For each of the basic types, test that roundtrip
        /// encoding - decoding is a no-op
        #[test]
        fn test_round_trips() {
            let erc = EthAddress([1; 20]);
            let address = Address::from_str("atest1v4ehgw36gep5ysecxq6nyv3jg3zygv3e89qn2vp48pryxsf4xpznvve5gvmy23fs89pryvf5a6ht90")
                .expect("Test failed");
            let amount = Amount::from(42u64);
            let confs = 50u32;
            let uint = Uint::from(42u64);
            let boolean = true;
            let string = String::from("test");
            let keccak = KeccakHash([2; 32]);

            let [token]: [Token; 1] = decode(
                &[ParamType::Address],
                encode(&[Token::Address(erc.0.into())]).as_slice(),
            )
            .expect("Test failed")
            .try_into()
            .expect("Test failed");
            assert_eq!(token.parse_eth_address().expect("Test failed"), erc);

            let [token]: [Token; 1] = decode(
                &[ParamType::String],
                encode(&[Token::String(address.to_string())]).as_slice(),
            )
            .expect("Test failed")
            .try_into()
            .expect("Test failed");
            assert_eq!(token.parse_address().expect("Test failed"), address);

            let [token]: [Token; 1] = decode(
                &[ParamType::Uint(64)],
                encode(&[Token::Uint(u64::from(amount).into())]).as_slice(),
            )
            .expect("Test failed")
            .try_into()
            .expect("Test failed");
            assert_eq!(token.parse_amount().expect("Test failed"), amount);

            let [token]: [Token; 1] = decode(
                &[ParamType::Uint(32)],
                encode(&[Token::Uint(confs.into())]).as_slice(),
            )
            .expect("Test failed")
            .try_into()
            .expect("Test failed");
            assert_eq!(token.parse_u32().expect("Test failed"), confs);

            let [token]: [Token; 1] = decode(
                &[ParamType::Uint(256)],
                encode(&[Token::Uint(uint.clone().into())]).as_slice(),
            )
            .expect("Test failed")
            .try_into()
            .expect("Test failed");
            assert_eq!(token.parse_uint256().expect("Test failed"), uint);

            let [token]: [Token; 1] = decode(
                &[ParamType::Bool],
                encode(&[Token::Bool(boolean)]).as_slice(),
            )
            .expect("Test failed")
            .try_into()
            .expect("Test failed");
            assert_eq!(token.parse_bool().expect("Test failed"), boolean);

            let [token]: [Token; 1] = decode(
                &[ParamType::String],
                encode(&[Token::String(string.clone())]).as_slice(),
            )
            .expect("Test failed")
            .try_into()
            .expect("Test failed");
            assert_eq!(token.parse_string().expect("Test failed"), string);

            let [token]: [Token; 1] = decode(
                &[ParamType::FixedBytes(32)],
                encode(&[Token::FixedBytes(keccak.0.to_vec())]).as_slice(),
            )
            .expect("Test failed")
            .try_into()
            .expect("Test failed");
            assert_eq!(token.parse_keccak().expect("Test failed"), keccak);
        }

        /// Test that serialization and deserialization of
        /// complex composite types is a no-op
        #[test]
        fn test_complex_round_trips() {
            let address = Address::from_str("atest1v4ehgw36gep5ysecxq6nyv3jg3zygv3e89qn2vp48pryxsf4xpznvve5gvmy23fs89pryvf5a6ht90")
                .expect("Test failed");
            let nam_transfers = RawTransfersToNamada {
                transfers: vec![
                    TransferToNamada {
                        amount: Default::default(),
                        asset: EthAddress([0; 20]),
                        receiver: address.clone(),
                    };
                    2
                ],
                nonce: Uint::from(1),
                confirmations: 0,
            };
            let eth_transfers = RawTransfersToEthereum {
                transfers: vec![
                    TransferToEthereum {
                        amount: Default::default(),
                        asset: EthAddress([1; 20]),
                        receiver: EthAddress([2; 20]),
                        gas_amount: Default::default(),
                        gas_payer: address,
                    };
                    2
                ],
                nonce: Uint::from(1),
            };
            let update = ValidatorSetUpdate {
                nonce: Uint::from(1),
                bridge_validator_hash: KeccakHash([1; 32]),
                governance_validator_hash: KeccakHash([2; 32]),
            };
            let changed = ChangedContract {
                name: "Test".to_string(),
                address: EthAddress([0; 20]),
            };
            let whitelist = UpdateBridgeWhitelist {
                nonce: Uint::from(1),
                whitelist: vec![
                    TokenWhitelist {
                        token: EthAddress([0; 20]),
                        cap: Amount::from(1000),
                    };
                    2
                ],
            };
            assert_eq!(
                RawTransfersToNamada::decode(&nam_transfers.clone().encode())
                    .expect("Test failed"),
                nam_transfers
            );
            assert_eq!(
                RawTransfersToEthereum::decode(&eth_transfers.clone().encode())
                    .expect("Test failed"),
                eth_transfers
            );
            assert_eq!(
                ValidatorSetUpdate::decode(&update.clone().encode())
                    .expect("Test failed"),
                update
            );
            assert_eq!(
                ChangedContract::decode(&changed.clone().encode())
                    .expect("Test failed"),
                changed
            );
            assert_eq!(
                UpdateBridgeWhitelist::decode(&whitelist.clone().encode())
                    .expect("Test failed"),
                whitelist
            );
        }
    }
}

pub use eth_events::*;
