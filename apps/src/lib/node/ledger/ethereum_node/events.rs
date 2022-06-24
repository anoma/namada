use std::convert::TryInto;
use std::fmt::Debug;
use std::str::FromStr;

use anoma::types::address::Address;
use anoma::types::token::Amount;
use ethabi::param_type::ParamType;
use ethabi::token::Token;
use ethabi::{decode, encode, Uint};
use itertools::Either;
use num256::Uint256;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Could not decode Ethereum event: {0}")]
    Decode(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub mod signatures {
    pub const TRANSFER_TO_NAMADA_SIG: &str =
        "TransferToNamada(uint256,address[],string[],uint256[],uint32)";
    pub const TRANSFER_TO_ERC_SIG: &str =
        "TransferToErc(uint256,address[],address[],uint256[],uint32)";
    pub const VALIDATOR_SET_UPDATE_SIG: &str =
        "ValidatorSetUpdate(uint256,bytes32,bytes32)";
    pub const NEW_CONTRACT_SIG: &str = "NewContract(string,address)";
    pub const UPGRADED_CONTRACT_SIG: &str = "UpgradedContract(string,address)";
    pub const UPDATE_BRIDGE_WHITELIST_SIG: &str =
        "UpdateBridgeWhiteList(uint256,address[],uint256[])";
    pub const SIGNATURES: [&str; 6] = [
        TRANSFER_TO_NAMADA_SIG,
        TRANSFER_TO_ERC_SIG,
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
                TRANSFER_TO_NAMADA_SIG | TRANSFER_TO_ERC_SIG => SigType::Bridge,
                _ => SigType::Governance,
            }
        }
    }
}

/// An event waiting for a certain number of confirmations
/// before being sent to the ledger
pub struct PendingEvent {
    /// number of confirmations to consider this event finalized
    confirmations: Uint256,
    /// the block height from which this event originated
    block_height: Uint256,
    /// the event itself
    pub event: EthereumEvent,
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
    ) -> Result<Self> {
        match signature {
            signatures::TRANSFER_TO_NAMADA_SIG => {
                RawTransfersToNamada::decode(data, TargetAddressType::Native)
                    .map(|txs| PendingEvent {
                        confirmations: txs.confirmations.into(),
                        block_height,
                        event: EthereumEvent::TransfersToNamada(
                            txs.transfers.unwrap_left(),
                        ),
                    })
            }
            signatures::TRANSFER_TO_ERC_SIG => {
                RawTransfersToNamada::decode(data, TargetAddressType::Erc20)
                    .map(|txs| PendingEvent {
                        confirmations: txs.confirmations.into(),
                        block_height,
                        event: EthereumEvent::TransfersToErc(
                            txs.transfers.unwrap_right(),
                        ),
                    })
            }
            signatures::VALIDATOR_SET_UPDATE_SIG => {
                ValidatorSetUpdate::decode(data).map(
                    |ValidatorSetUpdate {
                         nonce,
                         bridge_validator_hash,
                         governance_validator_hash,
                     }| PendingEvent {
                        confirmations: super::oracle::MIN_CONFIRMATIONS.into(),
                        block_height,
                        event: EthereumEvent::ValidatorSetUpdate {
                            nonce,
                            bridge_validator_hash,
                            governance_validator_hash,
                        },
                    },
                )
            }
            signatures::NEW_CONTRACT_SIG => RawChangedContract::decode(data)
                .map(|RawChangedContract { name, address }| PendingEvent {
                    confirmations: super::oracle::MIN_CONFIRMATIONS.into(),
                    block_height,
                    event: EthereumEvent::NewContract { name, address },
                }),
            signatures::UPGRADED_CONTRACT_SIG => RawChangedContract::decode(
                data,
            )
            .map(|RawChangedContract { name, address }| PendingEvent {
                confirmations: super::oracle::MIN_CONFIRMATIONS.into(),
                block_height,
                event: EthereumEvent::UpgradedContract { name, address },
            }),
            signatures::UPDATE_BRIDGE_WHITELIST_SIG => {
                UpdateBridgeWhitelist::decode(data).map(
                    |UpdateBridgeWhitelist { nonce, whitelist }| PendingEvent {
                        confirmations: super::oracle::MIN_CONFIRMATIONS.into(),
                        block_height,
                        event: EthereumEvent::UpdateBridgeWhitelist {
                            nonce,
                            whitelist,
                        },
                    },
                )
            }
            _ => unreachable!(),
        }
    }

    /// Check if the minimum number of confirmations has been
    /// reached at the input block height.
    pub fn is_confirmed(&self, height: &Uint256) -> bool {
        self.confirmations >= height.clone() - self.block_height.clone()
    }
}

/// Representation of address on Ethereum
#[derive(Clone, Debug, PartialEq)]
pub struct EthAddress(pub [u8; 20]);

/// A Keccak hash
#[derive(Clone, Debug, PartialEq)]
pub struct KeccakHash(pub [u8; 32]);

/// An Ethereum event to be processed by the Anoma ledger
#[derive(Debug)]
pub enum EthereumEvent {
    /// Event transferring batches of ether from Ethereum to wrapped ETH on
    /// Anoma
    TransfersToNamada(Vec<TransferToNamada>),
    /// Event transferring a batch of ERC20 tokens from Ethereum to a wrapped
    /// version on Anoma
    TransfersToErc(Vec<TransferToErc>),
    /// Event indication that the validator set has been updated
    /// in the governance contract
    ValidatorSetUpdate {
        /// Monotonically increasing nonce
        nonce: Uint,
        /// Hash of the validators in the bridge contract
        bridge_validator_hash: KeccakHash,
        /// Hash of the validators in the governance contract
        governance_validator_hash: KeccakHash,
    },
    /// Event indication that a new smart contract has been
    /// deployed
    NewContract {
        /// Name of the contract
        name: String,
        /// Address of the contract on Ethereum
        address: EthAddress,
    },
    /// Event indicating that a smart contract has been updated
    UpgradedContract {
        /// Name of the contract
        name: String,
        /// Address of the contract on Ethereum
        address: EthAddress,
    },
    /// Event indication a new Ethereum based token has been whitelisted for
    /// transfer across the bridge
    UpdateBridgeWhitelist {
        /// Monotonically increasing nonce
        nonce: Uint,
        /// Tokens to be allowed to be transferred across the bridge
        whitelist: Vec<TokenWhitelist>,
    },
}

/// An event transferring some kind of value from Ethereum to Anoma
#[derive(Debug)]
pub struct RawTransferToNamada<T: TargetAddress> {
    /// Quantity of ether in the transfer
    pub amount: Amount,
    /// Address paying the ether
    pub source: EthAddress,
    /// The address receiving wrapped assets on Anoma
    pub target: T,
}

/// Type alias for transferring ether to wrapped ETH
pub type TransferToNamada = RawTransferToNamada<Address>;
/// Type alias for transferring ERC20 to wrapped version on Anoma
pub type TransferToErc = RawTransferToNamada<EthAddress>;

/// struct for whitelisting a token from Ethereum.
/// Includes the address of issuing contract and
/// a cap on the max amount of this token allowed to be
/// held by the bridge.
#[derive(Debug)]
pub struct TokenWhitelist {
    /// Address of Ethereum smart contract issuing token
    pub token: EthAddress,
    /// Maximum amount of token allowed on the bridge
    pub cap: Amount,
}

/// A batch of [`RawTransferToNamada`] from an Ethereum event
struct RawTransfersToNamada {
    /// A list of transfers
    pub transfers: Either<Vec<TransferToNamada>, Vec<TransferToErc>>,
    /// A monotonically increasing nonce
    pub nonce: Uint,
    /// The number of confirmations needed to consider this batch
    /// finalized
    pub confirmations: u32,
}

/// Event emitted with the validator set changes
struct ValidatorSetUpdate {
    /// A monotonically increasing nonce
    nonce: Uint,
    /// Hash of the validators in the bridge contract
    bridge_validator_hash: KeccakHash,
    /// Hash of the validators in the governance contract
    governance_validator_hash: KeccakHash,
}

/// Event indicating a new smart contract has been
/// deployed or upgraded on Ethereum
struct RawChangedContract {
    /// Name of the contract
    name: String,
    /// Address of the contract on Ethereum
    address: EthAddress,
}

/// Event for whitelisting new tokens and their
/// rate limits
struct UpdateBridgeWhitelist {
    /// A monotonically increasing nonce
    nonce: Uint,
    /// Tokens to be allowed to be transferred across the bridge
    whitelist: Vec<TokenWhitelist>,
}

/// Type of address to transfer to on Anoma
enum TargetAddressType {
    /// Output of the bridge will be wrapped ETH
    Native,
    /// Output of the bridge will be a wrapped ERC20 token
    Erc20,
}

/// Trait for determining target address type
pub trait TargetAddress: Debug {
    fn to_token(&self) -> Token;
}

impl TargetAddress for Address {
    fn to_token(&self) -> Token {
        Token::String(self.encode())
    }
}

impl TargetAddress for EthAddress {
    fn to_token(&self) -> Token {
        Token::Address(self.0.into())
    }
}

impl RawTransfersToNamada {
    /// Parse ABI serialized data from an Ethereum event into
    /// an instance of [`RawTransfersToNamada`]
    fn decode(data: &[u8], address_type: TargetAddressType) -> Result<Self> {
        let name = match address_type {
            TargetAddressType::Native => "TransferToNamada",
            TargetAddressType::Erc20 => "TransferToErc",
        };

        let [nonce, sources, targets, amounts, confs]: [Token; 5] = decode(
            &[
                ParamType::Uint(256),
                ParamType::Array(Box::new(ParamType::Address)),
                match address_type {
                    TargetAddressType::Native => {
                        ParamType::Array(Box::new(ParamType::String))
                    }
                    TargetAddressType::Erc20 => {
                        ParamType::Array(Box::new(ParamType::Address))
                    }
                },
                ParamType::Array(Box::new(ParamType::Uint(256))),
                ParamType::Uint(32),
            ],
            data,
        )
        .map_err(|err| Error::Decode(format!("{:?}", err)))?
        .try_into()
        .map_err(|_| {
            Error::Decode(format!(
                "{} signature should contain five types",
                name
            ))
        })?;

        let sources = sources.parse_eth_address_array()?;
        let targets: Either<Vec<Address>, Vec<EthAddress>> = match address_type
        {
            TargetAddressType::Native => {
                Either::Left(targets.parse_address_array()?)
            }
            TargetAddressType::Erc20 => {
                Either::Right(targets.parse_eth_address_array()?)
            }
        };
        let amounts = amounts.parse_amount_array()?;
        if sources.len() != amounts.len() {
            Err(Error::Decode(
                "Number of source addresses is different from number of \
                 transfer amounts"
                    .into(),
            ))
        } else if targets.as_ref().either(|l| l.len(), |r| r.len())
            != sources.len()
        {
            Err(Error::Decode(
                "Number of source addresses is different from number of \
                 target addresses"
                    .into(),
            ))
        } else {
            Ok(Self {
                transfers: match targets {
                    Either::Left(targets) => Either::Left(Self::craft_transfers(sources, amounts, targets)),
                    Either::Right(targets) => Either::Right(Self::craft_transfers(sources, amounts, targets)),
                },
                nonce: nonce.parse_uint256()?,
                confirmations: confs.parse_u32()?,
            })
        }
    }

    /// Method that zips together the sources, amounts, and targets
    /// into a vector of transfers
    fn craft_transfers<T: TargetAddress>(
        sources: Vec<EthAddress>,
        amounts: Vec<Amount>,
        targets: Vec<T>
    ) -> Vec<RawTransferToNamada<T>> {
        sources
            .into_iter()
            .zip(targets.into_iter())
            .zip(amounts.into_iter())
            .map(|((source, target), amount)| RawTransferToNamada {
                source,
                target,
                amount,
            })
            .collect()
    }

    /// Serialize an instance [`RawTransfersToNamada`] using Ethereum's
    /// ABI serialization scheme.
    fn encode(self) -> Vec<u8> {
        let RawTransfersToNamada {
            transfers,
            nonce,
            confirmations,
        } = self;
        let [amounts, sources, targets] = match transfers {
            Either::Left(transfers) => Self::tokenize_transfers(transfers),
            Either::Right(transfers) => Self::tokenize_transfers(transfers),
        };

        encode(&[
            Token::Uint(nonce.into()),
            Token::Array(sources),
            Token::Array(targets),
            Token::Array(amounts),
            Token::Uint(confirmations.into()),
        ])
    }

    /// Serializeds a vector of transfers using the ABI scheme in a way
    /// that matches how the ethereum smart contracts encodes
    /// a batch of transfers in an event.
    fn tokenize_transfers<T: TargetAddress>(transfers: Vec<RawTransferToNamada<T>>) -> [Vec<Token>; 3] {
        let amounts: Vec<Token> = transfers
            .iter()
            .map(|RawTransferToNamada { amount, .. }| {
                Token::Uint(u64::from(*amount).into())
            })
            .collect();
        let (sources, targets): (Vec<Token>, Vec<Token>) = transfers
            .into_iter()
            .map(|RawTransferToNamada { source, target, .. }| {
                (Token::Address(source.0.into()), target.to_token())
            })
            .unzip();
        [amounts, sources, targets]
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
    fn encode(self) -> Vec<u8> {
        let ValidatorSetUpdate {
            nonce,
            bridge_validator_hash,
            governance_validator_hash,
        } = self;

        encode(&[
            Token::Uint(nonce),
            Token::FixedBytes(bridge_validator_hash.0.into()),
            Token::FixedBytes(governance_validator_hash.0.into()),
        ])
    }
}

impl RawChangedContract {
    /// Parse ABI serialized data from an Ethereum event into
    /// an instance of [`RawChangedContract`]
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

    /// Serialize an instance [`RawChangedContract`] using Ethereum's
    /// ABI serialization scheme.
    fn encode(self) -> Vec<u8> {
        let RawChangedContract { name, address } = self;
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
                "UpdatedBridgeWhitelist signature should contain three types"
                    .into(),
            )
        })?;

        let tokens = tokens.parse_eth_address_array()?;
        let caps = caps.parse_amount_array()?;
        if tokens.len() != caps.len() {
            Err(Error::Decode(
                "UpdatedBridgeWhitelist received different number of token \
                 address and token caps"
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
        encode(&[Token::Uint(nonce), Token::Array(tokens), Token::Array(caps)])
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
            Ok(uint)
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
    use super::*;

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

        assert_eq!(
            decode(
                &[ParamType::Address],
                encode(&[Token::Address(erc.0.into())]).as_slice()
            )
            .expect("Test failed"),
            erc
        )
    }
}
