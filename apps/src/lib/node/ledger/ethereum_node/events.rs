use std::convert::TryInto;
use std::str::FromStr;

use anoma::types::address::Address;
use anoma::types::token::Amount;
use ethabi::param_type::ParamType;
use ethabi::token::Token;
use ethabi::{decode, encode, Uint};
use num256::Uint256;

use super::{Error, Result};

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

/// Representation of address on Ethereum
#[derive(Clone, Debug, PartialEq)]
pub struct EthAddress(pub [u8; 20]);

/// A Keccak hash
#[derive(Clone, Debug, PartialEq)]
pub struct KeccakHash(pub [u8; 32]);

/// An Ethereum event to be processed by the Anoma ledger
pub enum EthereumEvent {
    TransfersToNamada(Vec<TransferToNamada>),
    TransfersToErc(Vec<TransferToErc>),
    ValidatorSetUpdate {
        nonce: Uint,
        bridge_validator_hash: KeccakHash,
        governance_validator_hash: KeccakHash,
    },
    NewContract {
        name: String,
        address: EthAddress,
    },
    UpgradedContract {
        name: String,
        address: EthAddress,
    },
    UpdateBridgeWhitelist {
        nonce: Uint,
        whitelist: Vec<TokenWhitelist>,
    },
}

/// An event waiting for a certain number of confirmations
/// before being sent to the ledger
pub struct PendingEvent {
    confirmations: Uint256,
    block_height: Uint256,
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
                RawTransfersToNamada::decode(data).map(|txs| PendingEvent {
                    confirmations: txs.confirmations.into(),
                    block_height,
                    event: EthereumEvent::TransfersToNamada(txs.transfers),
                })
            }
            signatures::TRANSFER_TO_ERC_SIG => {
                RawTransfersToNamada::decode(data).map(|txs| PendingEvent {
                    confirmations: txs.confirmations.into(),
                    block_height,
                    event: EthereumEvent::TransfersToErc(txs.transfers),
                })
            }
            signatures::VALIDATOR_SET_UPDATE_SIG => {
                ValidatorSetUpdate::decode(data).map(
                    |ValidatorSetUpdate {
                         nonce,
                         bridge_validator_hash,
                         governance_validator_hash,
                     }| PendingEvent {
                        confirmations: super::MIN_CONFIRMATIONS.into(),
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
                    confirmations: super::MIN_CONFIRMATIONS.into(),
                    block_height,
                    event: EthereumEvent::NewContract { name, address },
                }),
            signatures::UPGRADED_CONTRACT_SIG => RawChangedContract::decode(
                data,
            )
            .map(|RawChangedContract { name, address }| PendingEvent {
                confirmations: super::MIN_CONFIRMATIONS.into(),
                block_height,
                event: EthereumEvent::UpgradedContract { name, address },
            }),
            signatures::UPDATE_BRIDGE_WHITELIST_SIG => {
                UpdateBridgeWhitelist::decode(data).map(
                    |UpdateBridgeWhitelist { nonce, whitelist }| PendingEvent {
                        confirmations: super::MIN_CONFIRMATIONS.into(),
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
        &self.confirmations >= height - &self.block_height
    }
}

/// Type of address to transfer to on Anoma
enum TargetAddressType {
    Native,
    Erc20,
}

/// Trait for determining target address type
trait TargetAddress {
    fn address_type() -> TargetAddressType;
    fn into_token(&self) -> Token;
}

impl TargetAddress for Address {
    fn address_type() -> TargetAddressType {
        TargetAddressType::Native
    }
    fn into_token(&self) -> Token {
        Token::String(self.encode())
    }
}

impl TargetAddress for EthAddress {
    fn address_type() -> TargetAddressType {
        TargetAddressType::Erc20
    }
    fn into_token(&self) -> Token {
        Token::Address(self.0.into())
    }
}

/// An event transferring some kind of value from Ethereum to Anoma
pub struct RawTransferToNamada<T: TargetAddress> {
    amount: Amount,
    source: EthAddress,
    target: T,
}

/// A batch of RawTransferToNamadas from an Ethereum event
pub struct RawTransfersToNamada<T: TargetAddress> {
    transfers: Vec<RawTransferToNamada<T>>,
    nonce: Uint,
    confirmations: u32,
}

/// Type aliases
pub type TransferToNamada = RawTransferToNamada<Address>;
pub type TransferToErc = RawTransferToNamada<EthAddress>;

/// Event emitted with the validator set changes
struct ValidatorSetUpdate {
    nonce: Uint,
    bridge_validator_hash: KeccakHash,
    governance_validator_hash: KeccakHash,
}

/// Event indicating a new smart contract has been
/// deployed or upgraded on Ethereum
struct RawChangedContract {
    name: String,
    address: EthAddress,
}

/// struct for whitelisting a token from Ethereum.
/// Includes the address of issuing contract and
/// a cap on the max amount of this token allowed to be
/// held by the bridge.
pub struct TokenWhitelist {
    token: EthAddress,
    cap: Amount,
}

/// Event for whitelisting new tokens and their
/// rate limits
struct UpdateBridgeWhitelist {
    nonce: Uint,
    whitelist: Vec<TokenWhitelist>,
}

impl<T: TargetAddress> RawTransfersToNamada<T> {
    fn decode(data: &[u8]) -> Result<Self> {
        let name = match T::address_type() {
            TargetAddressType::Native => "TransferToNamada",
            TargetAddressType::Erc20 => "TransferToErc",
        };

        let [nonce, sources, targets, amounts, confs]: [Token; 5] = decode(
            &[
                ParamType::Uint(256),
                ParamType::Array(Box::new(ParamType::Address)),
                match T::address_type() {
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
        let targets: Vec<T> = match T::address_type() {
            TargetAddressType::Native => targets.parse_address_array()?,
            TargetAddressType::Erc20 => targets.parse_eth_address_array()?,
        };
        let amounts = amounts.parse_amount_array()?;
        if sources.len() != amounts.len() {
            Err(Error::Decode(
                "Number of source addresses is different from number of \
                 transfer amounts"
                    .into(),
            ))
        } else if targets.len() != sources.len() {
            Err(Error::Decode(
                "Number of source addresses is different from number of \
                 target addresses"
                    .into(),
            ))
        } else {
            Ok(RawTransfersToNamada {
                transfers: sources
                    .into_iter()
                    .zip(targets.into_iter())
                    .zip(amounts.into_iter())
                    .map(|((source, target), amount)| RawTransferToNamada {
                        source,
                        target,
                        amount,
                    })
                    .collect(),
                nonce: nonce.parse_uint256()?,
                confirmations: confs.parse_u32()?,
            })
        }
    }

    fn encode(self) -> Vec<u8> {
        let Self {
            transfers,
            nonce,
            confirmations,
        } = self;

        let amounts: Vec<Token> = transfers.iter()
            .map(|RawTransferToNamada{amount, ..}| Token::Uint(u64::from(*amount).into()))
            .collect();
        let (sources, targets): (Vec<Token>, Vec<Token>) = transfers.into_iter()
                .map(|RawTransferToNamada{source, target, ..}|
                    (Token::Address(source.0.into()), target.into_token())
                )
            .unzip();
        encode(&[
            Token::Uint(nonce),
            Token::Array(sources),
            Token::Array(targets),
            Token::Array(amounts),
            Token::Uint(confirmations.into()),
        ])
    }
}

impl ValidatorSetUpdate {
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

    fn encode(self) -> Vec<u8> {
        let RawChangedContract {
            name,
            address,
        } = self;
        encode(&[Token::String(name), Token::Address(address.0.into())])
    }
}

impl UpdateBridgeWhitelist {
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

    fn encode(self) -> Vec<u8> {
        let UpdateBridgeWhitelist {
            nonce,
            whitelist,
        } = self;

        let (tokens, caps): (Vec<Token>, Vec<Token>) = whitelist.into_iter()
            .map(| TokenWhitelist{token, cap} |
                (Token::Address(token.0.into()), Token::Uint(u64::from(cap).into()))
            )
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
            let bytes = bytes.try_into().map_err(Error::Decode(
                "Expect 32 bytes for a Keccak hash".into(),
            ))?;
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
                encode(&[Token::Address(erc.0.into())]).as_slice())
            .expect("Test failed"),
            erc
        )
    }
}