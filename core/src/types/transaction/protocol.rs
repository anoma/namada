/// Types for sending and verifying txs
/// used in Namada protocols
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::types::address::Address;

/// A data type containing information used to update the DKG session key
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct UpdateDkgSessionKey {
    /// The storage key of the validators public DKG session key
    pub address: Address,
    /// The serialization of the new public key associated with the validator
    pub dkg_public_key: Vec<u8>,
}

#[cfg(feature = "ferveo-tpke")]
mod protocol_txs {
    use std::io::{ErrorKind, Write};
    use std::path::Path;

    use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
    use ferveo::dkg::pv::Message;
    use serde_json;

    use super::*;
    use crate::proto::{Code, Data, Section, Signature, Tx, TxError};
    use crate::types::chain::ChainId;
    use crate::types::key::*;
    use crate::types::transaction::{Digest, EllipticCurve, Sha256, TxType};
    use crate::types::vote_extensions::{
        bridge_pool_roots, ethereum_events, validator_set_update,
    };

    const TX_NEW_DKG_KP_WASM: &str = "tx_update_dkg_session_keypair.wasm";

    #[derive(
        Clone,
        Debug,
        BorshSerialize,
        BorshDeserialize,
        BorshSchema,
        Serialize,
        Deserialize,
    )]
    /// Txs sent by validators as part of internal protocols
    pub struct ProtocolTx {
        /// we require ProtocolTxs be signed
        pub pk: common::PublicKey,
        /// The type of protocol message being sent
        pub tx: ProtocolTxType,
    }

    impl ProtocolTx {
        /// Validate the signature of a protocol tx
        pub fn validate_sig(
            &self,
            signed_hash: [u8; 32],
            sig: &common::Signature,
        ) -> Result<(), TxError> {
            common::SigScheme::verify_signature(&self.pk, &signed_hash, sig)
                .map_err(|err| {
                    TxError::SigError(format!(
                        "ProtocolTx signature verification failed: {}",
                        err
                    ))
                })
        }

        /// Produce a SHA-256 hash of this section
        pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
            hasher.update(
                self.try_to_vec().expect("unable to serialize protocol"),
            );
            hasher
        }
    }

    macro_rules! ethereum_tx_data_deserialize_inner {
        ($variant:ty) => {
            impl TryFrom<&Tx> for $variant {
                type Error = TxError;

                fn try_from(tx: &Tx) -> Result<Self, TxError> {
                    let tx_data = tx.data().ok_or_else(|| {
                        TxError::Deserialization(
                            "Expected protocol tx type associated data".into(),
                        )
                    })?;
                    Self::try_from_slice(&tx_data).map_err(|err| {
                        TxError::Deserialization(err.to_string())
                    })
                }
            }
        };
    }

    macro_rules! ethereum_tx_data_declare {
        (
            $( #[$outer_attrs:meta] )*
            {
                $(
                    $(#[$inner_attrs:meta])*
                    $variant:ident ($inner_ty:ty)
                ),* $(,)?
            }
        ) => {
            $( #[$outer_attrs] )*
            pub enum EthereumTxData {
                $(
                    $(#[$inner_attrs])*
                    $variant ( $inner_ty )
                ),*
            }

            /// All the variants of [`EthereumTxData`], stored
            /// in a trait.
            #[allow(missing_docs)]
            pub trait EthereumTxDataVariants {
                $( type $variant; )*
            }

            impl EthereumTxDataVariants for EthereumTxData {
                $( type $variant = $inner_ty; )*
            }

            #[allow(missing_docs)]
            pub mod ethereum_tx_data_variants {
                //! All the variants of [`EthereumTxData`], stored
                //! in a module.
                use super::*;

                $( pub type $variant = $inner_ty; )*
            }

            $( ethereum_tx_data_deserialize_inner!($inner_ty); )*
        };
    }

    ethereum_tx_data_declare! {
        /// Data associated with Ethereum protocol transactions.
        #[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema)]
        {
            /// Ethereum events contained in vote extensions that
            /// are compressed before being included on chain
            EthereumEvents(ethereum_events::VextDigest),
            /// Collection of signatures over the Ethereum bridge
            /// pool merkle root and nonce.
            BridgePool(bridge_pool_roots::MultiSignedVext),
            /// Validator set updates contained in vote extensions
            ValidatorSetUpdate(validator_set_update::VextDigest),
            /// Ethereum events seen by some validator
            EthEventsVext(ethereum_events::SignedVext),
            /// Signature over the Ethereum bridge pool merkle root and nonce.
            BridgePoolVext(bridge_pool_roots::SignedVext),
            /// Validator set update signed by some validator
            ValSetUpdateVext(validator_set_update::SignedVext),
        }
    }

    impl TryFrom<&Tx> for EthereumTxData {
        type Error = TxError;

        fn try_from(tx: &Tx) -> Result<Self, TxError> {
            let TxType::Protocol(protocol_tx) = tx.header().tx_type else {
                return Err(TxError::Deserialization(
                    "Expected protocol tx type".into(),
                ));
            };
            let Some(tx_data) = tx.data() else {
                return Err(TxError::Deserialization(
                    "Expected protocol tx type associated data".into(),
                ));
            };
            Self::deserialize(&protocol_tx.tx, &tx_data)
        }
    }

    impl EthereumTxData {
        /// Sign transaction Ethereum data and wrap it in a [`Tx`].
        pub fn sign(
            &self,
            signing_key: &common::SecretKey,
            chain_id: ChainId,
        ) -> Tx {
            let (tx_data, tx_type) = self.serialize();
            let mut outer_tx =
                Tx::from_type(TxType::Protocol(Box::new(ProtocolTx {
                    pk: signing_key.ref_to(),
                    tx: tx_type,
                })));
            outer_tx.header.chain_id = chain_id;
            outer_tx.set_data(Data::new(tx_data));
            outer_tx.add_section(Section::Signature(Signature::new(
                outer_tx.sechashes(),
                [(0, signing_key.clone())].into_iter().collect(),
                None,
            )));
            outer_tx
        }

        /// Serialize Ethereum protocol transaction data.
        pub fn serialize(&self) -> (Vec<u8>, ProtocolTxType) {
            macro_rules! match_of_type {
                ( $( $type:ident ),* $(,)?) => {
                    match self {
                        $( EthereumTxData::$type(x) =>
                            x.try_to_vec().map(|data| (data, ProtocolTxType::$type))),*
                    }
                }
            }
            match_of_type! {
                EthereumEvents,
                BridgePool,
                ValidatorSetUpdate,
                EthEventsVext,
                BridgePoolVext,
                ValSetUpdateVext,
            }
            .expect("Should be able to borsh-serialize tx data")
        }

        /// Deserialize Ethereum protocol transaction data.
        pub fn deserialize(
            tx_type: &ProtocolTxType,
            data: &[u8],
        ) -> Result<Self, TxError> {
            let deserialize: fn(&[u8]) -> _ = match tx_type {
                ProtocolTxType::EthereumEvents => |data| {
                    BorshDeserialize::try_from_slice(data)
                        .map(EthereumTxData::EthereumEvents)
                },
                ProtocolTxType::BridgePool => |data| {
                    BorshDeserialize::try_from_slice(data)
                        .map(EthereumTxData::BridgePool)
                },
                ProtocolTxType::ValidatorSetUpdate => |data| {
                    BorshDeserialize::try_from_slice(data)
                        .map(EthereumTxData::ValidatorSetUpdate)
                },
                ProtocolTxType::EthEventsVext => |data| {
                    BorshDeserialize::try_from_slice(data)
                        .map(EthereumTxData::EthEventsVext)
                },
                ProtocolTxType::BridgePoolVext => |data| {
                    BorshDeserialize::try_from_slice(data)
                        .map(EthereumTxData::BridgePoolVext)
                },
                ProtocolTxType::ValSetUpdateVext => |data| {
                    BorshDeserialize::try_from_slice(data)
                        .map(EthereumTxData::ValSetUpdateVext)
                },
                tx => {
                    return Err(TxError::Deserialization(format!(
                        "Not an Ethereum protocol tx: {tx:?}"
                    )));
                }
            };
            deserialize(data)
                .map_err(|err| TxError::Deserialization(err.to_string()))
        }
    }

    /// DKG message wrapper type that adds Borsh encoding.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct DkgMessage(pub Message<EllipticCurve>);

    #[derive(
        Clone,
        Debug,
        BorshSerialize,
        BorshDeserialize,
        BorshSchema,
        Serialize,
        Deserialize,
    )]
    #[allow(clippy::large_enum_variant)]
    /// Types of protocol messages to be sent
    pub enum ProtocolTxType {
        /// Messages to be given to the DKG state machine
        DKG(DkgMessage),
        /// Tx requesting a new DKG session keypair
        NewDkgKeypair,
        /// Ethereum events contained in vote extensions that
        /// are compressed before being included on chain
        EthereumEvents,
        /// Collection of signatures over the Ethereum bridge
        /// pool merkle root and nonce.
        BridgePool,
        /// Validator set updates contained in vote extensions
        ValidatorSetUpdate,
        /// Ethereum events seen by some validator
        EthEventsVext,
        /// Signature over the Ethereum bridge pool merkle root and nonce.
        BridgePoolVext,
        /// Validator set update signed by some validator
        ValSetUpdateVext,
    }

    impl ProtocolTxType {
        /// Create a new tx requesting a new DKG session keypair
        pub fn request_new_dkg_keypair<'a, F>(
            data: UpdateDkgSessionKey,
            signing_key: &common::SecretKey,
            wasm_dir: &'a Path,
            wasm_loader: F,
            chain_id: ChainId,
        ) -> Tx
        where
            F: FnOnce(&'a str, &'static str) -> Vec<u8>,
        {
            let code = wasm_loader(
                wasm_dir
                    .to_str()
                    .expect("Converting path to string should not fail"),
                TX_NEW_DKG_KP_WASM,
            );
            let mut outer_tx =
                Tx::from_type(TxType::Protocol(Box::new(ProtocolTx {
                    pk: signing_key.ref_to(),
                    tx: Self::NewDkgKeypair,
                })));
            outer_tx.header.chain_id = chain_id;
            outer_tx.set_code(Code::new(code));
            outer_tx.set_data(Data::new(
                data.try_to_vec()
                    .expect("Serializing request should not fail"),
            ));
            outer_tx.add_section(Section::Signature(Signature::new(
                vec![outer_tx.header_hash()],
                [(0, signing_key.clone())].into_iter().collect(),
                None,
            )));
            outer_tx
        }

        /// Determine if this [`ProtocolTxType`] is an Ethereum
        /// protocol tx.
        #[inline]
        pub fn is_ethereum(&self) -> bool {
            matches!(
                self,
                Self::EthereumEvents
                    | Self::BridgePool
                    | Self::ValidatorSetUpdate
                    | Self::EthEventsVext
                    | Self::BridgePoolVext
                    | Self::ValSetUpdateVext
            )
        }
    }

    impl BorshSerialize for DkgMessage {
        fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
            let blob = serde_json::to_string(&self.0)
                .map_err(|err| {
                    std::io::Error::new(ErrorKind::InvalidData, err)
                })?
                .as_bytes()
                .to_owned();
            BorshSerialize::serialize(&blob, writer)
        }
    }

    impl BorshDeserialize for DkgMessage {
        fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
            let blob: Vec<u8> = BorshDeserialize::deserialize(buf)?;
            let json = String::from_utf8(blob).map_err(|err| {
                std::io::Error::new(ErrorKind::InvalidData, err)
            })?;
            let msg = serde_json::from_str(&json).map_err(|err| {
                std::io::Error::new(ErrorKind::InvalidData, err)
            })?;
            Ok(Self(msg))
        }
    }

    impl BorshSchema for DkgMessage {
        fn add_definitions_recursively(
            definitions: &mut std::collections::HashMap<
                borsh::schema::Declaration,
                borsh::schema::Definition,
            >,
        ) {
            // Encoded as `Vec<u8>`;
            let elements = "u8".into();
            let definition = borsh::schema::Definition::Sequence { elements };
            definitions.insert(Self::declaration(), definition);
        }

        fn declaration() -> borsh::schema::Declaration {
            "DkgMessage".into()
        }
    }

    impl From<Message<EllipticCurve>> for ProtocolTxType {
        fn from(msg: Message<EllipticCurve>) -> ProtocolTxType {
            ProtocolTxType::DKG(DkgMessage(msg))
        }
    }
}

#[cfg(feature = "ferveo-tpke")]
pub use protocol_txs::*;
