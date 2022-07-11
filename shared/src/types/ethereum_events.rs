//! Types to do with interfacing with the Ethereum blockchain
use std::fmt::Debug;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};

use crate::proto::MultiSigned;
use crate::types::address::Address;
use crate::types::token::Amount;

/// An Ethereum event to be processed by the Anoma ledger
#[derive(
    Debug, PartialEq, Eq, Clone, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub enum EthereumEvent {
    /// Event transferring batches of ether from Ethereum to wrapped ETH on
    /// Anoma
    TransfersToNamada(Vec<TransferToNamada>),
}

/// Representation of address on Ethereum
#[derive(
    Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub struct EthAddress(pub [u8; 20]);

/// An event transferring some kind of value from Ethereum to Anoma
#[derive(
    Debug, PartialEq, Eq, Clone, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub struct TransferToNamada {
    /// Quantity of ether in the transfer
    pub amount: Amount,
    /// Address on Ethereum of the asset
    pub asset: EthereumAsset,
    /// The Namada address receiving wrapped assets on Anoma
    pub receiver: Address,
}

/// Represents Ethereum assets on the Ethereum blockchain
#[derive(
    Debug, PartialEq, Eq, Clone, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub enum EthereumAsset {
    /// Native ETH
    Eth,
    /// An ERC20 token and the address of its contract
    ERC20(EthAddress),
}

/// Contains types necessary for processing Ethereum events
/// in vote extensions
pub mod vote_extensions {
    use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
    use eyre::{eyre, Result};
    use num_rational::Ratio;

    use super::EthereumEvent;
    use crate::proto::MultiSigned;
    use crate::types::address::Address;
    use crate::types::storage::BlockHeight;

    /// A fraction of the total voting power. This should always be a reduced
    /// fraction that is between zero and one inclusive.
    #[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Debug)]
    pub struct FractionalVotingPower(Ratio<u64>);

    impl FractionalVotingPower {
        /// Create a new FractionalVotingPower. It must be between zero and one
        /// inclusive.
        pub fn new(numer: u64, denom: u64) -> Result<Self> {
            if denom == 0 {
                return Err(eyre!("denominator can't be zero"));
            }
            let ratio: Ratio<u64> = (numer, denom).into();
            if ratio > 1.into() {
                return Err(eyre!(
                    "fractional voting power cannot be greater than one"
                ));
            }
            Ok(Self(ratio))
        }
    }

    impl From<&FractionalVotingPower> for (u64, u64) {
        fn from(ratio: &FractionalVotingPower) -> Self {
            (ratio.0.numer().to_owned(), ratio.0.denom().to_owned())
        }
    }

    impl BorshSerialize for FractionalVotingPower {
        fn serialize<W: ark_serialize::Write>(
            &self,
            writer: &mut W,
        ) -> std::io::Result<()> {
            let (numer, denom): (u64, u64) = self.into();
            (numer, denom).serialize(writer)
        }
    }

    impl BorshDeserialize for FractionalVotingPower {
        fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
            let (numer, denom): (u64, u64) =
                BorshDeserialize::deserialize(buf)?;
            Ok(FractionalVotingPower(Ratio::<u64>::new(numer, denom)))
        }
    }

    impl BorshSchema for FractionalVotingPower {
        fn add_definitions_recursively(
            definitions: &mut std::collections::HashMap<
                borsh::schema::Declaration,
                borsh::schema::Definition,
            >,
        ) {
            let fields =
                borsh::schema::Fields::UnnamedFields(borsh::maybestd::vec![
                    u64::declaration(),
                    u64::declaration()
                ]);
            let definition = borsh::schema::Definition::Struct { fields };
            Self::add_definition(Self::declaration(), definition, definitions);
        }

        fn declaration() -> borsh::schema::Declaration {
            "FractionalVotingPower".into()
        }
    }

    /// This is created by the block proposer based on the Ethereum events
    /// included in the vote extensions of the previous Tendermint round
    #[derive(Debug, Clone, BorshSerialize, BorshDeserialize, BorshSchema)]
    pub struct MultiSignedEthEvent {
        /// Address and voting power of the signing validators
        pub signers: Vec<(Address, FractionalVotingPower)>,
        /// Events as signed by validators
        pub event: MultiSigned<(EthereumEvent, BlockHeight)>,
    }
