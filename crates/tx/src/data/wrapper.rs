/// Integration of Ferveo cryptographic primitives
/// to enable encrypted txs inside of normal txs.
/// *Not wasm compatible*
pub mod wrapper_tx {

    use std::num::ParseIntError;
    use std::str::FromStr;

    pub use ark_bls12_381::Bls12_381 as EllipticCurve;
    use masp_primitives::transaction::Transaction;
    use namada_core::address::{Address, MASP};
    use namada_core::borsh::{
        BorshDeserialize, BorshSchema, BorshSerialize, BorshSerializeExt,
    };
    use namada_core::hash::Hash;
    use namada_core::key::*;
    use namada_core::storage::Epoch;
    use namada_core::token::{Amount, DenominatedAmount, Transfer};
    use namada_core::uint::Uint;
    use namada_gas::Gas;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use thiserror::Error;

    use crate::data::{DecryptedTx, TxType};
    use crate::{Code, Data, Section, Tx};

    /// TODO: Determine a sane number for this
    const GAS_LIMIT_RESOLUTION: u64 = 1;

    /// Errors relating to decrypting a wrapper tx and its
    /// encrypted payload from a Tx type
    #[allow(missing_docs)]
    #[derive(Error, Debug)]
    pub enum WrapperTxErr {
        #[error(
            "The hash of the decrypted tx does not match the hash commitment"
        )]
        DecryptedHash,
        #[error("The decryption did not produce a valid Tx")]
        InvalidTx,
        #[error("The given Tx data did not contain a valid WrapperTx")]
        InvalidWrapperTx,
        #[error(
            "Attempted to sign WrapperTx with keypair whose public key \
             differs from that in the WrapperTx"
        )]
        InvalidKeyPair,
        #[error("The provided unshielding tx is invalid: {0}")]
        InvalidUnshield(String),
        #[error("The given Tx fee amount overflowed")]
        OverflowingFee,
        #[error("Error while converting the denominated fee amount")]
        DenominatedFeeConversion,
    }

    /// A fee is an amount of a specified token
    #[derive(
        Debug,
        Clone,
        PartialEq,
        BorshSerialize,
        BorshDeserialize,
        BorshSchema,
        Serialize,
        Deserialize,
        Eq,
    )]
    pub struct Fee {
        /// amount of fee per gas unit
        pub amount_per_gas_unit: DenominatedAmount,
        /// address of the token
        /// TODO: This should support multi-tokens
        pub token: Address,
    }

    /// Gas limits must be multiples of GAS_LIMIT_RESOLUTION
    /// This is done to minimize the amount of information leak from
    /// a wrapper tx. The larger the GAS_LIMIT_RESOLUTION, the
    /// less info leaked.
    ///
    /// This struct only stores the multiple of GAS_LIMIT_RESOLUTION,
    /// not the raw amount
    #[derive(
        Default,
        Debug,
        Clone,
        Copy,
        PartialEq,
        BorshSerialize,
        BorshDeserialize,
        BorshSchema,
        Serialize,
        Deserialize,
        Eq,
    )]
    pub struct GasLimit {
        multiplier: u64,
    }

    impl GasLimit {
        /// We refund unused gas up to GAS_LIMIT_RESOLUTION
        pub fn refund_amount(self, used_gas: u64) -> Amount {
            Amount::from_uint(
                if used_gas < (u64::from(self) - GAS_LIMIT_RESOLUTION) {
                    // we refund only up to GAS_LIMIT_RESOLUTION
                    Uint::from(GAS_LIMIT_RESOLUTION)
                } else if used_gas >= u64::from(self) {
                    // Gas limit was under estimated, no refund
                    Uint::zero()
                } else {
                    // compute refund
                    Uint::from(u64::from(self)) - used_gas
                },
                0,
            )
            .unwrap()
        }
    }

    /// Round the input number up to the next highest multiple
    /// of GAS_LIMIT_RESOLUTION
    impl From<u64> for GasLimit {
        fn from(amount: u64) -> GasLimit {
            if GAS_LIMIT_RESOLUTION * (amount / GAS_LIMIT_RESOLUTION) < amount {
                GasLimit {
                    multiplier: (amount / GAS_LIMIT_RESOLUTION) + 1,
                }
            } else {
                GasLimit {
                    multiplier: (amount / GAS_LIMIT_RESOLUTION),
                }
            }
        }
    }

    /// Get back the gas limit as a raw number
    impl From<GasLimit> for u64 {
        fn from(limit: GasLimit) -> u64 {
            limit.multiplier * GAS_LIMIT_RESOLUTION
        }
    }

    impl From<GasLimit> for Uint {
        fn from(limit: GasLimit) -> Self {
            Uint::from_u64(limit.into())
        }
    }

    impl FromStr for GasLimit {
        type Err = ParseIntError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            // Expect input to be the multiplier
            Ok(Self {
                multiplier: s.parse()?,
            })
        }
    }

    /// Get back the gas limit as a raw number, viewed as an Amount
    impl From<GasLimit> for Amount {
        fn from(limit: GasLimit) -> Amount {
            Amount::from_uint(limit.multiplier * GAS_LIMIT_RESOLUTION, 0)
                .unwrap()
        }
    }

    impl From<GasLimit> for Gas {
        // Derive a Gas instance with a sub amount which is exactly a whole
        // amount since the limit represents gas in whole units
        fn from(value: GasLimit) -> Self {
            Self::from_whole_units(u64::from(value))
        }
    }

    /// A transaction with an encrypted payload, an optional shielded pool
    /// unshielding tx for fee payment and some non-encrypted metadata for
    /// inclusion and / or verification purposes
    #[derive(
        Debug,
        Clone,
        BorshSerialize,
        BorshDeserialize,
        BorshSchema,
        Serialize,
        Deserialize,
    )]
    pub struct WrapperTx {
        /// The fee to be paid for including the tx
        pub fee: Fee,
        /// Used for signature verification and to determine an implicit
        /// account of the fee payer
        pub pk: common::PublicKey,
        /// The epoch in which the tx is to be submitted. This determines
        /// which decryption key will be used
        pub epoch: Epoch,
        /// Max amount of gas that can be used when executing the inner tx
        pub gas_limit: GasLimit,
        /// The hash of the optional, unencrypted, unshielding transaction for
        /// fee payment
        pub unshield_section_hash: Option<Hash>,
    }

    impl WrapperTx {
        /// Create a new wrapper tx from unencrypted tx, the personal keypair,
        /// an optional unshielding tx, and the metadata surrounding the
        /// inclusion of the tx. This method constructs the signature of
        /// relevant data and encrypts the transaction
        #[allow(clippy::too_many_arguments)]
        pub fn new(
            fee: Fee,
            pk: common::PublicKey,
            epoch: Epoch,
            gas_limit: GasLimit,
            unshield_hash: Option<Hash>,
        ) -> WrapperTx {
            Self {
                fee,
                pk,
                epoch,
                gas_limit,
                unshield_section_hash: unshield_hash,
            }
        }

        /// Get the address of the implicit account associated
        /// with the public key
        /// NOTE: this is safe in case someone tried to use the masp address to
        /// pay fees. All of the masp funds are kept in the established address,
        /// while the implicit one has no funds leading to a tx failure
        pub fn fee_payer(&self) -> Address {
            Address::from(&self.pk)
        }

        /// Produce a SHA-256 hash of this section
        pub fn hash<'a>(&self, hasher: &'a mut Sha256) -> &'a mut Sha256 {
            hasher.update(self.serialize_to_vec());
            hasher
        }

        /// Performs validation on the optional fee unshielding data carried by
        /// the wrapper and generates the tx for execution.
        pub fn check_and_generate_fee_unshielding(
            &self,
            transfer_code_hash: Hash,
            transfer_code_tag: Option<String>,
            descriptions_limit: u64,
            unshield: Transaction,
        ) -> Result<Tx, WrapperTxErr> {
            // Check that the number of descriptions is within a certain limit
            // to avoid a possible DoS vector
            let sapling_bundle = unshield.sapling_bundle().ok_or(
                WrapperTxErr::InvalidUnshield(
                    "Missing required sapling bundle".to_string(),
                ),
            )?;
            let spends = sapling_bundle.shielded_spends.len();
            let converts = sapling_bundle.shielded_converts.len();
            let outs = sapling_bundle.shielded_outputs.len();

            let descriptions = spends
                .checked_add(converts)
                .ok_or_else(|| {
                    WrapperTxErr::InvalidUnshield(
                        "Descriptions overflow".to_string(),
                    )
                })?
                .checked_add(outs)
                .ok_or_else(|| {
                    WrapperTxErr::InvalidUnshield(
                        "Descriptions overflow".to_string(),
                    )
                })?;

            if u64::try_from(descriptions)
                .map_err(|e| WrapperTxErr::InvalidUnshield(e.to_string()))?
                > descriptions_limit
            {
                return Err(WrapperTxErr::InvalidUnshield(
                    "Descriptions exceed the maximum amount allowed"
                        .to_string(),
                ));
            }
            self.generate_fee_unshielding(
                transfer_code_hash,
                transfer_code_tag,
                unshield,
            )
        }

        /// Generates the fee unshielding tx for execution.
        pub fn generate_fee_unshielding(
            &self,
            transfer_code_hash: Hash,
            transfer_code_tag: Option<String>,
            unshield: Transaction,
        ) -> Result<Tx, WrapperTxErr> {
            let mut tx =
                Tx::from_type(TxType::Decrypted(DecryptedTx::Decrypted));
            let masp_section = tx.add_section(Section::MaspTx(unshield));
            let masp_hash = Hash(
                masp_section
                    .hash(&mut Sha256::new())
                    .finalize_reset()
                    .into(),
            );

            let transfer = Transfer {
                source: MASP,
                target: self.fee_payer(),
                token: self.fee.token.clone(),
                amount: self.get_tx_fee()?,
                key: None,
                shielded: Some(masp_hash),
            };
            let data = transfer.serialize_to_vec();
            tx.set_data(Data::new(data));
            tx.set_code(Code::from_hash(transfer_code_hash, transfer_code_tag));

            Ok(tx)
        }

        /// Get the [`Amount`] of fees to be paid by the given wrapper. Returns
        /// an error if the amount overflows
        pub fn get_tx_fee(&self) -> Result<DenominatedAmount, WrapperTxErr> {
            self.fee
                .amount_per_gas_unit
                .checked_mul(Amount::from(self.gas_limit).into())
                .ok_or(WrapperTxErr::OverflowingFee)
        }
    }

    #[cfg(test)]
    mod test_gas_limits {
        use super::*;

        /// Test serializing and deserializing again gives back original object
        /// Test that serializing converts GasLimit to u64 correctly
        #[test]
        fn test_gas_limit_roundtrip() {
            let limit = GasLimit { multiplier: 1 };
            // Test serde roundtrip
            let js = serde_json::to_string(&1).expect("Test failed");
            assert_eq!(js, format!(r#"{}"#, GAS_LIMIT_RESOLUTION));
            let new_limit: u64 =
                serde_json::from_str(&js).expect("Test failed");
            assert_eq!(
                GasLimit {
                    multiplier: new_limit
                },
                limit
            );

            // Test borsh roundtrip
            let borsh = limit.serialize_to_vec();
            assert_eq!(
                limit,
                BorshDeserialize::deserialize(&mut borsh.as_ref())
                    .expect("Test failed")
            );
        }

        /// Test that when we deserialize a u64 that is not a multiple of
        /// GAS_LIMIT_RESOLUTION to a GasLimit, it rounds up to the next
        /// multiple
        #[test]
        fn test_deserialize_not_multiple_of_resolution() {
            let js = format!(r#"{}"#, &(GAS_LIMIT_RESOLUTION + 1));
            let limit: u64 = serde_json::from_str(&js).expect("Test failed");
            assert_eq!(
                GasLimit { multiplier: limit },
                GasLimit { multiplier: 2 }
            );
        }

        /// Test that refund is calculated correctly
        #[test]
        fn test_gas_limit_refund() {
            let limit = GasLimit { multiplier: 1 };
            let refund = limit.refund_amount(GAS_LIMIT_RESOLUTION - 1);
            assert_eq!(refund, Amount::from_uint(1, 0).expect("Test failed"));
        }

        /// Test that we don't refund more than GAS_LIMIT_RESOLUTION
        #[test]
        fn test_gas_limit_too_high_no_refund() {
            let limit = GasLimit { multiplier: 2 };
            let refund = limit.refund_amount(GAS_LIMIT_RESOLUTION - 1);
            assert_eq!(
                refund,
                Amount::from_uint(GAS_LIMIT_RESOLUTION, 0)
                    .expect("Test failed")
            );
        }

        /// Test that if gas usage was underestimated, we issue no refund
        #[test]
        fn test_gas_limit_too_low_no_refund() {
            let limit = GasLimit { multiplier: 1 };
            let refund = limit.refund_amount(GAS_LIMIT_RESOLUTION + 1);
            assert_eq!(refund, Amount::default());
        }
    }
}

pub use wrapper_tx::*;
