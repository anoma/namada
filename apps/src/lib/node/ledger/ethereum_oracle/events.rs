pub mod eth_events {
    use std::fmt::Debug;
    use std::str::FromStr;

    use ethbridge_bridge_events::{
        BridgeEvents, TransferToErcFilter, TransferToNamadaFilter,
    };
    use ethbridge_events::{DynEventCodec, Events as RawEvents};
    use ethbridge_governance_events::{
        GovernanceEvents, NewContractFilter, UpgradedContractFilter,
        ValidatorSetUpdateFilter,
    };
    use namada::core::types::ethereum_structs;
    use namada::eth_bridge::ethers::contract::EthEvent;
    use namada::types::address::Address;
    use namada::types::ethereum_events::{
        EthAddress, EthereumEvent, TransferToEthereum, TransferToEthereumKind,
        TransferToNamada, Uint,
    };
    use namada::types::keccak::KeccakHash;
    use namada::types::token::Amount;
    use num256::Uint256;
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum Error {
        #[error("Could not decode Ethereum event: {0}")]
        Decode(String),
        #[error("The given Ethereum contract is not in use: {0}")]
        NotInUse(String),
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

    impl PendingEvent {
        /// Decodes bytes into an [`EthereumEvent`] based on the signature.
        /// This is is turned into a [`PendingEvent`] along with the block
        /// height passed in here.
        ///
        /// If the event contains a confirmations field,
        /// this is passed to the corresponding [`PendingEvent`] field,
        /// otherwise a default is used.
        pub fn decode(
            event_codec: DynEventCodec,
            block_height: Uint256,
            log: &ethabi::RawLog,
            mut confirmations: Uint256,
        ) -> Result<Self> {
            let raw_event = event_codec
                .decode(log)
                .map_err(|e| Error::Decode(e.to_string()))?;
            // NOTE: **DO NOT** do any partial pattern matches
            // on the generated structs. destructuring will help
            // us to find bugs, if the representation of Ethereum
            // events changes between `ethbridge-rs` versions
            let event = match raw_event {
                RawEvents::Bridge(BridgeEvents::TransferToErcFilter(
                    TransferToErcFilter {
                        nonce,
                        transfers,
                        valid_map,
                        relayer_address,
                    },
                )) => EthereumEvent::TransfersToEthereum {
                    nonce: nonce.parse_uint256()?,
                    transfers: transfers.parse_transfer_to_eth_array()?,
                    valid_transfers_map: valid_map,
                    relayer: relayer_address.parse_address()?,
                },
                RawEvents::Bridge(BridgeEvents::TransferToNamadaFilter(
                    TransferToNamadaFilter {
                        nonce,
                        transfers,
                        valid_map,
                        confirmations: requested_confirmations,
                    },
                )) => {
                    confirmations = confirmations.max({
                        let mut num_buf = [0; 32];
                        requested_confirmations.to_little_endian(&mut num_buf);
                        Uint256::from_bytes_le(&num_buf)
                    });
                    EthereumEvent::TransfersToNamada {
                        nonce: nonce.parse_uint256()?,
                        transfers: transfers
                            .parse_transfer_to_namada_array()?,
                        valid_transfers_map: valid_map,
                    }
                }
                RawEvents::Governance(GovernanceEvents::NewContractFilter(
                    NewContractFilter { name: _, addr: _ },
                )) => {
                    return Err(Error::NotInUse(
                        NewContractFilter::name().into(),
                    ));
                }
                RawEvents::Governance(
                    GovernanceEvents::UpgradedContractFilter(
                        UpgradedContractFilter { name: _, addr: _ },
                    ),
                ) => {
                    return Err(Error::NotInUse(
                        UpgradedContractFilter::name().into(),
                    ));
                }
                RawEvents::Governance(
                    GovernanceEvents::ValidatorSetUpdateFilter(
                        ValidatorSetUpdateFilter {
                            validator_set_nonce,
                            bridge_validator_set_hash,
                            governance_validator_set_hash,
                        },
                    ),
                ) => EthereumEvent::ValidatorSetUpdate {
                    nonce: validator_set_nonce.into(),
                    bridge_validator_hash: bridge_validator_set_hash
                        .parse_keccak()?,
                    governance_validator_hash: governance_validator_set_hash
                        .parse_keccak()?,
                },
            };
            Ok(PendingEvent {
                confirmations,
                block_height,
                event,
            })
        }

        /// Check if the minimum number of confirmations has been
        /// reached at the input block height.
        pub fn is_confirmed(&self, height: &Uint256) -> bool {
            self.confirmations <= height.clone() - self.block_height.clone()
        }
    }

    macro_rules! parse_method {
        ($name:ident -> $type:ty) => {
            fn $name(self) -> Result<$type> {
                unimplemented!()
            }
        };
    }

    /// Trait to add parsing methods to foreign types.
    trait Parse: Sized {
        parse_method! { parse_eth_transfer_kind -> TransferToEthereumKind }
        parse_method! { parse_eth_address -> EthAddress }
        parse_method! { parse_address -> Address }
        parse_method! { parse_amount -> Amount }
        parse_method! { parse_u32 -> u32 }
        parse_method! { parse_uint256 -> Uint }
        parse_method! { parse_bool -> bool }
        parse_method! { parse_string -> String }
        parse_method! { parse_keccak -> KeccakHash }
        parse_method! { parse_amount_array -> Vec<Amount> }
        parse_method! { parse_eth_address_array -> Vec<EthAddress> }
        parse_method! { parse_address_array -> Vec<Address> }
        parse_method! { parse_string_array -> Vec<String> }
        parse_method! { parse_transfer_to_namada_array -> Vec<TransferToNamada> }
        parse_method! { parse_transfer_to_namada -> TransferToNamada }
        parse_method! { parse_transfer_to_eth_array -> Vec<TransferToEthereum> }
        parse_method! { parse_transfer_to_eth -> TransferToEthereum }
    }

    impl Parse for u8 {
        fn parse_eth_transfer_kind(self) -> Result<TransferToEthereumKind> {
            self.try_into()
                .map_err(|err| Error::Decode(format!("{:?}", err)))
        }
    }

    impl Parse for ethabi::Address {
        fn parse_eth_address(self) -> Result<EthAddress> {
            Ok(EthAddress(self.0))
        }
    }

    impl Parse for String {
        fn parse_address(self) -> Result<Address> {
            Address::from_str(&self)
                .map_err(|err| Error::Decode(format!("{:?}", err)))
        }

        fn parse_string(self) -> Result<String> {
            Ok(self)
        }
    }

    impl Parse for ethabi::Uint {
        fn parse_amount(self) -> Result<Amount> {
            Ok(Amount::from(self.as_u64()))
        }

        fn parse_u32(self) -> Result<u32> {
            Ok(self.as_u32())
        }

        fn parse_uint256(self) -> Result<Uint> {
            Ok(self.into())
        }
    }

    impl Parse for bool {
        fn parse_bool(self) -> Result<bool> {
            Ok(self)
        }
    }

    impl Parse for [u8; 32] {
        fn parse_keccak(self) -> Result<KeccakHash> {
            Ok(KeccakHash(self))
        }
    }

    impl Parse for Vec<ethabi::Uint> {
        fn parse_amount_array(self) -> Result<Vec<Amount>> {
            self.into_iter().try_fold(Vec::new(), |mut acc, amount| {
                acc.push(amount.parse_amount()?);
                Ok(acc)
            })
        }
    }

    impl Parse for Vec<ethabi::Address> {
        fn parse_eth_address_array(self) -> Result<Vec<EthAddress>> {
            self.into_iter().try_fold(Vec::new(), |mut acc, addr| {
                acc.push(addr.parse_eth_address()?);
                Ok(acc)
            })
        }
    }

    impl Parse for Vec<ethereum_structs::NamadaTransfer> {
        fn parse_transfer_to_namada_array(
            self,
        ) -> Result<Vec<TransferToNamada>> {
            self.into_iter().try_fold(Vec::new(), |mut acc, transf| {
                acc.push(transf.parse_transfer_to_namada()?);
                Ok(acc)
            })
        }
    }

    impl Parse for ethereum_structs::NamadaTransfer {
        fn parse_transfer_to_namada(self) -> Result<TransferToNamada> {
            let asset = self.from.parse_eth_address()?;
            let amount = self.amount.parse_amount()?;
            let receiver = self.to.parse_address()?;
            Ok(TransferToNamada {
                asset,
                amount,
                receiver,
            })
        }
    }

    impl Parse for Vec<ethereum_structs::Erc20Transfer> {
        fn parse_transfer_to_eth_array(
            self,
        ) -> Result<Vec<TransferToEthereum>> {
            self.into_iter().try_fold(Vec::new(), |mut acc, transf| {
                acc.push(transf.parse_transfer_to_eth()?);
                Ok(acc)
            })
        }
    }

    impl Parse for ethereum_structs::Erc20Transfer {
        fn parse_transfer_to_eth(self) -> Result<TransferToEthereum> {
            let kind = self.kind.parse_eth_transfer_kind()?;
            let asset = self.from.parse_eth_address()?;
            let receiver = self.to.parse_eth_address()?;
            let sender = self.sender.parse_address()?;
            let amount = self.amount.parse_amount()?;
            let gas_payer = self.fee_from.parse_address()?;
            let gas_amount = self.fee.parse_amount()?;
            Ok(TransferToEthereum {
                kind,
                asset,
                amount,
                sender,
                receiver,
                gas_amount,
                gas_payer,
            })
        }
    }

    impl Parse for Vec<String> {
        fn parse_address_array(self) -> Result<Vec<Address>> {
            self.into_iter().try_fold(Vec::new(), |mut acc, addr| {
                acc.push(addr.parse_address()?);
                Ok(acc)
            })
        }

        fn parse_string_array(self) -> Result<Vec<String>> {
            Ok(self)
        }
    }

    #[cfg(test)]
    mod test_events {
        use assert_matches::assert_matches;
        use ethabi::ethereum_types::{H160, U256};
        use ethbridge_events::{
            TRANSFER_TO_ERC_CODEC, TRANSFER_TO_NAMADA_CODEC,
            VALIDATOR_SET_UPDATE_CODEC,
        };
        use namada::eth_bridge::ethers::abi::AbiEncode;

        use super::*;

        /// Test that for Ethereum events for which a custom number of
        /// confirmations may be specified, if a value lower than the
        /// protocol-specified minimum confirmations is attempted to be used,
        /// then the protocol-specified minimum confirmations is used instead.
        #[test]
        fn test_min_confirmations_enforced() -> Result<()> {
            let arbitrary_block_height: Uint256 = 123u64.into();
            let min_confirmations: Uint256 = 100u64.into();
            let lower_than_min_confirmations = 5u64;

            let (codec, event) = (
                TRANSFER_TO_NAMADA_CODEC,
                TransferToNamadaFilter {
                    transfers: vec![],
                    valid_map: vec![],
                    nonce: 0.into(),
                    confirmations: lower_than_min_confirmations.into(),
                },
            );
            let pending_event = PendingEvent::decode(
                codec,
                arbitrary_block_height,
                &get_log(event.encode()),
                min_confirmations.clone(),
            )?;

            assert_matches!(
                pending_event,
                PendingEvent { confirmations, .. }
                    if confirmations == min_confirmations
            );

            Ok(())
        }

        /// Test decoding a [`TransferToNamadaFilter`] Ethereum event.
        #[test]
        fn test_transfer_to_namada_decode() {
            let data = vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 160, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 95, 189,
                178, 49, 86, 120, 175, 236, 179, 103, 240, 50, 217, 63, 100,
                47, 100, 24, 10, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 84,
                97, 116, 101, 115, 116, 49, 118, 52, 101, 104, 103, 119, 51,
                54, 120, 117, 117, 110, 119, 100, 54, 57, 56, 57, 112, 114,
                119, 100, 102, 107, 120, 113, 109, 110, 118, 115, 102, 106,
                120, 115, 54, 110, 118, 118, 54, 120, 120, 117, 99, 114, 115,
                51, 102, 51, 120, 99, 109, 110, 115, 51, 102, 99, 120, 100,
                122, 114, 118, 118, 122, 57, 120, 118, 101, 114, 122, 118, 122,
                114, 53, 54, 108, 101, 56, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 1,
            ];

            let raw: TransferToNamadaFilter = TRANSFER_TO_NAMADA_CODEC
                .decode(&get_log(data))
                .expect("Test failed")
                .try_into()
                .expect("Test failed");

            assert_eq!(
                raw.transfers,
                vec![ethereum_structs::NamadaTransfer {
                    amount: 100u64.into(),
                    from: ethabi::Address::from_str("0x5FbDB2315678afecb367f032d93F642f64180aa3").unwrap(),
                    to: "atest1v4ehgw36xuunwd6989prwdfkxqmnvsfjxs6nvv6xxucrs3f3xcmns3fcxdzrvvz9xverzvzr56le8f".into(),
                }]
            )
        }

        /// Test that for Ethereum events for which a custom number of
        /// confirmations may be specified, the custom number is used if it is
        /// at least the protocol-specified minimum confirmations.
        #[test]
        fn test_custom_confirmations_used() {
            let arbitrary_block_height: Uint256 = 123u64.into();
            let min_confirmations: Uint256 = 100u64.into();
            let higher_than_min_confirmations = 200u64;

            let (codec, event) = (
                TRANSFER_TO_NAMADA_CODEC,
                TransferToNamadaFilter {
                    transfers: vec![],
                    valid_map: vec![],
                    nonce: 0u64.into(),
                    confirmations: higher_than_min_confirmations.into(),
                },
            );
            let pending_event = PendingEvent::decode(
                codec,
                arbitrary_block_height,
                &get_log(event.encode()),
                min_confirmations,
            )
            .unwrap();

            assert_matches!(
                pending_event,
                PendingEvent { confirmations, .. }
                    if confirmations == higher_than_min_confirmations.into()
            );
        }

        /// For each of the basic constituent types of Namada's
        /// [`EthereumEvent`] enum variants, test that roundtrip
        /// decoding from/to [`ethabi`] types works as expected.
        #[test]
        fn test_decoding_roundtrips() {
            let erc = EthAddress([1; 20]);
            let address = Address::from_str("atest1v4ehgw36gep5ysecxq6nyv3jg3zygv3e89qn2vp48pryxsf4xpznvve5gvmy23fs89pryvf5a6ht90")
                .expect("Test failed");
            let amount = Amount::from(42u64);
            let confs = 50u32;
            let uint = Uint::from(42u64);
            let boolean = true;
            let string = String::from("test");
            let keccak = KeccakHash([2; 32]);

            let test_case = H160(erc.0);
            assert_eq!(
                test_case.parse_eth_address().expect("Test failed"),
                erc
            );

            let test_case = address.to_string();
            assert_eq!(
                test_case.parse_address().expect("Test failed"),
                address
            );

            let test_case: U256 = amount.into();
            assert_eq!(test_case.parse_amount().expect("Test failed"), amount);

            let test_case = U256::from(confs);
            assert_eq!(test_case.parse_u32().expect("Test failed"), confs);

            let test_case = U256(uint.0);
            assert_eq!(test_case.parse_uint256().expect("Test failed"), uint);

            let test_case = boolean;
            assert_eq!(test_case.parse_bool().expect("Test failed"), boolean);

            let test_case = string.clone();
            assert_eq!(test_case.parse_string().expect("Test failed"), string);

            let test_case = keccak.0;
            assert_eq!(test_case.parse_keccak().expect("Test failed"), keccak);
        }

        /// Test that serialization and deserialization of
        /// complex composite types is a no-op
        #[test]
        fn test_complex_round_trips() {
            let address: String =
                "atest1v4ehgw36gep5ysecxq6nyv3jg3zygv3e89qn2vp48pryxsf4xpznvve5gvmy23fs89pryvf5a6ht90"
                    .into();
            let nam_transfers = TransferToNamadaFilter {
                transfers: vec![
                    ethereum_structs::NamadaTransfer {
                        amount: 0u64.into(),
                        from: H160([0; 20]),
                        to: address.clone(),
                    };
                    2
                ],
                valid_map: vec![true; 2],
                nonce: 0u64.into(),
                confirmations: 0u64.into(),
            };
            let eth_transfers = TransferToErcFilter {
                transfers: vec![
                    ethereum_structs::Erc20Transfer {
                        kind: TransferToEthereumKind::Erc20 as u8,
                        from: H160([1; 20]),
                        to: H160([2; 20]),
                        sender: address.clone(),
                        amount: 0u64.into(),
                        fee_from: address.clone(),
                        fee: 0u64.into(),
                    };
                    2
                ],
                valid_map: vec![true; 2],
                nonce: 0u64.into(),
                relayer_address: address,
            };
            let update = ValidatorSetUpdateFilter {
                validator_set_nonce: 0u64.into(),
                bridge_validator_set_hash: [1; 32],
                governance_validator_set_hash: [2; 32],
            };
            assert_eq!(
                {
                    let decoded: TransferToNamadaFilter =
                        TRANSFER_TO_NAMADA_CODEC
                            .decode(&get_log(nam_transfers.clone().encode()))
                            .expect("Test failed")
                            .try_into()
                            .expect("Test failed");
                    decoded
                },
                nam_transfers
            );
            assert_eq!(
                {
                    let decoded: TransferToErcFilter = TRANSFER_TO_ERC_CODEC
                        .decode(&get_log(eth_transfers.clone().encode()))
                        .expect("Test failed")
                        .try_into()
                        .expect("Test failed");
                    decoded
                },
                eth_transfers
            );
            assert_eq!(
                {
                    let decoded: ValidatorSetUpdateFilter =
                        VALIDATOR_SET_UPDATE_CODEC
                            .decode(&get_log(update.clone().encode()))
                            .expect("Test failed")
                            .try_into()
                            .expect("Test failed");
                    decoded
                },
                update
            );
        }

        /// Return an Ethereum events log, from the given encoded event
        /// data.
        fn get_log(data: Vec<u8>) -> ethabi::RawLog {
            ethabi::RawLog {
                data,
                topics: vec![],
            }
        }
    }
}

pub use eth_events::*;
