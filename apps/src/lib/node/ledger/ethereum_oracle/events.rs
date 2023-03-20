pub mod signatures {
    /// Used to determine which smart contract address
    /// a signature belongs to
    #[derive(Copy, Clone)]
    pub enum SigType {
        Bridge,
        Governance,
    }
}

pub mod eth_events {
    use std::fmt::Debug;
    use std::str::FromStr;

    use ethbridge_bridge_events::{
        BridgeEvents, TransferToErcFilter, TransferToNamadaFilter,
    };
    use ethbridge_governance_events::{
        GovernanceEvents, NewContractFilter, UpdateBridgeWhitelistFilter,
        UpgradedContractFilter, ValidatorSetUpdateFilter,
    };
    use namada::core::types::ethereum_structs;
    use namada::eth_bridge::ethers::contract::{EthEvent, EthLogDecode};
    use namada::types::address::Address;
    use namada::types::ethereum_events::{
        EthAddress, EthereumEvent, TokenWhitelist, TransferToEthereum,
        TransferToNamada, Uint,
    };
    use namada::types::keccak::KeccakHash;
    use namada::types::token::Amount;
    use num256::Uint256;
    use thiserror::Error;

    pub use super::signatures::SigType;

    #[derive(Error, Debug)]
    pub enum Error {
        #[error("Could not decode Ethereum event: {0}")]
        Decode(String),
        #[error("The given Ethereum contract is not in use: {0}")]
        NotInUse(String),
    }

    pub type Result<T> = std::result::Result<T, Error>;

    /// Storage enum for events decoded with `ethbridge-rs`.
    pub enum RawEvents {
        /// Events emitted by the Bridge contract.
        Bridge(BridgeEvents),
        /// Events emitted by the Governance contract.
        Governance(GovernanceEvents),
    }

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
            signature_type: SigType,
            block_height: Uint256,
            log: &ethabi::RawLog,
            confirmations: Uint256,
        ) -> Result<Self> {
            let raw_event = match signature_type {
                SigType::Bridge => RawEvents::Bridge(
                    BridgeEvents::decode_log(log)
                        .map_err(|e| Error::Decode(e.to_string()))?,
                ),
                SigType::Governance => RawEvents::Governance(
                    GovernanceEvents::decode_log(log)
                        .map_err(|e| Error::Decode(e.to_string()))?,
                ),
            };
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
                        confirmations: _,
                    },
                )) => EthereumEvent::TransfersToNamada {
                    nonce: nonce.parse_uint256()?,
                    transfers: transfers.parse_transfer_to_namada_array()?,
                    valid_transfers_map: valid_map,
                },
                RawEvents::Governance(GovernanceEvents::NewContractFilter(
                    NewContractFilter { name: _, addr: _ },
                )) => {
                    return Err(Error::NotInUse(
                        NewContractFilter::name().into(),
                    ));
                }
                RawEvents::Governance(
                    GovernanceEvents::UpdateBridgeWhitelistFilter(
                        UpdateBridgeWhitelistFilter {
                            nonce,
                            tokens,
                            token_cap,
                        },
                    ),
                ) => {
                    let mut whitelist = vec![];

                    for (token, cap) in
                        tokens.into_iter().zip(token_cap.into_iter())
                    {
                        whitelist.push(TokenWhitelist {
                            token: token.parse_eth_address()?,
                            cap: cap.parse_amount()?,
                        });
                    }

                    EthereumEvent::UpdateBridgeWhitelist {
                        nonce: nonce.parse_uint256()?,
                        whitelist,
                    }
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

    /// Trait to add parsing methods to foreign types.
    trait Parse: Sized {
        fn parse_eth_address(self) -> Result<EthAddress> {
            unimplemented!()
        }
        fn parse_address(self) -> Result<Address> {
            unimplemented!()
        }
        fn parse_amount(self) -> Result<Amount> {
            unimplemented!()
        }
        fn parse_u32(self) -> Result<u32> {
            unimplemented!()
        }
        fn parse_uint256(self) -> Result<Uint> {
            unimplemented!()
        }
        fn parse_bool(self) -> Result<bool> {
            unimplemented!()
        }
        fn parse_string(self) -> Result<String> {
            unimplemented!()
        }
        fn parse_keccak(self) -> Result<KeccakHash> {
            unimplemented!()
        }
        fn parse_amount_array(self) -> Result<Vec<Amount>> {
            unimplemented!()
        }
        fn parse_eth_address_array(self) -> Result<Vec<EthAddress>> {
            unimplemented!()
        }
        fn parse_address_array(self) -> Result<Vec<Address>> {
            unimplemented!()
        }
        fn parse_string_array(self) -> Result<Vec<String>> {
            unimplemented!()
        }
        fn parse_transfer_to_namada_array(
            self,
        ) -> Result<Vec<TransferToNamada>> {
            unimplemented!()
        }
        fn parse_transfer_to_namada(self) -> Result<TransferToNamada> {
            unimplemented!()
        }
        fn parse_transfer_to_eth_array(
            self,
        ) -> Result<Vec<TransferToEthereum>> {
            unimplemented!()
        }
        fn parse_transfer_to_eth(self) -> Result<TransferToEthereum> {
            unimplemented!()
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
            let asset = self.from.parse_eth_address()?;
            let receiver = self.to.parse_eth_address()?;
            let sender = self.sender.parse_address()?;
            let amount = self.amount.parse_amount()?;
            let gas_payer = self.fee_from.parse_address()?;
            let gas_amount = self.fee.parse_amount()?;
            Ok(TransferToEthereum {
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

    //#[cfg(test)]
    #[cfg(FALSE)]
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
                        sender: address.clone(),
                        receiver: EthAddress([2; 20]),
                        gas_amount: Default::default(),
                        gas_payer: address.clone(),
                    };
                    2
                ],
                nonce: Uint::from(1),
                relayer: address,
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
