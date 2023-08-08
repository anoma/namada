//! Helper structures to build transactions

use borsh::BorshSerialize;
use masp_primitives::transaction::Transaction;
use namada_core::ledger::testnet_pow;
use namada_core::proto::{
    Code, Data, MaspBuilder, MultiSignature, Section, Signature, Tx,
};
use namada_core::types::account::AccountPublicKeysMap;
use namada_core::types::chain::ChainId;
use namada_core::types::hash::Hash;
use namada_core::types::key::common;
use namada_core::types::storage::Epoch;
use namada_core::types::transaction::{Fee, GasLimit, TxType, WrapperTx};

use crate::types::time::DateTimeUtc;

/// A helper structure to build transations
#[derive(Default)]
pub struct TxBuilder {
    chain_id: ChainId,
    expiration: Option<DateTimeUtc>,
    sections: Vec<Section>,
    wrapper: Option<WrapperTx>,
    gas_payer: Option<common::SecretKey>,
    signing_keys: Vec<common::SecretKey>,
    account_public_keys_map: Option<AccountPublicKeysMap>,
}

impl TxBuilder {
    /// Initialize a new transaction builder
    pub fn new(chain_id: ChainId, expiration: Option<DateTimeUtc>) -> Self {
        Self {
            chain_id,
            expiration,
            sections: vec![],
            wrapper: None,
            gas_payer: None,
            signing_keys: vec![],
            account_public_keys_map: None,
        }
    }

    /// Add an extra section to the tx builder by hash
    pub fn add_extra_section_from_hash(mut self, hash: Hash) -> (Self, Hash) {
        let sec = self._add_section(Section::ExtraData(Code::from_hash(hash)));
        (self, sec.get_hash())
    }

    /// Add an extra section to the tx builder by code
    pub fn add_extra_section(mut self, code: Vec<u8>) -> (Self, Hash) {
        let sec = self._add_section(Section::ExtraData(Code::new(code)));
        (self, sec.get_hash())
    }

    /// Add a masp tx section to the tx builder
    pub fn add_masp_tx_section(mut self, tx: Transaction) -> (Self, Hash) {
        let sec = self._add_section(Section::MaspTx(tx));
        (self, sec.get_hash())
    }

    /// Add a masp builder section to the tx builder
    pub fn add_masp_builder(mut self, builder: MaspBuilder) -> Self {
        let _sec = self._add_section(Section::MaspBuilder(builder));
        self
    }

    /// Add wasm code to the tx builder from hash
    pub fn add_code_from_hash(mut self, code_hash: Hash) -> Self {
        self._add_section(Section::Code(Code::from_hash(code_hash)));
        self
    }

    /// Add wasm code to the tx builder
    pub fn add_code(mut self, code: Vec<u8>) -> Self {
        self._add_section(Section::Code(Code::new(code)));
        self
    }

    /// Add wasm data to the tx builder
    pub fn add_data(mut self, data: impl BorshSerialize) -> Self {
        let bytes = data.try_to_vec().expect("Encoding tx data shouldn't fail");
        self._add_section(Section::Data(Data::new(bytes)));
        self
    }

    /// Add wasm data already serialized to the tx builder
    pub fn add_serialized_data(mut self, bytes: Vec<u8>) -> Self {
        self._add_section(Section::Data(Data::new(bytes)));
        self
    }

    /// Add wrapper tx to the tx builder
    pub fn add_wrapper(
        mut self,
        fee: Fee,
        gas_payer: common::PublicKey,
        epoch: Epoch,
        gas_limit: GasLimit,
        #[cfg(not(feature = "mainnet"))] requires_pow: Option<
            testnet_pow::Solution,
        >,
    ) -> Self {
        self.wrapper = Some(WrapperTx::new(
            fee,
            gas_payer,
            epoch,
            gas_limit,
            #[cfg(not(feature = "mainnet"))]
            requires_pow,
        ));
        self
    }

    /// Add fee payer keypair to the tx builder
    pub fn add_gas_payer(mut self, keypair: common::SecretKey) -> Self {
        self.gas_payer = Some(keypair);
        self
    }

    /// Add signing keys to the tx builder
    pub fn add_signing_keys(
        mut self,
        keypairs: Vec<common::SecretKey>,
        account_public_keys_map: AccountPublicKeysMap,
    ) -> Self {
        self.signing_keys = keypairs;
        self.account_public_keys_map = Some(account_public_keys_map);
        self
    }

    /// Generate the corresponding tx
    pub fn unsigned_build(self) -> Tx {
        let mut tx = Tx::new(TxType::Raw);
        tx.header.chain_id = self.chain_id;
        tx.header.expiration = self.expiration;

        for section in self.sections.clone() {
            tx.add_section(section);
        }

        for section in self.sections {
            match section {
                Section::Data(_) => tx.set_data_sechash(section.get_hash()),
                Section::Code(_) => tx.set_code_sechash(section.get_hash()),
                _ => continue,
            }
        }
        if let Some(wrapper) = self.wrapper {
            tx.update_header(TxType::Wrapper(Box::new(wrapper)));
        }

        tx
    }

    /// Generate the corresponding tx
    pub fn signed_build(self) -> Tx {
        let account_public_keys_map = self.account_public_keys_map.clone();
        let gas_payer = self.gas_payer.clone();
        let signing_keys = self.signing_keys.clone();
        let mut tx = self.unsigned_build();

        tx.protocol_filter();

        if let Some(account_public_keys_map) = account_public_keys_map {
            let hashes = tx
                .sections
                .iter()
                .filter_map(|section| match section {
                    Section::Data(_) | Section::Code(_) => {
                        Some(section.get_hash())
                    }
                    _ => None,
                })
                .collect();
            tx.add_section(Section::SectionSignature(MultiSignature::new(
                hashes,
                &signing_keys,
                &account_public_keys_map,
            )));
        }

        if let Some(keypair) = gas_payer {
            let mut sections_hashes = tx
                .sections
                .iter()
                .map(|section| section.get_hash())
                .collect::<Vec<Hash>>();
            sections_hashes.push(tx.header_hash());
            tx.add_section(Section::Signature(Signature::new(
                sections_hashes,
                &keypair,
            )));
        }

        tx
    }

    /// Internal method to add a section to the builder
    fn _add_section(&mut self, section: Section) -> Section {
        self.sections.push(section);
        self.sections.last().unwrap().clone()
    }
}
