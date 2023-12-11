use borsh_ext::BorshSerializeExt;
use namada_core::ledger::governance::storage::proposal::ProposalType;
use namada_core::proto::Section;
use namada_core::proto::Signer;
use namada_core::proto::TxError;
use namada_core::proto::{Signature, Tx};
use namada_core::types::address::Address;
use namada_core::types::chain::ChainId;
use namada_core::types::dec::Dec;
use namada_core::types::hash::Hash;
use namada_core::types::key::{common, secp256k1};
use namada_core::types::storage::Epoch;
use namada_core::types::time::DateTimeUtc;
use namada_core::types::token;
use namada_core::types::token::{Amount, DenominatedAmount, MaspDenom};
use namada_core::types::transaction::Fee;
use namada_core::types::transaction::GasLimit;
use std::collections::BTreeMap;
use std::str::FromStr;

//FIXME: instead of this file would be better to call finalize(args) on every transaction type that would produce a signed wrapper with the provided args
pub struct Wrapper(Tx);

impl Wrapper {
    /// Takes a transaction and a signature and wraps them in a wrapper
    /// transaction ready for submission
    pub fn new(
        mut tx: Tx,
        fee: Fee,
        fee_payer: common::PublicKey,
        gas_limit: GasLimit,
        //FIXME: fix masp unshielding
        unshield_hash: Option<Hash>,
    ) -> Self {
        tx.add_wrapper(
            fee,
            fee_payer,
            Epoch::default(),
            gas_limit,
            unshield_hash,
        );

        Self(tx)
    }

    /// Returns the message to be signed for this transaction
    pub fn get_msg_to_sign(mut self) -> (Self, Vec<Hash>) {
        self.0.protocol_filter();
        let msg = self.0.sechashes();

        (self, msg)
    }

    /// Attach the given outer signature to the transaction
    pub fn attach_signature(
        mut self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        self.0.add_section(Section::Signature(Signature {
            targets: self.0.sechashes(),
            signer: Signer::PubKeys(vec![signer]),
            signatures: [(0, signature)].into_iter().collect(),
        }));

        self
    }

    /// Validate this wrapper transaction
    pub fn validate_tx(
        &self,
    ) -> std::result::Result<Option<&Signature>, TxError> {
        self.0.validate_tx()
    }
}
