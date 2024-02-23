use namada_sdk::hash::Hash;
use namada_sdk::key::common;
use namada_sdk::storage::Epoch;
use namada_sdk::tx::data::{Fee, GasLimit};
use namada_sdk::tx::{Section, Signature, Signer, Tx, TxError};

#[allow(missing_docs)]
pub struct Wrapper(Tx);

impl Wrapper {
    /// Takes a transaction and a signature and wraps them in a wrapper
    /// transaction ready for submission
    pub fn new(
        mut tx: Tx,
        fee: Fee,
        fee_payer: common::PublicKey,
        gas_limit: GasLimit,
        // FIXME: fix masp unshielding
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
    pub fn get_sign_bytes(mut self) -> (Self, Vec<Hash>) {
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
    pub fn validate_tx(&self) -> Result<Option<&Signature>, TxError> {
        self.0.validate_tx()
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}
