//! Implementation of the [`PrepareProposal`] ABCI++ method for the Shell

use super::*;

impl Shell {
    /// Begin a new block.
    ///
    /// We include half of the new wrapper txs given to us from the mempool
    /// by tendermint. The rest of the block is filled with decryptions
    /// of the wrapper txs from the previously committed block.
    ///
    /// INVARIANT: Any changes applied in this method must be reverted if the
    /// proposal is rejected (unless we can simply overwrite them in the
    /// next block).
    pub fn prepare_proposal(
        &mut self,
        req: RequestPrepareProposal,
    ) -> response::PrepareProposal {
        // We can safely reset meter, because if the block is rejected, we'll
        // reset again on the next proposal, until the proposal is accepted
        self.gas_meter.reset();
        // TODO: This should not be hardcoded
        let privkey = <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();

        // filter in half of the new txs from Tendermint, only keeping wrappers
        let number_of_new_txs = 1 + req.block_data.len() / 2;
        let mut txs: Vec<TxBytes> = req
            .block_data
            .into_iter()
            .take(number_of_new_txs)
            .filter(|tx| {
                matches!(
                    process_tx(Tx::try_from(tx.as_slice()).unwrap()).unwrap(),
                    TxType::Wrapper(_)
                )
            })
            .collect();

        // decrypt the wrapper txs included in the previous block
        let mut decrypted_txs = self
            .storage
            .wrapper_txs
            .iter()
            .map(|tx| {
                Tx::from(match tx.decrypt(privkey) {
                    Ok(tx) => DecryptedTx::Decrypted(tx),
                    _ => DecryptedTx::Undecryptable(tx.clone()),
                })
                .to_bytes()
            })
            .collect();

        txs.append(&mut decrypted_txs);
        response::PrepareProposal { block_data: txs }
    }
}
