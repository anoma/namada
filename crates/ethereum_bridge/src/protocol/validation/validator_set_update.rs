//! Validator set update validation.

use namada_core::storage::Epoch;
use namada_proof_of_stake::pos_queries::PosQueries;
use namada_state::{DBIter, StorageHasher, WlStorage, DB};
use namada_vote_ext::validator_set_update;

use super::VoteExtensionError;
use crate::storage::eth_bridge_queries::EthBridgeQueries;

/// Validates a validator set update vote extension issued at the
/// epoch provided as an argument.
///
/// # Validation checks
///
/// To validate a [`validator_set_update::SignedVext`], Namada nodes
/// check if:
///
///  * The signing validator is a consensus validator during the epoch
///    `signing_epoch` inside the extension.
///  * A validator set update proof is not available yet for `signing_epoch`.
///  * The validator correctly signed the extension, with its Ethereum hot key.
///  * The validator signed over the epoch inside of the extension, whose value
///    should not be greater than `last_epoch`.
///  * The voting powers in the vote extension correspond to the voting powers
///    of the validators of `signing_epoch + 1`.
///  * The voting powers signed over were Ethereum ABI encoded, normalized to
///    `2^32`, and sorted in descending order.
pub fn validate_valset_upd_vext<D, H>(
    wl_storage: &WlStorage<D, H>,
    ext: &validator_set_update::SignedVext,
    last_epoch: Epoch,
) -> Result<(), VoteExtensionError>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    if wl_storage.storage.last_block.is_none() {
        tracing::debug!(
            "Dropping validator set update vote extension issued at genesis"
        );
        return Err(VoteExtensionError::UnexpectedBlockHeight);
    }
    let signing_epoch = ext.data.signing_epoch;
    if signing_epoch > last_epoch {
        tracing::debug!(
            vext_epoch = ?signing_epoch,
            ?last_epoch,
            "Validator set update vote extension issued for an epoch \
             greater than the last one.",
        );
        return Err(VoteExtensionError::UnexpectedEpoch);
    }
    if wl_storage
        .ethbridge_queries()
        .valset_upd_seen(signing_epoch.next())
    {
        let err = VoteExtensionError::ValsetUpdProofAvailable;
        tracing::debug!(
            proof_epoch = ?signing_epoch.next(),
            "{err}"
        );
        return Err(err);
    }
    // verify if the new epoch validators' voting powers in storage match
    // the voting powers in the vote extension
    for (eth_addr_book, namada_addr, namada_power) in wl_storage
        .ethbridge_queries()
        .get_consensus_eth_addresses(Some(signing_epoch.next()))
        .iter()
    {
        let &ext_power = match ext.data.voting_powers.get(&eth_addr_book) {
            Some(voting_power) => voting_power,
            _ => {
                tracing::debug!(
                    ?eth_addr_book,
                    "Could not find expected Ethereum addresses in valset upd \
                     vote extension",
                );
                return Err(VoteExtensionError::ValidatorMissingFromExtension);
            }
        };
        if namada_power != ext_power {
            tracing::debug!(
                validator = %namada_addr,
                expected = ?namada_power,
                got = ?ext_power,
                "Found unexpected voting power value in valset upd vote extension",
            );
            return Err(VoteExtensionError::DivergesFromStorage);
        }
    }
    // get the public key associated with this validator
    let validator = &ext.data.validator_addr;
    let pk = wl_storage
        .pos_queries()
        .read_validator_eth_hot_key(validator, Some(signing_epoch))
        .ok_or_else(|| {
            tracing::debug!(
                %validator,
                "Could not get Ethereum hot key from Storage for some validator, \
                 while validating valset upd vote extension"
            );
            VoteExtensionError::PubKeyNotInStorage
        })?;
    // verify the signature of the vote extension
    ext.verify(&pk).map_err(|err| {
        tracing::debug!(
            ?err,
            ?ext.sig,
            ?pk,
            %validator,
            "Failed to verify the signature of a valset upd vote \
             extension issued by some validator"
        );
        VoteExtensionError::VerifySigFailed
    })?;
    Ok(())
}
