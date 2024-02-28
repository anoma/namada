//! Ethereum events validation.

use namada_core::storage::BlockHeight;
use namada_proof_of_stake::pos_queries::PosQueries;
use namada_state::{DBIter, StorageHasher, WlState, DB};
use namada_tx::Signed;
use namada_vote_ext::ethereum_events;

use super::VoteExtensionError;
use crate::storage::eth_bridge_queries::EthBridgeQueries;

/// Validates an Ethereum events vote extension issued at the provided
/// block height.
///
/// Checks that at epoch of the provided height:
///  * The inner Namada address corresponds to a consensus validator.
///  * The validator correctly signed the extension.
///  * The validator signed over the correct height inside of the extension.
///  * There are no duplicate Ethereum events in this vote extension, and the
///    events are sorted in ascending order.
pub fn validate_eth_events_vext<D, H>(
    state: &WlState<D, H>,
    ext: &Signed<ethereum_events::Vext>,
    last_height: BlockHeight,
) -> Result<(), VoteExtensionError>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    // NOTE: for ABCI++, we should pass
    // `last_height` here, instead of `ext.data.block_height`
    let ext_height_epoch =
        match state.pos_queries().get_epoch(ext.data.block_height) {
            Some(epoch) => epoch,
            _ => {
                tracing::debug!(
                    block_height = ?ext.data.block_height,
                    "The epoch of the Ethereum events vote extension's \
                     block height should always be known",
                );
                return Err(VoteExtensionError::UnexpectedEpoch);
            }
        };
    if !state
        .ethbridge_queries()
        .is_bridge_active_at(ext_height_epoch)
    {
        tracing::debug!(
            vext_epoch = ?ext_height_epoch,
            "The Ethereum bridge was not enabled when the Ethereum
             events' vote extension was cast",
        );
        return Err(VoteExtensionError::EthereumBridgeInactive);
    }
    if ext.data.block_height > last_height {
        tracing::debug!(
            ext_height = ?ext.data.block_height,
            ?last_height,
            "Ethereum events vote extension issued for a block height \
             higher than the chain's last height."
        );
        return Err(VoteExtensionError::UnexpectedBlockHeight);
    }
    if ext.data.block_height.0 == 0 {
        tracing::debug!("Dropping vote extension issued at genesis");
        return Err(VoteExtensionError::UnexpectedBlockHeight);
    }
    validate_eth_events(state, &ext.data)?;
    // get the public key associated with this validator
    let validator = &ext.data.validator_addr;
    let (_, pk) = state
        .pos_queries()
        .get_validator_from_address(validator, Some(ext_height_epoch))
        .map_err(|err| {
            tracing::debug!(
                ?err,
                %validator,
                "Could not get public key from Storage for some validator, \
                 while validating Ethereum events vote extension"
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
            "Failed to verify the signature of an Ethereum events vote \
             extension issued by some validator"
        );
        VoteExtensionError::VerifySigFailed
    })?;
    Ok(())
}

/// Validate a batch of Ethereum events contained in
/// an [`ethereum_events::Vext`].
///
/// The supplied Ethereum events must be ordered in
/// ascending ordering, must not contain any dupes
/// and must have valid nonces.
fn validate_eth_events<D, H>(
    state: &WlState<D, H>,
    ext: &ethereum_events::Vext,
) -> Result<(), VoteExtensionError>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    // verify if we have any duplicate Ethereum events,
    // and if these are sorted in ascending order
    let have_dupes_or_non_sorted = {
        !ext.ethereum_events
            // TODO: move to `array_windows` when it reaches Rust stable
            .windows(2)
            .all(|evs| evs[0] < evs[1])
    };
    let validator = &ext.validator_addr;
    if have_dupes_or_non_sorted {
        tracing::debug!(
            %validator,
            "Found duplicate or non-sorted Ethereum events in a vote extension from \
             some validator"
        );
        return Err(VoteExtensionError::HaveDupesOrNonSorted);
    }
    // for the proposal to be valid, at least one of the
    // event's nonces must be valid
    if ext
        .ethereum_events
        .iter()
        .any(|event| state.ethbridge_queries().validate_eth_event_nonce(event))
    {
        Ok(())
    } else {
        Err(VoteExtensionError::InvalidEthEventNonce)
    }
}
