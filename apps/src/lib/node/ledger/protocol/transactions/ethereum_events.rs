use anoma::types::address::Address;
use anoma::types::ethereum_events::{
    EthereumAsset, EthereumEvent, TransferToNamada,
};
use anoma::types::token::Amount;

#[derive(Debug, PartialEq, Eq)]
pub struct EthMsg;

pub struct EventHash;

pub struct Mint {
    asset: EthereumAsset,
    receiver: Address,
    amount: Amount,
    event_hash: EventHash,
}

/// We calculate mints for any EthMsg where seen = true
/// But the mint will only be applied if seen is transitioning from false (or
/// uninitialized) to true in storage
pub(crate) fn calculate_mints(msgs: Vec<EthMsg>) -> Vec<Mint> {
    // let mints = [];
    // for msg in msgs:
    // if msg.seen:
    // mints += [construct_mint(msg)]
    // return mints
    vec![]
}

pub(crate) fn construct_mints(event: EthereumEvent) -> Vec<Mint> {
    let mut mints = vec![];
    match event {
        EthereumEvent::TransfersToNamada(transfers) => {
            for transfer in transfers {
                let TransferToNamada {
                    amount,
                    asset,
                    receiver,
                } = transfer;
                mints.push(Mint {
                    asset,
                    receiver,
                    amount,
                    event_hash: EventHash, // TODO: hash `event`
                })
            }
        }
    }
    mints
}
