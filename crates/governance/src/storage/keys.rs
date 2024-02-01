use namada_core::address::Address;
use namada_core::storage::{DbKeySeg, Key, KeySeg};
use namada_macros::StorageKeys;

use crate::ADDRESS;

/// Storage keys for governance internal address.
#[derive(StorageKeys)]
struct Keys {
    proposal: &'static str,
    vote: &'static str,
    author: &'static str,
    proposal_type: &'static str,
    content: &'static str,
    start_epoch: &'static str,
    end_epoch: &'static str,
    grace_epoch: &'static str,
    funds: &'static str,
    proposal_code: &'static str,
    committing_epoch: &'static str,
    min_fund: &'static str,
    max_code_size: &'static str,
    min_period: &'static str,
    max_period: &'static str,
    max_content: &'static str,
    min_grace_epoch: &'static str,
    counter: &'static str,
    pending: &'static str,
    result: &'static str,
}

/// Check if key is inside governance address space
pub fn is_governance_key(key: &Key) -> bool {
    matches!(&key.segments[0], DbKeySeg::AddressSeg(addr) if addr == &ADDRESS)
}

/// Check if a key is a vote key
pub fn is_vote_key(key: &Key) -> bool {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(id),
            DbKeySeg::StringSeg(vote),
            DbKeySeg::AddressSeg(_validator_address),
            DbKeySeg::AddressSeg(_address),
        ] if addr == &ADDRESS
            && prefix == Keys::VALUES.proposal
            && vote == Keys::VALUES.vote =>
        {
            id.parse::<u64>().is_ok()
        }
        _ => false,
    }
}

/// Check if key is author key
pub fn is_author_key(key: &Key) -> bool {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(id),
            DbKeySeg::StringSeg(author),
        ] if addr == &ADDRESS
            && prefix == Keys::VALUES.proposal
            && author == Keys::VALUES.author =>
        {
            id.parse::<u64>().is_ok()
        }
        _ => false,
    }
}

/// Check if key is proposal code key
pub fn is_proposal_code_key(key: &Key) -> bool {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(id),
            DbKeySeg::StringSeg(proposal_code),
        ] if addr == &ADDRESS
            && prefix == Keys::VALUES.proposal
            && proposal_code == Keys::VALUES.proposal_code =>
        {
            id.parse::<u64>().is_ok()
        }
        _ => false,
    }
}

/// Check if key is grace epoch key
pub fn is_grace_epoch_key(key: &Key) -> bool {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(id),
            DbKeySeg::StringSeg(grace_epoch),
        ] if addr == &ADDRESS
            && prefix == Keys::VALUES.proposal
            && grace_epoch == Keys::VALUES.grace_epoch =>
        {
            id.parse::<u64>().is_ok()
        }
        _ => false,
    }
}

/// Check if key is content key
pub fn is_content_key(key: &Key) -> bool {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(id),
            DbKeySeg::StringSeg(content),
        ] if addr == &ADDRESS
            && prefix == Keys::VALUES.proposal
            && content == Keys::VALUES.content =>
        {
            id.parse::<u64>().is_ok()
        }
        _ => false,
    }
}

/// Check if key is balance key
pub fn is_balance_key(key: &Key) -> bool {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(id),
            DbKeySeg::StringSeg(funds),
        ] if addr == &ADDRESS
            && prefix == Keys::VALUES.proposal
            && funds == Keys::VALUES.funds =>
        {
            id.parse::<u64>().is_ok()
        }
        _ => false,
    }
}

/// Check if key is start epoch key
pub fn is_start_epoch_key(key: &Key) -> bool {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(id),
            DbKeySeg::StringSeg(start_epoch),
        ] if addr == &ADDRESS
            && prefix == Keys::VALUES.proposal
            && start_epoch == Keys::VALUES.start_epoch =>
        {
            id.parse::<u64>().is_ok()
        }
        _ => false,
    }
}

/// Check if key is epoch key
pub fn is_end_epoch_key(key: &Key) -> bool {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(id),
            DbKeySeg::StringSeg(end_epoch),
        ] if addr == &ADDRESS
            && prefix == Keys::VALUES.proposal
            && end_epoch == Keys::VALUES.end_epoch =>
        {
            id.parse::<u64>().is_ok()
        }
        _ => false,
    }
}

/// Check if key is proposal type key
pub fn is_proposal_type_key(key: &Key) -> bool {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(id),
            DbKeySeg::StringSeg(proposal_type),
        ] if addr == &ADDRESS
            && prefix == Keys::VALUES.proposal
            && proposal_type == Keys::VALUES.proposal_type =>
        {
            id.parse::<u64>().is_ok()
        }
        _ => false,
    }
}

/// Check if key is counter key
pub fn is_counter_key(key: &Key) -> bool {
    matches!(&key.segments[..], [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(counter)] if addr == &ADDRESS && counter == Keys::VALUES.counter)
}

/// Check if key is a proposal fund parameter key
pub fn is_min_proposal_fund_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
             DbKeySeg::AddressSeg(addr),
             DbKeySeg::StringSeg(min_funds_param),
         ] if addr == &ADDRESS && min_funds_param == Keys::VALUES.min_fund)
}

/// Check if key is a proposal max content parameter key
pub fn is_max_content_size_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
             DbKeySeg::AddressSeg(addr),
             DbKeySeg::StringSeg(max_content_size_param),
         ] if addr == &ADDRESS
             && max_content_size_param == Keys::VALUES.max_content)
}

/// Check if key is a max proposal size key
pub fn is_max_proposal_code_size_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
             DbKeySeg::AddressSeg(addr),
             DbKeySeg::StringSeg(max_content_size_param),
         ] if addr == &ADDRESS
             && max_content_size_param == Keys::VALUES.max_code_size)
}

/// Check if key is a min proposal period param key
pub fn is_min_proposal_voting_period_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
             DbKeySeg::AddressSeg(addr),
             DbKeySeg::StringSeg(min_proposal_voting_period_param),
         ] if addr == &ADDRESS
             && min_proposal_voting_period_param == Keys::VALUES.min_period)
}

/// Check if key is a max proposal period param key
pub fn is_max_proposal_period_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
             DbKeySeg::AddressSeg(addr),
             DbKeySeg::StringSeg(max_proposal_period_param),
         ] if addr == &ADDRESS
             && max_proposal_period_param == Keys::VALUES.max_period)
}

/// Check if key is a min grace epoch key
pub fn is_commit_proposal_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(prefix),
        DbKeySeg::StringSeg(epoch_prefix),
        DbKeySeg::StringSeg(_epoch),
        DbKeySeg::StringSeg(_id),
    ] if addr == &ADDRESS
        && prefix == Keys::VALUES.proposal
        && epoch_prefix == Keys::VALUES.committing_epoch
    )
}

/// Check if key is a commit proposal key
pub fn is_min_grace_epoch_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
                    DbKeySeg::AddressSeg(addr),
                    DbKeySeg::StringSeg(min_grace_epoch_param),
                ] if addr == &ADDRESS
                    && min_grace_epoch_param == Keys::VALUES.min_grace_epoch)
}

/// Check if key is parameter key
pub fn is_parameter_key(key: &Key) -> bool {
    is_min_proposal_fund_key(key)
        || is_max_content_size_key(key)
        || is_max_proposal_code_size_key(key)
        || is_min_proposal_voting_period_key(key)
        || is_max_proposal_period_key(key)
        || is_min_grace_epoch_key(key)
}

/// Check if key is start epoch or end epoch key
pub fn is_start_or_end_epoch_key(key: &Key) -> bool {
    is_end_epoch_key(key) || is_start_epoch_key(key)
}

/// Get governance prefix key
pub fn proposal_prefix() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&Keys::VALUES.proposal.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get key for the minimum proposal fund
pub fn get_min_proposal_fund_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&Keys::VALUES.min_fund.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get maximum proposal code size key
pub fn get_max_proposal_code_size_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&Keys::VALUES.max_code_size.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get minimum proposal period key
pub fn get_min_proposal_voting_period_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&Keys::VALUES.min_period.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get maximum proposal period key
pub fn get_max_proposal_period_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&Keys::VALUES.max_period.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get maximum proposal content key
pub fn get_max_proposal_content_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&Keys::VALUES.max_content.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get min grace epoch proposal key
pub fn get_min_proposal_grace_epoch_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&Keys::VALUES.min_grace_epoch.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get key of proposal ids counter
pub fn get_counter_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&Keys::VALUES.counter.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get key of proposal content
pub fn get_content_key(id: u64) -> Key {
    proposal_prefix()
        .push(&id.to_string())
        .expect("Cannot obtain a storage key")
        .push(&Keys::VALUES.content.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get key of proposal author
pub fn get_author_key(id: u64) -> Key {
    proposal_prefix()
        .push(&id.to_string())
        .expect("Cannot obtain a storage key")
        .push(&Keys::VALUES.author.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get key of a proposal type
pub fn get_proposal_type_key(id: u64) -> Key {
    proposal_prefix()
        .push(&id.to_string())
        .expect("Cannot obtain a storage key")
        .push(&Keys::VALUES.proposal_type.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get key of proposal voting start epoch
pub fn get_voting_start_epoch_key(id: u64) -> Key {
    proposal_prefix()
        .push(&id.to_string())
        .expect("Cannot obtain a storage key")
        .push(&Keys::VALUES.start_epoch.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get key of proposal voting end epoch
pub fn get_voting_end_epoch_key(id: u64) -> Key {
    proposal_prefix()
        .push(&id.to_string())
        .expect("Cannot obtain a storage key")
        .push(&Keys::VALUES.end_epoch.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get key of proposal funds
pub fn get_funds_key(id: u64) -> Key {
    proposal_prefix()
        .push(&id.to_string())
        .expect("Cannot obtain a storage key")
        .push(&Keys::VALUES.funds.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get proposal grace epoch key
pub fn get_grace_epoch_key(id: u64) -> Key {
    proposal_prefix()
        .push(&id.to_string())
        .expect("Cannot obtain a storage key")
        .push(&Keys::VALUES.grace_epoch.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get the proposal committing key prefix
pub fn get_commiting_proposals_prefix(epoch: u64) -> Key {
    proposal_prefix()
        .push(&Keys::VALUES.committing_epoch.to_owned())
        .expect("Cannot obtain a storage key")
        .push(&epoch.to_string())
        .expect("Cannot obtain a storage key")
}

/// Get proposal code key
pub fn get_proposal_code_key(id: u64) -> Key {
    proposal_prefix()
        .push(&id.to_string())
        .expect("Cannot obtain a storage key")
        .push(&Keys::VALUES.proposal_code.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get the committing proposal key
pub fn get_committing_proposals_key(id: u64, epoch: u64) -> Key {
    get_commiting_proposals_prefix(epoch)
        .push(&id.to_string())
        .expect("Cannot obtain a storage key")
}

/// Get proposal vote prefix key
pub fn get_proposal_vote_prefix_key(id: u64) -> Key {
    proposal_prefix()
        .push(&id.to_string())
        .expect("Cannot obtain a storage key")
        .push(&Keys::VALUES.vote.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get the vote key for a specific proposal id
pub fn get_vote_proposal_key(
    id: u64,
    voter_address: Address,
    delegation_address: Address,
) -> Key {
    get_proposal_vote_prefix_key(id)
        .push(&delegation_address)
        .expect("Cannot obtain a storage key")
        .push(&voter_address)
        .expect("Cannot obtain a storage key")
}

/// Get the proposal execution key
pub fn get_proposal_execution_key(id: u64) -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&Keys::VALUES.pending.to_owned())
        .expect("Cannot obtain a storage key")
        .push(&id.to_string())
        .expect("Cannot obtain a storage key")
}

/// Get the proposal result key
pub fn get_proposal_result_key(id: u64) -> Key {
    proposal_prefix()
        .push(&id.to_string())
        .expect("Cannot obtain a storage key")
        .push(&Keys::VALUES.result.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get proposal id from key
pub fn get_proposal_id(key: &Key) -> Option<u64> {
    match key.get_at(2) {
        Some(id) => match id {
            DbKeySeg::AddressSeg(_) => None,
            DbKeySeg::StringSeg(res) => res.parse::<u64>().ok(),
        },
        None => None,
    }
}

/// Get the committing epoch from a proposal committing key
pub fn get_commit_proposal_epoch(key: &Key) -> Option<u64> {
    match key.get_at(3) {
        Some(id) => match id {
            DbKeySeg::AddressSeg(_) => None,
            DbKeySeg::StringSeg(res) => res.parse::<u64>().ok(),
        },
        None => None,
    }
}

/// Get the proposal id from a proposal committing key
pub fn get_commit_proposal_id(key: &Key) -> Option<u64> {
    match key.get_at(4) {
        Some(id) => match id {
            DbKeySeg::AddressSeg(_) => None,
            DbKeySeg::StringSeg(res) => res.parse::<u64>().ok(),
        },
        None => None,
    }
}
/// Get the delegation address from vote key
pub fn get_vote_delegation_address(key: &Key) -> Option<&Address> {
    match key.get_at(4) {
        Some(addr) => match addr {
            DbKeySeg::AddressSeg(res) => Some(res),
            DbKeySeg::StringSeg(_) => None,
        },
        None => None,
    }
}

/// Get voter address from vote key
pub fn get_voter_address(key: &Key) -> Option<&Address> {
    match key.get_at(5) {
        Some(addr) => match addr {
            DbKeySeg::AddressSeg(res) => Some(res),
            DbKeySeg::StringSeg(_) => None,
        },
        None => None,
    }
}
