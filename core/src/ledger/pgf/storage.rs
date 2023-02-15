use std::str::FromStr;

use borsh::BorshDeserialize;

use crate::ledger::pgf::ADDRESS;
use crate::ledger::storage_api::token::Amount;
use crate::types::address::Address;
use crate::types::storage::{DbKeySeg, Key, KeySeg};

const CPGF_RECIPIENTS: &str = "cpgf_recipients";
const SPENDING_CAP: &str = "spending_cap";
const SPENT_AMOUNT: &str = "spent_amount";
const CANDIDACY_EXPIRATION: &str = "candidacy_expiration";
const CANDIDATES: &str = "candidates";
const ACTIVE_COUNSIL: &str = "active_counsil";
const PROJECTS: &str = "projects";

/// Check if key is inside pfg address space
pub fn is_pgf_key(key: &Key) -> bool {
    matches!(&key.segments[0], DbKeySeg::AddressSeg(addr) if addr == &ADDRESS)
}

/// Check if a key is a PGF candidate key
pub fn is_candidates_key(key: &Key) -> bool {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(_address),
            DbKeySeg::StringSeg(spending_cap),
        ] if addr == &ADDRESS
            && prefix == CANDIDATES =>
        {
            spending_cap.parse::<u64>().is_ok()
        }
        _ => false,
    }
}

/// Check if key is PGF spent amount key
pub fn is_spent_amount_key(key: &Key) -> bool {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix)
        ] if addr == &ADDRESS && prefix == SPENT_AMOUNT => {
            true
        }
        _ => false
    }
}

pub fn is_project_key(key: &Key) -> bool {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(addr),
            DbKeySeg::StringSeg(prefix)
        ] if addr == &ADDRESS && prefix == PROJECTS => {
            true
        }
        _ => false
    }
}

/// Get continuous PGF recipients addresses key
pub fn cpgf_recipient_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&CPGF_RECIPIENTS.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get PGF spending cap key
pub fn get_spending_cap_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&SPENDING_CAP.to_owned())
        .expect("Cannot obtain a storage key")
}


/// Get PGF council spent amount key
pub fn get_spent_amount_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&SPENT_AMOUNT.to_owned())
        .expect("Cannot obtain a storage key")
}


/// Get PGF candidacy expiration
pub fn get_candidacy_expiration_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&CANDIDACY_EXPIRATION.to_owned())
        .expect("Cannot obtain a storage key")
}


/// Get PGF candidate key
pub fn get_candidate_key(address: &Address, spending_cap: Amount) -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&CANDIDATES.to_owned())
        .expect("Cannot obtain a storage key")
        .push(&address.to_owned())
        .expect("Cannot obtain a storage key")
        .push(&spending_cap.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get PGF active council key
pub fn get_active_counsil_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&ACTIVE_COUNSIL.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get PGF candidate address
pub fn get_candidate_address(key: &Key) -> Option<&Address> {
    match key.get_at(2) {
        Some(addr) => match addr {
            DbKeySeg::AddressSeg(res) => Some(res),
            DbKeySeg::StringSeg(_) => None,
        },
        None => None,
    }
}

/// Get PGF candidate address
pub fn get_candidate_spending_cap(key: &Key) -> Option<Amount> {
    match key.get_at(3) {
        Some(addr) => match addr {
            DbKeySeg::AddressSeg(_) => None,
            DbKeySeg::StringSeg(amount) => {
                Amount::try_from_slice(amount.as_bytes()).ok()
            },
        },
        None => None,
    }
}