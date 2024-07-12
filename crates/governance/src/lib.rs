//! Governance library code

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::arithmetic_side_effects,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::marker::PhantomData;

use namada_core::address::{self, Address};

/// governance CLI structures
pub mod cli;
pub mod event;
/// governance parameters
pub mod parameters;
/// governance public good fundings
pub mod pgf;
/// governance storage
pub mod storage;
/// Governance utility functions/structs
pub mod utils;
pub mod vp;

use namada_state::{StorageRead, StorageWrite};
pub use namada_systems::governance::*;
use parameters::GovernanceParameters;
pub use storage::proposal::{InitProposalData, ProposalType, VoteProposalData};
pub use storage::vote::ProposalVote;
pub use storage::{init_proposal, is_proposal_accepted, vote_proposal};

/// The governance internal address
pub const ADDRESS: Address = address::GOV;

/// Governance storage `Keys/Read/Write` implementation
#[derive(Debug)]
pub struct Store<S>(PhantomData<S>);

impl<S> Read<S> for Store<S>
where
    S: StorageRead,
{
    fn is_proposal_accepted(storage: &S, tx_data: &[u8]) -> Result<bool> {
        storage::is_proposal_accepted(storage, tx_data)
    }

    fn max_proposal_period(storage: &S) -> Result<u64> {
        storage::get_max_proposal_period(storage)
    }
}

impl<S> Write<S> for Store<S>
where
    S: StorageRead + StorageWrite,
{
    fn init_default_params(storage: &mut S) -> Result<()> {
        let params = GovernanceParameters::default();
        params.init_storage(storage)
    }
}
