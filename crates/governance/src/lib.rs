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

pub use storage::proposal::{InitProposalData, ProposalType, VoteProposalData};
pub use storage::vote::ProposalVote;
pub use storage::{init_proposal, is_proposal_accepted, vote_proposal};

/// The governance internal address
pub const ADDRESS: Address = address::GOV;
