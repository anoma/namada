//! Queries router and handlers for validity predicates

// Re-export to show in rustdoc!
pub use governance::Gov;
use governance::GOV;
pub use pos::Pos;
use pos::POS;
pub use token::Token;
use token::TOKEN;
mod governance;
pub use pgf::Pgf;
use pgf::PGF;
mod pgf;

pub mod pos;
mod token;

// Validity predicate queries
router! {VP,
    ( "pos" ) = (sub POS),
    ( "token" ) = (sub TOKEN),
    ( "governance" ) = (sub GOV),
    ( "pgf" ) = (sub PGF),
}
