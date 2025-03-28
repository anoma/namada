//! Queries router and handlers for validity predicates

// Re-export to show in rustdoc!
use governance::GOV;
pub use governance::Gov;
use pos::POS;
pub use pos::Pos;
use token::TOKEN;
pub use token::Token;
mod governance;
use pgf::PGF;
pub use pgf::Pgf;
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
