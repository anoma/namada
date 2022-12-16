// Re-export to show in rustdoc!
pub use pos::Pos;
use pos::POS;
mod pos;

// Validity predicate queries
router! {VP,
    ( "pos" ) = (sub POS),
}
