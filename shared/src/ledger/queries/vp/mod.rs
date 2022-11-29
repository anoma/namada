use pos::{Pos, POS};
mod pos;

// Validity predicate queries
router! {VP,
    ( "pos" ) = (sub POS),
}
