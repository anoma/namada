use namada_core::types::storage::KeySeg;
use namada_core::types::token;

/// A wrapper over `token::Amount`, whose `KeySeg` implementation has reverse
/// order of the `token::Amount` type.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReverseOrdTokenAmount(
    /// The token amount (this is the actual value, not inverted)
    pub token::Amount,
);

impl From<ReverseOrdTokenAmount> for token::Amount {
    fn from(ReverseOrdTokenAmount(amount): ReverseOrdTokenAmount) -> Self {
        amount
    }
}

impl From<token::Amount> for ReverseOrdTokenAmount {
    fn from(amount: token::Amount) -> Self {
        Self(amount)
    }
}

/// Invert the token amount
fn invert(amount: token::Amount) -> token::Amount {
    token::MAX_AMOUNT - amount
}

impl KeySeg for ReverseOrdTokenAmount {
    fn parse(string: String) -> namada_core::types::storage::Result<Self>
    where
        Self: Sized,
    {
        let amount = token::Amount::parse(string)?;
        Ok(Self(invert(amount)))
    }

    fn raw(&self) -> String {
        invert(self.0).raw()
    }

    fn to_db_key(&self) -> namada_core::types::storage::DbKeySeg {
        invert(self.0).to_db_key()
    }
}

impl std::fmt::Display for ReverseOrdTokenAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for ReverseOrdTokenAmount {
    type Err = <token::Amount as std::str::FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let amount = token::Amount::from_str(s)?;
        Ok(Self(amount))
    }
}
