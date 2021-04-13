use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq, Hash)]
pub enum Topic {
    Dkg,
    Intent,
}

impl std::fmt::Display for Topic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Dkg => "dkg",
                Self::Intent => "intent",
            }
        )
    }
}
