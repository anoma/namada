use ed25519_dalek::PublicKey;

pub type Address = String;

#[derive(Clone, Debug)]
pub enum Account {
    Validator(ValidatorAccount),
    Basic(BasicAccount),
}
#[derive(Clone, Debug)]
pub struct BasicAccount {
    pub balance: u64,
    pub vality_predicate: (),
}

#[derive(Clone, Debug)]
pub struct ValidatorAccount {
    pub pk: PublicKey,
    pub voting_power: u64,
    pub balance: u64,
    pub vality_predicate: (),
}
