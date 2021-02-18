//! The storage module handles both the current state in-memory and the stored
//! state in DB.

// TODO add storage error type

mod db;

use blake2b_rs::{Blake2b, Blake2bBuilder};
use sparse_merkle_tree::{
    blake2b::Blake2bHasher, default_store::DefaultStore, SparseMerkleTree, H256,
};
use std::collections::HashMap;

pub struct Storage {
    tree: MerkleTree,
    balances: HashMap<Address, Balance>,
}

type MerkleTree = SparseMerkleTree<Blake2bHasher, H256, DefaultStore<H256>>;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Address {
    Validator(ValidatorAddress),
    Basic(BasicAddress),
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct BasicAddress(String);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ValidatorAddress(String);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Balance(u64);

impl Storage {
    pub fn new() -> Self {
        let tree = MerkleTree::default();
        let balances = HashMap::new();
        Self { tree, balances }
    }

    pub fn merkle_root(&self) -> &H256 {
        self.tree.root()
    }

    pub fn update_balance(
        &mut self,
        addr: Address,
        balance: Balance,
    ) -> Result<(), String> {
        let key = addr.hash();
        let value = balance.hash();
        self.tree
            .update(key, value)
            .map_err(|err| format!("SMT error {}", err))?;
        self.balances.insert(addr, balance);
        Ok(())
    }

    // TODO this doesn't belong here, but just for convenience...
    pub fn transfer(
        &mut self,
        src: Address,
        dest: Address,
        amount: u64,
    ) -> Result<(), String> {
        match self.balances.get(&src) {
            None => return Err("Source not found".to_owned()),
            Some(&Balance(src_balance)) => {
                if src_balance < amount {
                    return Err("Source balance is too low".to_owned());
                };
                self.update_balance(src, Balance::new(src_balance - amount))?;
                match self.balances.get(&dest) {
                    None => self.update_balance(dest, Balance::new(amount))?,
                    Some(&Balance(dest_balance)) => self.update_balance(
                        dest,
                        Balance::new(dest_balance + amount),
                    )?,
                }
                Ok(())
            }
        }
    }
}

impl Address {
    fn hash(&self) -> H256 {
        match self {
            Address::Basic(addr) => addr.hash(),
            Address::Validator(addr) => addr.hash(),
        }
    }
}

impl BasicAddress {
    pub fn new_address(addr: String) -> Address {
        Address::Basic(Self(addr))
    }

    fn hash(&self) -> H256 {
        hash_string(&self.0)
    }
}

impl ValidatorAddress {
    pub fn new_address(addr: String) -> Address {
        Address::Validator(Self(addr))
    }

    fn hash(&self) -> H256 {
        hash_string(&self.0)
    }
}

impl Balance {
    pub fn new(balance: u64) -> Self {
        Self(balance)
    }

    fn hash(&self) -> H256 {
        if self.0 == 0 {
            return H256::zero();
        }
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(&self.0.to_le_bytes());
        hasher.finalize(&mut buf);
        buf.into()
    }
}

fn hash_string(str: &String) -> H256 {
    if str.is_empty() {
        return H256::zero();
    }
    let mut buf = [0u8; 32];
    let mut hasher = new_blake2b();
    hasher.update(str.as_bytes());
    hasher.finalize(&mut buf);
    buf.into()
}

fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32).personal(b"personal hasher").build()
}
