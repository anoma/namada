use crate::cli::args;

use anoma::types::{
    address::Address,
    key::ed25519::{Keypair, PublicKey},
};
use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::{BufReader, ErrorKind, Read, Write};

pub type Alias = String;

#[derive(Debug)]
pub struct KP(Keypair);

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct Store {
    keys: HashMap<Alias, KP>,
    addresses: HashMap<Alias, Address>,
}

impl BorshSerialize for KP {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // We need to turn the keypair to bytes first..
        let vec = self.0.to_bytes().to_vec();
        // .. and then encode them with Borsh
        let bytes = vec.try_to_vec().expect("Keypair bytes shouldn't fail");

        writer.write_all(&bytes)
    }
}

impl BorshDeserialize for KP {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        // deserialize the bytes first
        let bytes: Vec<u8> =
            BorshDeserialize::deserialize(buf).map_err(|e| {
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("Error decoding ed25519 public key: {}", e),
                )
            })?;
        ed25519_dalek::Keypair::from_bytes(&bytes)
            .map(KP)
            .map_err(|e| {
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("Error decoding ed25519 keypair: {}", e),
                )
            })
    }
}

impl Store {
    pub fn new() -> Self {
        Self {
            addresses: HashMap::new(),
            keys: HashMap::new(),
        }
    }
    pub fn fetch_by_alias(&self, alias: Alias) -> Option<&Keypair> {
        self.keys.get(&alias).map(|keypair| &keypair.0)
    }

    pub fn fetch_by_public_key(
        &self,
        public_key: PublicKey,
    ) -> Option<&Keypair> {
        self.keys
            .values()
            .find(|keypair| public_key.is_same_key(keypair.0.public))
            .map(|keypair| &keypair.0)
    }

    pub fn insert_new_keypair(&mut self, alias: Alias) {
        let keypair = Self::generate_keypair();

        let previous = self.keys.insert(alias, KP(keypair));

        match previous {
            None => self.save().unwrap(),
            Some(keypair) => {
                if show_overwrite_confirmation(&keypair.0) {
                    self.save().unwrap();
                } else {
                    return ();
                }
            }
        }
    }

    fn generate_keypair() -> Keypair {
        use rand::rngs::OsRng;

        let mut csprng = OsRng {};

        Keypair::generate(&mut csprng)
    }

    fn save(&self) -> std::io::Result<()> {
        let mut file = File::create("anoma_store")?;

        file.write_all(&self.try_to_vec().unwrap())?;

        Ok(())
    }

    fn load() -> std::io::Result<Self> {
        let file = File::open("anoma_store")?;

        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new();

        reader.read_to_end(&mut buffer)?;

        Store::try_from_slice(&buffer)
    }
}

fn show_overwrite_confirmation(_key: &Keypair) -> bool {
    false
}

// WIP
pub fn generate_key(args: args::Generate) {
    let store = Store::load();

    match store {
        Err(err) => match err.kind() {
            ErrorKind::NotFound => {
                let mut st = Store::new();
                insert_keypair_into_store(&mut st, args.alias);
            }
            _ => {
                println!("Error: {:?}", err)
            }
        },
        Ok(mut st) => {
            insert_keypair_into_store(&mut st, args.alias);
        }
    }
}

fn insert_keypair_into_store(store: &mut Store, alias: Option<String>) {
    match alias {
        None => {
            let mut input = String::new();

            println!("Please type an alias for your new keypair");
            io::stdin().read_line(&mut input);
            store.insert_new_keypair(input);
        }
        Some(str) => store.insert_new_keypair(str),
    }
}
