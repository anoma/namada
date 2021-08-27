use crate::cli::args;

use anoma::types::{
    address::Address,
    key::ed25519::{Keypair, PublicKey, PublicKeyHash},
};

use std::collections::HashMap;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};

use borsh::{BorshDeserialize, BorshSerialize};
use orion::{aead, kdf};

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

    pub fn insert_new_keypair(&mut self, alias: Option<Alias>) -> Option<KP> {
        let keypair = Self::generate_keypair();

        let alias = alias.unwrap_or_else(|| {
            let public_key = PublicKey::from(keypair.public);

            PublicKeyHash::from(public_key).into()
        });

        self.keys.insert(alias, KP(keypair))
    }

    fn generate_keypair() -> Keypair {
        use rand::rngs::OsRng;

        let mut csprng = OsRng {};

        Keypair::generate(&mut csprng)
    }
}

#[derive(Debug)]
pub struct StoreHandler {
    store: Store,
    password: String,
    salt: orion::kdf::Salt,
}

pub enum Error {
    DecryptionError,
    DeserializingError,
}

impl Error {
    pub fn print(&self) {
        use Error::*;

        match self {
            DecryptionError => eprint!("There was an error decrypting your storage file. Are you sure you password is correct?"),
            DeserializingError => eprintln!("There was an error deserializing your file. This means that either your storage file is invalid or was corrupted.")
        }
    }
}

impl StoreHandler {
    pub fn new(password: String) -> Self {
        let salt = kdf::Salt::default();

        Self {
            store: Store::new(),
            password,
            salt,
        }
    }

    pub fn load(
        password: String,
        encrypted_data: Vec<u8>,
    ) -> Result<Self, Error> {
        let (salt, cipher) = encrypted_data.split_at(16);

        let salt = kdf::Salt::from_slice(&salt)
            .map_err(|_| Error::DeserializingError)?;

        let secret_key = kdf::Password::from_slice(&password.as_bytes())
            .and_then(|password| {
                kdf::derive_key(&password, &salt, 3, 1 << 16, 32)
            })
            .expect("Generation of Secret Key shouldn't faile");

        let decrypted_data = aead::open(&secret_key, cipher)
            .map_err(|_| Error::DecryptionError)?;

        let store = Store::try_from_slice(&decrypted_data)
            .map_err(|_| Error::DeserializingError)?;

        Ok(Self {
            store,
            password,
            salt,
        })
    }

    pub fn save(&self) -> std::io::Result<()> {
        let secret_key = kdf::Password::from_slice(&self.password.as_bytes())
            .and_then(|password| {
                kdf::derive_key(&password, &self.salt, 3, 1 << 16, 32)
            })
            .expect("Generation of Secret Key shouldn't fail");

        let data = self
            .store
            .try_to_vec()
            .expect("Serializing of store shouldn't fail");

        let encrypted_data = aead::seal(&secret_key, &data)
            .expect("Encryption of data shouldn't fail");

        let file_data = [self.salt.as_ref(), &encrypted_data].concat();

        let mut file = File::create("anoma_store")?;

        file.write_all(file_data.as_ref())?;

        Ok(())
    }
}

pub fn generate_key(args: args::Generate) {
    let store = File::open("anoma_store");

    match store {
        Err(err) => match err.kind() {
            ErrorKind::NotFound => {
                println!("Seems like you don't have a store yet. You'll need to have one to use the wallet.");
                println!("We're going to need you to input a password, so we can encrypt your store.");

                let password =
                    rpassword::read_password_from_tty(Some("Password: "))
                        .unwrap_or_default();

                let mut handler = StoreHandler::new(password);
                insert_keypair_into_store(&mut handler, args.alias);
            }
            _ => {
                eprintln!("Error: {:?}", err)
            }
        },
        Ok(mut file) => {
            let password =
                rpassword::read_password_from_tty(Some("Password: "))
                    .unwrap_or_default();

            let mut store_data = Vec::new();

            file.read_to_end(&mut store_data).unwrap();

            match StoreHandler::load(password, store_data) {
                Ok(mut handler) => {
                    insert_keypair_into_store(&mut handler, args.alias)
                }
                Err(error) => error.print(),
            }
        }
    }
}

fn insert_keypair_into_store(handler: &mut StoreHandler, alias: Option<Alias>) {
    handler.store.insert_new_keypair(alias);
    handler.save().unwrap();
}
