use crate::cli::args;

use anoma::types::{
    address::Address,
    key::ed25519::{Keypair, PublicKey, PublicKeyHash},
};
use borsh::{BorshDeserialize, BorshSerialize};
use std::{collections::HashMap, num::NonZeroU32};
use std::fs::File;
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

    pub fn insert_new_keypair(&mut self, alias: Option<Alias>) -> Option<KP>{
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

fn show_overwrite_confirmation(_key: &Keypair) -> bool {
    false
}

#[derive(Debug)]
pub struct StoreHandler {
    store: Store,
    nonce_bytes: [u8; 12],
    password: String,
}

impl StoreHandler {
    pub fn new(password: String) -> Self {
        use rand::{thread_rng, Rng};

        let mut rng = thread_rng();

        let nonce_bytes: [u8; 12] = rng.gen();

        Self {
            store: Store::new(),
            nonce_bytes,
            password,
        }
    }

    // pub fn load(password: String, mut bytes: Vec<u8>) -> Self {
    //     let cipher = Self::make_cipher(&password);

    //     println!("{:?}", bytes);
    //     let (nonce_bytes, encrypted_data) =
    //         Self::split_nonce_encrypted_data(&mut bytes);
    //     let nonce = Nonce::from_slice(nonce_bytes.as_ref());

    //     println!("{:?}\n{:?}", nonce_bytes, encrypted_data);

    //     let decrypted_data =
    //         cipher.decrypt(nonce, encrypted_data.as_ref()).unwrap();

    //     let store = Store::try_from_slice(decrypted_data.as_ref()).unwrap();

    //     Self {
    //         nonce_bytes,
    //         password,
    //         store,
    //     }
    // }

    pub fn save(&self) -> std::io::Result<()> {
        use ring::aead::*;
        use ring::pbkdf2::*;
        use ring::rand::SystemRandom;

        let password = self.password.as_bytes();

        let salt = b"randomsalt";

        let mut key = [0; 32];

        let iterations = NonZeroU32::new(100).unwrap();

        derive(PBKDF2_HMAC_SHA256, iterations, salt, &password, &mut key);

        let content: Vec<u8> = self.store.try_to_vec().expect("Content serialization should not fail");

        let mut in_out = content.clone();

        for _ in 0..CHACHA20_POLY1305.tag_len() {
            in_out.push(0);
        }

        let mut nonce = Nonce::assume_unique_for_key(self.nonce_bytes);


        let sealing_key = SealingKey::new(&CHACHA20_POLY1305, &key);

        let output_size = seal_in_place(&sealing_key, &nonce, [], &mut in_out,
                                        CHACHA20_POLY1305.tag_len()).unwrap();

        let mut file = File::create("anoma_store")?;

        let persistent_data = [&self.nonce_bytes, &encrypted_data[..]].concat();

        file.write_all(persistent_data.as_ref())?;

        Ok(())
    }

    fn split_nonce_encrypted_data(bytes: &mut Vec<u8>) -> ([u8; 12], Vec<u8>) {
        use std::convert::TryInto;

        let encrypted_data = bytes.split_off(12);
        let nonce_bytes: [u8; 12] = (&bytes[0..12]).try_into().unwrap();

        (nonce_bytes, encrypted_data)
    }
}

pub fn generate_key(args: args::Generate) {
    let store = File::open("anoma_store");

    match store {
        Err(err) => match err.kind() {
            ErrorKind::NotFound => {
                println!("Seems like you don't have a store yet. You'll need to have one to use the wallet.");
                println!("We're going to need you to input a password, so we can encrypt your store.");

                let password = rpassword::read_password_from_tty(Some("Password: ")).unwrap_or_default();

                let mut handler = StoreHandler::new(password);
                insert_keypair_into_store(&mut handler, args.alias);
            }
            _ => {
                println!("Error: {:?}", err)
            }
        },
        Ok(mut file) => {
            let password = rpassword::read_password_from_tty(Some("Password: ")).unwrap_or_default();

            let mut store_data = Vec::new();

            file.read_to_end(&mut store_data).unwrap();

            let mut handler = StoreHandler::load(password, store_data);

            insert_keypair_into_store(&mut handler, args.alias);
        }
    }
}

fn insert_keypair_into_store(handler: &mut StoreHandler, alias: Option<Alias>) {
    handler.store.insert_new_keypair(alias);
    handler.save().unwrap();
}
