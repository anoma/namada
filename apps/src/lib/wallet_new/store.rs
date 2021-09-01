use std::collections::HashMap;
use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};

use anoma::types::address::{Address, ImplicitAddress};
use anoma::types::key::ed25519::{Keypair, PublicKey, PublicKeyHash};
use borsh::{BorshDeserialize, BorshSerialize};
use orion::{aead, kdf};

use crate::cli::args;

pub type Alias = String;

#[derive(Table)]
struct KeysTable {
    #[table(title = "Alias")]
    alias: &'static str,
    #[table(title = "Public Key")]
    public_key: &'static str,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Default)]
pub struct Store {
    keys: HashMap<Alias, Keypair>,
    addresses: HashMap<Alias, Address>,
}

impl Store {
    pub fn fetch_by_alias(&self, alias: Alias) -> Option<&Keypair> {
        self.keys.get(&alias)
    }

    pub fn fetch_by_public_key(
        &self,
        public_key: PublicKey,
    ) -> Option<&Keypair> {
        self.keys
            .values()
            .find(|keypair| public_key == keypair.public)
    }

    pub fn insert_new_keypair(
        &mut self,
        alias: Option<Alias>,
    ) -> Option<Keypair> {
        let keypair = Self::generate_keypair();

        let public_key_hash: PublicKeyHash =
            PublicKeyHash::from(&keypair.public);

        let address = Address::Implicit(ImplicitAddress::Ed25519(
            public_key_hash.clone(),
        ));

        let alias = alias.unwrap_or_else(|| public_key_hash.into());

        self.addresses.insert(alias.clone(), address);

        self.keys.insert(alias, keypair)
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
            DecryptionError => eprint!(
                "There was an error decrypting your storage file. Are you \
                 sure you password is correct?"
            ),
            DeserializingError => eprintln!(
                "There was an error deserializing your file. This means that \
                 either your storage file is invalid or was corrupted."
            ),
        }
    }
}

impl StoreHandler {
    pub fn new(password: String) -> Self {
        let salt = kdf::Salt::default();

        Self {
            store: Store::default(),
            password,
            salt,
        }
    }

    pub fn load(
        password: String,
        encrypted_data: Vec<u8>,
    ) -> Result<Self, Error> {
        println!("Decrypting your store...");

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
        println!("Encrypting your store...");

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

pub fn generate_key(args: args::KeyGen) {
    let store = File::open("anoma_store");

    match store {
        Err(err) => match err.kind() {
            ErrorKind::NotFound => {
                println!(
                    "Seems like you don't have a store yet. You'll need to \
                     have one to use the wallet."
                );
                println!(
                    "We're going to need you to input a password, so we can \
                     encrypt your store."
                );

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

// fn pretty_print(keypair: Keypair) {
//     keypair.public.
// }

// error enum with different variants
fn load_store() -> Result<StoreHandler, &'static str> {
    let store = File::open("anoma_store");

    let password = rpassword::read_password_from_tty(Some("Password: "))
        .unwrap_or_default();

    let mut store_data = Vec::new();

    match store {
        Ok(mut file) => {
            file.read_to_end(&mut store_data).unwrap();
            match StoreHandler::load(password, store_data) {
                Ok(handler) => Ok(handler),
                Err(_) => Err("Could not load store"),
            }
        }
        Err(_) => Err("Could not load store"),
    }
}

pub fn export_key_to_file(args: args::Export) {
    use std::io;

    load_store()
        .and_then(|handler| {
            let alias = args.alias.unwrap_or_else(|| {
                let mut read_alias = String::new();

                io::stdin().read_to_string(&mut read_alias).unwrap();
                read_alias
            });

            handler
                .store
                .fetch_by_alias(alias.clone())
                .map(|keypair| {
                    let file_data = keypair.public.to_bytes().to_vec();

                    let mut file =
                        File::create(format!("key_{}", alias)).unwrap();

                    file.write_all(file_data.as_ref()).unwrap();

                    ()
                })
                .ok_or("No keypair was found with the given alias")
        })
        .unwrap_or_else(|err| eprintln!("{}", err));
}

// Implement public key exportation to file, fetch by public key
pub fn fetch(args: args::KeyFind) {
    // TODO public key args is unused/unimplemented
    match (args.alias, args.value) {
        (None, None) => println!("An alias needs to be supplied"),
        (Some(key), _) | (_, Some(key)) => match load_store() {
            Ok(handler) => match handler.store.fetch_by_alias(key) {
                None => {
                    println!("No keypairs were found with this alias")
                }
                Some(keypair) => {
                    println!("public key: {}", keypair.public);
                    if args.show_secret {
                        println!("secret key: {}", keypair.secret);
                    }
                }
            },
            Err(error) => println!("{}", error),
        },
    }
}

// List all known keys
pub fn list(args: args::KeyList) {
    match load_store() {
        Ok(handler) => {
            let stdout = io::stdout();
            let mut w = stdout.lock();
            writeln!(w, "Known keys:").unwrap();
            for (alias, keypair) in handler.store.keys {
                writeln!(w, "  alias \"{}\":", alias).unwrap();
                writeln!(w, "    public: {}", keypair.public).unwrap();
                if args.show_secret {
                    writeln!(w, "    secret: {}", keypair.secret).unwrap();
                }
            }
        }
        Err(error) => println!("{}", error),
    }
}

enum ConfirmationResponse {
    Overwrite,
    Cancel,
}

fn insert_keypair_into_store(handler: &mut StoreHandler, alias: Option<Alias>) {
    println!(
        "Creating keypair and address with {} as alias",
        alias.as_ref().unwrap_or(&"its public key hash".to_string())
    );

    match handler.store.insert_new_keypair(alias) {
        None => handler.save().unwrap(),
        Some(_) => match show_overwrite_confirmation() {
            ConfirmationResponse::Overwrite => {
                handler.save().unwrap();
                println!("Key and address overwritten successfully.");
            }
            _ => println!("Key creation cancelled."),
        },
    }
}

fn show_overwrite_confirmation() -> ConfirmationResponse {
    println!(
        "You're trying to create an alias that already exists in your store."
    );
    print!("Would you like to replace it? [y/N]: ");

    io::stdout().flush().unwrap();

    for byte in io::stdin().lock().bytes() {
        match byte.unwrap() {
            b'y' | b'Y' => return ConfirmationResponse::Overwrite,
            b'n' | b'N' | b'\n' => return ConfirmationResponse::Cancel,
            _ => {
                print!("Invalid option.");
                io::stdout().flush().unwrap();
                return show_overwrite_confirmation();
            }
        }
    }

    return ConfirmationResponse::Cancel;
}
