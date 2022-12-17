use serde::{Deserialize, Serialize};
use crate::types::key::*;
use crate::types::masp::{
    ExtendedSpendingKey, ExtendedViewingKey, PaymentAddress,
};
use std::collections::HashMap;
use super::alias::{self, Alias};
use crate::types::address::{Address, ImplicitAddress};
use bimap::BiHashMap;
use crate::types::key::dkg_session_keys::DkgKeypair;
use masp_primitives::zip32::ExtendedFullViewingKey;
use std::str::FromStr;
use crate::ledger::wallet::WalletUtils;
use std::marker::PhantomData;
#[cfg(feature = "masp-tx-gen")]
use rand_core::RngCore;

use super::pre_genesis;
use crate::ledger::wallet::{store, StoredKeypair};

pub enum ConfirmationResponse {
    Replace,
    Reselect(Alias),
    Skip,
}

/// Special keys for a validator
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ValidatorKeys {
    /// Special keypair for signing protocol txs
    pub protocol_keypair: common::SecretKey,
    /// Special session keypair needed by validators for participating
    /// in the DKG protocol
    pub dkg_keypair: Option<DkgKeypair>,
}

impl ValidatorKeys {
    /// Get the protocol keypair
    pub fn get_protocol_keypair(&self) -> &common::SecretKey {
        &self.protocol_keypair
    }
}

/// Special data associated with a validator
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ValidatorData {
    /// The address associated to a validator
    pub address: Address,
    /// special keys for a validator
    pub keys: ValidatorKeys,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Store {
    /// Known viewing keys
    view_keys: HashMap<Alias, ExtendedViewingKey>,
    /// Known spending keys
    spend_keys: HashMap<Alias, StoredKeypair<ExtendedSpendingKey>>,
    /// Known payment addresses
    payment_addrs: HashMap<Alias, PaymentAddress>,
    /// Cryptographic keypairs
    keys: HashMap<Alias, StoredKeypair<common::SecretKey>>,
    /// Anoma address book
    addresses: BiHashMap<Alias, Address>,
    /// Known mappings of public key hashes to their aliases in the `keys`
    /// field. Used for look-up by a public key.
    pkhs: HashMap<PublicKeyHash, Alias>,
    /// Special keys if the wallet belongs to a validator
    pub(crate) validator_data: Option<ValidatorData>,
}

impl Store {
    /// Find the stored key by an alias, a public key hash or a public key.
    pub fn find_key(
        &self,
        alias_pkh_or_pk: impl AsRef<str>,
    ) -> Option<&StoredKeypair<common::SecretKey>> {
        let alias_pkh_or_pk = alias_pkh_or_pk.as_ref();
        // Try to find by alias
        self.keys
            .get(&alias_pkh_or_pk.into())
            // Try to find by PKH
            .or_else(|| {
                let pkh = PublicKeyHash::from_str(alias_pkh_or_pk).ok()?;
                self.find_key_by_pkh(&pkh)
            })
            // Try to find by PK
            .or_else(|| {
                let pk = common::PublicKey::from_str(alias_pkh_or_pk).ok()?;
                self.find_key_by_pk(&pk)
            })
    }

    pub fn find_spending_key(
        &self,
        alias: impl AsRef<str>,
    ) -> Option<&StoredKeypair<ExtendedSpendingKey>> {
        self.spend_keys.get(&alias.into())
    }

    pub fn find_viewing_key(
        &self,
        alias: impl AsRef<str>,
    ) -> Option<&ExtendedViewingKey> {
        self.view_keys.get(&alias.into())
    }

    pub fn find_payment_addr(
        &self,
        alias: impl AsRef<str>,
    ) -> Option<&PaymentAddress> {
        self.payment_addrs.get(&alias.into())
    }

    /// Find the stored key by a public key.
    pub fn find_key_by_pk(
        &self,
        pk: &common::PublicKey,
    ) -> Option<&StoredKeypair<common::SecretKey>> {
        let pkh = PublicKeyHash::from(pk);
        self.find_key_by_pkh(&pkh)
    }

    /// Find the stored key by a public key hash.
    pub fn find_key_by_pkh(
        &self,
        pkh: &PublicKeyHash,
    ) -> Option<&StoredKeypair<common::SecretKey>> {
        let alias = self.pkhs.get(pkh)?;
        self.keys.get(alias)
    }

    /// Find the stored alias for a public key hash.
    pub fn find_alias_by_pkh(&self, pkh: &PublicKeyHash) -> Option<Alias> {
        self.pkhs.get(pkh).cloned()
    }

    /// Find the stored address by an alias.
    pub fn find_address(&self, alias: impl AsRef<str>) -> Option<&Address> {
        self.addresses.get_by_left(&alias.into())
    }

    /// Find an alias by the address if it's in the wallet.
    pub fn find_alias(&self, address: &Address) -> Option<&Alias> {
        self.addresses.get_by_right(address)
    }

    /// Get all known keys by their alias, paired with PKH, if known.
    pub fn get_keys(
        &self,
    ) -> HashMap<
        Alias,
        (&StoredKeypair<common::SecretKey>, Option<&PublicKeyHash>),
    > {
        let mut keys: HashMap<
            Alias,
            (&StoredKeypair<common::SecretKey>, Option<&PublicKeyHash>),
        > = self
            .pkhs
            .iter()
            .filter_map(|(pkh, alias)| {
                let key = &self.keys.get(alias)?;
                Some((alias.clone(), (*key, Some(pkh))))
            })
            .collect();
        self.keys.iter().for_each(|(alias, key)| {
            if !keys.contains_key(alias) {
                keys.insert(alias.clone(), (key, None));
            }
        });
        keys
    }

    /// Get all known addresses by their alias, paired with PKH, if known.
    pub fn get_addresses(&self) -> &BiHashMap<Alias, Address> {
        &self.addresses
    }

    /// Get all known payment addresses by their alias.
    pub fn get_payment_addrs(&self) -> &HashMap<Alias, PaymentAddress> {
        &self.payment_addrs
    }

    /// Get all known viewing keys by their alias.
    pub fn get_viewing_keys(&self) -> &HashMap<Alias, ExtendedViewingKey> {
        &self.view_keys
    }

    /// Get all known spending keys by their alias.
    pub fn get_spending_keys(
        &self,
    ) -> &HashMap<Alias, StoredKeypair<ExtendedSpendingKey>> {
        &self.spend_keys
    }

    #[cfg(feature = "masp-tx-gen")]
    fn generate_spending_key() -> ExtendedSpendingKey {
        use rand::rngs::OsRng;
        let mut spend_key = [0; 32];
        OsRng.fill_bytes(&mut spend_key);
        masp_primitives::zip32::ExtendedSpendingKey::master(spend_key.as_ref())
            .into()
    }

    /// Generate a new keypair and insert it into the store with the provided
    /// alias. If none provided, the alias will be the public key hash.
    /// If no password is provided, the keypair will be stored raw without
    /// encryption. Returns the alias of the key and a reference-counting
    /// pointer to the key.
    pub fn gen_key<U: WalletUtils>(
        &mut self,
        scheme: SchemeType,
        alias: Option<String>,
        password: Option<String>,
    ) -> (Alias, common::SecretKey) {
        let sk = gen_sk(scheme);
        let pkh: PublicKeyHash = PublicKeyHash::from(&sk.ref_to());
        let (keypair_to_store, raw_keypair) = StoredKeypair::new(sk, password);
        let address = Address::Implicit(ImplicitAddress(pkh.clone()));
        let alias: Alias = alias.unwrap_or_else(|| pkh.clone().into()).into();
        if self
            .insert_keypair::<U>(alias.clone(), keypair_to_store, pkh)
            .is_none()
        {
            panic!("Action cancelled, no changes persisted.");
        }
        if self.insert_address::<U>(alias.clone(), address).is_none() {
            panic!("Action cancelled, no changes persisted.");
        }
        (alias, raw_keypair)
    }

    /// Generate a spending key similarly to how it's done for keypairs
    pub fn gen_spending_key<U: WalletUtils>(
        &mut self,
        alias: String,
        password: Option<String>,
    ) -> (Alias, ExtendedSpendingKey) {
        let spendkey = Self::generate_spending_key();
        let viewkey = ExtendedFullViewingKey::from(&spendkey.into()).into();
        let (spendkey_to_store, _raw_spendkey) =
            StoredKeypair::new(spendkey, password);
        let alias = Alias::from(alias);
        if self
            .insert_spending_key::<U>(alias.clone(), spendkey_to_store, viewkey)
            .is_none()
        {
            panic!("Action cancelled, no changes persisted.");
        }
        (alias, spendkey)
    }

    /// Add validator data to the store
    pub fn add_validator_data(
        &mut self,
        address: Address,
        keys: ValidatorKeys,
    ) {
        self.validator_data = Some(ValidatorData { address, keys });
    }

    /// Returns the validator data, if it exists
    pub fn get_validator_data(&self) -> Option<&ValidatorData> {
        self.validator_data.as_ref()
    }

    /// Returns the validator data, if it exists
    pub fn validator_data(&mut self) -> Option<&mut ValidatorData> {
        self.validator_data.as_mut()
    }

    /// Insert a new key with the given alias. If the alias is already used,
    /// will prompt for overwrite/reselection confirmation. If declined, then
    /// keypair is not inserted and nothing is returned, otherwise selected
    /// alias is returned.
    pub fn insert_keypair<U: WalletUtils>(
        &mut self,
        alias: Alias,
        keypair: StoredKeypair<common::SecretKey>,
        pkh: PublicKeyHash,
    ) -> Option<Alias> {
        if alias.is_empty() {
            println!(
                "Empty alias given, defaulting to {}.",
                Into::<Alias>::into(pkh.to_string())
            );
        }
        // Addresses and keypairs can share aliases, so first remove any
        // addresses sharing the same namesake before checking if alias has been
        // used.
        let counterpart_address = self.addresses.remove_by_left(&alias);
        if self.contains_alias(&alias) {
            match U::show_overwrite_confirmation(&alias, "a key") {
                ConfirmationResponse::Replace => {}
                ConfirmationResponse::Reselect(new_alias) => {
                    // Restore the removed address in case the recursive prompt
                    // terminates with a cancellation
                    counterpart_address
                        .map(|x| self.addresses.insert(alias.clone(), x.1));
                    return self.insert_keypair::<U>(new_alias, keypair, pkh);
                }
                ConfirmationResponse::Skip => {
                    // Restore the removed address since this insertion action
                    // has now been cancelled
                    counterpart_address
                        .map(|x| self.addresses.insert(alias.clone(), x.1));
                    return None;
                }
            }
        }
        self.remove_alias(&alias);
        self.keys.insert(alias.clone(), keypair);
        self.pkhs.insert(pkh, alias.clone());
        // Since it is intended for the inserted keypair to share its namesake
        // with the pre-existing address
        counterpart_address.map(|x| self.addresses.insert(alias.clone(), x.1));
        Some(alias)
    }

    /// Insert spending keys similarly to how it's done for keypairs
    pub fn insert_spending_key<U: WalletUtils>(
        &mut self,
        alias: Alias,
        spendkey: StoredKeypair<ExtendedSpendingKey>,
        viewkey: ExtendedViewingKey,
    ) -> Option<Alias> {
        if alias.is_empty() {
            eprintln!("Empty alias given.");
            return None;
        }
        if self.contains_alias(&alias) {
            match U::show_overwrite_confirmation(&alias, "a spending key") {
                ConfirmationResponse::Replace => {}
                ConfirmationResponse::Reselect(new_alias) => {
                    return self
                        .insert_spending_key::<U>(new_alias, spendkey, viewkey);
                }
                ConfirmationResponse::Skip => return None,
            }
        }
        self.remove_alias(&alias);
        self.spend_keys.insert(alias.clone(), spendkey);
        // Simultaneously add the derived viewing key to ease balance viewing
        self.view_keys.insert(alias.clone(), viewkey);
        Some(alias)
    }

    /// Insert viewing keys similarly to how it's done for keypairs
    pub fn insert_viewing_key<U: WalletUtils>(
        &mut self,
        alias: Alias,
        viewkey: ExtendedViewingKey,
    ) -> Option<Alias> {
        if alias.is_empty() {
            eprintln!("Empty alias given.");
            return None;
        }
        if self.contains_alias(&alias) {
            match U::show_overwrite_confirmation(&alias, "a viewing key") {
                ConfirmationResponse::Replace => {}
                ConfirmationResponse::Reselect(new_alias) => {
                    return self.insert_viewing_key::<U>(new_alias, viewkey);
                }
                ConfirmationResponse::Skip => return None,
            }
        }
        self.remove_alias(&alias);
        self.view_keys.insert(alias.clone(), viewkey);
        Some(alias)
    }

    /// Check if any map of the wallet contains the given alias
    fn contains_alias(&self, alias: &Alias) -> bool {
        self.payment_addrs.contains_key(alias)
            || self.view_keys.contains_key(alias)
            || self.spend_keys.contains_key(alias)
            || self.keys.contains_key(alias)
            || self.addresses.contains_left(alias)
    }

    /// Completely remove the given alias from all maps in the wallet
    fn remove_alias(&mut self, alias: &Alias) {
        self.payment_addrs.remove(alias);
        self.view_keys.remove(alias);
        self.spend_keys.remove(alias);
        self.keys.remove(alias);
        self.addresses.remove_by_left(alias);
        self.pkhs.retain(|_key, val| val != alias);
    }

    /// Insert payment addresses similarly to how it's done for keypairs
    pub fn insert_payment_addr<U: WalletUtils>(
        &mut self,
        alias: Alias,
        payment_addr: PaymentAddress,
    ) -> Option<Alias> {
        if alias.is_empty() {
            eprintln!("Empty alias given.");
            return None;
        }
        if self.contains_alias(&alias) {
            match U::show_overwrite_confirmation(&alias, "a payment address") {
                ConfirmationResponse::Replace => {}
                ConfirmationResponse::Reselect(new_alias) => {
                    return self.insert_payment_addr::<U>(new_alias, payment_addr);
                }
                ConfirmationResponse::Skip => return None,
            }
        }
        self.remove_alias(&alias);
        self.payment_addrs.insert(alias.clone(), payment_addr);
        Some(alias)
    }

    /// Helper function to restore keypair given alias-keypair mapping and the
    /// pkhs-alias mapping.
    fn restore_keypair(
        &mut self,
        alias: Alias,
        key: Option<StoredKeypair<common::SecretKey>>,
        pkh: Option<PublicKeyHash>,
    ) {
        key.map(|x| self.keys.insert(alias.clone(), x));
        pkh.map(|x| self.pkhs.insert(x, alias.clone()));
    }

    /// Insert a new address with the given alias. If the alias is already used,
    /// will prompt for overwrite/reselection confirmation, which when declined,
    /// the address won't be added. Return the selected alias if the address has
    /// been added.
    pub fn insert_address<U: WalletUtils>(
        &mut self,
        alias: Alias,
        address: Address,
    ) -> Option<Alias> {
        if alias.is_empty() {
            println!("Empty alias given, defaulting to {}.", address.encode());
        }
        // Addresses and keypairs can share aliases, so first remove any keys
        // sharing the same namesake before checking if alias has been used.
        let counterpart_key = self.keys.remove(&alias);
        let mut counterpart_pkh = None;
        self.pkhs.retain(|k, v| {
            if v == &alias {
                counterpart_pkh = Some(k.clone());
                false
            } else {
                true
            }
        });
        if self.addresses.contains_left(&alias) {
            match U::show_overwrite_confirmation(&alias, "an address") {
                ConfirmationResponse::Replace => {}
                ConfirmationResponse::Reselect(new_alias) => {
                    // Restore the removed keypair in case the recursive prompt
                    // terminates with a cancellation
                    self.restore_keypair(
                        alias,
                        counterpart_key,
                        counterpart_pkh,
                    );
                    return self.insert_address::<U>(new_alias, address);
                }
                ConfirmationResponse::Skip => {
                    // Restore the removed keypair since this insertion action
                    // has now been cancelled
                    self.restore_keypair(
                        alias,
                        counterpart_key,
                        counterpart_pkh,
                    );
                    return None;
                }
            }
        }
        self.remove_alias(&alias);
        self.addresses.insert(alias.clone(), address);
        // Since it is intended for the inserted address to share its namesake
        // with the pre-existing keypair
        self.restore_keypair(alias.clone(), counterpart_key, counterpart_pkh);
        Some(alias)
    }

    /// Extend this store from pre-genesis validator wallet.
    pub fn extend_from_pre_genesis_validator(
        &mut self,
        validator_address: Address,
        validator_alias: Alias,
        other: pre_genesis::ValidatorWallet,
    ) {
        let account_key_alias = alias::validator_key(&validator_alias);
        let consensus_key_alias =
            alias::validator_consensus_key(&validator_alias);
        let tendermint_node_key_alias =
            alias::validator_tendermint_node_key(&validator_alias);

        let keys = [
            (account_key_alias.clone(), other.store.account_key),
            (consensus_key_alias.clone(), other.store.consensus_key),
            (
                tendermint_node_key_alias.clone(),
                other.store.tendermint_node_key,
            ),
        ];
        self.keys.extend(keys.into_iter());

        let account_pk = other.account_key.ref_to();
        let consensus_pk = other.consensus_key.ref_to();
        let tendermint_node_pk = other.tendermint_node_key.ref_to();
        let addresses = [
            (account_key_alias.clone(), (&account_pk).into()),
            (consensus_key_alias.clone(), (&consensus_pk).into()),
            (
                tendermint_node_key_alias.clone(),
                (&tendermint_node_pk).into(),
            ),
        ];
        self.addresses.extend(addresses.into_iter());

        let pkhs = [
            ((&account_pk).into(), account_key_alias),
            ((&consensus_pk).into(), consensus_key_alias),
            ((&tendermint_node_pk).into(), tendermint_node_key_alias),
        ];
        self.pkhs.extend(pkhs.into_iter());

        self.validator_data = Some(ValidatorData {
            address: validator_address,
            keys: other.store.validator_keys,
        });
    }

    pub fn decode(data: Vec<u8>) -> Result<Self, toml::de::Error> {
        toml::from_slice(&data)
    }

    pub fn encode(&self) -> Vec<u8> {
        toml::to_vec(self).expect("Serializing of store shouldn't fail")
    }
}

/// Generate a new secret key.
pub fn gen_sk(scheme: SchemeType) -> common::SecretKey {
    use rand::rngs::OsRng;
    let mut csprng = OsRng {};
    match scheme {
        SchemeType::Ed25519 => ed25519::SigScheme::generate(&mut csprng)
            .try_to_sk()
            .unwrap(),
        SchemeType::Secp256k1 => secp256k1::SigScheme::generate(&mut csprng)
            .try_to_sk()
            .unwrap(),
        SchemeType::Common => common::SigScheme::generate(&mut csprng)
            .try_to_sk()
            .unwrap(),
    }
}
