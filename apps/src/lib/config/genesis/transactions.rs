//! Genesis transactions

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::net::SocketAddr;

use borsh::{BorshDeserialize, BorshSerialize};
use borsh_ext::BorshSerializeExt;
use namada::core::types::address::Address;
use namada::core::types::string_encoding::StringEncoded;
use namada::proto::{
    standalone_signature, verify_standalone_sig, SerializeWithBorsh,
};
use namada::types::dec::Dec;
use namada::types::key::{common, RefTo, VerifySigError};
use namada::types::time::{DateTimeUtc, MIN_UTC};
use namada::types::token;
use namada::types::token::{DenominatedAmount, NATIVE_MAX_DECIMAL_PLACES};
use namada_sdk::wallet::alias::Alias;
use namada_sdk::wallet::pre_genesis::ValidatorWallet;
use namada_sdk::wallet::Wallet;
use serde::{Deserialize, Serialize};

use super::templates::{DenominatedBalances, Parameters, ValidityPredicates};
use crate::config::genesis::chain::DeriveEstablishedAddress;
use crate::config::genesis::templates::{
    TemplateValidation, Unvalidated, Validated,
};
use crate::config::genesis::GenesisAddress;
use crate::wallet::CliWalletUtils;

pub const PRE_GENESIS_TX_TIMESTAMP: DateTimeUtc = MIN_UTC;

pub struct GenesisValidatorData {
    pub commission_rate: Dec,
    pub max_commission_rate_change: Dec,
    pub net_address: SocketAddr,
    pub self_bond_amount: token::DenominatedAmount,
    pub email: String,
    pub description: Option<String>,
    pub website: Option<String>,
    pub discord_handle: Option<String>,
}

/// Panics if given `txs.validator_accounts` is not empty, because validator
/// transactions must be signed with a validator wallet (see
/// `init-genesis-validator` command).
pub fn sign_txs(
    txs: UnsignedTransactions,
    wallet: &mut Wallet<CliWalletUtils>,
) -> Transactions<Unvalidated> {
    let UnsignedTransactions {
        established_account,
        validator_account,
        bond,
    } = txs;

    // Validate input first
    if validator_account.is_some() && !validator_account.unwrap().is_empty() {
        panic!(
            "Validator transactions must be signed with a validator wallet."
        );
    }

    if let Some(bonds) = bond.as_ref() {
        for bond in bonds {
            if bond.source.address() == bond.validator {
                panic!(
                    "Validator self-bonds must be signed with a validator \
                     wallet."
                )
            }
        }
    }

    // Sign all the transactions
    let established_account = established_account.map(|tx| {
        tx.into_iter()
            .map(|tx| sign_established_account_tx(tx, wallet))
            .collect()
    });
    let validator_account = None;
    let bond = bond.map(|tx| {
        tx.into_iter()
            .map(|tx| sign_delegation_bond_tx(tx, wallet, &established_account))
            .collect()
    });

    Transactions {
        established_account,
        validator_account,
        bond,
    }
}

/// Parse [`UnsignedTransactions`] from bytes.
pub fn parse_unsigned(
    bytes: &[u8],
) -> Result<UnsignedTransactions, toml::de::Error> {
    toml::from_slice(bytes)
}

/// Create signed [`Transactions`] for a genesis validator.
pub fn init_validator(
    GenesisValidatorData {
        commission_rate,
        max_commission_rate_change,
        net_address,
        self_bond_amount,
        email,
        description,
        website,
        discord_handle,
    }: GenesisValidatorData,
    validator_wallet: &ValidatorWallet,
) -> Transactions<Unvalidated> {
    let unsigned_validator_account_tx = UnsignedValidatorAccountTx {
        account_key: StringEncoded::new(validator_wallet.account_key.ref_to()),
        consensus_key: StringEncoded::new(
            validator_wallet.consensus_key.ref_to(),
        ),
        protocol_key: StringEncoded::new(
            validator_wallet
                .store
                .validator_keys
                .protocol_keypair
                .ref_to(),
        ),
        tendermint_node_key: StringEncoded::new(
            validator_wallet.tendermint_node_key.ref_to(),
        ),

        eth_hot_key: StringEncoded::new(validator_wallet.eth_hot_key.ref_to()),
        eth_cold_key: StringEncoded::new(
            validator_wallet.eth_cold_key.ref_to(),
        ),
        // No custom validator VPs yet
        vp: "vp_validator".to_string(),
        commission_rate,
        max_commission_rate_change,
        email,
        description,
        website,
        discord_handle,
        net_address,
    };
    let unsigned_validator_addr =
        unsigned_validator_account_tx.derive_address();
    let unsigned_validator_established_addr =
        unsigned_validator_account_tx.derive_established_address();
    let validator_account = Some(vec![sign_validator_account_tx(
        unsigned_validator_account_tx,
        validator_wallet,
    )]);

    let bond = if self_bond_amount.amount.is_zero() {
        None
    } else {
        let unsigned_bond_tx = BondTx {
            source: GenesisAddress::EstablishedAddress(
                unsigned_validator_established_addr,
            ),
            validator: unsigned_validator_addr,
            amount: self_bond_amount,
        };
        let bond_tx = sign_self_bond_tx(unsigned_bond_tx, validator_wallet);
        Some(vec![bond_tx])
    };

    Transactions {
        validator_account,
        bond,
        ..Default::default()
    }
}

pub fn sign_established_account_tx(
    unsigned_tx: UnsignedEstablishedAccountTx,
    wallet: &mut Wallet<CliWalletUtils>,
) -> SignedEstablishedAccountTx {
    let key = unsigned_tx.public_key.as_ref().map(|pk| {
        let secret = wallet
            .find_key_by_pk(pk, None)
            .expect("Key for source must be present to sign with it.");
        let sig = sign_tx(&unsigned_tx, &secret);
        SignedPk {
            pk: pk.clone(),
            authorization: sig,
        }
    });
    let UnsignedEstablishedAccountTx { vp, public_key: _ } = unsigned_tx;

    SignedEstablishedAccountTx {
        vp,
        public_key: key,
    }
}

pub fn sign_validator_account_tx(
    unsigned_tx: UnsignedValidatorAccountTx,
    validator_wallet: &ValidatorWallet,
) -> SignedValidatorAccountTx {
    // Sign the tx with every validator key to authorize their usage
    let account_key_sig = sign_tx(&unsigned_tx, &validator_wallet.account_key);
    let consensus_key_sig =
        sign_tx(&unsigned_tx, &validator_wallet.consensus_key);
    let protocol_key_sig = sign_tx(
        &unsigned_tx,
        &validator_wallet.store.validator_keys.protocol_keypair,
    );
    let eth_hot_key_sig = sign_tx(&unsigned_tx, &validator_wallet.eth_hot_key);
    let eth_cold_key_sig =
        sign_tx(&unsigned_tx, &validator_wallet.eth_cold_key);
    let tendermint_node_key_sig =
        sign_tx(&unsigned_tx, &validator_wallet.tendermint_node_key);

    let ValidatorAccountTx {
        account_key,
        consensus_key,
        protocol_key,
        tendermint_node_key,
        vp,
        commission_rate,
        max_commission_rate_change,
        email,
        description,
        website,
        discord_handle,
        net_address,
        eth_hot_key,
        eth_cold_key,
    } = unsigned_tx;

    let account_key = SignedPk {
        pk: account_key,
        authorization: account_key_sig,
    };
    let consensus_key = SignedPk {
        pk: consensus_key,
        authorization: consensus_key_sig,
    };
    let protocol_key = SignedPk {
        pk: protocol_key,
        authorization: protocol_key_sig,
    };
    let tendermint_node_key = SignedPk {
        pk: tendermint_node_key,
        authorization: tendermint_node_key_sig,
    };

    let eth_hot_key = SignedPk {
        pk: eth_hot_key,
        authorization: eth_hot_key_sig,
    };

    let eth_cold_key = SignedPk {
        pk: eth_cold_key,
        authorization: eth_cold_key_sig,
    };

    SignedValidatorAccountTx {
        account_key,
        consensus_key,
        protocol_key,
        tendermint_node_key,
        vp,
        commission_rate,
        max_commission_rate_change,
        email,
        description,
        website,
        discord_handle,
        net_address,
        eth_hot_key,
        eth_cold_key,
    }
}

pub fn sign_self_bond_tx(
    unsigned_tx: BondTx<Unvalidated>,
    validator_wallet: &ValidatorWallet,
) -> SignedBondTx<Unvalidated> {
    unsigned_tx.sign(&validator_wallet.account_key)
}

pub fn sign_delegation_bond_tx(
    unsigned_tx: BondTx<Unvalidated>,
    wallet: &mut Wallet<CliWalletUtils>,
    established_accounts: &Option<Vec<EstablishedAccountTx<SignedPk>>>,
) -> SignedBondTx<Unvalidated> {
    let source_key =
        look_up_sk_from(&unsigned_tx.source, wallet, established_accounts);
    unsigned_tx.sign(&source_key)
}

pub fn sign_tx<T: BorshSerialize>(
    tx_data: &T,
    keypair: &common::SecretKey,
) -> StringEncoded<common::Signature> {
    StringEncoded::new(namada::proto::standalone_signature::<
        T,
        SerializeWithBorsh,
    >(keypair, tx_data))
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct Transactions<T: TemplateValidation> {
    pub established_account: Option<Vec<SignedEstablishedAccountTx>>,
    pub validator_account: Option<Vec<SignedValidatorAccountTx>>,
    pub bond: Option<Vec<T::BondTx>>,
}

impl<T: TemplateValidation> Transactions<T> {
    /// Take the union of two sets of transactions
    pub fn merge(&mut self, mut other: Self) {
        self.established_account = self
            .established_account
            .take()
            .map(|mut txs| {
                if let Some(new_txs) = other.established_account.as_mut() {
                    txs.append(new_txs);
                }
                txs
            })
            .or(other.established_account);
        self.validator_account = self
            .validator_account
            .take()
            .map(|mut txs| {
                if let Some(new_txs) = other.validator_account.as_mut() {
                    txs.append(new_txs);
                }
                txs
            })
            .or(other.validator_account);
        self.bond = self
            .bond
            .take()
            .map(|mut txs| {
                if let Some(new_txs) = other.bond.as_mut() {
                    txs.append(new_txs);
                }
                txs
            })
            .or(other.bond);
    }
}

impl<T: TemplateValidation> Default for Transactions<T> {
    fn default() -> Self {
        Self {
            established_account: None,
            validator_account: None,
            bond: None,
        }
    }
}

impl Transactions<Validated> {
    /// Check that there is at least one validator.
    pub fn has_at_least_one_validator(&self) -> bool {
        self.validator_account
            .as_ref()
            .map(|txs| !txs.is_empty())
            .unwrap_or_default()
    }

    /// Check if there is at least one validator with positive Tendermint voting
    /// power. The voting power is converted from `token::Amount` of the
    /// validator's stake using the `tm_votes_per_token` PoS parameter.
    pub fn has_validator_with_positive_voting_power(
        &self,
        votes_per_token: Dec,
    ) -> bool {
        self.bond
            .as_ref()
            .map(|txs| {
                let mut stakes: BTreeMap<&Address, token::Amount> =
                    BTreeMap::new();
                for tx in txs {
                    let entry = stakes.entry(&tx.validator).or_default();
                    *entry += tx.amount.amount;
                }

                stakes.into_values().any(|stake| {
                    let tendermint_voting_power =
                        namada::ledger::pos::into_tm_voting_power(
                            votes_per_token,
                            stake,
                        );
                    if tendermint_voting_power > 0 {
                        return true;
                    }
                    false
                })
            })
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UnsignedTransactions {
    pub established_account: Option<Vec<UnsignedEstablishedAccountTx>>,
    pub validator_account: Option<Vec<UnsignedValidatorAccountTx>>,
    pub bond: Option<Vec<BondTx<Unvalidated>>>,
}

pub type UnsignedValidatorAccountTx =
    ValidatorAccountTx<StringEncoded<common::PublicKey>>;

pub type SignedValidatorAccountTx = ValidatorAccountTx<SignedPk>;

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
)]
pub struct ValidatorAccountTx<PK> {
    pub vp: String,
    /// Commission rate charged on rewards for delegators (bounded inside
    /// 0-1)
    pub commission_rate: Dec,
    /// Maximum change in commission rate permitted per epoch
    pub max_commission_rate_change: Dec,
    /// Validator metadata
    pub email: String,
    pub description: Option<String>,
    pub website: Option<String>,
    pub discord_handle: Option<String>,
    /// P2P IP:port
    pub net_address: SocketAddr,
    /// PKs have to come last in TOML to avoid `ValueAfterTable` error
    pub account_key: PK,
    pub consensus_key: PK,
    pub protocol_key: PK,
    pub tendermint_node_key: PK,
    pub eth_hot_key: PK,
    pub eth_cold_key: PK,
}

impl DeriveEstablishedAddress for UnsignedValidatorAccountTx {
    const SALT: &'static str = "validator-account-tx";
}

pub type UnsignedEstablishedAccountTx =
    EstablishedAccountTx<StringEncoded<common::PublicKey>>;

pub type SignedEstablishedAccountTx = EstablishedAccountTx<SignedPk>;

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
)]
pub struct EstablishedAccountTx<PK> {
    pub vp: String,
    /// PKs have to come last in TOML to avoid `ValueAfterTable` error
    pub public_key: Option<PK>,
}

impl DeriveEstablishedAddress for UnsignedEstablishedAccountTx {
    const SALT: &'static str = "established-account-tx";
}

pub type SignedBondTx<T> = Signed<BondTx<T>>;

impl<T> SignedBondTx<T>
where
    T: BorshSerialize + TemplateValidation,
{
    /// Verify the signature of `BondTx`. This should not depend
    /// on whether the contained amount is denominated or not.
    ///
    /// Since we denominate amounts as part of validation, we can
    /// only verify signatures on [`SignedBondTx`]
    /// types.
    pub fn verify_sig(
        &self,
        pk: &common::PublicKey,
    ) -> Result<(), VerifySigError> {
        let Self { data, signature } = self;
        verify_standalone_sig::<_, SerializeWithBorsh>(
            &data.data_to_sign(),
            pk,
            signature,
        )
    }
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
)]
pub struct BondTx<T: TemplateValidation> {
    pub source: GenesisAddress,
    pub validator: Address,
    pub amount: T::Amount,
}

impl<T> BondTx<T>
where
    T: TemplateValidation + BorshSerialize,
{
    /// The signable data. This does not include the phantom data.
    fn data_to_sign(&self) -> Vec<u8> {
        [
            self.source.serialize_to_vec(),
            self.validator.serialize_to_vec(),
            self.amount.serialize_to_vec(),
        ]
        .concat()
    }
}

impl BondTx<Unvalidated> {
    /// Add the correct denomination to the contained amount
    pub fn denominate(self) -> eyre::Result<BondTx<Validated>> {
        let BondTx {
            source,
            validator,
            amount,
        } = self;
        let amount = amount
            .increase_precision(NATIVE_MAX_DECIMAL_PLACES.into())
            .map_err(|e| {
                eprintln!(
                    "A bond amount in the transactions.toml file was \
                     incorrectly formatted:\n{}",
                    e
                );
                e
            })?;
        Ok(BondTx {
            source,
            validator,
            amount,
        })
    }

    /// Sign the transfer.
    ///
    /// Since we denominate amounts as part of validation, we can
    /// only verify signatures on [`SignedBondTx`]
    /// types. Thus we only allow signing of [`BondTx<Unvalidated>`]
    /// types.
    pub fn sign(self, key: &common::SecretKey) -> SignedBondTx<Unvalidated> {
        let sig = standalone_signature::<_, SerializeWithBorsh>(
            key,
            &self.data_to_sign(),
        );
        SignedBondTx {
            data: self,
            signature: StringEncoded { raw: sig },
        }
    }
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
)]
pub struct Signed<T> {
    #[serde(flatten)]
    pub data: T,
    pub signature: StringEncoded<common::Signature>,
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
)]
pub struct SignedPk {
    pub pk: StringEncoded<common::PublicKey>,
    pub authorization: StringEncoded<common::Signature>,
}

pub fn validate(
    transactions: Transactions<Unvalidated>,
    vps: Option<&ValidityPredicates>,
    balances: Option<&DenominatedBalances>,
    parameters: Option<&Parameters<Validated>>,
) -> Option<Transactions<Validated>> {
    let mut is_valid = true;

    let mut all_used_addresses: BTreeSet<Address> = BTreeSet::default();
    let mut established_accounts: BTreeMap<Address, Option<common::PublicKey>> =
        BTreeMap::default();
    let mut validator_accounts: BTreeMap<Address, common::PublicKey> =
        BTreeMap::default();

    let Transactions {
        ref established_account,
        ref validator_account,
        bond,
    } = transactions;

    if let Some(txs) = established_account {
        for tx in txs {
            if !validate_established_account(
                tx,
                vps,
                &mut all_used_addresses,
                &mut established_accounts,
            ) {
                is_valid = false;
            }
        }
    }

    if let Some(txs) = validator_account {
        for tx in txs {
            if !validate_validator_account(
                tx,
                vps,
                &mut all_used_addresses,
                &mut validator_accounts,
            ) {
                is_valid = false;
            }
        }
    }

    // Make a mutable copy of the balances for tracking changes applied from txs
    let mut token_balances: BTreeMap<Alias, TokenBalancesForValidation> =
        balances
            .map(|balances| {
                balances
                    .token
                    .iter()
                    .map(|(token, token_balances)| {
                        (
                            token.clone(),
                            TokenBalancesForValidation {
                                amounts: token_balances.0.clone(),
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();

    let validated_bonds = if let Some(txs) = bond {
        if !txs.is_empty() {
            match parameters {
                Some(parameters) => {
                    let bond_number = txs.len();
                    let validated_bonds: Vec<_> = txs
                        .into_iter()
                        .filter_map(|tx| {
                            validate_bond(
                                tx,
                                &mut token_balances,
                                &established_accounts,
                                &validator_accounts,
                                parameters,
                            )
                        })
                        .collect();
                    if validated_bonds.len() != bond_number {
                        is_valid = false;
                        None
                    } else {
                        Some(validated_bonds)
                    }
                }
                None => {
                    eprintln!(
                        "Unable to validate bonds without a valid parameters \
                         file."
                    );
                    is_valid = false;
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    is_valid.then_some(Transactions {
        established_account: transactions.established_account.map(
            |established_accounts| {
                established_accounts
                    .into_iter()
                    .map(|acct| EstablishedAccountTx {
                        vp: acct.vp,
                        public_key: acct.public_key,
                    })
                    .collect()
            },
        ),
        validator_account: transactions.validator_account.map(
            |validator_accounts| {
                validator_accounts
                    .into_iter()
                    .map(|acct| ValidatorAccountTx {
                        vp: acct.vp,
                        commission_rate: acct.commission_rate,
                        max_commission_rate_change: acct
                            .max_commission_rate_change,
                        email: acct.email,
                        description: acct.description,
                        website: acct.website,
                        discord_handle: acct.discord_handle,
                        net_address: acct.net_address,
                        account_key: acct.account_key,
                        consensus_key: acct.consensus_key,
                        protocol_key: acct.protocol_key,
                        tendermint_node_key: acct.tendermint_node_key,
                        eth_hot_key: acct.eth_hot_key,
                        eth_cold_key: acct.eth_cold_key,
                    })
                    .collect()
            },
        ),
        bond: validated_bonds,
    })
}

fn validate_bond(
    tx: SignedBondTx<Unvalidated>,
    balances: &mut BTreeMap<Alias, TokenBalancesForValidation>,
    established_accounts: &BTreeMap<Address, Option<common::PublicKey>>,
    validator_accounts: &BTreeMap<Address, common::PublicKey>,
    parameters: &Parameters<Validated>,
) -> Option<BondTx<Validated>> {
    // Check signature
    let mut is_valid = {
        let source = &tx.data.source;
        if let Some(source_pk) = match source {
            GenesisAddress::EstablishedAddress(address) => {
                // Try to find the source's PK in either established_accounts or
                // validator_accounts
                let established_addr = Address::Established(address.clone());
                established_accounts
                    .get(&established_addr)
                    .cloned()
                    .flatten()
                    .or_else(|| {
                        validator_accounts.get(&established_addr).cloned()
                    })
            }
            GenesisAddress::PublicKey(pk) => Some(pk.raw.clone()),
        } {
            if tx.verify_sig(&source_pk).is_err() {
                eprintln!("Invalid bond tx signature.",);
                false
            } else {
                true
            }
        } else {
            eprintln!(
                "Invalid bond tx. Couldn't verify bond's signature, because \
                 the source accounts \"{source}\" public key cannot be found."
            );
            false
        }
    };

    // Make sure the native token amount is denominated correctly
    let validated_bond = tx.data.denominate().ok()?;
    let BondTx {
        source,
        validator,
        amount,
        ..
    } = &validated_bond;

    // Check that the validator exists
    if !validator_accounts.contains_key(validator) {
        eprintln!(
            "Invalid bond tx. The target validator \"{validator}\" account \
             not found."
        );
        is_valid = false;
    }

    // Check and update token balance of the source
    let native_token = &parameters.parameters.native_token;
    match balances.get_mut(native_token) {
        Some(balances) => {
            let balance = balances.amounts.get_mut(source);
            match balance {
                Some(balance) => {
                    if *balance < *amount {
                        eprintln!(
                            "Invalid bond tx. Source {source} doesn't have \
                             enough balance of token \"{native_token}\" to \
                             transfer {}. Got {}.",
                            amount, balance,
                        );
                        is_valid = false;
                    } else {
                        // Deduct the amount from source
                        if amount == balance {
                            balances.amounts.remove(source);
                        } else {
                            balance.amount -= amount.amount;
                        }
                    }
                }
                None => {
                    eprintln!(
                        "Invalid transfer tx. Source {source} has no balance \
                         of token \"{native_token}\"."
                    );
                    is_valid = false;
                }
            }
        }
        None => {
            eprintln!(
                "Invalid bond tx. Token \"{native_token}\" not found in \
                 balances."
            );
            is_valid = false;
        }
    }

    is_valid.then_some(validated_bond)
}

#[derive(Clone, Debug)]
pub struct TokenBalancesForValidation {
    /// Accumulator for tokens transferred to accounts
    pub amounts: BTreeMap<GenesisAddress, DenominatedAmount>,
}

pub fn validate_established_account(
    tx: &SignedEstablishedAccountTx,
    vps: Option<&ValidityPredicates>,
    all_used_addresses: &mut BTreeSet<Address>,
    established_accounts: &mut BTreeMap<Address, Option<common::PublicKey>>,
) -> bool {
    let mut is_valid = true;

    let established_address = EstablishedAccountTx::from(tx).derive_address();
    established_accounts.insert(
        established_address.clone(),
        tx.public_key.as_ref().map(|signed| signed.pk.raw.clone()),
    );

    // Check that the established address is unique
    if all_used_addresses.contains(&established_address) {
        eprintln!(
            "A duplicate address \"{}\" found in a `established_account` tx.",
            established_address
        );
        is_valid = false;
    } else {
        all_used_addresses.insert(established_address);
    }

    // Check the VP exists
    if !vps
        .map(|vps| vps.wasm.contains_key(&tx.vp))
        .unwrap_or_default()
    {
        eprintln!(
            "An `established_account` tx `vp` \"{}\" not found in Validity \
             predicates file.",
            tx.vp
        );
        is_valid = false;
    }

    // If PK is used, check the authorization
    if let Some(pk) = tx.public_key.as_ref() {
        if !validate_established_account_sig(pk, tx) {
            is_valid = false;
        }
    }

    is_valid
}

fn validate_established_account_sig(
    SignedPk { pk, authorization }: &SignedPk,
    tx: &SignedEstablishedAccountTx,
) -> bool {
    let unsigned = UnsignedEstablishedAccountTx::from(tx);
    validate_signature(&unsigned, &pk.raw, &authorization.raw)
}

pub fn validate_validator_account(
    tx: &ValidatorAccountTx<SignedPk>,
    vps: Option<&ValidityPredicates>,
    all_used_addresses: &mut BTreeSet<Address>,
    validator_accounts: &mut BTreeMap<Address, common::PublicKey>,
) -> bool {
    let mut is_valid = true;

    let established_address = ValidatorAccountTx::from(tx).derive_address();
    validator_accounts
        .insert(established_address.clone(), tx.account_key.pk.raw.clone());

    // Check that address is unique
    if all_used_addresses.contains(&established_address) {
        eprintln!(
            "A duplicate address \"{}\" found in a `validator_account` tx.",
            established_address
        );
        is_valid = false;
    } else {
        all_used_addresses.insert(established_address.clone());
    }

    // Check the VP exists
    if !vps
        .map(|vps| vps.wasm.contains_key(&tx.vp))
        .unwrap_or_default()
    {
        eprintln!(
            "A `validator_account` tx `vp` \"{}\" not found in Validity \
             predicates file.",
            tx.vp
        );
        is_valid = false;
    }

    // Check keys authorizations
    let unsigned = UnsignedValidatorAccountTx::from(tx);
    if !validate_signature(
        &unsigned,
        &tx.account_key.pk.raw,
        &tx.account_key.authorization.raw,
    ) {
        eprintln!(
            "Invalid `account_key` authorization for `validator_account` tx \
             with address \"{}\".",
            established_address
        );
        is_valid = false;
    }
    if !validate_signature(
        &unsigned,
        &tx.consensus_key.pk.raw,
        &tx.consensus_key.authorization.raw,
    ) {
        eprintln!(
            "Invalid `consensus_key` authorization for `validator_account` tx \
             with address \"{}\".",
            established_address
        );
        is_valid = false;
    }
    if !validate_signature(
        &unsigned,
        &tx.protocol_key.pk.raw,
        &tx.protocol_key.authorization.raw,
    ) {
        eprintln!(
            "Invalid `protocol_key` authorization for `validator_account` tx \
             with address \"{}\".",
            established_address
        );
        is_valid = false;
    }
    if !validate_signature(
        &unsigned,
        &tx.tendermint_node_key.pk.raw,
        &tx.tendermint_node_key.authorization.raw,
    ) {
        eprintln!(
            "Invalid `tendermint_node_key` authorization for \
             `validator_account` tx with address \"{}\".",
            established_address
        );
        is_valid = false;
    }

    if !validate_signature(
        &unsigned,
        &tx.eth_hot_key.pk.raw,
        &tx.eth_hot_key.authorization.raw,
    ) {
        eprintln!(
            "Invalid `eth_hot_key` authorization for `validator_account` tx \
             with address \"{}\".",
            established_address
        );
        is_valid = false;
    }

    if !validate_signature(
        &unsigned,
        &tx.eth_cold_key.pk.raw,
        &tx.eth_cold_key.authorization.raw,
    ) {
        eprintln!(
            "Invalid `eth_cold_key` authorization for `validator_account` tx \
             with address \"{}\".",
            established_address
        );
        is_valid = false;
    }

    is_valid
}

fn validate_signature<T: BorshSerialize + Debug>(
    tx_data: &T,
    pk: &common::PublicKey,
    sig: &common::Signature,
) -> bool {
    match verify_standalone_sig::<T, SerializeWithBorsh>(tx_data, pk, sig) {
        Ok(()) => true,
        Err(err) => {
            eprintln!(
                "Invalid tx signature in tx {tx_data:?}, failed with: {err}."
            );
            false
        }
    }
}

impl From<&SignedEstablishedAccountTx> for UnsignedEstablishedAccountTx {
    fn from(tx: &SignedEstablishedAccountTx) -> Self {
        let SignedEstablishedAccountTx { vp, public_key } = tx;
        Self {
            vp: vp.clone(),
            public_key: public_key.as_ref().map(|signed| signed.pk.clone()),
        }
    }
}

impl From<&SignedValidatorAccountTx> for UnsignedValidatorAccountTx {
    fn from(tx: &SignedValidatorAccountTx) -> Self {
        let SignedValidatorAccountTx {
            vp,
            commission_rate,
            max_commission_rate_change,
            email,
            description,
            website,
            discord_handle,
            net_address,
            account_key,
            consensus_key,
            protocol_key,
            tendermint_node_key,
            eth_hot_key,
            eth_cold_key,
            ..
        } = tx;

        Self {
            vp: vp.clone(),
            commission_rate: *commission_rate,
            max_commission_rate_change: *max_commission_rate_change,
            email: email.clone(),
            description: description.clone(),
            website: website.clone(),
            discord_handle: discord_handle.clone(),
            net_address: *net_address,
            account_key: account_key.pk.clone(),
            consensus_key: consensus_key.pk.clone(),
            protocol_key: protocol_key.pk.clone(),
            tendermint_node_key: tendermint_node_key.pk.clone(),
            eth_hot_key: eth_hot_key.pk.clone(),
            eth_cold_key: eth_cold_key.pk.clone(),
        }
    }
}

impl From<&SignedBondTx<Unvalidated>> for BondTx<Unvalidated> {
    fn from(tx: &SignedBondTx<Unvalidated>) -> Self {
        let SignedBondTx { data, .. } = tx;
        data.clone()
    }
}

/// Attempt to look-up a secret key.
fn look_up_sk_from(
    source: &GenesisAddress,
    wallet: &mut Wallet<CliWalletUtils>,
    established_accounts: &Option<Vec<EstablishedAccountTx<SignedPk>>>,
) -> common::SecretKey {
    // Try to look-up the source from wallet first
    match source {
        GenesisAddress::EstablishedAddress(_) => None,
        GenesisAddress::PublicKey(pk) => wallet.find_key_by_pk(pk, None).ok(),
    }
    .unwrap_or_else(|| {
        // If it's not in the wallet, it must be an established account
        // so we need to look-up its public key first
        let pk = established_accounts
            .as_ref()
            .unwrap_or_else(|| {
                panic!(
                    "Signing failed. Cannot find \"{source}\" in the wallet \
                     and there are no established accounts."
                );
            })
            .iter()
            .find_map(|account| match source {
                GenesisAddress::EstablishedAddress(address) => {
                    // delegation from established account
                    if &EstablishedAccountTx::from(account)
                        .derive_established_address()
                        == address
                    {
                        Some(
                            &account
                                .public_key
                                .as_ref()
                                .unwrap_or_else(|| {
                                    panic!(
                                        "Signing failed. The established \
                                         account \"{source}\" has no public \
                                         key. Add a public to be able to sign \
                                         bonds."
                                    );
                                })
                                .pk
                                .raw,
                        )
                    } else {
                        None
                    }
                }
                GenesisAddress::PublicKey(pk) => {
                    // delegation from an implicit account
                    Some(&pk.raw)
                }
            })
            .unwrap_or_else(|| {
                panic!(
                    "Signing failed. Cannot find \"{source}\" in the wallet \
                     or in the established accounts."
                );
            });
        wallet.find_key_by_pk(pk, None).unwrap_or_else(|err| {
            panic!(
                "Signing failed. Cannot find key for established account \
                 \"{source}\" in the wallet. Failed with {err}."
            );
        })
    })
}
