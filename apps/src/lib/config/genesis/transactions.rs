//! Genesis transactions

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Display, Formatter};
use std::net::SocketAddr;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use namada::core::types::string_encoding::StringEncoded;
use namada::proto::Tx;
use namada::types::key::dkg_session_keys::DkgPublicKey;
use namada::types::key::{common, RefTo};
use namada::types::time::{DateTimeUtc, MIN_UTC};
use namada::types::token;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use super::templates::{
    Balances, Parameters, TokenBalances, ValidityPredicates,
};
use crate::wallet::pre_genesis::ValidatorWallet;
use crate::wallet::{Alias, FindKeyError, Wallet};

pub const PRE_GENESIS_TX_TIMESTAMP: DateTimeUtc = MIN_UTC;

pub struct GenesisValidatorData {
    pub source_key: common::SecretKey,
    pub alias: Alias,
    pub commission_rate: Decimal,
    pub max_commission_rate_change: Decimal,
    pub net_address: SocketAddr,
    pub transfer_from_source_amount: token::Amount,
    pub self_bond_amount: token::Amount,
}

/// Panics if given `txs.validator_accounts` is not empty, because validator
/// transactions must be signed with a validator wallet (see
/// `init-genesis-validator` command).
pub fn sign_txs(
    txs: UnsignedTransactions,
    wallet: &mut Wallet,
) -> Transactions {
    let UnsignedTransactions {
        established_account,
        validator_account,
        transfer,
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
            if let AliasOrPk::Alias(source) = &bond.source {
                if source == &bond.validator {
                    panic!(
                        "Validator self-bonds must be signed with a validator \
                         wallet."
                    )
                }
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
    let transfer = transfer.map(|tx| {
        tx.into_iter()
            .map(|tx| sign_transfer_tx(tx, wallet))
            .collect()
    });
    let bond = bond.map(|tx| {
        tx.into_iter()
            .map(|tx| sign_delegation_bond_tx(tx, wallet, &established_account))
            .collect()
    });

    Transactions {
        established_account,
        validator_account,
        transfer,
        bond,
    }
}

/// Parse [`UnsignedTransaction`] from bytes.
pub fn parse_unsigned(
    bytes: &[u8],
) -> Result<UnsignedTransactions, toml::de::Error> {
    toml::from_slice(bytes)
}

/// Create signed [`Transactions`] for a genesis validator.
pub fn init_validator(
    GenesisValidatorData {
        source_key,
        alias,
        commission_rate,
        max_commission_rate_change,
        net_address,
        transfer_from_source_amount,
        self_bond_amount,
    }: GenesisValidatorData,
    source_wallet: &mut Wallet,
    validator_wallet: &ValidatorWallet,
) -> Transactions {
    let unsigned_validator_account_tx = UnsignedValidatorAccountTx {
        alias: alias.clone(),
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
        dkg_key: StringEncoded::new(
            validator_wallet
                .store
                .validator_keys
                .dkg_keypair
                .as_ref()
                .expect("Missing validator DKG key")
                .public(),
        ),
        tendermint_node_key: StringEncoded::new(
            validator_wallet.tendermint_node_key.ref_to(),
        ),
        // No custom validator VPs yet
        vp: "vp_validator".to_string(),
        commission_rate,
        max_commission_rate_change,
        net_address,
    };
    let validator_account = Some(vec![sign_validator_account_tx(
        unsigned_validator_account_tx,
        validator_wallet,
    )]);

    let transfer = if transfer_from_source_amount == token::Amount::default() {
        None
    } else {
        let unsigned_transfer_tx = TransferTx {
            // Only native token can be staked
            token: Alias::from("NAM"),
            source: StringEncoded::new(source_key.ref_to()),
            target: alias.clone(),
            amount: transfer_from_source_amount,
        };
        let transfer_tx = sign_transfer_tx(unsigned_transfer_tx, source_wallet);
        Some(vec![transfer_tx])
    };

    let bond = if self_bond_amount == token::Amount::default() {
        None
    } else {
        let unsigned_bond_tx = BondTx {
            source: AliasOrPk::Alias(alias.clone()),
            validator: alias,
            amount: self_bond_amount,
        };
        let bond_tx = sign_self_bond_tx(unsigned_bond_tx, validator_wallet);
        Some(vec![bond_tx])
    };

    Transactions {
        validator_account,
        transfer,
        bond,
        ..Default::default()
    }
}

pub fn sign_established_account_tx(
    unsigned_tx: UnsignedEstablishedAccountTx,
    wallet: &mut Wallet,
) -> SignedEstablishedAccountTx {
    let key = unsigned_tx.public_key.as_ref().map(|pk| {
        let secret = wallet
            .find_key_by_pk(pk)
            .expect("Key for source must be present to sign with it.");
        let sig = sign_tx(&unsigned_tx, &secret);
        SignedPk {
            pk: pk.clone(),
            authorization: sig,
        }
    });
    let UnsignedEstablishedAccountTx {
        alias,
        vp,
        public_key: _,
    } = unsigned_tx;

    SignedEstablishedAccountTx {
        alias,
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
    let tendermint_node_key_sig =
        sign_tx(&unsigned_tx, &validator_wallet.tendermint_node_key);

    let ValidatorAccountTx {
        alias,
        account_key,
        consensus_key,
        protocol_key,
        dkg_key,
        tendermint_node_key,
        vp,
        commission_rate,
        max_commission_rate_change,
        net_address,
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

    SignedValidatorAccountTx {
        alias,
        account_key,
        consensus_key,
        protocol_key,
        dkg_key,
        tendermint_node_key,
        vp,
        commission_rate,
        max_commission_rate_change,
        net_address,
    }
}

pub fn sign_transfer_tx(
    unsigned_tx: TransferTx,
    source_wallet: &mut Wallet,
) -> SignedTransferTx {
    let source_key = source_wallet
        .find_key_by_pk(&unsigned_tx.source)
        .expect("Key for sourc must be present to sign with it.");

    let source_sig = sign_tx(&unsigned_tx, &source_key);
    Signed {
        data: unsigned_tx,
        signature: source_sig,
    }
}

pub fn sign_self_bond_tx(
    unsigned_tx: BondTx,
    validator_wallet: &ValidatorWallet,
) -> SignedBondTx {
    let source_sig = sign_tx(&unsigned_tx, &validator_wallet.account_key);
    Signed {
        data: unsigned_tx,
        signature: source_sig,
    }
}

pub fn sign_delegation_bond_tx(
    unsigned_tx: BondTx,
    wallet: &mut Wallet,
    established_accounts: &Option<Vec<EstablishedAccountTx<SignedPk>>>,
) -> SignedBondTx {
    let alias = &unsigned_tx.source;
    // Try to look-up the source from wallet first - if it's an alias of an
    // implicit account that should give us the right key
    let found_key = match alias {
        AliasOrPk::Alias(alias) => wallet.find_key(&alias.normalize()),
        AliasOrPk::PublicKey(pk) => wallet.find_key_by_pk(pk),
    };
    let source_key = match found_key {
        Ok(key) => key,
        Err(FindKeyError::KeyNotFound) => {
            // If it's not in the wallet, it must be an established account
            // so we need to look-up its public key first
            let pk = established_accounts
                .as_ref()
                .unwrap_or_else(|| {
                    panic!(
                        "Signing a bond failed. Cannot find \"{alias}\" in \
                         the wallet and there are no established accounts."
                    );
                })
                .iter()
                .find_map(|account| match alias {
                    AliasOrPk::Alias(alias) => {
                        // delegation from established account
                        if &account.alias == alias {
                            Some(
                                &account
                                    .public_key
                                    .as_ref()
                                    .unwrap_or_else(|| {
                                        panic!(
                                            "Signing a bond failed. The \
                                             established account \"{alias}\" \
                                             has no public key. Add a public \
                                             to be able to sign bonds."
                                        );
                                    })
                                    .pk
                                    .raw,
                            )
                        } else {
                            None
                        }
                    }
                    AliasOrPk::PublicKey(pk) => {
                        // delegation from an implicit account
                        Some(&pk.raw)
                    }
                })
                .unwrap_or_else(|| {
                    panic!(
                        "Signing a bond failed. Cannot find \"{alias}\" in \
                         the wallet or in the established accounts."
                    );
                });
            wallet.find_key_by_pk(pk).unwrap_or_else(|err| {
                panic!(
                    "Signing a bond failed. Cannot find key for established \
                     account \"{alias}\" in the wallet. Failed with {err}."
                );
            })
        }
        Err(err) => panic!(
            "Signing a bond failed. Failed to read the key for \"{alias}\" \
             from wallet with {err}."
        ),
    };

    let source_sig = sign_tx(&unsigned_tx, &source_key);
    Signed {
        data: unsigned_tx,
        signature: source_sig,
    }
}

fn sign_tx<T: BorshSerialize>(
    tx_data: &T,
    keypair: &common::SecretKey,
) -> StringEncoded<common::Signature> {
    let tx_data_bytes = tx_data
        .try_to_vec()
        .expect("Encode unsigned validator account tx");
    let tx = Tx {
        code: vec![],
        data: Some(tx_data_bytes),
        timestamp: PRE_GENESIS_TX_TIMESTAMP,
    };
    StringEncoded::new(tx.standalone_signature(keypair))
}

#[derive(
    Clone,
    Debug,
    Default,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct Transactions {
    pub established_account: Option<Vec<SignedEstablishedAccountTx>>,
    pub validator_account: Option<Vec<SignedValidatorAccountTx>>,
    pub transfer: Option<Vec<SignedTransferTx>>,
    pub bond: Option<Vec<SignedBondTx>>,
}
impl Transactions {
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
        votes_per_token: Decimal,
    ) -> bool {
        self.bond
            .as_ref()
            .map(|txs| {
                let mut stakes: BTreeMap<&Alias, token::Amount> =
                    BTreeMap::new();
                for tx in txs {
                    let entry = stakes.entry(&tx.data.validator).or_default();
                    *entry += tx.data.amount;
                }

                stakes.into_iter().any(|(_validator, stake)| {
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
    pub transfer: Option<Vec<TransferTx>>,
    pub bond: Option<Vec<BondTx>>,
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
    pub alias: Alias,
    pub dkg_key: StringEncoded<DkgPublicKey>,
    pub vp: String,
    /// Commission rate charged on rewards for delegators (bounded inside
    /// 0-1)
    pub commission_rate: Decimal,
    /// Maximum change in commission rate permitted per epoch
    pub max_commission_rate_change: Decimal,
    /// P2P IP:port
    pub net_address: SocketAddr,
    /// PKs have to come last in TOML to avoid `ValueAfterTable` error
    pub account_key: PK,
    pub consensus_key: PK,
    pub protocol_key: PK,
    pub tendermint_node_key: PK,
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
    pub alias: Alias,
    pub vp: String,
    /// PKs have to come last in TOML to avoid `ValueAfterTable` error
    pub public_key: Option<PK>,
}

pub type SignedTransferTx = Signed<TransferTx>;

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
pub struct TransferTx {
    pub token: Alias,
    pub source: StringEncoded<common::PublicKey>,
    pub target: Alias,
    pub amount: token::Amount,
}

pub type SignedBondTx = Signed<BondTx>;

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
pub struct BondTx {
    pub source: AliasOrPk,
    pub validator: Alias,
    pub amount: token::Amount,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub enum AliasOrPk {
    /// `alias = "value"` in toml (encoded via `AliasSerHelper`)
    Alias(Alias),
    /// `public_key = "value"` in toml (encoded via `PkSerHelper`)
    PublicKey(StringEncoded<common::PublicKey>),
}

impl Serialize for AliasOrPk {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            AliasOrPk::Alias(alias) => Serialize::serialize(alias, serializer),
            AliasOrPk::PublicKey(pk) => Serialize::serialize(pk, serializer),
        }
    }
}

impl<'de> Deserialize<'de> for AliasOrPk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FieldVisitor;

        impl<'de> serde::de::Visitor<'de> for FieldVisitor {
            type Value = AliasOrPk;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str(
                    "a bech32m encoded `common::PublicKey` or an alias",
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                // Try to deserialize a PK first
                let maybe_pk =
                    StringEncoded::<common::PublicKey>::from_str(value);
                match maybe_pk {
                    Ok(pk) => Ok(AliasOrPk::PublicKey(pk)),
                    Err(_) => {
                        // If that doesn't work, use it as an alias
                        let alias = Alias::from_str(value)
                            .map_err(serde::de::Error::custom)?;
                        Ok(AliasOrPk::Alias(alias))
                    }
                }
            }
        }

        deserializer.deserialize_str(FieldVisitor)
    }
}

impl Display for AliasOrPk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AliasOrPk::Alias(alias) => write!(f, "{}", alias),
            AliasOrPk::PublicKey(pk) => write!(f, "{}", pk),
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
    transactions: &Transactions,
    vps: Option<&ValidityPredicates>,
    balances: Option<&Balances>,
    parameters: Option<&Parameters>,
) -> bool {
    let mut is_valid = true;

    let mut all_used_aliases: BTreeSet<Alias> = BTreeSet::default();
    let mut established_accounts: BTreeMap<Alias, Option<common::PublicKey>> =
        BTreeMap::default();
    let mut validator_accounts: BTreeMap<Alias, common::PublicKey> =
        BTreeMap::default();

    let Transactions {
        established_account,
        validator_account,
        transfer,
        bond,
    } = transactions;

    if let Some(txs) = established_account {
        for tx in txs {
            if !validate_established_account(
                tx,
                vps,
                &mut all_used_aliases,
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
                &mut all_used_aliases,
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
                                // Add an accumulator for tokens transferred to
                                // aliases
                                aliases: BTreeMap::new(),
                                pks: token_balances.clone(),
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();

    if let Some(txs) = transfer {
        for tx in txs {
            if !validate_transfer(tx, &mut token_balances, &all_used_aliases) {
                is_valid = false;
            }
        }
    }

    if let Some(txs) = bond {
        if !txs.is_empty() {
            match parameters {
                Some(parameters) => {
                    for tx in txs {
                        if !validate_bond(
                            tx,
                            &mut token_balances,
                            &established_accounts,
                            &validator_accounts,
                            parameters,
                        ) {
                            is_valid = false;
                        }
                    }
                }
                None => {
                    eprintln!(
                        "Unable to validate bonds without a valid parameters \
                         file."
                    );
                    is_valid = false;
                }
            }
        }
    }

    is_valid
}

fn validate_bond(
    tx: &SignedBondTx,
    balances: &mut BTreeMap<Alias, TokenBalancesForValidation>,
    established_accounts: &BTreeMap<Alias, Option<common::PublicKey>>,
    validator_accounts: &BTreeMap<Alias, common::PublicKey>,
    parameters: &Parameters,
) -> bool {
    let mut is_valid = true;

    let SignedBondTx {
        data:
            BondTx {
                source,
                validator,
                amount,
            },
        signature,
    } = tx;

    let unsigned: BondTx = tx.into();

    // Check signature
    if let Some(source_pk) = match source {
        AliasOrPk::Alias(alias) => {
            // Try to find the source's PK in either established_accounts or
            // validator_accounts
            established_accounts
                .get(alias)
                .cloned()
                .flatten()
                .or_else(|| validator_accounts.get(alias).cloned())
        }
        AliasOrPk::PublicKey(pk) => Some(pk.raw.clone()),
    } {
        if !validate_signature(&unsigned, &source_pk, &signature.raw) {
            eprintln!("Invalid bond tx signature.",);
            is_valid = false;
        }
    } else {
        eprintln!(
            "Invalid bond tx. Couldn't verify bond's signature, because the \
             source accounts \"{source}\" public key cannot be found."
        );
        is_valid = false;
    }

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
            let balance = match source {
                AliasOrPk::Alias(source) => balances.aliases.get_mut(source),
                AliasOrPk::PublicKey(source) => balances.pks.0.get_mut(source),
            };
            match balance {
                Some(balance) => {
                    if *balance < *amount {
                        eprintln!(
                            "Invalid bond tx. Source {source} doesn't have \
                             enough balance of token \"{native_token}\" to \
                             transfer {amount}. Got {balance}."
                        );
                        is_valid = false;
                    } else {
                        // Deduct the amount from source
                        if amount == balance {
                            match source {
                                AliasOrPk::Alias(source) => {
                                    balances.aliases.remove(source);
                                }
                                AliasOrPk::PublicKey(source) => {
                                    balances.pks.0.remove(source);
                                }
                            }
                        } else {
                            *balance -= *amount;
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

    is_valid
}

#[derive(Clone, Debug)]
pub struct TokenBalancesForValidation {
    /// Accumulator for tokens transferred to aliases
    pub aliases: BTreeMap<Alias, token::Amount>,
    /// Token balances from the balances file, associated with PKs
    pub pks: TokenBalances,
}

pub fn validate_established_account(
    tx: &SignedEstablishedAccountTx,
    vps: Option<&ValidityPredicates>,
    all_used_aliases: &mut BTreeSet<Alias>,
    established_accounts: &mut BTreeMap<Alias, Option<common::PublicKey>>,
) -> bool {
    let mut is_valid = true;

    established_accounts.insert(
        tx.alias.clone(),
        tx.public_key.as_ref().map(|signed| signed.pk.raw.clone()),
    );

    // Check that alias is unique
    if all_used_aliases.contains(&tx.alias) {
        eprintln!(
            "A duplicate alias \"{}\" found in a `established_account` tx.",
            tx.alias
        );
        is_valid = false;
    } else {
        all_used_aliases.insert(tx.alias.clone());
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
    all_used_aliases: &mut BTreeSet<Alias>,
    validator_accounts: &mut BTreeMap<Alias, common::PublicKey>,
) -> bool {
    let mut is_valid = true;

    validator_accounts.insert(tx.alias.clone(), tx.account_key.pk.raw.clone());

    // Check that alias is unique
    if all_used_aliases.contains(&tx.alias) {
        eprintln!(
            "A duplicate alias \"{}\" found in a `validator_account` tx.",
            tx.alias
        );
        is_valid = false;
    } else {
        all_used_aliases.insert(tx.alias.clone());
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
             with alias \"{}\".",
            tx.alias
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
             with alias \"{}\".",
            tx.alias
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
             with alias \"{}\".",
            tx.alias
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
             `validator_account` tx with alias \"{}\".",
            tx.alias
        );
        is_valid = false;
    }

    is_valid
}

/// Updates the token balances with all the valid transfers applied
pub fn validate_transfer(
    tx: &SignedTransferTx,
    balances: &mut BTreeMap<Alias, TokenBalancesForValidation>,
    all_used_aliases: &BTreeSet<Alias>,
) -> bool {
    let mut is_valid = true;

    let SignedTransferTx {
        data:
            TransferTx {
                token,
                source,
                target,
                amount,
            },
        signature,
    } = tx;

    let unsigned: TransferTx = tx.into();

    // Check signature
    if !validate_signature(&unsigned, &source.raw, &signature.raw) {
        eprintln!("Invalid transfer tx signature.",);
        is_valid = false;
    }

    // Check that the target exists
    if !all_used_aliases.contains(target) {
        eprintln!(
            "Invalid transfer tx. The target alias \"{target}\" no matching \
             account found."
        );
        is_valid = false;
    }

    // Check token balance of the source and update token balances of the source
    // and target
    match balances.get_mut(token) {
        Some(balances) => match balances.pks.0.get_mut(source) {
            Some(balance) => {
                if *balance < *amount {
                    eprintln!(
                        "Invalid transfer tx. Source {source} doesn't have \
                         enough balance of token \"{token}\" to transfer \
                         {amount}. Got {balance}."
                    );
                    is_valid = false;
                } else {
                    // Deduct the amount from source
                    if amount == balance {
                        balances.pks.0.remove(source);
                    } else {
                        *balance -= *amount;
                    }

                    // Add the amount to target
                    let target_balance =
                        balances.aliases.entry(target.clone()).or_default();
                    *target_balance += *amount;
                }
            }
            None => {
                eprintln!(
                    "Invalid transfer tx. Source {source} has no balance of \
                     token \"{token}\"."
                );
                is_valid = false;
            }
        },
        None => {
            eprintln!(
                "Invalid transfer tx. Token \"{token}\" not found in balances."
            );
            is_valid = false;
        }
    }

    is_valid
}

fn validate_signature<T: BorshSerialize + Debug>(
    tx_data: &T,
    pk: &common::PublicKey,
    sig: &common::Signature,
) -> bool {
    let tx_data_bytes = tx_data
        .try_to_vec()
        .expect("Encode unsigned validator account tx");
    let tx = Tx {
        code: vec![],
        data: Some(tx_data_bytes),
        timestamp: PRE_GENESIS_TX_TIMESTAMP,
    };
    match tx.verify_standalone_sig(pk, sig) {
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
        let SignedEstablishedAccountTx {
            alias,
            vp,
            public_key,
        } = tx;
        Self {
            alias: alias.clone(),
            vp: vp.clone(),
            public_key: public_key.as_ref().map(|signed| signed.pk.clone()),
        }
    }
}

impl From<&SignedValidatorAccountTx> for UnsignedValidatorAccountTx {
    fn from(tx: &SignedValidatorAccountTx) -> Self {
        let SignedValidatorAccountTx {
            alias,
            dkg_key,
            vp,
            commission_rate,
            max_commission_rate_change,
            net_address,
            account_key,
            consensus_key,
            protocol_key,
            tendermint_node_key,
        } = tx;

        Self {
            alias: alias.clone(),
            dkg_key: dkg_key.clone(),
            vp: vp.clone(),
            commission_rate: *commission_rate,
            max_commission_rate_change: *max_commission_rate_change,
            net_address: *net_address,
            account_key: account_key.pk.clone(),
            consensus_key: consensus_key.pk.clone(),
            protocol_key: protocol_key.pk.clone(),
            tendermint_node_key: tendermint_node_key.pk.clone(),
        }
    }
}

impl From<&SignedTransferTx> for TransferTx {
    fn from(tx: &SignedTransferTx) -> Self {
        let SignedTransferTx { data, signature: _ } = tx;
        data.clone()
    }
}

impl From<&SignedBondTx> for BondTx {
    fn from(tx: &SignedBondTx) -> Self {
        let SignedBondTx { data, signature: _ } = tx;
        data.clone()
    }
}
