#![allow(clippy::disallowed_methods)]

use std::collections::BTreeMap;

use criterion::{criterion_group, criterion_main, Criterion};
use namada_apps_lib::collections::HashSet;
use namada_apps_lib::key::{common, ed25519, RefTo, SigScheme};
use namada_apps_lib::time::DateTimeUtc;
use namada_apps_lib::tx::data::{Fee, GasLimit, TxType, WrapperTx};
use namada_apps_lib::tx::{self, Signer, Tx};
use namada_apps_lib::{address, token};
use namada_node::bench_utils::BenchShell;
use namada_node::shell::{MempoolTxType, ResultCode};
use rand::rngs::StdRng;
use rand::SeedableRng;

/// The value of namada-mainnet-genesis `max_tx_bytes` protocol parameter
const MAX_TX_BYTES: usize = 1048576;

/// Benchmark mempool validation with a tx containing the max. number of bytes
/// allowed by mainnet genesis parameters, filled with smallest data sections,
/// but without an authorization section.
fn max_tx_sections_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("non_uniq_sections_validation");

    let bench_shell = BenchShell::default();
    let shell = bench_shell.read();

    let chain_id = shell.chain_id.clone();
    let timestamp = DateTimeUtc::now();
    let gas_limit = GasLimit::from(u64::MAX);
    let mut rng = StdRng::from_seed([0; 32]);
    let secret_key = ed25519::SigScheme::generate(&mut rng);
    let pk = common::PublicKey::Ed25519(secret_key.ref_to());

    let amount = token::Amount::from_u64(1);
    let amount_per_gas_unit =
        token::DenominatedAmount::new(amount, token::Denomination(0u8));
    let token = address::testing::nam();
    let fee = Fee {
        amount_per_gas_unit,
        token,
    };
    let wrapper = WrapperTx { fee, pk, gas_limit };
    let tx_type = TxType::Wrapper(Box::new(wrapper));

    let batch = HashSet::new();
    let header = tx::Header {
        chain_id,
        expiration: None,
        timestamp,
        batch,
        atomic: false,
        tx_type,
    };

    let (tx_1_section_len, section_additional_len) = {
        let tx = Tx {
            header: header.clone(),
            sections: vec![tx::Section::Data(tx::Data::new(vec![0_u8]))],
        };
        let tx_bytes = tx.try_to_bytes().unwrap();
        let tx_1_section_len = tx_bytes.len();

        let tx = Tx {
            header: header.clone(),
            sections: vec![
                tx::Section::Data(tx::Data::new(vec![0_u8])),
                tx::Section::Data(tx::Data::new(vec![0_u8])),
            ],
        };
        let tx_bytes = tx.try_to_bytes().unwrap();
        let tx_2_sections_len = tx_bytes.len();

        (tx_1_section_len, tx_2_sections_len - tx_1_section_len)
    };

    let sections_available_space = MAX_TX_BYTES - tx_1_section_len;
    let num_of_sections = sections_available_space / section_additional_len + 1;

    let mut sections = Vec::with_capacity(num_of_sections);
    for _ in 0..num_of_sections {
        sections.push(tx::Section::Data(tx::Data::new(vec![0_u8])));
    }
    let tx = Tx {
        header: header.clone(),
        sections,
    };
    let tx_bytes = tx.try_to_bytes().unwrap();
    assert!(tx_bytes.len() <= MAX_TX_BYTES);

    let res = shell.mempool_validate(&tx_bytes, MempoolTxType::NewTransaction);
    assert_eq!(res.code, ResultCode::InvalidSig.into());

    group.bench_function("Shell::mempool_validate", |b| {
        b.iter(|| {
            shell.mempool_validate(&tx_bytes, MempoolTxType::NewTransaction);
        });
    });
}

/// Benchmark mempool validation with a tx containing the max. number of bytes
/// allowed by mainnet genesis parameters, filled with smallest data sections
/// and an authorization section.
fn max_tx_sections_with_auth_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("uniq_sections_auth_validation");

    let bench_shell = BenchShell::default();
    let shell = bench_shell.read();

    let chain_id = shell.chain_id.clone();
    let timestamp = DateTimeUtc::now();
    let gas_limit = GasLimit::from(u64::MAX);
    let mut rng = StdRng::from_seed([0; 32]);
    let secret_key = ed25519::SigScheme::generate(&mut rng);
    let pk = common::PublicKey::Ed25519(secret_key.ref_to());

    let amount = token::Amount::from_u64(1);
    let amount_per_gas_unit =
        token::DenominatedAmount::new(amount, token::Denomination(0u8));
    let token = address::testing::nam();
    let fee = Fee {
        amount_per_gas_unit,
        token,
    };
    let wrapper = WrapperTx { fee, pk, gas_limit };
    let tx_type = TxType::Wrapper(Box::new(wrapper));

    let batch = HashSet::new();
    let header = tx::Header {
        chain_id,
        expiration: None,
        timestamp,
        batch,
        atomic: false,
        tx_type,
    };

    let (tx_1_section_len, section_additional_len) = {
        let data = tx::Section::Data(tx::Data::new(vec![0_u8]));
        let data_hash = data.get_hash();
        let targets = vec![
            tx::Section::Header(header.clone()).get_hash(),
            data_hash,
            data_hash,
        ];
        let auth = tx::Authorization {
            targets,
            signer: Signer::PubKeys(vec![]),
            signatures: BTreeMap::default(),
        };
        let tx = Tx {
            header: header.clone(),
            sections: vec![data.clone(), tx::Section::Authorization(auth)],
        };
        let tx_bytes = tx.try_to_bytes().unwrap();
        let tx_1_section_len = tx_bytes.len();

        let targets = vec![
            tx::Section::Header(header.clone()).get_hash(),
            data_hash,
            data_hash,
            data_hash,
        ];
        let auth = tx::Authorization {
            targets,
            signer: Signer::PubKeys(vec![]),
            signatures: BTreeMap::default(),
        };
        let tx = Tx {
            header: header.clone(),
            sections: vec![
                data.clone(),
                data,
                tx::Section::Authorization(auth),
            ],
        };
        let tx_bytes = tx.try_to_bytes().unwrap();
        let tx_2_sections_len = tx_bytes.len();

        (tx_1_section_len, tx_2_sections_len - tx_1_section_len)
    };

    let sections_available_space = MAX_TX_BYTES - tx_1_section_len;
    let num_of_sections = sections_available_space / section_additional_len + 1;

    // Generate unique sections and add a target for each
    let mut sections = Vec::with_capacity(num_of_sections + 1);
    let mut targets = Vec::with_capacity(num_of_sections + 1);
    targets.push(tx::Section::Header(header.clone()).get_hash());
    for _ in 0..num_of_sections {
        let data = tx::Section::Data(tx::Data::new(vec![0_u8]));
        let data_hash = data.get_hash();
        sections.push(data);
        targets.push(data_hash);
    }

    // Add auth raw hash target and section. Add the authorization section last
    // so that `Tx::verify_signatures` has to iterate through all sections
    let auth = tx::Authorization {
        targets: targets.clone(),
        signer: Signer::PubKeys(vec![]),
        signatures: BTreeMap::default(),
    };
    let raw_hash = auth.get_raw_hash();
    targets.push(raw_hash);
    let auth = tx::Authorization {
        targets,
        signer: Signer::PubKeys(vec![]),
        signatures: BTreeMap::default(),
    };
    sections.push(tx::Section::Authorization(auth));

    let tx = Tx {
        header: header.clone(),
        sections,
    };
    let tx_bytes = tx.try_to_bytes().unwrap();
    assert!(tx_bytes.len() <= MAX_TX_BYTES);

    let res = shell.mempool_validate(&tx_bytes, MempoolTxType::NewTransaction);
    assert_eq!(res.code, ResultCode::InvalidSig.into());

    group.bench_function("Shell::mempool_validate", |b| {
        b.iter(|| {
            shell.mempool_validate(&tx_bytes, MempoolTxType::NewTransaction);
        });
    });
}

criterion_group!(
    mempool_validate,
    max_tx_sections_validation,
    max_tx_sections_with_auth_validation,
);
criterion_main!(mempool_validate);
