//! MASP verification wrappers.

pub mod shielded_ctx;
#[cfg(test)]
mod test_utils;
pub mod types;
pub mod utils;

use std::env;
use std::fmt::Debug;
use std::ops::Deref;
use std::path::PathBuf;

use borsh::{BorshDeserialize, BorshSerialize};
use lazy_static::lazy_static;
#[cfg(feature = "mainnet")]
use masp_primitives::consensus::MainNetwork as Network;
#[cfg(not(feature = "mainnet"))]
use masp_primitives::consensus::TestNetwork as Network;
use masp_primitives::transaction::components::sapling::{
    Authorized as SaplingAuthorized, Bundle as SaplingBundle,
};
use masp_primitives::transaction::components::transparent::builder::TransparentBuilder;
use masp_primitives::transaction::components::TxOut;
use masp_primitives::transaction::sighash::{signature_hash, SignableInput};
use masp_primitives::transaction::txid::TxIdDigester;
use masp_primitives::transaction::{Authorized, Transaction, TransactionData};
use masp_proofs::prover::LocalTxProver;
use masp_proofs::sapling::BatchValidator;
use namada_core::arith::checked;
pub use namada_core::masp::{
    encode_asset_type, AssetData, BalanceOwner, ExtendedViewingKey,
    PaymentAddress, TransferSource, TransferTarget,
};
use namada_state::StorageError;
use rand_core::OsRng;
pub use shielded_ctx::ShieldedContext;
pub use types::PVKs;
pub use utils::{
    find_valid_diversifier, preload_verifying_keys, ShieldedUtils,
};

use crate::masp::types::PartialAuthorized;
use crate::masp::utils::{get_params_dir, load_pvks};

/// Env var to point to a dir with MASP parameters. When not specified,
/// the default OS specific path is used.
pub const ENV_VAR_MASP_PARAMS_DIR: &str = "NAMADA_MASP_PARAMS_DIR";

/// Randomness seed for MASP integration tests to build proofs with
/// deterministic rng.
pub const ENV_VAR_MASP_TEST_SEED: &str = "NAMADA_MASP_TEST_SEED";

/// The network to use for MASP
const NETWORK: Network = Network;

// TODO these could be exported from masp_proof crate
/// Spend circuit name
pub const SPEND_NAME: &str = "masp-spend.params";
/// Output circuit name
pub const OUTPUT_NAME: &str = "masp-output.params";
/// Convert circuit name
pub const CONVERT_NAME: &str = "masp-convert.params";

lazy_static! {
    /// MASP verifying keys load from parameters
    static ref VERIFIYING_KEYS: PVKs =
        {
        let params_dir = get_params_dir();
        let [spend_path, convert_path, output_path] =
            [SPEND_NAME, CONVERT_NAME, OUTPUT_NAME].map(|p| params_dir.join(p));

        #[cfg(feature = "download-params")]
        if !spend_path.exists() || !convert_path.exists() || !output_path.exists() {
            let paths = masp_proofs::download_masp_parameters(None).expect(
                "MASP parameters were not present, expected the download to \
                succeed",
            );
            if paths.spend != spend_path
                || paths.convert != convert_path
                || paths.output != output_path
            {
                panic!(
                    "unrecoverable: downloaded missing masp params, but to an \
                    unfamiliar path"
                )
            }
        }
        // size and blake2b checked here
        let params = masp_proofs::load_parameters(
            spend_path.as_path(),
            output_path.as_path(),
            convert_path.as_path(),
        );
        PVKs {
            spend_vk: params.spend_params.vk,
            convert_vk: params.convert_params.vk,
            output_vk: params.output_params.vk,
        }
    };
}

/// Partially deauthorize the transparent bundle
pub fn partial_deauthorize(
    tx_data: &TransactionData<Authorized>,
) -> Option<TransactionData<PartialAuthorized>> {
    let transp = tx_data.transparent_bundle().and_then(|x| {
        let mut tb = TransparentBuilder::empty();
        for vin in &x.vin {
            tb.add_input(TxOut {
                asset_type: vin.asset_type,
                value: vin.value,
                address: vin.address,
            })
            .ok()?;
        }
        for vout in &x.vout {
            tb.add_output(&vout.address, vout.asset_type, vout.value)
                .ok()?;
        }
        tb.build()
    });
    if tx_data.transparent_bundle().is_some() != transp.is_some() {
        return None;
    }
    Some(TransactionData::from_parts(
        tx_data.version(),
        tx_data.consensus_branch_id(),
        tx_data.lock_time(),
        tx_data.expiry_height(),
        transp,
        tx_data.sapling_bundle().cloned(),
    ))
}

/// Verify a shielded transaction.
pub fn verify_shielded_tx<F>(
    transaction: &Transaction,
    consume_verify_gas: F,
) -> Result<(), StorageError>
where
    F: Fn(u64) -> std::result::Result<(), StorageError>,
{
    tracing::info!("entered verify_shielded_tx()");

    let sapling_bundle = if let Some(bundle) = transaction.sapling_bundle() {
        bundle
    } else {
        return Err(StorageError::SimpleMessage("no sapling bundle"));
    };
    let tx_data = transaction.deref();

    // Partially deauthorize the transparent bundle
    let unauth_tx_data = match partial_deauthorize(tx_data) {
        Some(tx_data) => tx_data,
        None => {
            return Err(StorageError::SimpleMessage(
                "Failed to partially de-authorize",
            ));
        }
    };

    let txid_parts = unauth_tx_data.digest(TxIdDigester);
    // the commitment being signed is shared across all Sapling inputs; once
    // V4 transactions are deprecated this should just be the txid, but
    // for now we need to continue to compute it here.
    let sighash =
        signature_hash(&unauth_tx_data, &SignableInput::Shielded, &txid_parts);

    tracing::info!("sighash computed");

    let PVKs {
        spend_vk,
        convert_vk,
        output_vk,
    } = load_pvks();

    #[cfg(not(feature = "testing"))]
    let mut ctx = BatchValidator::new();
    #[cfg(feature = "testing")]
    let mut ctx = testing::MockBatchValidator::default();

    // Charge gas before check bundle
    charge_masp_check_bundle_gas(sapling_bundle, &consume_verify_gas)?;

    if !ctx.check_bundle(sapling_bundle.to_owned(), sighash.as_ref().to_owned())
    {
        tracing::debug!("failed check bundle");
        return Err(StorageError::SimpleMessage("Invalid sapling bundle"));
    }
    tracing::debug!("passed check bundle");

    // Charge gas before final validation
    charge_masp_validate_gas(sapling_bundle, consume_verify_gas)?;
    if !ctx.validate(spend_vk, convert_vk, output_vk, OsRng) {
        return Err(StorageError::SimpleMessage(
            "Invalid proofs or signatures",
        ));
    }
    Ok(())
}

fn charge_masp_check_bundle_gas<F>(
    sapling_bundle: &SaplingBundle<SaplingAuthorized>,
    consume_verify_gas: F,
) -> Result<(), namada_state::StorageError>
where
    F: Fn(u64) -> std::result::Result<(), namada_state::StorageError>,
{
    consume_verify_gas(checked!(
        (sapling_bundle.shielded_spends.len() as u64)
            * namada_gas::MASP_SPEND_CHECK_GAS
    )?)?;

    consume_verify_gas(checked!(
        (sapling_bundle.shielded_converts.len() as u64)
            * namada_gas::MASP_CONVERT_CHECK_GAS
    )?)?;

    consume_verify_gas(checked!(
        (sapling_bundle.shielded_outputs.len() as u64)
            * namada_gas::MASP_OUTPUT_CHECK_GAS
    )?)
}

fn charge_masp_validate_gas<F>(
    sapling_bundle: &SaplingBundle<SaplingAuthorized>,
    consume_verify_gas: F,
) -> Result<(), namada_state::StorageError>
where
    F: Fn(u64) -> std::result::Result<(), namada_state::StorageError>,
{
    consume_verify_gas(checked!(
        ((sapling_bundle.shielded_spends.len() as u64) + 1)
            * namada_gas::MASP_VERIFY_SIG_GAS
    )?)?;

    // If at least one note is present charge the fixed costs. Then charge the
    // variable cost for every other note, amortized on the fixed expected
    // number of cores
    if let Some(remaining_notes) =
        sapling_bundle.shielded_spends.len().checked_sub(1)
    {
        consume_verify_gas(namada_gas::MASP_FIXED_SPEND_GAS)?;
        consume_verify_gas(checked!(
            namada_gas::MASP_VARIABLE_SPEND_GAS * remaining_notes as u64
                / namada_gas::MASP_PARALLEL_GAS_DIVIDER
        )?)?;
    }

    if let Some(remaining_notes) =
        sapling_bundle.shielded_converts.len().checked_sub(1)
    {
        consume_verify_gas(namada_gas::MASP_FIXED_CONVERT_GAS)?;
        consume_verify_gas(checked!(
            namada_gas::MASP_VARIABLE_CONVERT_GAS * remaining_notes as u64
                / namada_gas::MASP_PARALLEL_GAS_DIVIDER
        )?)?;
    }

    if let Some(remaining_notes) =
        sapling_bundle.shielded_spends.len().checked_sub(1)
    {
        consume_verify_gas(namada_gas::MASP_FIXED_OUTPUT_GAS)?;
        consume_verify_gas(checked!(
            namada_gas::MASP_VARIABLE_OUTPUT_GAS * remaining_notes as u64
                / namada_gas::MASP_PARALLEL_GAS_DIVIDER
        )?)?;
    }

    Ok(())
}

mod tests {
    /// quick and dirty test. will fail on size check
    #[test]
    #[should_panic(expected = "parameter file size is not correct")]
    fn test_wrong_masp_params() {
        use std::io::Write;

        use super::{CONVERT_NAME, OUTPUT_NAME, SPEND_NAME};

        let tempdir = tempfile::tempdir()
            .expect("expected a temp dir")
            .into_path();
        let fake_params_paths =
            [SPEND_NAME, OUTPUT_NAME, CONVERT_NAME].map(|p| tempdir.join(p));
        for path in &fake_params_paths {
            let mut f =
                std::fs::File::create(path).expect("expected a temp file");
            f.write_all(b"fake params")
                .expect("expected a writable temp file");
            f.sync_all()
                .expect("expected a writable temp file (on sync)");
        }

        std::env::set_var(super::ENV_VAR_MASP_PARAMS_DIR, tempdir.as_os_str());
        // should panic here
        masp_proofs::load_parameters(
            &fake_params_paths[0],
            &fake_params_paths[1],
            &fake_params_paths[2],
        );
    }

    /// a more involved test, using dummy parameters with the right
    /// size but the wrong hash.
    #[test]
    #[should_panic(expected = "parameter file is not correct")]
    fn test_wrong_masp_params_hash() {
        use masp_primitives::ff::PrimeField;
        use masp_proofs::bellman::groth16::{
            generate_random_parameters, Parameters,
        };
        use masp_proofs::bellman::{Circuit, ConstraintSystem, SynthesisError};
        use masp_proofs::bls12_381::{Bls12, Scalar};

        use super::{CONVERT_NAME, OUTPUT_NAME, SPEND_NAME};

        struct FakeCircuit<E: PrimeField> {
            x: E,
        }

        impl<E: PrimeField> Circuit<E> for FakeCircuit<E> {
            fn synthesize<CS: ConstraintSystem<E>>(
                self,
                cs: &mut CS,
            ) -> Result<(), SynthesisError> {
                let x = cs.alloc(|| "x", || Ok(self.x)).unwrap();
                cs.enforce(
                    || {
                        "this is an extra long constraint name so that rustfmt \
                         is ok with wrapping the params of enforce()"
                    },
                    |lc| lc + x,
                    |lc| lc + x,
                    |lc| lc + x,
                );
                Ok(())
            }
        }

        let dummy_circuit = FakeCircuit { x: Scalar::zero() };
        let mut rng = rand::thread_rng();
        let fake_params: Parameters<Bls12> =
            generate_random_parameters(dummy_circuit, &mut rng)
                .expect("expected to generate fake params");

        let tempdir = tempfile::tempdir()
            .expect("expected a temp dir")
            .into_path();
        // TODO: get masp to export these consts
        let fake_params_paths = [
            (SPEND_NAME, 49848572u64),
            (OUTPUT_NAME, 16398620u64),
            (CONVERT_NAME, 22570940u64),
        ]
        .map(|(p, s)| (tempdir.join(p), s));
        for (path, size) in &fake_params_paths {
            let mut f =
                std::fs::File::create(path).expect("expected a temp file");
            fake_params
                .write(&mut f)
                .expect("expected a writable temp file");
            // the dummy circuit has one constraint, and therefore its
            // params should always be smaller than the large masp
            // circuit params. so this truncate extends the file, and
            // extra bytes at the end do not make it invalid.
            f.set_len(*size)
                .expect("expected to truncate the temp file");
            f.sync_all()
                .expect("expected a writable temp file (on sync)");
        }

        std::env::set_var(super::ENV_VAR_MASP_PARAMS_DIR, tempdir.as_os_str());
        // should panic here
        masp_proofs::load_parameters(
            &fake_params_paths[0].0,
            &fake_params_paths[1].0,
            &fake_params_paths[2].0,
        );
    }
}

#[cfg(any(test, feature = "testing"))]
/// Tests and strategies for transactions
pub mod testing {
    use std::ops::AddAssign;
    use std::sync::Mutex;

    use bls12_381::{Bls12, G1Affine, G2Affine};
    use masp_primitives::asset_type::AssetType;
    use masp_primitives::consensus::testing::arb_height;
    use masp_primitives::constants::SPENDING_KEY_GENERATOR;
    use masp_primitives::convert::AllowedConversion;
    use masp_primitives::ff::PrimeField;
    use masp_primitives::group::GroupEncoding;
    use masp_primitives::memo::MemoBytes;
    use masp_primitives::merkle_tree::MerklePath;
    use masp_primitives::sapling::note_encryption::{
        try_sapling_note_decryption, PreparedIncomingViewingKey,
    };
    use masp_primitives::sapling::prover::TxProver;
    use masp_primitives::sapling::redjubjub::{PublicKey, Signature};
    use masp_primitives::sapling::{
        Diversifier, Node, Note, ProofGenerationKey, Rseed,
    };
    use masp_primitives::transaction::builder::Builder;
    use masp_primitives::transaction::components::sapling::builder::{
        RngBuildParams, StoredBuildParams,
    };
    use masp_primitives::transaction::components::sapling::Bundle;
    use masp_primitives::transaction::components::{
        I128Sum, OutputDescription, U64Sum, GROTH_PROOF_SIZE,
    };
    use masp_primitives::transaction::fees::fixed::FeeRule;
    use masp_primitives::transaction::{Authorization, TransparentAddress};
    use masp_primitives::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};
    use masp_proofs::bellman::groth16;
    use masp_proofs::bellman::groth16::Proof;
    use namada_core::collections::HashMap;
    use namada_core::token::MaspDigitPos;
    use proptest::prelude::*;
    use proptest::sample::SizeRange;
    use proptest::test_runner::TestRng;
    use proptest::{collection, option, prop_compose};
    use rand_core::CryptoRng;

    use super::*;
    use crate::address::testing::arb_address;
    use crate::masp::types::{ShieldedTransfer, WalletMap};
    use crate::masp_primitives::consensus::BranchId;
    use crate::masp_primitives::constants::VALUE_COMMITMENT_RANDOMNESS_GENERATOR;
    use crate::masp_primitives::merkle_tree::FrozenCommitmentTree;
    use crate::masp_primitives::sapling::keys::OutgoingViewingKey;
    use crate::masp_primitives::sapling::redjubjub::PrivateKey;
    use crate::masp_primitives::transaction::components::transparent::testing::arb_transparent_address;
    use crate::storage::testing::arb_epoch;
    use crate::token::testing::arb_denomination;

    /// A context object for verifying the Sapling components of MASP
    /// transactions. Same as BatchValidator, but always assumes the
    /// proofs and signatures to be valid.
    pub struct MockBatchValidator {
        inner: BatchValidator,
    }

    impl Default for MockBatchValidator {
        fn default() -> Self {
            MockBatchValidator {
                inner: BatchValidator::new(),
            }
        }
    }

    impl MockBatchValidator {
        /// Checks the bundle against Sapling-specific consensus rules, and adds
        /// its proof and signatures to the validator.
        ///
        /// Returns `false` if the bundle doesn't satisfy all of the consensus
        /// rules. This `BatchValidator` can continue to be used
        /// regardless, but some or all of the proofs and signatures
        /// from this bundle may have already been added to the batch even if
        /// it fails other consensus rules.
        pub fn check_bundle(
            &mut self,
            bundle: Bundle<
                masp_primitives::transaction::components::sapling::Authorized,
            >,
            sighash: [u8; 32],
        ) -> bool {
            self.inner.check_bundle(bundle, sighash)
        }

        /// Batch-validates the accumulated bundles.
        ///
        /// Returns `true` if every proof and signature in every bundle added to
        /// the batch validator is valid, or `false` if one or more are
        /// invalid. No attempt is made to figure out which of the
        /// accumulated bundles might be invalid; if that information is
        /// desired, construct separate [`BatchValidator`]s for sub-batches of
        /// the bundles.
        pub fn validate<R: RngCore + CryptoRng>(
            self,
            _spend_vk: &groth16::VerifyingKey<Bls12>,
            _convert_vk: &groth16::VerifyingKey<Bls12>,
            _output_vk: &groth16::VerifyingKey<Bls12>,
            mut _rng: R,
        ) -> bool {
            true
        }
    }

    /// This function computes `value` in the exponent of the value commitment
    /// base
    fn masp_compute_value_balance(
        asset_type: AssetType,
        value: i128,
    ) -> Option<jubjub::ExtendedPoint> {
        // Compute the absolute value (failing if -i128::MAX is
        // the value)
        let abs = match value.checked_abs() {
            Some(a) => a as u128,
            None => return None,
        };

        // Is it negative? We'll have to negate later if so.
        let is_negative = value.is_negative();

        // Compute it in the exponent
        let mut abs_bytes = [0u8; 32];
        abs_bytes[0..16].copy_from_slice(&abs.to_le_bytes());
        let mut value_balance = asset_type.value_commitment_generator()
            * jubjub::Fr::from_bytes(&abs_bytes).unwrap();

        // Negate if necessary
        if is_negative {
            value_balance = -value_balance;
        }

        // Convert to unknown order point
        Some(value_balance.into())
    }

    /// A context object for creating the Sapling components of a Zcash
    /// transaction.
    pub struct SaplingProvingContext {
        bsk: jubjub::Fr,
        // (sum of the Spend value commitments) - (sum of the Output value
        // commitments)
        cv_sum: jubjub::ExtendedPoint,
    }

    /// An implementation of TxProver that does everything except generating
    /// valid zero-knowledge proofs. Uses the supplied source of randomness to
    /// carry out its operations.
    pub struct MockTxProver<R: RngCore>(pub Mutex<R>);

    impl<R: RngCore> TxProver for MockTxProver<R> {
        type SaplingProvingContext = SaplingProvingContext;

        fn new_sapling_proving_context(&self) -> Self::SaplingProvingContext {
            SaplingProvingContext {
                bsk: jubjub::Fr::zero(),
                cv_sum: jubjub::ExtendedPoint::identity(),
            }
        }

        fn spend_proof(
            &self,
            ctx: &mut Self::SaplingProvingContext,
            proof_generation_key: ProofGenerationKey,
            _diversifier: Diversifier,
            _rseed: Rseed,
            ar: jubjub::Fr,
            asset_type: AssetType,
            value: u64,
            _anchor: bls12_381::Scalar,
            _merkle_path: MerklePath<Node>,
            rcv: jubjub::Fr,
        ) -> Result<
            ([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint, PublicKey),
            (),
        > {
            // Accumulate the value commitment randomness in the context
            {
                let mut tmp = rcv;
                tmp.add_assign(&ctx.bsk);

                // Update the context
                ctx.bsk = tmp;
            }

            // Construct the value commitment
            let value_commitment = asset_type.value_commitment(value, rcv);

            // This is the result of the re-randomization, we compute it for the
            // caller
            let rk = PublicKey(proof_generation_key.ak.into())
                .randomize(ar, SPENDING_KEY_GENERATOR);

            // Compute value commitment
            let value_commitment: jubjub::ExtendedPoint =
                value_commitment.commitment().into();

            // Accumulate the value commitment in the context
            ctx.cv_sum += value_commitment;

            let mut zkproof = [0u8; GROTH_PROOF_SIZE];
            let proof = Proof::<Bls12> {
                a: G1Affine::generator(),
                b: G2Affine::generator(),
                c: G1Affine::generator(),
            };
            proof
                .write(&mut zkproof[..])
                .expect("should be able to serialize a proof");
            Ok((zkproof, value_commitment, rk))
        }

        fn output_proof(
            &self,
            ctx: &mut Self::SaplingProvingContext,
            _esk: jubjub::Fr,
            _payment_address: masp_primitives::sapling::PaymentAddress,
            _rcm: jubjub::Fr,
            asset_type: AssetType,
            value: u64,
            rcv: jubjub::Fr,
        ) -> ([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint) {
            // Accumulate the value commitment randomness in the context
            {
                let mut tmp = rcv.neg(); // Outputs subtract from the total.
                tmp.add_assign(&ctx.bsk);

                // Update the context
                ctx.bsk = tmp;
            }

            // Construct the value commitment for the proof instance
            let value_commitment = asset_type.value_commitment(value, rcv);

            // Compute the actual value commitment
            let value_commitment_point: jubjub::ExtendedPoint =
                value_commitment.commitment().into();

            // Accumulate the value commitment in the context. We do this to
            // check internal consistency.
            ctx.cv_sum -= value_commitment_point; // Outputs subtract from the total.

            let mut zkproof = [0u8; GROTH_PROOF_SIZE];
            let proof = Proof::<Bls12> {
                a: G1Affine::generator(),
                b: G2Affine::generator(),
                c: G1Affine::generator(),
            };
            proof
                .write(&mut zkproof[..])
                .expect("should be able to serialize a proof");

            (zkproof, value_commitment_point)
        }

        fn convert_proof(
            &self,
            ctx: &mut Self::SaplingProvingContext,
            allowed_conversion: AllowedConversion,
            value: u64,
            _anchor: bls12_381::Scalar,
            _merkle_path: MerklePath<Node>,
            rcv: jubjub::Fr,
        ) -> Result<([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint), ()>
        {
            // Accumulate the value commitment randomness in the context
            {
                let mut tmp = rcv;
                tmp.add_assign(&ctx.bsk);

                // Update the context
                ctx.bsk = tmp;
            }

            // Construct the value commitment
            let value_commitment =
                allowed_conversion.value_commitment(value, rcv);

            // Compute value commitment
            let value_commitment: jubjub::ExtendedPoint =
                value_commitment.commitment().into();

            // Accumulate the value commitment in the context
            ctx.cv_sum += value_commitment;

            let mut zkproof = [0u8; GROTH_PROOF_SIZE];
            let proof = Proof::<Bls12> {
                a: G1Affine::generator(),
                b: G2Affine::generator(),
                c: G1Affine::generator(),
            };
            proof
                .write(&mut zkproof[..])
                .expect("should be able to serialize a proof");

            Ok((zkproof, value_commitment))
        }

        fn binding_sig(
            &self,
            ctx: &mut Self::SaplingProvingContext,
            assets_and_values: &I128Sum,
            sighash: &[u8; 32],
        ) -> Result<Signature, ()> {
            // Initialize secure RNG
            let mut rng = self.0.lock().unwrap();

            // Grab the current `bsk` from the context
            let bsk = PrivateKey(ctx.bsk);

            // Grab the `bvk` using DerivePublic.
            let bvk = PublicKey::from_private(
                &bsk,
                VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
            );

            // In order to check internal consistency, let's use the accumulated
            // value commitments (as the verifier would) and apply
            // value_balance to compare against our derived bvk.
            {
                let final_bvk = assets_and_values
                    .components()
                    .map(|(asset_type, value_balance)| {
                        // Compute value balance for each asset
                        // Error for bad value balances (-INT128_MAX value)
                        masp_compute_value_balance(*asset_type, *value_balance)
                    })
                    .try_fold(ctx.cv_sum, |tmp, value_balance| {
                        // Compute cv_sum minus sum of all value balances
                        Result::<_, ()>::Ok(tmp - value_balance.ok_or(())?)
                    })?;

                // The result should be the same, unless the provided
                // valueBalance is wrong.
                if bvk.0 != final_bvk {
                    return Err(());
                }
            }

            // Construct signature message
            let mut data_to_be_signed = [0u8; 64];
            data_to_be_signed[0..32].copy_from_slice(&bvk.0.to_bytes());
            data_to_be_signed[32..64].copy_from_slice(&sighash[..]);

            // Sign
            Ok(bsk.sign(
                &data_to_be_signed,
                &mut *rng,
                VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
            ))
        }
    }

    #[derive(Debug, Clone)]
    /// Adapts a CSPRNG from a PRNG for proptesting
    pub struct TestCsprng<R: RngCore>(R);

    impl<R: RngCore> CryptoRng for TestCsprng<R> {}

    impl<R: RngCore> RngCore for TestCsprng<R> {
        fn next_u32(&mut self) -> u32 {
            self.0.next_u32()
        }

        fn next_u64(&mut self) -> u64 {
            self.0.next_u64()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.fill_bytes(dest)
        }

        fn try_fill_bytes(
            &mut self,
            dest: &mut [u8],
        ) -> Result<(), rand::Error> {
            self.0.try_fill_bytes(dest)
        }
    }

    prop_compose! {
        /// Expose a random number generator
        pub fn arb_rng()(rng in Just(()).prop_perturb(|(), rng| rng)) -> TestRng {
            rng
        }
    }

    prop_compose! {
        /// Generate an arbitrary output description with the given value
        pub fn arb_output_description(
            asset_type: AssetType,
            value: u64,
        )(
            mut rng in arb_rng().prop_map(TestCsprng),
        ) -> (Option<OutgoingViewingKey>, masp_primitives::sapling::PaymentAddress, AssetType, u64, MemoBytes) {
            let mut spending_key_seed = [0; 32];
            rng.fill_bytes(&mut spending_key_seed);
            let spending_key = masp_primitives::zip32::ExtendedSpendingKey::master(spending_key_seed.as_ref());

            let viewing_key = ExtendedFullViewingKey::from(&spending_key).fvk.vk;
            let (div, _g_d) = find_valid_diversifier(&mut rng);
            let payment_addr = viewing_key
                .to_payment_address(div)
                .expect("a PaymentAddress");

            (None, payment_addr, asset_type, value, MemoBytes::empty())
        }
    }

    prop_compose! {
        /// Generate an arbitrary spend description with the given value
        pub fn arb_spend_description(
            asset_type: AssetType,
            value: u64,
        )(
            address in arb_transparent_address(),
            expiration_height in arb_height(BranchId::MASP, &Network),
            mut rng in arb_rng().prop_map(TestCsprng),
            bparams_rng in arb_rng().prop_map(TestCsprng),
            prover_rng in arb_rng().prop_map(TestCsprng),
        ) -> (ExtendedSpendingKey, Diversifier, Note, Node) {
            let mut spending_key_seed = [0; 32];
            rng.fill_bytes(&mut spending_key_seed);
            let spending_key = masp_primitives::zip32::ExtendedSpendingKey::master(spending_key_seed.as_ref());

            let viewing_key = ExtendedFullViewingKey::from(&spending_key).fvk.vk;
            let (div, _g_d) = find_valid_diversifier(&mut rng);
            let payment_addr = viewing_key
                .to_payment_address(div)
                .expect("a PaymentAddress");

            let mut builder = Builder::<Network, _>::new(
                NETWORK,
                // NOTE: this is going to add 20 more blocks to the actual
                // expiration but there's no other exposed function that we could
                // use from the masp crate to specify the expiration better
                expiration_height.unwrap(),
            );
            // Add a transparent input to support our desired shielded output
            builder.add_transparent_input(TxOut { asset_type, value, address }).unwrap();
            // Finally add the shielded output that we need
            builder.add_sapling_output(None, payment_addr, asset_type, value, MemoBytes::empty()).unwrap();
            // Build a transaction in order to get its shielded outputs
            let (transaction, metadata) = builder.build(
                &MockTxProver(Mutex::new(prover_rng)),
                &FeeRule::non_standard(U64Sum::zero()),
                &mut rng,
                &mut RngBuildParams::new(bparams_rng),
            ).unwrap();
            // Extract the shielded output from the transaction
            let shielded_output = &transaction
                .sapling_bundle()
                .unwrap()
                .shielded_outputs[metadata.output_index(0).unwrap()];

            // Let's now decrypt the constructed notes
            let (note, pa, _memo) = try_sapling_note_decryption::<_, OutputDescription<<<Authorized as Authorization>::SaplingAuth as masp_primitives::transaction::components::sapling::Authorization>::Proof>>(
                &NETWORK,
                1.into(),
                &PreparedIncomingViewingKey::new(&viewing_key.ivk()),
                shielded_output,
            ).unwrap();
            assert_eq!(payment_addr, pa);
            // Make a path to out new note
            let node = Node::new(shielded_output.cmu.to_repr());
            (spending_key, div, note, node)
        }
    }

    prop_compose! {
        /// Generate an arbitrary MASP denomination
        pub fn arb_masp_digit_pos()(denom in 0..4u8) -> MaspDigitPos {
            MaspDigitPos::from(denom)
        }
    }

    // Maximum value for a note partition
    const MAX_MONEY: u64 = 100;
    // Maximum number of partitions for a note
    const MAX_SPLITS: usize = 3;

    prop_compose! {
        /// Arbitrarily partition the given vector of integers into sets and sum
        /// them
        pub fn arb_partition(values: Vec<u64>)(buckets in ((!values.is_empty()) as usize)..=values.len())(
            values in Just(values.clone()),
            assigns in collection::vec(0..buckets, values.len()),
            buckets in Just(buckets),
        ) -> Vec<u64> {
            let mut buckets = vec![0; buckets];
            for (bucket, value) in assigns.iter().zip(values) {
                buckets[*bucket] += value;
            }
            buckets
        }
    }

    prop_compose! {
        /// Generate arbitrary spend descriptions with the given asset type
        /// partitioning the given values
        pub fn arb_spend_descriptions(
            asset: AssetData,
            values: Vec<u64>,
        )(partition in arb_partition(values))(
            spend_description in partition
                .iter()
                .map(|value| arb_spend_description(
                    encode_asset_type(
                        asset.token.clone(),
                        asset.denom,
                        asset.position,
                        asset.epoch,
                    ).unwrap(),
                    *value,
                )).collect::<Vec<_>>()
        ) -> Vec<(ExtendedSpendingKey, Diversifier, Note, Node)> {
            spend_description
        }
    }

    prop_compose! {
        /// Generate arbitrary output descriptions with the given asset type
        /// partitioning the given values
        pub fn arb_output_descriptions(
            asset: AssetData,
            values: Vec<u64>,
        )(partition in arb_partition(values))(
            output_description in partition
                .iter()
                .map(|value| arb_output_description(
                    encode_asset_type(
                        asset.token.clone(),
                        asset.denom,
                        asset.position,
                        asset.epoch,
                    ).unwrap(),
                    *value,
                )).collect::<Vec<_>>()
        ) -> Vec<(Option<OutgoingViewingKey>, masp_primitives::sapling::PaymentAddress, AssetType, u64, MemoBytes)> {
            output_description
        }
    }

    prop_compose! {
        /// Generate arbitrary spend descriptions with the given asset type
        /// partitioning the given values
        pub fn arb_txouts(
            asset: AssetData,
            values: Vec<u64>,
            address: TransparentAddress,
        )(
            partition in arb_partition(values),
        ) -> Vec<TxOut> {
            partition
                .iter()
                .map(|value| TxOut {
                    asset_type: encode_asset_type(
                        asset.token.clone(),
                        asset.denom,
                        asset.position,
                        asset.epoch,
                    ).unwrap(),
                    value: *value,
                    address,
                }).collect::<Vec<_>>()
        }
    }

    prop_compose! {
        /// Generate an arbitrary shielded MASP transaction builder
        pub fn arb_shielded_builder(asset_range: impl Into<SizeRange>)(
            assets in collection::hash_map(
                arb_pre_asset_type(),
                collection::vec(..MAX_MONEY, ..MAX_SPLITS),
                asset_range,
            ),
        )(
            expiration_height in arb_height(BranchId::MASP, &Network),
            spend_descriptions in assets
                .iter()
                .map(|(asset, values)| arb_spend_descriptions(asset.clone(), values.clone()))
                .collect::<Vec<_>>(),
            output_descriptions in assets
                .iter()
                .map(|(asset, values)| arb_output_descriptions(asset.clone(), values.clone()))
                .collect::<Vec<_>>(),
            assets in Just(assets),
        ) -> (
            Builder::<Network>,
            HashMap<AssetData, u64>,
        ) {
            let mut builder = Builder::<Network, _>::new(
                NETWORK,
                // NOTE: this is going to add 20 more blocks to the actual
                // expiration but there's no other exposed function that we could
                // use from the masp crate to specify the expiration better
                expiration_height.unwrap(),
            );
            let mut leaves = Vec::new();
            // First construct a Merkle tree containing all notes to be used
            for (_esk, _div, _note, node) in spend_descriptions.iter().flatten() {
                leaves.push(*node);
            }
            let tree = FrozenCommitmentTree::new(&leaves);
            // Then use the notes knowing that they all have the same anchor
            for (idx, (esk, div, note, _node)) in spend_descriptions.iter().flatten().enumerate() {
                builder.add_sapling_spend(*esk, *div, *note, tree.path(idx)).unwrap();
            }
            for (ovk, payment_addr, asset_type, value, memo) in output_descriptions.into_iter().flatten() {
                builder.add_sapling_output(ovk, payment_addr, asset_type, value, memo).unwrap();
            }
            (builder, assets.into_iter().map(|(k, v)| (k, v.iter().sum())).collect())
        }
    }

    prop_compose! {
        /// Generate an arbitrary pre-asset type
        pub fn arb_pre_asset_type()(
            token in arb_address(),
            denom in arb_denomination(),
            position in arb_masp_digit_pos(),
            epoch in option::of(arb_epoch()),
        ) -> AssetData {
            AssetData {
                token,
                denom,
                position,
                epoch,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary shielding MASP transaction builder
        pub fn arb_shielding_builder(
            source: TransparentAddress,
            asset_range: impl Into<SizeRange>,
        )(
            assets in collection::hash_map(
                arb_pre_asset_type(),
                collection::vec(..MAX_MONEY, ..MAX_SPLITS),
                asset_range,
            ),
        )(
            expiration_height in arb_height(BranchId::MASP, &Network),
            txins in assets
                .iter()
                .map(|(asset, values)| arb_txouts(asset.clone(), values.clone(), source))
                .collect::<Vec<_>>(),
            output_descriptions in assets
                .iter()
                .map(|(asset, values)| arb_output_descriptions(asset.clone(), values.clone()))
                .collect::<Vec<_>>(),
            assets in Just(assets),
        ) -> (
            Builder::<Network>,
            HashMap<AssetData, u64>,
        ) {
            let mut builder = Builder::<Network, _>::new(
                NETWORK,
                // NOTE: this is going to add 20 more blocks to the actual
                // expiration but there's no other exposed function that we could
                // use from the masp crate to specify the expiration better
                expiration_height.unwrap(),
            );
            for txin in txins.into_iter().flatten() {
                builder.add_transparent_input(txin).unwrap();
            }
            for (ovk, payment_addr, asset_type, value, memo) in output_descriptions.into_iter().flatten() {
                builder.add_sapling_output(ovk, payment_addr, asset_type, value, memo).unwrap();
            }
            (builder, assets.into_iter().map(|(k, v)| (k, v.iter().sum())).collect())
        }
    }

    prop_compose! {
        /// Generate an arbitrary deshielding MASP transaction builder
        pub fn arb_deshielding_builder(
            target: TransparentAddress,
            asset_range: impl Into<SizeRange>,
        )(
            assets in collection::hash_map(
                arb_pre_asset_type(),
                collection::vec(..MAX_MONEY, ..MAX_SPLITS),
                asset_range,
            ),
        )(
            expiration_height in arb_height(BranchId::MASP, &Network),
            spend_descriptions in assets
                .iter()
                .map(|(asset, values)| arb_spend_descriptions(asset.clone(), values.clone()))
                .collect::<Vec<_>>(),
            txouts in assets
                .iter()
                .map(|(asset, values)| arb_txouts(asset.clone(), values.clone(), target))
                .collect::<Vec<_>>(),
            assets in Just(assets),
        ) -> (
            Builder::<Network>,
            HashMap<AssetData, u64>,
        ) {
            let mut builder = Builder::<Network, _>::new(
                NETWORK,
                // NOTE: this is going to add 20 more blocks to the actual
                // expiration but there's no other exposed function that we could
                // use from the masp crate to specify the expiration better
                expiration_height.unwrap(),
            );
            let mut leaves = Vec::new();
            // First construct a Merkle tree containing all notes to be used
            for (_esk, _div, _note, node) in spend_descriptions.iter().flatten() {
                leaves.push(*node);
            }
            let tree = FrozenCommitmentTree::new(&leaves);
            // Then use the notes knowing that they all have the same anchor
            for (idx, (esk, div, note, _node)) in spend_descriptions.into_iter().flatten().enumerate() {
                builder.add_sapling_spend(esk, div, note, tree.path(idx)).unwrap();
            }
            for txout in txouts.into_iter().flatten() {
                builder.add_transparent_output(&txout.address, txout.asset_type, txout.value).unwrap();
            }
            (builder, assets.into_iter().map(|(k, v)| (k, v.iter().sum())).collect())
        }
    }

    prop_compose! {
        /// Generate an arbitrary MASP shielded transfer
        pub fn arb_shielded_transfer(
            asset_range: impl Into<SizeRange>,
        )(asset_range in Just(asset_range.into()))(
            (builder, asset_types) in arb_shielded_builder(asset_range),
            epoch in arb_epoch(),
            prover_rng in arb_rng().prop_map(TestCsprng),
            mut rng in arb_rng().prop_map(TestCsprng),
            bparams_rng in arb_rng().prop_map(TestCsprng),
        ) -> (ShieldedTransfer, HashMap<AssetData, u64>, StoredBuildParams) {
            let mut rng_build_params = RngBuildParams::new(bparams_rng);
            let (masp_tx, metadata) = builder.clone().build(
                &MockTxProver(Mutex::new(prover_rng)),
                &FeeRule::non_standard(U64Sum::zero()),
                &mut rng,
                &mut rng_build_params,
            ).unwrap();
            (ShieldedTransfer {
                builder: builder.map_builder(WalletMap),
                metadata,
                masp_tx,
                epoch,
            }, asset_types, rng_build_params.to_stored().unwrap())
        }
    }

    prop_compose! {
        /// Generate an arbitrary MASP shielded transfer
        pub fn arb_shielding_transfer(
            source: TransparentAddress,
            asset_range: impl Into<SizeRange>,
        )(asset_range in Just(asset_range.into()))(
            (builder, asset_types) in arb_shielding_builder(
                source,
                asset_range,
            ),
            epoch in arb_epoch(),
            prover_rng in arb_rng().prop_map(TestCsprng),
            mut rng in arb_rng().prop_map(TestCsprng),
            bparams_rng in arb_rng().prop_map(TestCsprng),
        ) -> (ShieldedTransfer, HashMap<AssetData, u64>, StoredBuildParams) {
            let mut rng_build_params =  RngBuildParams::new(bparams_rng);
            let (masp_tx, metadata) = builder.clone().build(
                &MockTxProver(Mutex::new(prover_rng)),
                &FeeRule::non_standard(U64Sum::zero()),
                &mut rng,
                &mut rng_build_params,
            ).unwrap();
            (ShieldedTransfer {
                builder: builder.map_builder(WalletMap),
                metadata,
                masp_tx,
                epoch,
            }, asset_types, rng_build_params.to_stored().unwrap())
        }
    }

    prop_compose! {
        /// Generate an arbitrary MASP shielded transfer
        pub fn arb_deshielding_transfer(
            target: TransparentAddress,
            asset_range: impl Into<SizeRange>,
        )(asset_range in Just(asset_range.into()))(
            (builder, asset_types) in arb_deshielding_builder(
                target,
                asset_range,
            ),
            epoch in arb_epoch(),
            prover_rng in arb_rng().prop_map(TestCsprng),
            mut rng in arb_rng().prop_map(TestCsprng),
            bparams_rng in arb_rng().prop_map(TestCsprng),
        ) -> (ShieldedTransfer, HashMap<AssetData, u64>, StoredBuildParams) {
            let mut rng_build_params = RngBuildParams::new(bparams_rng);
            let (masp_tx, metadata) = builder.clone().build(
                &MockTxProver(Mutex::new(prover_rng)),
                &FeeRule::non_standard(U64Sum::zero()),
                &mut rng,
                &mut rng_build_params,
            ).unwrap();
            (ShieldedTransfer {
                builder: builder.map_builder(WalletMap),
                metadata,
                masp_tx,
                epoch,
            }, asset_types, rng_build_params.to_stored().unwrap())
        }
    }
}

#[cfg(feature = "std")]
/// Implementation of MASP functionality depending on a standard filesystem
pub mod fs {
    use std::fs::{self, OpenOptions};
    use std::io::Write;

    use super::*;
    use crate::masp::shielded_ctx::ShieldedContext;
    use crate::masp::types::ContextSyncStatus;
    use crate::masp::utils::ShieldedUtils;

    /// Shielded context file name
    const FILE_NAME: &str = "shielded.dat";
    const TMP_FILE_NAME: &str = "shielded.tmp";
    const SPECULATIVE_FILE_NAME: &str = "speculative_shielded.dat";
    const SPECULATIVE_TMP_FILE_NAME: &str = "speculative_shielded.tmp";

    #[derive(Debug, BorshSerialize, BorshDeserialize, Clone)]
    /// An implementation of ShieldedUtils for standard filesystems
    pub struct FsShieldedUtils {
        #[borsh(skip)]
        context_dir: PathBuf,
    }

    impl FsShieldedUtils {
        /// Initialize a shielded transaction context that identifies notes
        /// decryptable by any viewing key in the given set
        pub fn new(context_dir: PathBuf) -> ShieldedContext<Self> {
            // Make sure that MASP parameters are downloaded to enable MASP
            // transaction building and verification later on
            let params_dir = get_params_dir();
            let spend_path = params_dir.join(SPEND_NAME);
            let convert_path = params_dir.join(CONVERT_NAME);
            let output_path = params_dir.join(OUTPUT_NAME);
            if !(spend_path.exists()
                && convert_path.exists()
                && output_path.exists())
            {
                #[allow(clippy::print_stdout)]
                {
                    println!("MASP parameters not present, downloading...");
                }
                masp_proofs::download_masp_parameters(None)
                    .expect("MASP parameters not present or downloadable");
                #[allow(clippy::print_stdout)]
                {
                    println!(
                        "MASP parameter download complete, resuming \
                         execution..."
                    );
                }
            }
            // Finally initialize a shielded context with the supplied directory

            let sync_status =
                if fs::read(context_dir.join(SPECULATIVE_FILE_NAME)).is_ok() {
                    // Load speculative state
                    ContextSyncStatus::Speculative
                } else {
                    ContextSyncStatus::Confirmed
                };

            let utils = Self { context_dir };
            ShieldedContext {
                utils,
                sync_status,
                ..Default::default()
            }
        }
    }

    impl Default for FsShieldedUtils {
        fn default() -> Self {
            Self {
                context_dir: PathBuf::from(FILE_NAME),
            }
        }
    }

    #[cfg_attr(feature = "async-send", async_trait::async_trait)]
    #[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
    impl ShieldedUtils for FsShieldedUtils {
        fn local_tx_prover(&self) -> LocalTxProver {
            if let Ok(params_dir) = env::var(ENV_VAR_MASP_PARAMS_DIR) {
                let params_dir = PathBuf::from(params_dir);
                let spend_path = params_dir.join(SPEND_NAME);
                let convert_path = params_dir.join(CONVERT_NAME);
                let output_path = params_dir.join(OUTPUT_NAME);
                LocalTxProver::new(&spend_path, &output_path, &convert_path)
            } else {
                LocalTxProver::with_default_location()
                    .expect("unable to load MASP Parameters")
            }
        }

        async fn load(
            &self,
            sync_status: ContextSyncStatus,
            force_confirmed: bool,
        ) -> std::io::Result<ShieldedContext<Self>> {
            // Try to load shielded context from file
            let file_name = if force_confirmed {
                FILE_NAME
            } else {
                match sync_status {
                    ContextSyncStatus::Confirmed => FILE_NAME,
                    ContextSyncStatus::Speculative => SPECULATIVE_FILE_NAME,
                }
            };
            let bytes = fs::read(self.context_dir.join(file_name))?;
            Ok(ShieldedContext {
                utils: self.clone(),
                ..ShieldedContext::<Self>::deserialize(&mut &bytes[..])?
            })
        }

        async fn save(
            &self,
            ctx: &ShieldedContext<Self>,
        ) -> std::io::Result<()> {
            // TODO: use mktemp crate?
            let (tmp_file_name, file_name) = match ctx.sync_status {
                ContextSyncStatus::Confirmed => (TMP_FILE_NAME, FILE_NAME),
                ContextSyncStatus::Speculative => {
                    (SPECULATIVE_TMP_FILE_NAME, SPECULATIVE_FILE_NAME)
                }
            };
            let tmp_path = self.context_dir.join(tmp_file_name);
            {
                // First serialize the shielded context into a temporary file.
                // Inability to create this file implies a simultaneuous write
                // is in progress. In this case, immediately
                // fail. This is unproblematic because the data
                // intended to be stored can always be re-fetched
                // from the blockchain.
                let mut ctx_file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(tmp_path.clone())?;
                let mut bytes = Vec::new();
                ctx.serialize(&mut bytes)
                    .expect("cannot serialize shielded context");
                ctx_file.write_all(&bytes[..])?;
            }
            // Atomically update the old shielded context file with new data.
            // Atomicity is required to prevent other client instances from
            // reading corrupt data.
            std::fs::rename(tmp_path, self.context_dir.join(file_name))?;

            // Remove the speculative file if present since it's state is
            // overruled by the confirmed one we just saved
            if let ContextSyncStatus::Confirmed = ctx.sync_status {
                let _ = std::fs::remove_file(
                    self.context_dir.join(SPECULATIVE_FILE_NAME),
                );
            }

            Ok(())
        }
    }
}
