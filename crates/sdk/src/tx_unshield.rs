use masp_primitives::asset_type::AssetType;
use masp_primitives::transaction::builder::{self, Builder};
use masp_primitives::transaction::components::sapling::fees::{
    ConvertView, InputView as SaplingInputView, OutputView as SaplingOutputView,
};
use masp_primitives::transaction::components::transparent::fees::{
    InputView as TransparentInputView, OutputView as TransparentOutputView,
};
use masp_primitives::transaction::components::I128Sum;
use namada_account::common;
use namada_core::address::MASP;
use namada_core::collections::HashSet;
use namada_core::masp::{
    AssetData, ExtendedSpendingKey, TransferSource, TransferTarget,
};
use namada_core::time::DateTimeUtc;
use namada_token::masp::shielded_wallet::ShieldedApi;
use namada_token::masp::TransferErr::Build;
use namada_token::masp::{
    MaspDataLog, MaspFeeData, MaspTransferData, ShieldedTransfer,
};
use namada_token::storage_key::balance_key;
use namada_token::{self as token, DenominatedAmount, Transfer};
pub use namada_tx::{Authorization, *};
use namada_vp::Address;
use smooth_operator::checked;
use tendermint_rpc::Error as RpcError;

use crate::args::{SdkTypes, TxUnshieldingTransferData};
use crate::error::{Error, Result, TxSubmitError};
use crate::rpc::{self, validate_amount};
use crate::signing::{self, validate_fee, SigningTxData};
use crate::{args, Namada};

/// Try to decode the given asset type and add its decoding to the supplied set.
/// Returns true only if a new decoding has been added to the given set.
async fn add_asset_type(
    asset_types: &mut HashSet<AssetData>,
    context: &impl Namada,
    asset_type: AssetType,
) -> bool {
    if let Some(asset_type) = context
        .shielded_mut()
        .await
        .decode_asset_type(context.client(), asset_type)
        .await
    {
        asset_types.insert(asset_type)
    } else {
        false
    }
}

/// Collect the asset types used in the given Builder and decode them. This
/// function provides the data necessary for offline wallets to present asset
/// type information.
async fn used_asset_types<P, K, N>(
    context: &impl Namada,
    builder: &Builder<P, K, N>,
) -> std::result::Result<HashSet<AssetData>, RpcError> {
    let mut asset_types = HashSet::new();
    // Collect all the asset types used in the Sapling inputs
    for input in builder.sapling_inputs() {
        add_asset_type(&mut asset_types, context, input.asset_type()).await;
    }
    // Collect all the asset types used in the transparent inputs
    for input in builder.transparent_inputs() {
        add_asset_type(&mut asset_types, context, input.coin().asset_type())
            .await;
    }
    // Collect all the asset types used in the Sapling outputs
    for output in builder.sapling_outputs() {
        add_asset_type(&mut asset_types, context, output.asset_type()).await;
    }
    // Collect all the asset types used in the transparent outputs
    for output in builder.transparent_outputs() {
        add_asset_type(&mut asset_types, context, output.asset_type()).await;
    }
    // Collect all the asset types used in the Sapling converts
    for output in builder.sapling_converts() {
        for (asset_type, _) in
            I128Sum::from(output.conversion().clone()).components()
        {
            add_asset_type(&mut asset_types, context, *asset_type).await;
        }
    }
    Ok(asset_types)
}

// Construct the shielded part of the transaction, if any
pub async fn construct_shielded_parts<N: Namada>(
    context: &N,
    data: Vec<MaspTransferData>,
    fee_data: Option<MaspFeeData>,
    update_ctx: bool,
    expiration: Option<DateTimeUtc>,
) -> Result<Option<(ShieldedTransfer, HashSet<AssetData>)>> {
    // Precompute asset types to increase chances of success in decoding
    // TODO: Would be better to pass addresses into this function
    let token_map = context.wallet().await.get_addresses();
    let tokens = token_map.values().collect();

    let stx_result = {
        let mut shielded = context.shielded_mut().await;
        _ = shielded
            .precompute_asset_types(context.client(), tokens)
            .await;

        shielded
            .gen_shielded_transfer(
                context, data, fee_data, expiration, update_ctx,
            )
            .await
    };

    let shielded_parts = match stx_result {
        Ok(Some(stx)) => stx,
        Ok(None) => return Ok(None),
        Err(Build {
            error: builder::Error::InsufficientFunds(_),
            data,
        }) => {
            if let Some(MaspDataLog {
                source,
                token,
                amount,
            }) = data
            {
                if let Some(source) = source {
                    return Err(TxSubmitError::NegativeBalanceAfterTransfer(
                        Box::new(source.effective_address()),
                        amount.to_string(),
                        Box::new(token.clone()),
                    )
                    .into());
                }
                return Err(TxSubmitError::MaspError(format!(
                    "Insufficient funds: Could not collect enough funds to \
                     pay for fees: token {token}, amount: {amount}"
                ))
                .into());
            }
            return Err(TxSubmitError::MaspError(
                "Insufficient funds".to_string(),
            )
            .into());
        }
        Err(err) => {
            return Err(TxSubmitError::MaspError(err.to_string()).into());
        }
    };

    // Get the decoded asset types used in the transaction to give offline
    // wallet users more information
    #[allow(clippy::disallowed_methods)]
    let asset_types = used_asset_types(context, &shielded_parts.builder)
        .await
        .unwrap_or_default();

    Ok(Some((shielded_parts, asset_types)))
}

// Check if the transaction will need to pay fees via the masp and extract the
// right masp data
pub async fn get_masp_fee_payment_amount<N: Namada>(
    context: &N,
    args: &args::Tx<SdkTypes>,
    fee_amount: DenominatedAmount,
    fee_payer: &common::PublicKey,
    gas_spending_keys: Vec<ExtendedSpendingKey>,
) -> Result<Option<MaspFeeData>> {
    let fee_payer_address = Address::from(fee_payer);
    let balance_key = balance_key(&args.fee_token, &fee_payer_address);
    #[allow(clippy::disallowed_methods)]
    let balance = rpc::query_storage_value::<_, token::Amount>(
        context.client(),
        &balance_key,
    )
    .await
    .unwrap_or_default();
    let total_fee = checked!(fee_amount.amount() * u64::from(args.gas_limit))?;

    Ok(match total_fee.checked_sub(balance) {
        Some(diff) if !diff.is_zero() => Some(MaspFeeData {
            sources: gas_spending_keys,
            target: fee_payer_address,
            token: args.fee_token.clone(),
            amount: DenominatedAmount::new(diff, fee_amount.denom()),
        }),
        _ => None,
    })
}

pub async fn signing_data<N: Namada>(
    context: &N,
    tx: &args::Tx,
    disposable_signing_key: bool,
) -> Result<SigningTxData> {
    let signing_data = signing::aux_signing_data(
        context,
        tx,
        Some(MASP),
        Some(MASP),
        vec![],
        disposable_signing_key,
    )
    .await?;

    Ok(signing_data)
}

pub async fn fee_data<N: Namada>(
    context: &N,
    args: &args::TxUnshieldingTransfer,
    signing_data: &SigningTxData,
) -> Result<(DenominatedAmount, Option<MaspFeeData>)> {
    let fee_per_gas_unit = validate_fee(context, &args.tx).await?;

    // Add masp fee payment if necessary
    let masp_fee_data = get_masp_fee_payment_amount(
        context,
        &args.tx,
        fee_per_gas_unit,
        &signing_data.fee_payer,
        args.gas_spending_keys.clone(),
    )
    .await?;

    Ok((fee_per_gas_unit, masp_fee_data))
}

/// .
///
/// # Errors
///
/// This function will return an error if .
pub async fn validate_amounts<N: Namada>(
    context: &N,
    data: &Vec<args::TxUnshieldingTransferData>,
    force: bool,
) -> Result<Vec<(DenominatedAmount, args::TxUnshieldingTransferData)>> {
    let mut res = vec![];
    for d in data {
        // Validate the amount given
        let validated_amount =
            validate_amount(context, d.amount.to_owned(), &d.token, force)
                .await?;

        let value = (validated_amount, d.clone());
        res.push(value);
    }

    Ok(res)
}

pub async fn add_transfer_data(
    source: ExtendedSpendingKey,
    amounts: Vec<(DenominatedAmount, args::TxUnshieldingTransferData)>,
    mut data: Transfer,
    mut transfer_data: Vec<MaspTransferData>,
) -> Result<(Transfer, Vec<MaspTransferData>)> {
    for (validated_amount, d) in amounts {
        transfer_data.push(MaspTransferData {
            source: TransferSource::ExtendedSpendingKey(source),
            target: TransferTarget::Address(d.target.to_owned()),
            token: d.token.to_owned(),
            amount: validated_amount,
        });

        data = data
            .transfer(
                MASP,
                d.target.to_owned(),
                d.token.to_owned(),
                validated_amount,
            )
            .ok_or(Error::Other("Combined transfer overflows".to_string()))?;
    }

    Ok((data, transfer_data))
}

pub fn add_fee_data(
    masp_fee_data: &Option<MaspFeeData>,
    data: Transfer,
) -> Result<Transfer> {
    match masp_fee_data {
        Some(fee_data) => {
            // Add another unshield to the list
            data.transfer(
                MASP,
                fee_data.target.to_owned(),
                fee_data.token.to_owned(),
                fee_data.amount,
            )
            .ok_or(Error::Other("Combined transfer overflows".to_string()))
        }
        None => Ok(data),
    }
}

pub fn add_shielded_parts_fn(
    shielded_parts: (ShieldedTransfer, HashSet<AssetData>),
) -> impl FnOnce(&mut Tx, &mut Transfer) -> Result<()> {
    let add_shielded_parts = |tx: &mut Tx, data: &mut token::Transfer| {
        // Add the MASP Transaction and its Builder to facilitate validation
        let (
            ShieldedTransfer {
                builder,
                masp_tx,
                metadata,
                epoch: _,
            },
            asset_types,
        ) = shielded_parts;
        // Add a MASP Transaction section to the Tx and get the tx hash
        let shielded_section_hash = tx.add_masp_tx_section(masp_tx).1;

        tx.add_masp_builder(MaspBuilder {
            asset_types,
            // Store how the Info objects map to Descriptors/Outputs
            metadata,
            // Store the data that was used to construct the Transaction
            builder,
            // Link the Builder to the Transaction by hash code
            target: shielded_section_hash,
        });

        data.shielded_section_hash = Some(shielded_section_hash);
        tracing::debug!("Transfer data {data:?}");
        Ok(())
    };

    add_shielded_parts
}
