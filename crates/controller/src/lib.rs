//! Inflation PD-controller

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::arithmetic_side_effects,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::print_stderr
)]

use namada_core::arith::{self, checked};
use namada_core::dec::Dec;
use namada_core::uint::Uint;
use thiserror::Error;

#[allow(missing_docs)]
#[derive(Clone, Debug)]
pub struct PDController {
    total_native_amount: Uint,
    max_reward_rate: Dec,
    last_inflation_amount: Uint,
    p_gain_nom: Dec,
    d_gain_nom: Dec,
    epochs_per_year: u64,
    target_metric: Dec,
    last_metric: Dec,
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Arithmetic {0}")]
    Arith(#[from] arith::Error),
    #[error("Decimal {0}")]
    Dec(#[from] namada_core::dec::Error),
    #[error("Max inflation overflow")]
    MaxInflationOverflow,
    #[error("Inflation amount overflow")]
    InflationOverflow,
}

impl PDController {
    /// Instantiate a new PD-controller
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        total_native_amount: Uint,
        max_reward_rate: Dec,
        last_inflation_amount: Uint,
        p_gain_nom: Dec,
        d_gain_nom: Dec,
        epochs_per_year: u64,
        target_metric: Dec,
        last_metric: Dec,
    ) -> PDController {
        PDController {
            total_native_amount,
            max_reward_rate,
            last_inflation_amount,
            p_gain_nom,
            d_gain_nom,
            epochs_per_year,
            target_metric,
            last_metric,
        }
    }

    /// Compute inflation amount
    pub fn compute_inflation(
        &self,
        control_coeff: Dec,
        current_metric: Dec,
    ) -> Result<Uint, Error> {
        let control = self.compute_control(control_coeff, current_metric)?;
        self.compute_inflation_aux(control)
    }

    /// Get total native amount as decimal
    pub fn get_total_native_dec(&self) -> Result<Dec, Error> {
        Dec::try_from(self.total_native_amount).map_err(Into::into)
    }

    /// Get epochs per year
    pub fn get_epochs_per_year(&self) -> u64 {
        self.epochs_per_year
    }

    fn get_max_inflation(&self) -> Result<Uint, Error> {
        let total_native = self.get_total_native_dec()?;
        let epochs_py: Dec = self.epochs_per_year.into();
        let max_inflation =
            checked!(total_native * self.max_reward_rate / epochs_py)?;
        max_inflation.to_uint().ok_or(Error::MaxInflationOverflow)
    }

    // TODO: could possibly use I256 instead of Dec here (need to account for
    // negative vals)
    fn compute_inflation_aux(&self, control: Dec) -> Result<Uint, Error> {
        let last_inflation_amount = Dec::try_from(self.last_inflation_amount)?;
        let new_inflation_amount = checked!(last_inflation_amount + control)?;
        let new_inflation_amount = if new_inflation_amount.is_negative() {
            Uint::zero()
        } else {
            new_inflation_amount
                .to_uint()
                .ok_or(Error::InflationOverflow)?
        };

        let max_inflation = self.get_max_inflation()?;
        Ok(std::cmp::min(new_inflation_amount, max_inflation))
    }

    // NOTE: This formula is the comactification of all the old intermediate
    // computations that were done in multiple steps (as in the specs)
    fn compute_control(
        &self,
        coeff: Dec,
        current_metric: Dec,
    ) -> Result<Dec, arith::Error> {
        let val: Dec = checked!(
            current_metric * (self.d_gain_nom - self.p_gain_nom)
                + (self.target_metric * self.p_gain_nom)
                - (self.last_metric * self.d_gain_nom)
        )?;
        checked!(coeff * val)
    }
}
