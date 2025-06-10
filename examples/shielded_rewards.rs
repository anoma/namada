use std::fs::OpenOptions;
use std::io::{Error, Read, Write};

use namada_core::token::DenominatedAmount;
use namada_core::uint::Uint;
use serde::{Deserialize, Serialize};

/// Default value for the native currency code
const DEFAULT_NATIVE_CODE: &str = "NAM";
/// Default decimal points in the native token
const DEFAULT_NATIVE_DECIMALS: u8 = 6;
/// Default value for the incentivised token currency code
const DEFAULT_INCENT_CODE: &str = "OSMO";
/// Default decimal points for the incentivised token
const DEFAULT_INCENT_DECIMALS: u8 = 6;
/// Default number of MASP epochs per year
const DEFAULT_MASP_EPOCHS_PER_YEAR: u64 = 365;
/// Default proportion of the target locked amount that triggers inflation
const DEFAULT_INFLATION_THRESHOLD: &str = "0.01";
/// Number of decimal places to report the nominal proportional gain with
const KP_GAIN_DECIMALS: u8 = 6;
/// Number of decimal places to report the maximum reward rate threshold with
const MAX_REWARD_RATE_THRESHOLD_DECIMALS: u8 = 75;

#[derive(Serialize, Deserialize, Default)]
/// Parameters that control the operation of shielded rewards
pub struct ShieldedRewardsParams {
    /// MASP epochs per year
    masp_epochs_per_year: Option<u64>,
    /// Native token currency code
    native_code: Option<String>,
    /// Native token decimal places
    native_decimals: Option<u8>,
    /// Exchange rate USD/native token
    native_exchange_rate: Option<DenominatedAmount>,
    /// Native token supply in native token
    native_supply: Option<DenominatedAmount>,
    /// Incentivised token currency code
    incent_code: Option<String>,
    /// Incentivised token decimal places
    incent_decimals: Option<u8>,
    /// Exchange rate USD/incentivised token
    incent_exchange_rate: Option<DenominatedAmount>,
    /// Target locked amount in incentivised token
    lock_target: Option<DenominatedAmount>,
    /// Incentivisation threshold in incentivised token
    incent_threshold: Option<DenominatedAmount>,
    /// Inflation in native token
    inflation: Option<DenominatedAmount>,
    /// Precision
    precision: Option<Uint>,
    /// Maximum reward rate
    maximum_reward_rate: Option<DenominatedAmount>,
    /// Locked amount tolerance as proportion of target
    inflation_threshold: Option<DenominatedAmount>,
}

/// Computes bounds on inflation, token precision, and nominal proportional gain
/// sufficient to yield non-zero rewards
pub fn main() -> std::io::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: shielded-rewards <params.toml>");
        eprintln!(
            "Reads a shielded rewards parameter TOML at the given path, and \
             computes how the varous parameters constrain each other.
                   Any missing parameters are interactively requested and \
             written to the path,."
        );
        return Result::Err(Error::other("Incorrect command line arguments."));
    }
    let mut params = String::new();
    let mut params_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&args[1])?;
    params_file.read_to_string(&mut params)?;
    std::mem::drop(params_file);
    let mut params: ShieldedRewardsParams =
        toml::from_str(&params).map_err(Error::other)?;
    let stdin = std::io::stdin();

    // Let Y be the total MASP epochs per year
    let masp_epochs_per_year =
        if let Some(masp_epochs_per_year) = params.masp_epochs_per_year {
            println!("MASP epochs per year: {}", masp_epochs_per_year);
            masp_epochs_per_year
        } else {
            print!("MASP epochs per year ({}): ", DEFAULT_MASP_EPOCHS_PER_YEAR);
            std::io::stdout().flush()?;
            let mut masp_epochs_per_year = String::new();
            stdin.read_line(&mut masp_epochs_per_year)?;
            let masp_epochs_per_year = masp_epochs_per_year.trim();
            let masp_epochs_per_year = if masp_epochs_per_year.is_empty() {
                DEFAULT_MASP_EPOCHS_PER_YEAR
            } else {
                masp_epochs_per_year
                    .parse()
                    .map_err(std::io::Error::other)?
            };
            params.masp_epochs_per_year = Some(masp_epochs_per_year);
            std::fs::write(
                &args[1],
                toml::to_string_pretty(&params).map_err(Error::other)?,
            )?;
            masp_epochs_per_year
        };

    // Get the currency code for the native token
    let native_code = if let Some(native_code) = &params.native_code {
        println!("Native token currency code: {}", native_code);
        native_code.clone()
    } else {
        print!("Native token currency code ({}): ", DEFAULT_NATIVE_CODE);
        std::io::stdout().flush()?;
        let mut native_code = String::new();
        stdin.read_line(&mut native_code)?;
        let native_code = native_code.trim();
        let native_code = if native_code.is_empty() {
            DEFAULT_NATIVE_CODE
        } else {
            native_code
        }
        .to_string();
        params.native_code = Some(native_code.clone());
        std::fs::write(
            &args[1],
            toml::to_string_pretty(&params).map_err(Error::other)?,
        )?;
        native_code
    };

    // Get the decimal places for the native token
    let native_decimals = if let Some(native_decimals) = params.native_decimals
    {
        println!("Native token decimal places: {}", native_decimals);
        native_decimals
    } else {
        print!(
            "Native token decimal places ({}): ",
            DEFAULT_NATIVE_DECIMALS
        );
        std::io::stdout().flush()?;
        let mut native_decimals = String::new();
        stdin.read_line(&mut native_decimals)?;
        let native_decimals = native_decimals.trim();
        let native_decimals = if native_decimals.is_empty() {
            DEFAULT_NATIVE_DECIMALS
        } else {
            native_decimals
                .parse::<u8>()
                .map_err(std::io::Error::other)?
        };
        params.native_decimals = Some(native_decimals);
        std::fs::write(
            &args[1],
            toml::to_string_pretty(&params).map_err(Error::other)?,
        )?;
        native_decimals
    };

    // Get the exchange rate for the native token
    let native_exchange_rate =
        if let Some(native_exchange_rate) = params.native_exchange_rate {
            println!(
                "Exchange rate USD/{}: {}",
                native_code, native_exchange_rate
            );
            native_exchange_rate
        } else {
            print!("Exchange rate USD/{}: ", native_code);
            std::io::stdout().flush()?;
            let mut native_exchange_rate_str = String::new();
            stdin.read_line(&mut native_exchange_rate_str)?;
            let native_exchange_rate_str = native_exchange_rate_str.trim();
            let native_exchange_rate = native_exchange_rate_str
                .parse::<DenominatedAmount>()
                .map_err(std::io::Error::other)?;
            params.native_exchange_rate = Some(native_exchange_rate);
            std::fs::write(
                &args[1],
                toml::to_string_pretty(&params).map_err(Error::other)?,
            )?;
            native_exchange_rate
        };

    // Let S be the total supply of NAM
    let native_supply = if let Some(native_supply) = params.native_supply {
        println!("Native token supply in {}: {}", native_code, native_supply);
        native_supply
    } else {
        print!("Native token supply in {}: ", native_code);
        std::io::stdout().flush()?;
        let mut native_supply_str = String::new();
        stdin.read_line(&mut native_supply_str)?;
        let native_supply_str = native_supply_str.trim();
        let native_supply = native_supply_str
            .parse::<DenominatedAmount>()
            .map_err(std::io::Error::other)?;
        let native_supply = native_supply
            .increase_precision(native_decimals.into())
            .map_err(std::io::Error::other)?;
        params.native_supply = Some(native_supply);
        std::fs::write(
            &args[1],
            toml::to_string_pretty(&params).map_err(Error::other)?,
        )?;
        native_supply
    };

    // Get the currency code for the incentivised token
    let incent_code = if let Some(incent_code) = &params.incent_code {
        println!("Incentivised token currency code: {}", incent_code,);
        incent_code.clone()
    } else {
        println!(
            "Incentivised token currency code ({}): ",
            DEFAULT_INCENT_CODE,
        );
        std::io::stdout().flush()?;
        let mut incent_code = String::new();
        stdin.read_line(&mut incent_code)?;
        let incent_code = incent_code.trim();
        let incent_code = if incent_code.is_empty() {
            DEFAULT_INCENT_CODE
        } else {
            incent_code
        }
        .to_string();
        params.incent_code = Some(incent_code.clone());
        std::fs::write(
            &args[1],
            toml::to_string_pretty(&params).map_err(Error::other)?,
        )?;
        incent_code
    };

    // Get the decimal places of the incentivised token
    let incent_decimals = if let Some(incent_decimals) = params.incent_decimals
    {
        println!("Incentivised token decimal places: {}", incent_decimals,);
        incent_decimals
    } else {
        print!(
            "Incentivised token decimal places ({}): ",
            DEFAULT_INCENT_DECIMALS
        );
        std::io::stdout().flush()?;
        let mut incent_decimals = String::new();
        stdin.read_line(&mut incent_decimals)?;
        let incent_decimals = incent_decimals.trim();
        let incent_decimals = if incent_decimals.is_empty() {
            DEFAULT_INCENT_DECIMALS
        } else {
            incent_decimals
                .parse::<u8>()
                .map_err(std::io::Error::other)?
        };
        params.incent_decimals = Some(incent_decimals);
        std::fs::write(
            &args[1],
            toml::to_string_pretty(&params).map_err(Error::other)?,
        )?;
        incent_decimals
    };

    // Get the exchange rate for the incentivised token
    let incent_exchange_rate =
        if let Some(incent_exchange_rate) = params.incent_exchange_rate {
            println!(
                "Exchange rate USD/{}: {}",
                incent_code, incent_exchange_rate
            );
            incent_exchange_rate
        } else {
            print!("Exchange rate USD/{}: ", incent_code);
            std::io::stdout().flush()?;
            let mut incent_exchange_rate_str = String::new();
            stdin.read_line(&mut incent_exchange_rate_str)?;
            let incent_exchange_rate_str = incent_exchange_rate_str.trim();
            let incent_exchange_rate = incent_exchange_rate_str
                .parse::<DenominatedAmount>()
                .map_err(std::io::Error::other)?;
            params.incent_exchange_rate = Some(incent_exchange_rate);
            std::fs::write(
                &args[1],
                toml::to_string_pretty(&params).map_err(Error::other)?,
            )?;
            incent_exchange_rate
        };

    // Let X be the target amount of TOK locked in the MASP
    let lock_target = if let Some(lock_target) = params.lock_target {
        println!("Target locked amount in {}: {}", incent_code, lock_target);
        lock_target
    } else {
        print!("Target locked amount in {}: ", incent_code);
        std::io::stdout().flush()?;
        let mut lock_target_str = String::new();
        stdin.read_line(&mut lock_target_str)?;
        let lock_target_str = lock_target_str.trim();
        let lock_target = lock_target_str
            .parse::<DenominatedAmount>()
            .map_err(std::io::Error::other)?;
        let lock_target = lock_target
            .increase_precision(incent_decimals.into())
            .map_err(std::io::Error::other)?;
        params.lock_target = Some(lock_target);
        std::fs::write(
            &args[1],
            toml::to_string_pretty(&params).map_err(Error::other)?,
        )?;
        lock_target
    };

    // Let M be the desired minimum amount of TOK required to get rewards
    let incent_threshold =
        if let Some(incent_threshold) = params.incent_threshold {
            println!(
                "Incentivisation threshold in {}: {}",
                incent_code, incent_threshold
            );
            incent_threshold
        } else {
            print!("Incentivisation threshold in {}: ", incent_code);
            std::io::stdout().flush()?;
            let mut incent_threshold_str = String::new();
            stdin.read_line(&mut incent_threshold_str)?;
            let incent_threshold = incent_threshold_str
                .trim()
                .parse::<DenominatedAmount>()
                .map_err(std::io::Error::other)?;
            let incent_threshold = incent_threshold
                .increase_precision(incent_decimals.into())
                .map_err(std::io::Error::other)?;
            params.incent_threshold = Some(incent_threshold);
            std::fs::write(
                &args[1],
                toml::to_string_pretty(&params).map_err(Error::other)?,
            )?;
            incent_threshold
        };

    // It must be the case that X/I <= M. Or equivalently I >= X/M.
    let min_inflation = lock_target.amount().raw_amount()
        / incent_threshold.amount().raw_amount();
    let min_inflation =
        DenominatedAmount::new(min_inflation.into(), native_decimals.into());
    println!(
        "Inflation must be more than {} {} to realize non-zero rewards for \
         users holding more than {} {} in a pool holding {} {}.",
        min_inflation,
        native_code,
        incent_threshold,
        incent_code,
        lock_target,
        incent_code
    );

    // Let I be the computed amount of uNAM inflation in a single round of the
    // mechanism due to the incentivised token TOK.
    let inflation = if let Some(inflation) = params.inflation {
        println!(
            "Inflation in {} (>= {}): {}",
            native_code, min_inflation, inflation
        );
        inflation
    } else {
        print!("Inflation in {} (>= {}): ", native_code, min_inflation);
        std::io::stdout().flush()?;
        let mut inflation_str = String::new();
        stdin.read_line(&mut inflation_str)?;
        let inflation = inflation_str
            .trim()
            .parse::<DenominatedAmount>()
            .map_err(std::io::Error::other)?;
        let inflation = inflation
            .increase_precision(native_decimals.into())
            .map_err(std::io::Error::other)?;
        params.inflation = Some(inflation);
        std::fs::write(
            &args[1],
            toml::to_string_pretty(&params).map_err(Error::other)?,
        )?;
        inflation
    };

    // Let P be the precision of the token TOK. A necessary condition for there
    // to be inflation is that floor(I*P/X)>=1.
    let min_precision =
        lock_target.amount().raw_amount() / inflation.amount().raw_amount();
    // A necessary condition for users holding more than the threshold to get
    // rewards is that P <= M.
    let max_precision = incent_threshold.amount().raw_amount();
    println!(
        "At an inflation of {} {}, the precision must be between {} and {} in \
         order to realize non-zero rewards.",
        inflation, native_code, min_precision, max_precision
    );

    // Get a precision, P, in the computed range from the user
    let precision = if let Some(precision) = params.precision {
        println!(
            "Precision ([{}, {}]): {}",
            min_precision, max_precision, precision
        );
        precision
    } else {
        print!("Precision ([{}, {}]): ", min_precision, max_precision);
        std::io::stdout().flush()?;
        let mut precision_str = String::new();
        stdin.read_line(&mut precision_str)?;
        let precision = Uint::from_str_radix(precision_str.trim(), 10)
            .map_err(std::io::Error::other)?;
        params.precision = Some(precision);
        std::fs::write(
            &args[1],
            toml::to_string_pretty(&params).map_err(Error::other)?,
        )?;
        precision
    };

    // A reward of I*P/X uNAM is obtained for every P TOK locked in the pool
    let reward_per_precision = (inflation.amount().raw_amount() * precision)
        / lock_target.amount().raw_amount();
    let precision =
        DenominatedAmount::new(precision.into(), incent_decimals.into());
    let reward_per_precision = DenominatedAmount::new(
        reward_per_precision.into(),
        native_decimals.into(),
    );
    let precision_usd = precision.checked_mul(incent_exchange_rate).ok_or(
        std::io::Error::other("unable to multiply precision by exchange rate"),
    )?;
    let reward_usd_per_precision = reward_per_precision
        .checked_mul(native_exchange_rate)
        .ok_or(std::io::Error::other(
            "unable to multiply minimum reward by exchange rate",
        ))?;
    let exchanged_reward_rate = reward_usd_per_precision
        .checked_div(precision_usd)
        .ok_or(std::io::Error::other("unable to divide "))?;
    // Summarise the rewards from the perrspective of end-users
    println!(
        "For every {} {} held in the shielded pool, a shielded reward of {} \
         {} will be distributed every MASP epoch. Concretely this means that \
         for every {} USD worth of {} held in the shielded pool, a {} \
         shielded reward worth {} USD will be rewarded. Hence there's \
         effectively a reward rate of {} when all quantities are expressed in \
         the same units.",
        precision,
        incent_code,
        reward_per_precision,
        native_code,
        precision_usd,
        incent_code,
        native_code,
        reward_usd_per_precision,
        exchanged_reward_rate,
    );

    // Let C be the maximum reward rate for the token TOK. It must be that
    // S*C/Y >= I, which implies that the reward rate C >= (I*Y)/S
    let inflation_per_year = inflation
        .checked_mul(DenominatedAmount::new(
            masp_epochs_per_year.into(),
            0.into(),
        ))
        .ok_or(std::io::Error::other(
            "unable to compute inflation per year",
        ))?;
    let max_reward_rate_threshold = inflation_per_year
        .checked_div_precision(
            native_supply,
            MAX_REWARD_RATE_THRESHOLD_DECIMALS.into(),
        )
        .ok_or(std::io::Error::other(
            "unable to divide inflation by native supply",
        ))?;
    println!(
        "The maximum reward rate must exceed {} for it to be possible to \
         achieve an inflation of {} {}.",
        max_reward_rate_threshold, inflation, native_code
    );

    // Get the maximum reward rate, C, from the user.
    let maximum_reward_rate =
        if let Some(maximum_reward_rate) = params.maximum_reward_rate {
            println!(
                "Maximum reward rate (>= {}): {}",
                max_reward_rate_threshold, maximum_reward_rate
            );
            maximum_reward_rate
        } else {
            print!("Maximum reward rate (>= {}): ", max_reward_rate_threshold);
            std::io::stdout().flush()?;
            let mut maximum_reward_rate_str = String::new();
            stdin.read_line(&mut maximum_reward_rate_str)?;
            let maximum_reward_rate = maximum_reward_rate_str
                .trim()
                .parse::<DenominatedAmount>()
                .map_err(std::io::Error::other)?;
            params.maximum_reward_rate = Some(maximum_reward_rate);
            std::fs::write(
                &args[1],
                toml::to_string_pretty(&params).map_err(Error::other)?,
            )?;
            maximum_reward_rate
        };

    // Let T be the threshold such that shielded rewards are guaranteed when E
    // exceeds T
    let inflation_threshold =
        if let Some(inflation_threshold) = params.inflation_threshold {
            println!(
                "Locked amount tolerance as proportion of target: {}",
                inflation_threshold
            );
            inflation_threshold
        } else {
            print!(
                "Locked amount tolerance as proportion of target ({}): ",
                DEFAULT_INFLATION_THRESHOLD
            );
            std::io::stdout().flush()?;
            let mut inflation_threshold = String::new();
            stdin.read_line(&mut inflation_threshold)?;
            let inflation_threshold = inflation_threshold.trim();
            let inflation_threshold = if inflation_threshold.is_empty() {
                DEFAULT_INFLATION_THRESHOLD
            } else {
                inflation_threshold
            }
            .parse::<DenominatedAmount>()
            .map_err(std::io::Error::other)?;
            params.inflation_threshold = Some(inflation_threshold);
            std::fs::write(
                &args[1],
                toml::to_string_pretty(&params).map_err(Error::other)?,
            )?;
            inflation_threshold
        };

    let inflation_threshold = lock_target
        .checked_mul(inflation_threshold)
        .ok_or(std::io::Error::other(
            "unable to multiply lock target by inflation threshold",
        ))?
        .approximate(native_decimals.into())
        .map_err(std::io::Error::other)?
        .0;

    // Setting KP_nom >= (I*Y)/(C*T) makes the control value exceed I since it
    // implies KP_nom*(C/Y)*T >= I which implies KP_nom*(C/Y)*E >= I
    let nominal_proportional_gain_threshold = inflation_per_year
        .redenominate(0)
        .checked_div_precision(
            maximum_reward_rate
                .checked_mul(inflation_threshold.redenominate(0))
                .ok_or(std::io::Error::other(
                    "unable to multiply maximum reward rate by inflation \
                     threshold",
                ))?,
            KP_GAIN_DECIMALS.into(),
        )
        .ok_or(std::io::Error::other(
            "unable to multiply maximum reward rate by inflation threshold",
        ))?;
    println!(
        "Under the assumption that the locked amount is more than {} {} less \
         than the target and the error derivative is non-positive, a nominal \
         proportional gain exceeding {} is sufficient to achieve inflation \
         exceeding {} {}",
        inflation_threshold,
        incent_code,
        nominal_proportional_gain_threshold,
        inflation,
        native_code
    );
    Ok(())
}
