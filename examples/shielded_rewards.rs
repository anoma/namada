use std::io::Write;

use namada_core::token::DenominatedAmount;
use namada_core::uint::Uint;

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

/// Computes bounds on inflation, token precision, and nominal proportional gain
/// sufficient to yield non-zero rewards
pub fn main() -> std::io::Result<()> {
    let stdin = std::io::stdin();

    // Let Y be the total MASP epochs per year
    print!("MASP epochs per year ({}): ", DEFAULT_MASP_EPOCHS_PER_YEAR);
    std::io::stdout().flush()?;
    let mut masp_epochs_per_year = String::new();
    stdin.read_line(&mut masp_epochs_per_year)?;
    let masp_epochs_per_year = masp_epochs_per_year.trim();
    let masp_epochs_per_year = if masp_epochs_per_year.is_empty() {
        DEFAULT_MASP_EPOCHS_PER_YEAR
    } else {
        masp_epochs_per_year
            .parse::<u64>()
            .map_err(std::io::Error::other)?
    };

    // Get the currency code for the native token
    print!("Native token currency code ({}): ", DEFAULT_NATIVE_CODE);
    std::io::stdout().flush()?;
    let mut native_code = String::new();
    stdin.read_line(&mut native_code)?;
    let native_code = native_code.trim();
    let native_code = if native_code.is_empty() {
        DEFAULT_NATIVE_CODE
    } else {
        native_code
    };

    // Get the decimal places for the native token
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

    // Get the exchange rate for the native token
    print!("Exchange rate USD/{}: ", native_code);
    std::io::stdout().flush()?;
    let mut native_exchange_rate = String::new();
    stdin.read_line(&mut native_exchange_rate)?;
    let native_exchange_rate = native_exchange_rate
        .trim()
        .parse::<DenominatedAmount>()
        .map_err(std::io::Error::other)?;

    // Let S be the total supply of NAM
    print!("Native token supply in {}: ", native_code);
    std::io::stdout().flush()?;
    let mut native_supply = String::new();
    stdin.read_line(&mut native_supply)?;
    let native_supply = native_supply
        .trim()
        .parse::<DenominatedAmount>()
        .map_err(std::io::Error::other)?;
    let native_supply = native_supply
        .increase_precision(native_decimals.into())
        .map_err(std::io::Error::other)?;

    // Get the currency code for the incentivised token
    print!(
        "Incentivised token currency code ({}): ",
        DEFAULT_INCENT_CODE
    );
    std::io::stdout().flush()?;
    let mut incent_code = String::new();
    stdin.read_line(&mut incent_code)?;
    let incent_code = incent_code.trim();
    let incent_code = if incent_code.is_empty() {
        DEFAULT_INCENT_CODE
    } else {
        incent_code
    };

    // Get the decimal places of the incentivised token
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

    // Get the exchange rate for the incentivised token
    print!("Exchange rate USD/{}: ", incent_code);
    std::io::stdout().flush()?;
    let mut incent_exchange_rate = String::new();
    stdin.read_line(&mut incent_exchange_rate)?;
    let incent_exchange_rate = incent_exchange_rate
        .trim()
        .parse::<DenominatedAmount>()
        .map_err(std::io::Error::other)?;

    // Let X be the target amount of TOK locked in the MASP
    print!("Target locked amount in {}: ", incent_code);
    std::io::stdout().flush()?;
    let mut lock_target = String::new();
    stdin.read_line(&mut lock_target)?;
    let lock_target = lock_target
        .trim()
        .parse::<DenominatedAmount>()
        .map_err(std::io::Error::other)?;
    let lock_target = lock_target
        .increase_precision(incent_decimals.into())
        .map_err(std::io::Error::other)?;

    // Let M be the desired minimum amount of TOK required to get rewards
    print!("Incentivisation threshold in {}: ", incent_code);
    std::io::stdout().flush()?;
    let mut incent_threshold = String::new();
    stdin.read_line(&mut incent_threshold)?;
    let incent_threshold = incent_threshold
        .trim()
        .parse::<DenominatedAmount>()
        .map_err(std::io::Error::other)?;
    let incent_threshold = incent_threshold
        .increase_precision(incent_decimals.into())
        .map_err(std::io::Error::other)?;

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
    print!("Inflation (>= {}) in {}: ", min_inflation, native_code);
    std::io::stdout().flush()?;

    // Let I be the computed amount of uNAM inflation in a single round of the
    // mechanism due to the incentivised token TOK.
    let mut inflation = String::new();
    stdin.read_line(&mut inflation)?;
    let inflation = inflation
        .trim()
        .parse::<DenominatedAmount>()
        .map_err(std::io::Error::other)?;
    let inflation = inflation
        .increase_precision(native_decimals.into())
        .map_err(std::io::Error::other)?;

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
    print!("Precision ([{}, {}]): ", min_precision, max_precision);
    std::io::stdout().flush()?;
    let mut precision = String::new();
    stdin.read_line(&mut precision)?;
    let precision = Uint::from_str_radix(precision.trim(), 10)
        .map_err(std::io::Error::other)?;

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
    print!("Maximum reward rate (>= {}): ", max_reward_rate_threshold);
    std::io::stdout().flush()?;
    let mut maximum_reward_rate = String::new();
    stdin.read_line(&mut maximum_reward_rate)?;
    let maximum_reward_rate = maximum_reward_rate
        .trim()
        .parse::<DenominatedAmount>()
        .map_err(std::io::Error::other)?;

    // Let T be the threshold such that shielded rewards are guaranteed when E
    // exceeds T
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
            .parse::<DenominatedAmount>()
            .map_err(std::io::Error::other)?
    } else {
        inflation_threshold
            .parse::<DenominatedAmount>()
            .map_err(std::io::Error::other)?
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
