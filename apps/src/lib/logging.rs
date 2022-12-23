//! A module for anything related to logging
use std::env;

use color_eyre::eyre::Result;
use eyre::WrapErr;
use tracing_log::LogTracer;
use tracing_subscriber::filter::{Directive, EnvFilter};
use tracing_subscriber::fmt::Subscriber;

pub const ENV_KEY: &str = "NAMADA_LOG";

// Env var to enable/disable color log
const COLOR_ENV_KEY: &str = "NAMADA_LOG_COLOR";
// Env var to enable/disable json formatting
const JSON_ENV_KEY: &str = "NAMADA_JSON_FMT";

pub fn init_from_env_or(default: impl Into<Directive>) -> Result<()> {
    let filter = filter_from_env_or(default);
    set_subscriber(filter)?;
    init_log_tracer()
}

pub fn filter_from_env_or(default: impl Into<Directive>) -> EnvFilter {
    env::var(ENV_KEY)
        .map(EnvFilter::new)
        .unwrap_or_else(|_| EnvFilter::default().add_directive(default.into()))
}

pub fn set_subscriber(filter: EnvFilter) -> Result<()> {
    let with_color = if let Ok(val) = env::var(COLOR_ENV_KEY) {
        val.to_ascii_lowercase() != "false"
    } else {
        true
    };
    let json_format = if let Ok(val) = env::var(JSON_ENV_KEY) {
        val.to_ascii_lowercase() != "false"
    } else {
        true
    };
    if json_format {
        let my_collector = Subscriber::builder()
            .with_ansi(with_color)
            .json()
            .with_env_filter(filter)
            .finish();
        tracing::subscriber::set_global_default(my_collector)
            .wrap_err("Failed to set log subscriber")
    } else {
        let my_collector = Subscriber::builder()
            .with_ansi(with_color)
            .with_env_filter(filter)
            .finish();
        tracing::subscriber::set_global_default(my_collector)
            .wrap_err("Failed to set log subscriber")
    }
}

pub fn init_log_tracer() -> Result<()> {
    LogTracer::init().wrap_err("Failed to initialize log adapter")
}
