//! A module for anything related to logging
use std::env;

use color_eyre::eyre::Result;
use eyre::WrapErr;
use tracing_subscriber::filter::{Directive, EnvFilter};
use tracing_subscriber::fmt::Subscriber;

pub const ENV_KEY: &str = "ANOMA_LOG";

pub fn init_from_env_or(default: impl Into<Directive>) -> Result<()> {
    let filter = filter_from_env_or(default);
    let my_collector = Subscriber::builder().with_env_filter(filter).finish();
    tracing::subscriber::set_global_default(my_collector)
        .wrap_err("Failed to set log subscriber")
}

pub fn filter_from_env_or(default: impl Into<Directive>) -> EnvFilter {
    env::var(ENV_KEY)
        .map(EnvFilter::new)
        .unwrap_or_else(|_| EnvFilter::default().add_directive(default.into()))
}

pub fn set_subscriber(filter: EnvFilter) -> Result<()> {
    let my_collector = Subscriber::builder().with_env_filter(filter).finish();
    tracing::subscriber::set_global_default(my_collector)
        .wrap_err("Failed to set log subscriber")
}
