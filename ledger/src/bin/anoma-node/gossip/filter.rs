use std::path::Path;

use anoma::protobuf::types::{Intent, PublicFilter};
use thiserror::Error;

use crate::vm;

#[derive(Error, Debug)]
pub enum Error {
    #[error("error while running the filter: {0}")]
    RunnerError(vm::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

pub trait FilterValidate {
    fn from_file(path: impl AsRef<Path>) -> PublicFilter;
    fn validate(&self, intent: &Intent) -> Result<bool>;
}

impl FilterValidate for PublicFilter {
    fn from_file(path: impl AsRef<Path>) -> PublicFilter {
        PublicFilter {
            code: std::fs::read(path).unwrap(),
        }
    }

    fn validate(&self, intent: &Intent) -> Result<bool> {
        let filter_runner = vm::FilterRunner::new();
        filter_runner
            .run(self.code.clone(), &intent.data)
            .map_err(Error::RunnerError)
    }
}
