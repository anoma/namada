//! Node and client configuration settings

use std::path::PathBuf;

pub struct Config {
    pub home_dir: PathBuf,
    // TODO add anoma and tendermint address
}

impl Default for Config {
    fn default() -> Self {
        Self {
            home_dir: PathBuf::from(".anoma"),
        }
    }
}

impl Config {
    pub fn tendermint_home_dir(&self) -> PathBuf {
        self.home_dir.join("tendermint")
    }
}
