use std::path::Path;

use eyre::Context;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub fn read_toml<T: DeserializeOwned>(
    path: &Path,
    which_file: &str,
) -> eyre::Result<T> {
    let file_contents = std::fs::read_to_string(path).wrap_err_with(|| {
        format!(
            "Couldn't read {which_file} config file from {}",
            path.to_string_lossy()
        )
    })?;
    toml::from_str(&file_contents).wrap_err_with(|| {
        format!(
            "Couldn't parse {which_file} TOML from {}",
            path.to_string_lossy()
        )
    })
}

pub fn write_toml<T: Serialize>(
    data: &T,
    path: &Path,
    which_file: &str,
) -> eyre::Result<()> {
    let file_contents = toml::to_vec(data)
        .wrap_err_with(|| format!("Couldn't format {which_file} to TOML."))?;
    std::fs::write(path, file_contents).wrap_err_with(|| {
        format!(
            "Couldn't write {which_file} TOML to {}",
            path.to_string_lossy()
        )
    })
}
