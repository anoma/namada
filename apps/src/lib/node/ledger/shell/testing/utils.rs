use std::path::{Path, PathBuf};

use tempfile::tempdir;

/// Namada binaries
#[derive(Debug)]
#[allow(dead_code)]
pub enum Bin {
    Node,
    Client,
    Wallet,
    Relayer,
}

/// A temporary directory for testing
#[derive(Debug)]
pub struct TestDir(PathBuf);

impl TestDir {
    /// Creat a new temp directory. This will have to be manually
    /// cleaned up.
    pub fn new() -> Self {
        let temp = tempdir().unwrap();
        Self(temp.into_path())
    }

    /// Get the path of the directory
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Manually remove the test directory from the
    /// file system.
    pub fn clean_up(self) {
        if let Err(e) = std::fs::remove_dir_all(&self.0) {
            println!(
                "Failed to clean up test dir at {}: {e:?}",
                self.0.to_string_lossy()
            );
        }
    }
}

impl Default for TestDir {
    fn default() -> Self {
        Self::new()
    }
}
