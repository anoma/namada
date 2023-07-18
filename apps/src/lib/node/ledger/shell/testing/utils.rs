use std::fs::File;
use std::path::{Path, PathBuf};

use tempfile::tempdir;
use namada::io::TESTIN;

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

/// A file that removes itself on drop
struct TempFile(PathBuf);
impl TempFile {
    fn new(path: PathBuf) -> (Self, File) {
        let f = File::create(&path).unwrap();
        (Self(path), f)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        _ = std::fs::remove_file(&self.0);
    }
}

/// Namada binaries
#[derive(Debug)]
#[allow(dead_code)]
pub enum Bin {
    Node,
    Client,
    Wallet,
    Relayer,
}

/// Test helper that captures stdout of
/// a process.
pub struct CapturedOutput<T = ()> {
    pub output: String,
    pub result: T,
    input: String,
}

impl CapturedOutput {
    pub fn with_input(input: String) -> Self {
        Self {
            output: "".to_string(),
            result: (),
            input,
        }
    }
}

impl<T> CapturedOutput<T> {

    /// Run a client command and capture
    /// the output to the mocked stdout.
    pub fn of<F>(func: F) -> Self
    where
        F: FnOnce() -> T,
    {
        let mut capture = Self {
            output: Default::default(),
            result: func(),
            input: Default::default(),
        };
        capture.output = namada::io::TESTOUT.lock().unwrap().read_string();
        capture
    }

    /// Run a client command with input to the mocked stdin and capture
    /// the output to the mocked stdout.
    pub fn run<U, F>(&self, func: F) -> CapturedOutput<U>
    where
        F: FnOnce() -> U,
    {
        {
            // write the input to the mocked stdin
            let mut buf = TESTIN.lock().unwrap();
            buf.clear();
            buf.extend_from_slice(self.input.as_bytes());
        }
        CapturedOutput::of(func)
    }

    /// Check if the captured output contains the regex.
    pub fn matches(&self, needle: regex::Regex) -> bool {
        needle.captures(&self.output).is_some()
    }

    /// Check if the captured output contains the string.
    pub fn contains(&self, needle: &str) -> bool {
        let needle = regex::Regex::new(needle).unwrap();
        self.matches(needle)
    }
}
