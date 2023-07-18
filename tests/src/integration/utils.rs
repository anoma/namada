use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;

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
    pub(crate) fn of<F>(func: F) -> Self
    where
        F: FnOnce() -> T,
    {
        std::io::set_output_capture(Some(Default::default()));
        let mut capture = Self {
            output: Default::default(),
            result: func(),
            input: Default::default(),
        };
        let captured = std::io::set_output_capture(None);
        let captured = captured.unwrap();
        let captured = Arc::try_unwrap(captured).unwrap();
        let captured = captured.into_inner().unwrap();
        capture.output = String::from_utf8(captured).unwrap();
        capture
    }

    /// Run a client command with input to the mocked stdin and capture
    /// the output to the mocked stdout
    pub fn run<U, F>(&self, func: F) -> CapturedOutput<U>
    where
        F: FnOnce() -> U,
    {
        {
            // write the input to the mocked stdin
            let mut buf = namada_apps::cli::TESTIN.lock().unwrap();
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
