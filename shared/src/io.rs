//! An abstraction over I/O to handle various use cases including
//! CLI, testing, and web browsers

use std::io::Write;
use lazy_static::lazy_static;

/// The max number of bytes that the is currently remembered from stdout while
/// testing.
const TESTOUT_BUF_SIZE: usize = 100_000;

lazy_static! {
    /// A replacement for stdout in testing. The maximum number of bytes
    /// it holds is limited to prevent memory issues.
    pub static ref TESTOUT: std::sync::Arc<std::sync::Mutex<FixedBuffer<u8>>> =
    std::sync::Arc::new(std::sync::Mutex::new(FixedBuffer::new(TESTOUT_BUF_SIZE)));
}

lazy_static! {
    /// A replacement for stdin in testing.
    pub static ref TESTIN: std::sync::Arc<std::sync::Mutex<Vec<u8>>> =
    std::sync::Arc::new(std::sync::Mutex::new(vec![]));
}

/// A function that chooses how to dispatch output
/// to users. There is a hierarchy of feature flags
/// that determines this. If no flags are set,
/// it is printed to stdout.
pub fn displayln_aux(output: impl AsRef<str>) {
    let output = output.as_ref();
    if cfg!(feature = "testing") {
        let mut display = TESTOUT.lock().unwrap();
        display.append(output.as_bytes().to_vec());
        display.append("\n".as_bytes().to_vec());
    } else {
        println!("{}", output);
    }
}

/// Locks the staout for writing out to users.
pub fn writeln_aux(
    output: impl AsRef<str>,
    w: &mut std::io::StdoutLock,
) -> std::io::Result<()> {
    let output = output.as_ref();
    if cfg!(feature = "testing") {
        displayln_aux(output);
        Ok(())
    } else {
        writeln!(w, "{}", output)
    }
}

#[macro_export]
/// A macro for formatting and displaying output to users.
macro_rules! display_line {
    () => {
        $crate::io::displayln_aux("\n");
    };
    ($w:expr;$($arg:tt)*) => {{
        $crate::io::writeln_aux(format!("{}", format_args!($($arg)*)), $w)
    }};
    ($($arg:tt)*) => {{
        $crate::io::displayln_aux(format!("{}", format_args!($($arg)*)));
    }};
}

/// Same as above without adding a newline at the end
pub fn display_aux(output: impl AsRef<str>) {
    let output = output.as_ref();
    if cfg!(feature = "testing") {
        let mut display = TESTOUT.lock().unwrap();
        display.append(output.as_bytes().to_vec());
    } else {
        print!("{}", output);
    }
}

#[allow(dead_code)]
/// Same as above without adding a newline at the end
pub fn write_aux(
    output: impl AsRef<str>,
    w: &mut std::io::StdoutLock,
) -> std::io::Result<()> {
    let output = output.as_ref();
    if cfg!(feature = "testing") {
        display_aux(output);
        Ok(())
    } else {
        write!(w, "{}", output)
    }
}

#[macro_export]
/// Same as above without adding a newline at the end
macro_rules! display {
    () => {
        $crate::io::display_aux("\n");
    };
    ($w:expr;$($arg:tt)*) => {{
        $crate::io::write_aux(format!("{}", format_args!($($arg)*)), $w)
    }};
    ($($arg:tt)*) => {{
        $crate::io::display_aux(format!("{}", format_args!($($arg)*)));
    }};
}

/// A function that chooses how to dispatch error msgs
/// to users. There is a hierarchy of feature flags
/// that determines this. If no flags are set,
/// it is printed to stdout.
pub fn error_display(output: impl AsRef<str>) {
    let output = output.as_ref();
    if cfg!(feature = "testing") {
        displayln_aux(output);
    } else {
        eprintln!("{}", output);
    }
}

#[macro_export]
/// A macro for formatting and displaying errors to users.
macro_rules! edisplay {
    ($($arg:tt)*) => {{
        $crate::io::error_display(format!("{}", format_args!($($arg)*)));
    }};
}

/// A generic function for displaying a prompt to users and reading
/// in their response.
fn prompt_aux<R, W>(mut reader: R, mut writer: W, question: &str) -> String
where
    R: std::io::Read,
    W: Write,
{
    write!(&mut writer, "{}", question).expect("Unable to write");
    writer.flush().unwrap();
    let mut s = String::new();
    reader.read_to_string(&mut s).expect("Unable to read");
    s
}

/// A function that chooses how to dispatch prompts
/// to users. There is a hierarchy of feature flags
/// that determines this. If no flags are set,
/// the question is printed to stdout and response
/// read from stdin.
pub fn dispatch_prompt(question: impl AsRef<str>) -> String {
    if cfg!(feature = "testing") {
        prompt_aux(
            TESTIN.lock().unwrap().as_slice(),
            std::io::stdout(),
            question.as_ref()
        )
    } else {
        prompt_aux(
            std::io::stdin().lock(),
            std::io::stdout(),
            question.as_ref(),
        )
    }
}

#[macro_export]
/// A convenience macro for formatting the user prompt before
/// forwarding it to the `[dispatch_prompt]` method.
macro_rules! prompt {
    ($($arg:tt)*) => {{
        $crate::io::dispatch_prompt(format!("{}", format_args!($($arg)*)))
    }}
}

/// A buffer with an max size. Drops elements from the front on
/// size overflow.
pub struct FixedBuffer<T: Clone> {
    inner: Vec<T>,
    max_size: usize,
}

impl<T: Clone> FixedBuffer<T> {
    fn new(max_size: usize) -> Self {
        Self {
            inner: vec![],
            max_size,
        }
    }

    /// Remove the first `size` elements from the buffer.
    fn roll(&mut self, size: usize) {
        self.inner = self.inner[size..].to_vec();
    }

    /// Add data to the end of the buffer, deleting from the
    /// front as necessary.
    fn append(&mut self, mut other: Vec<T>) {
        // if new data exceeds max size, take the tail.
        if other.len() > self.max_size {
            self.inner = other[(other.len() - self.max_size)..].to_vec();
            return;
        }
        // check if appending the data overflows buffer
        let free_space = self.max_size - self.inner.len();
        if other.len() > free_space {
            // delete the minimum amount of data from the front of the buffer
            // to fit new data.
            self.roll(other.len() - free_space);
        }
        self.inner.append(&mut other);
    }
}

impl FixedBuffer<u8> {
    /// Read the inner buffer out to string
    pub fn read_string(&mut self) -> String {
        let mut fresh = vec![];
        std::mem::swap(&mut fresh, &mut self.inner);
        String::from_utf8(fresh).unwrap()
    }
}

#[cfg(test)]
mod testing {
    use super::*;

    #[test]
    fn test_buffer() {
        let mut buffer = FixedBuffer::<u64>::new(10);
        buffer.inner = (1u64..=9_u64).collect();
        buffer.append(vec![10, 11, 12, 13, 14, 15]);
        assert_eq!(buffer.inner, (6u64..=15_u64).collect::<Vec<u64>>());
        buffer.append((20u64..=40_u64).collect());
        assert_eq!(buffer.inner, (31u64..=40_u64).collect::<Vec<u64>>());
    }
}
