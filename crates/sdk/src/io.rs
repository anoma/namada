//! Traits for implementing IO handlers. This is to enable
//! generic IO. The defaults are the obvious Rust native
//! functions.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use crate::{MaybeSend, MaybeSync};

/// NOOP progress bar implementation.
#[derive(Debug, Clone, Copy)]
pub struct DevNullProgressBar;

/// Mechanism that allows keeping track of the progress
/// of some operation.
pub trait ProgressBar {
    /// Query the amount of virtual elements the progress tracker
    /// is tracking.
    fn upper_limit(&self) -> u64;

    /// Set the amount of virtual elements the progress tracker
    /// is tracking.
    fn set_upper_limit(&mut self, limit: u64);

    /// Announce that `amount` virtual elements have been
    /// processed.
    fn increment_by(&mut self, amount: u64);

    /// Specify a message to be display alongside the bar.
    fn message(&mut self, message: String);

    /// Signal that a progress bar has completed
    fn finish(&mut self);
}

impl ProgressBar for DevNullProgressBar {
    fn upper_limit(&self) -> u64 {
        0
    }

    fn set_upper_limit(&mut self, _: u64) {}

    fn increment_by(&mut self, _: u64) {}

    fn message(&mut self, _: String) {}

    fn finish(&mut self) {}
}

#[cfg(not(target_family = "wasm"))]
impl ProgressBar for kdam::Bar {
    fn upper_limit(&self) -> u64 {
        self.total as u64
    }

    fn set_upper_limit(&mut self, limit: u64) {
        self.total = limit as usize;
    }

    fn increment_by(&mut self, amount: u64) {
        kdam::BarExt::update(self, amount as usize).unwrap();
    }

    fn message(&mut self, message: String) {
        kdam::BarExt::write(self, message).unwrap();
    }

    fn finish(&mut self) {
        println!();
    }
}

/// A trait that abstracts out I/O operations
#[cfg_attr(feature = "async-send", async_trait::async_trait)]
#[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
pub trait Io {
    /// Print the given string
    fn print(&self, output: impl AsRef<str>) {
        print!("{}", output.as_ref());
    }

    /// Flush the output
    fn flush(&self) {
        use std::io::Write;
        std::io::stdout().flush().unwrap();
    }

    /// Print the given string with a newline
    fn println(&self, output: impl AsRef<str>) {
        println!("{}", output.as_ref());
    }

    /// Print the given string into the given Writer
    fn write<W: std::io::Write>(
        &self,
        mut writer: W,
        output: impl AsRef<str>,
    ) -> std::io::Result<()> {
        write!(writer, "{}", output.as_ref())
    }

    /// Print the given string into the given Writer and terminate with newline
    fn writeln<W: std::io::Write>(
        &self,
        mut writer: W,
        output: impl AsRef<str>,
    ) -> std::io::Result<()> {
        writeln!(writer, "{}", output.as_ref())
    }

    /// Print the given error string
    fn eprintln(&self, output: impl AsRef<str>) {
        eprintln!("{}", output.as_ref());
    }

    /// Read a string from input
    async fn read(&self) -> std::io::Result<String> {
        #[cfg(not(target_family = "wasm"))]
        {
            read_aux(tokio::io::stdin()).await
        }
        #[cfg(target_family = "wasm")]
        {
            unreachable!("Wasm should not perform general IO")
        }
    }

    /// Display the given prompt and return the string input
    async fn prompt(
        &self,
        question: impl AsRef<str> + MaybeSync + MaybeSend,
    ) -> String {
        #[cfg(not(target_family = "wasm"))]
        {
            prompt_aux(
                tokio::io::stdin(),
                tokio::io::stdout(),
                question.as_ref(),
            )
            .await
        }
        #[cfg(target_family = "wasm")]
        {
            unreachable!(
                "Wasm should not perform general IO; received call for input \
                 with question\n: {}",
                question.as_ref()
            )
        }
    }
}

/// Rust native I/O handling.
#[derive(Default)]
pub struct StdIo;

#[cfg_attr(feature = "async-send", async_trait::async_trait)]
#[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
impl Io for StdIo {}

/// Ignores all I/O operations.
pub struct NullIo;

#[cfg_attr(feature = "async-send", async_trait::async_trait)]
#[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
impl Io for NullIo {
    fn print(&self, _output: impl AsRef<str>) {}

    fn flush(&self) {}

    fn println(&self, _output: impl AsRef<str>) {}

    fn write<W: std::io::Write>(
        &self,
        mut _writer: W,
        _output: impl AsRef<str>,
    ) -> std::io::Result<()> {
        Ok(())
    }

    fn writeln<W: std::io::Write>(
        &self,
        mut _writer: W,
        _output: impl AsRef<str>,
    ) -> std::io::Result<()> {
        Ok(())
    }

    fn eprintln(&self, _output: impl AsRef<str>) {}

    async fn read(&self) -> std::io::Result<String> {
        panic!("Unsupported operation")
    }

    async fn prompt(
        &self,
        _question: impl AsRef<str> + MaybeSend + MaybeSync,
    ) -> String {
        panic!("Unsupported operation")
    }
}

/// A generic function for displaying a prompt to users and reading
/// in their response.
#[cfg(not(target_family = "wasm"))]
pub async fn prompt_aux<R, W>(
    mut reader: R,
    mut writer: W,
    question: &str,
) -> String
where
    R: tokio::io::AsyncReadExt + Unpin,
    W: tokio::io::AsyncWriteExt + Unpin,
{
    writer
        .write_all(question.as_bytes())
        .await
        .expect("Unable to write");
    writer.flush().await.unwrap();
    let mut s = String::new();
    reader.read_to_string(&mut s).await.expect("Unable to read");
    s
}

/// A generic function for reading input from users
#[cfg(not(target_family = "wasm"))]
pub async fn read_aux<R>(mut reader: R) -> tokio::io::Result<String>
where
    R: tokio::io::AsyncReadExt + Unpin,
{
    let mut s = String::new();
    reader.read_to_string(&mut s).await?;
    Ok(s)
}

/// Convenience macro for formatting arguments to
/// [`Io::print`]
#[macro_export]
macro_rules! display {
    ($io:expr) => {
        $io.print("")
    };
    ($io:expr, $w:expr; $($args:tt)*) => {
        $io.write($w, format_args!($($args)*).to_string())
    };
    ($io:expr,$($args:tt)*) => {
        $io.print(format_args!($($args)*).to_string())
    };
}

/// Convenience macro for formatting arguments to
/// [`Io::println`] and [`Io::writeln`]
#[macro_export]
macro_rules! display_line {
    ($io:expr) => {
        $io.println("")
    };
    ($io:expr, $w:expr; $($args:tt)*) => {
        $io.writeln($w, format_args!($($args)*).to_string())
    };
    ($io:expr,$($args:tt)*) => {
        $io.println(format_args!($($args)*).to_string())
    };
}

/// Convenience macro for formatting arguments to
/// [`Io::eprintln`]
#[macro_export]
macro_rules! edisplay_line {
    ($io:expr,$($args:tt)*) => {
        $io.eprintln(format_args!($($args)*).to_string())
    };
}

#[macro_export]
/// A convenience macro for formatting the user prompt before
/// forwarding it to the [`Io::prompt`] method.
macro_rules! prompt {
    ($io:expr,$($arg:tt)*) => {{
        $io.prompt(format!("{}", format_args!($($arg)*)))
    }}
}
