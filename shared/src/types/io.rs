//! Traits for implementing IO handlers. This is to enable
//! generic IO. The defaults are the obvious Rust native
//! functions.

/// Rust native I/O handling.
pub struct StdIo;

#[async_trait::async_trait(?Send)]
impl Io for StdIo {}

#[async_trait::async_trait(?Send)]
#[allow(missing_docs)]
pub trait Io {
    fn print(&self, output: impl AsRef<str>) {
        print!("{}", output.as_ref());
    }

    fn flush(&self) {
        use std::io::Write;
        std::io::stdout().flush().unwrap();
    }

    fn println(&self, output: impl AsRef<str>) {
        println!("{}", output.as_ref());
    }

    fn write<W: std::io::Write>(
        &self,
        mut writer: W,
        output: impl AsRef<str>,
    ) -> std::io::Result<()> {
        write!(writer, "{}", output.as_ref())
    }

    fn writeln<W: std::io::Write>(
        &self,
        mut writer: W,
        output: impl AsRef<str>,
    ) -> std::io::Result<()> {
        writeln!(writer, "{}", output.as_ref())
    }

    fn eprintln(&self, output: impl AsRef<str>) {
        eprintln!("{}", output.as_ref());
    }

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

    async fn prompt(&self, question: impl AsRef<str>) -> String {
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
