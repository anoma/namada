//! An abstraction over I/O to handle various use cases including
//! CLI, testing, and web browsers

use std::io::Write;

/// A function that chooses how to dispatch output
/// to users. There is a hierarchy of feature flags
/// that determines this. If no flags are set,
/// it is printed to stdout.
pub fn displayln_aux(output: impl AsRef<str>) {
    let output = output.as_ref();
    println!("{}", output);
}

/// Locks the staout for writing out to users.
pub fn writeln_aux(
    output: impl AsRef<str>,
    w: &mut std::io::StdoutLock,
) -> std::io::Result<()> {
    let output = output.as_ref();
    writeln!(w, "{}", output)
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
    print!("{}", output);
}

#[allow(dead_code)]
/// Same as above without adding a newline at the end
pub fn write_aux(
    output: impl AsRef<str>,
    w: &mut std::io::StdoutLock,
) -> std::io::Result<()> {
    let output = output.as_ref();
    write!(w, "{}", output)
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
    eprintln!("{}", output);
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
    prompt_aux(
        std::io::stdin().lock(),
        std::io::stdout(),
        question.as_ref(),
    )
}

#[macro_export]
/// A convenience macro for formatting the user prompt before
/// forwarding it to the `[dispatch_prompt]` method.
macro_rules! prompt {
    ($($arg:tt)*) => {{
        $crate::io::dispatch_prompt(format!("{}", format_args!($($arg)*)))
    }}
}
