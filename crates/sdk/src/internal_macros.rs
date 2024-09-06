macro_rules! echo_error {
    ($io:expr, $($arg:tt)*) => {{
        let msg = ::alloc::format!($($arg)*);
        namada_io::edisplay_line!($io, "{msg}");
        msg
    }}
}

macro_rules! trace_error {
    ($level:ident, $($arg:tt)*) => {{
        let msg = ::alloc::format!($($arg)*);
        ::tracing::$level!("{msg}");
        msg
    }}
}

pub(crate) use {echo_error, trace_error};
