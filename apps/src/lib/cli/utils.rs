//! Command line interface utilities
use std::fmt::Debug;
use std::io::Write;
use std::marker::PhantomData;
use std::str::FromStr;

use clap::{ArgAction, ArgMatches};
use color_eyre::eyre::Result;
use lazy_static::lazy_static;

use super::args;
use super::context::{Context, FromContext};
use crate::cli::api::CliIo;

// We only use static strings
pub type App = clap::Command;
pub type ClapArg = clap::Arg;

pub trait Cmd: Sized {
    fn add_sub(app: App) -> App;
    fn parse(matches: &ArgMatches) -> Option<Self>;

    fn parse_or_print_help(app: App) -> Result<(Self, Context)> {
        let matches = app.clone().get_matches();
        match Self::parse(&matches) {
            Some(cmd) => {
                let global_args = args::Global::parse(&matches);
                let context = Context::new::<CliIo>(global_args)?;
                Ok((cmd, context))
            }
            None => {
                let mut app = app;
                app.print_help().unwrap();
                safe_exit(2);
            }
        }
    }
}

pub trait SubCmd: Sized {
    const CMD: &'static str;
    fn parse(matches: &ArgMatches) -> Option<Self>;
    fn def() -> App;
}

pub trait Args {
    fn parse(matches: &ArgMatches) -> Self;
    fn def(app: App) -> App;
}

pub struct Arg<T> {
    pub name: &'static str,
    pub r#type: PhantomData<T>,
}

pub struct ArgOpt<T> {
    pub name: &'static str,
    pub r#type: PhantomData<T>,
}

pub struct ArgDefault<T> {
    pub name: &'static str,
    pub default: DefaultFn<T>,
    pub r#type: PhantomData<T>,
}

pub struct ArgDefaultFromCtx<T> {
    pub name: &'static str,
    pub default: DefaultFn<String>,
    pub r#type: PhantomData<T>,
}

/// This wrapper type is a workaround for "function pointers in const fn are
/// unstable", which allows us to use this type in a const fn, because the
/// type-checker doesn't inspect the wrapped type.
/// Const function pointers: <https://github.com/rust-lang/rust/issues/63997>.
pub struct DefaultFn<T>(pub fn() -> T);

pub struct ArgFlag {
    pub name: &'static str,
}

#[allow(dead_code)]
pub struct ArgMulti<T> {
    pub name: &'static str,
    pub r#type: PhantomData<T>,
}

pub const fn arg<T>(name: &'static str) -> Arg<T> {
    Arg {
        name,
        r#type: PhantomData,
    }
}

pub const fn arg_opt<T>(name: &'static str) -> ArgOpt<T> {
    ArgOpt {
        name,
        r#type: PhantomData,
    }
}

pub const fn arg_default<T>(
    name: &'static str,
    default: DefaultFn<T>,
) -> ArgDefault<T> {
    ArgDefault {
        name,
        default,
        r#type: PhantomData,
    }
}

pub const fn arg_default_from_ctx<T>(
    name: &'static str,
    default: DefaultFn<String>,
) -> ArgDefaultFromCtx<T> {
    ArgDefaultFromCtx {
        name,
        default,
        r#type: PhantomData,
    }
}

pub const fn flag(name: &'static str) -> ArgFlag {
    ArgFlag { name }
}

#[allow(dead_code)]
pub const fn arg_multi<T>(name: &'static str) -> ArgMulti<T> {
    ArgMulti {
        name,
        r#type: PhantomData,
    }
}

impl<T> Arg<T> {
    pub const fn opt(self) -> ArgOpt<T> {
        ArgOpt {
            name: self.name,
            r#type: PhantomData,
        }
    }

    pub const fn default(self, default: DefaultFn<T>) -> ArgDefault<T> {
        ArgDefault {
            name: self.name,
            default,
            r#type: PhantomData,
        }
    }

    #[allow(dead_code)]
    pub const fn multi(self) -> ArgMulti<T> {
        ArgMulti {
            name: self.name,
            r#type: PhantomData,
        }
    }
}

impl<T> Arg<T> {
    pub fn def(&self) -> ClapArg {
        ClapArg::new(self.name)
            .long(self.name)
            .num_args(1)
            .required(true)
    }
}

impl<T> Arg<T>
where
    T: FromStr,
    <T as FromStr>::Err: Debug,
{
    pub fn parse(&self, matches: &ArgMatches) -> T {
        parse_opt(matches, self.name).unwrap()
    }
}

impl<T> Arg<FromContext<T>> {
    pub fn parse(&self, matches: &ArgMatches) -> FromContext<T> {
        let raw = matches.get_one::<String>(self.name).unwrap();
        FromContext::new(raw.to_string())
    }
}

impl<T> ArgOpt<T> {
    pub fn def(&self) -> ClapArg {
        ClapArg::new(self.name).long(self.name).num_args(1)
    }
}

impl<T> ArgOpt<T>
where
    T: FromStr,
    <T as FromStr>::Err: Debug,
{
    pub fn parse(&self, matches: &ArgMatches) -> Option<T> {
        parse_opt(matches, self.name)
    }
}

impl<T> ArgOpt<FromContext<T>> {
    pub fn parse(&self, matches: &ArgMatches) -> Option<FromContext<T>> {
        let raw = matches.get_one::<String>(self.name).map(|s| s.as_str())?;
        Some(FromContext::new(raw.to_string()))
    }
}

impl<T> ArgDefault<T>
where
    T: FromStr,
    <T as FromStr>::Err: Debug,
{
    pub fn def(&self) -> ClapArg {
        ClapArg::new(self.name).long(self.name).num_args(1)
    }

    pub fn parse(&self, matches: &ArgMatches) -> T {
        parse_opt(matches, self.name).unwrap_or_else(|| {
            let DefaultFn(default) = self.default;
            default()
        })
    }
}

impl<T> ArgMulti<FromContext<T>>
where
    T: FromStr,
    <T as FromStr>::Err: Debug,
{
    pub fn def(&self) -> ClapArg {
        ClapArg::new(self.name)
            .long(self.name)
            .num_args(1..)
            .value_delimiter(',')
    }

    pub fn parse(&self, matches: &ArgMatches) -> Vec<FromContext<T>> {
        matches
            .get_many(self.name)
            .unwrap_or_default()
            .map(|raw: &String| FromContext::new(raw.to_string()))
            .collect()
    }
}

impl<T> ArgDefaultFromCtx<FromContext<T>>
where
    T: FromStr,
    <T as FromStr>::Err: Debug,
{
    pub fn def(&self) -> ClapArg {
        ClapArg::new(self.name).long(self.name).num_args(1)
    }

    pub fn parse(&self, matches: &ArgMatches) -> FromContext<T> {
        let raw = parse_opt(matches, self.name).unwrap_or_else(|| {
            let DefaultFn(default) = self.default;
            default()
        });
        FromContext::new(raw)
    }
}

impl ArgFlag {
    pub fn def(&self) -> ClapArg {
        ClapArg::new(self.name)
            .long(self.name)
            .action(ArgAction::SetTrue)
    }

    pub fn parse(&self, matches: &ArgMatches) -> bool {
        matches.get_flag(self.name)
    }
}

#[allow(dead_code)]
impl<T> ArgMulti<T>
where
    T: FromStr,
    <T as FromStr>::Err: Debug,
{
    pub fn def(&self) -> ClapArg {
        ClapArg::new(self.name)
            .long(self.name)
            .action(ArgAction::Append)
    }

    pub fn parse(&self, matches: &ArgMatches) -> Vec<T> {
        matches
            .get_many(self.name)
            .unwrap_or_default()
            .map(|raw: &String| {
                raw.parse().unwrap_or_else(|e| {
                    eprintln!(
                        "Failed to parse the {} argument. Raw value: {}, \
                         error: {:?}",
                        self.name, raw, e
                    );
                    safe_exit(1)
                })
            })
            .collect()
    }
}

/// Extensions for defining commands and arguments.
/// Every function here should have a matcher in [`ArgMatchesExt`].
pub trait AppExt {
    fn add_args<T: Args>(self) -> Self;
}

/// Extensions for finding matching commands and arguments.
/// The functions match commands and arguments defined in [`AppExt`].
pub trait ArgMatchesExt {
    fn args_parse<T: Args>(&self) -> T;
}

impl AppExt for App {
    fn add_args<T: Args>(self) -> Self {
        T::def(self)
    }
}

impl ArgMatchesExt for ArgMatches {
    fn args_parse<T: Args>(&self) -> T {
        T::parse(self)
    }
}

pub fn parse_opt<T>(args: &ArgMatches, field: &str) -> Option<T>
where
    T: FromStr,
    T::Err: Debug,
{
    args.get_one::<String>(field).map(|s| {
        s.as_str().parse().unwrap_or_else(|e| {
            eprintln!(
                "Failed to parse the argument {}. Raw value: {}, error: {:?}",
                field, s, e
            );
            safe_exit(1)
        })
    })
}

#[cfg(not(feature = "testing"))]
/// A helper to exit after flushing output, borrowed from `clap::util` module.
pub fn safe_exit(code: i32) -> ! {
    let _ = std::io::stdout().lock().flush();
    let _ = std::io::stderr().lock().flush();

    std::process::exit(code)
}

#[cfg(feature = "testing")]
/// A helper to exit after flushing output, borrowed from `clap::util` module.
pub fn safe_exit(_: i32) -> ! {
    let _ = std::io::stdout().lock().flush();
    let _ = std::io::stderr().lock().flush();

    panic!("Test failed because the client exited unexpectedly.")
}

lazy_static! {
    /// A replacement for stdin in testing.
    pub static ref TESTIN: std::sync::Arc<std::sync::Mutex<Vec<u8>>> =
    std::sync::Arc::new(std::sync::Mutex::new(vec![]));
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
            question.as_ref(),
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
        $crate::cli::dispatch_prompt(format!("{}", format_args!($($arg)*)))
    }}
}
