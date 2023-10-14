use std::marker::PhantomData;
use std::str::FromStr;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
use std::{env, fmt};

// TODO: allow custom fmt fn
#[derive(Clone)]
pub struct DbgPrintDiff<T>
where
    T: fmt::Debug,
{
    last: String,
    phantom_t: PhantomData<T>,
}
impl<T> DbgPrintDiff<T>
where
    T: fmt::Debug,
{
    pub fn new() -> Self {
        Self {
            last: Default::default(),
            phantom_t: PhantomData,
        }
    }

    /// Store a state in dbg format string
    pub fn store(&self, data: &T) -> Self {
        Self {
            last: Self::fmt_data(data),
            phantom_t: PhantomData,
        }
    }

    /// Diff a state in dbg format string against the stored state
    pub fn print_diff_and_store(&self, data: &T) -> Self {
        let dbg_str = Self::fmt_data(data);
        println!(
            "{}",
            pretty_assertions::StrComparison::new(&self.last, &dbg_str,)
        );
        Self {
            last: dbg_str,
            phantom_t: PhantomData,
        }
    }

    fn fmt_data(data: &T) -> String {
        format!("{:#?}", data)
    }
}

const ENV_VAR_TEST_PAUSES: &str = "TEST_PAUSES";

pub fn pause_for_enter() {
    if paused_enabled() {
        println!("Press Enter to continue");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
    }
}

fn paused_enabled() -> bool {
    // Cache the result of reading the environment variable
    static ENABLED: AtomicUsize = AtomicUsize::new(0);
    match ENABLED.load(Relaxed) {
        0 => {}
        1 => return false,
        _ => return true,
    }
    let enabled: bool = matches!(
        env::var(ENV_VAR_TEST_PAUSES).map(|val| {
            FromStr::from_str(&val).unwrap_or_else(|_| {
                panic!("Expected a bool for {ENV_VAR_TEST_PAUSES} env var.")
            })
        }),
        Ok(true),
    );
    ENABLED.store(enabled as usize + 1, Relaxed);
    enabled
}
