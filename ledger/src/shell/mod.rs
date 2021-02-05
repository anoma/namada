mod tendermint;
mod shell;

use env_logger::Env;

pub fn run() {
    // init logging
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    // run tendermint with our shell
    let shell = shell::Shell::new();
    tendermint::run(shell)
}
