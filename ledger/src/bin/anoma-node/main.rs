mod cli;
mod gossip;
mod rpc;
mod shell;

fn main() {
    // init logging
    env_logger::init_from_env("ANOMA_LOG");

    // run the CLI
    cli::main();
}
