use std::fs::File;
use std::io::{BufRead, BufReader, LineWriter, Write};
use std::str::FromStr;

use namada_core::types::key::common;

fn parse(file: &str) -> Vec<String> {
    let file = File::open(file).unwrap();
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let mut valid = vec![];
    while let Ok(length) = reader.read_line(&mut line) {
        if length == 0 {
            break;
        }
        match common::PublicKey::from_str(line.trim()) {
            Ok(_) => valid.push(line.clone()),
            e => println!("Address {} done goobered: {:?}", line, e),
        }
        line.clear()
    }
    valid
}

fn write_to_file(outfile: &str, valid: Vec<String>)  {
    let out = File::create(outfile).unwrap();
    let mut write = LineWriter::new(out);
    for pk in valid {
        write.write_all(pk.as_bytes()).unwrap();
    }
    write.flush().unwrap();
}

fn main() {
    let valid = parse("balances.txt");
    write_to_file("filtered.txt", valid);
}
