//use std::io::{Write, stdout};

//use crossterm::{execute, ExecutableCommand, cursor};

extern crate sha1;


#[test]
fn sha1_test(){
    let precomputed_hash = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12";

    let hashed = sha1::Sha1::from("The quick brown fox jumps over the lazy dog").digest();

    assert_eq!(hashed.to_string(), precomputed_hash);
}

fn main() -> Result<(), ()>{

    Ok(())
}
