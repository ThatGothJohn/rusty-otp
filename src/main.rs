//use std::io::{Write, stdout};

//use crossterm::{execute, ExecutableCommand, cursor};

extern crate sha1;

fn hmac_sha1 (mut key: String, message: String) -> Result<String, ()> {
    const BLOCKSIZE: usize = 512;
    if key.len() * 8 > BLOCKSIZE {
        key = sha1::Sha1::from(key).digest().to_string();
    } else {
        while key.len() * 8 < BLOCKSIZE {
            key.push('\0');
        }
    }

    let key_bytes = key.as_bytes();

    let mut i_key_pad = [0 as u8; BLOCKSIZE];
    let mut o_key_pad = [0 as u8; BLOCKSIZE];

    for i in 0..BLOCKSIZE/8 {
        i_key_pad[i] = key_bytes[i] ^ 0x36;
        o_key_pad[i] = key_bytes[i] ^ 0x5c;
    }

    //FIXME: do better error handling
    let i_key_pad_string = String::from_utf8(i_key_pad.to_vec()).unwrap();
    let o_key_pad_string = String::from_utf8(o_key_pad.to_vec()).unwrap();

    let ret = sha1::Sha1::from(o_key_pad_string+
        &sha1::Sha1::from(
            i_key_pad_string + &message.as_str()
        ).digest().to_string()).digest().to_string();

    Ok(ret.to_owned())
}



#[test]
fn sha1_test(){
    let precomputed_hash = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12";

    let hashed = sha1::Sha1::from("The quick brown fox jumps over the lazy dog").digest();

    assert_eq!(hashed.to_string(), precomputed_hash);

    let test_key = "WHDQ9I4W5FZSCCI0".to_owned();
    let test_message = "1397552400".to_owned();

    let hmac_string = hmac_sha1(test_key,test_message);

    assert_eq!(hmac_string.unwrap(), "206bfb33934df4f39580897444fa0371776bf97a");
}

fn main() -> Result<(), ()>{

    Ok(())
}
