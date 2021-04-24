use std::{convert::TryInto, time, thread};
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

fn dynamic_truncation (hmac_string : String) -> Result<String, ()> {
    //FIXME: do better error handling, such as a hexidecimal digit check
    let offset : usize = hmac_string.chars().last().unwrap().to_digit(16).unwrap().try_into().unwrap();

    let truncated = hmac_string.as_str()[offset*2..offset*2+8].to_owned();

    let decimal = u32::from_str_radix(truncated.as_str(), 16).unwrap().to_string();

    let decimal_offset = decimal.len();
    let otp_code = decimal.as_str()[decimal_offset-6..decimal_offset].to_owned();

    Ok(otp_code)
}

fn generate_totp () -> Result<String, ()> {
    let seconds_since_epoch = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_secs();

    let rounded_s_s_e = seconds_since_epoch - (seconds_since_epoch % 30);

    let hash = hmac_sha1(SECRET_KEY.to_owned(), rounded_s_s_e.to_string()).unwrap();

    let totp = dynamic_truncation(hash).unwrap();
    Ok(totp)
}


#[test]
fn test_suite(){
    let precomputed_hash = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12";

    let hashed = sha1::Sha1::from("The quick brown fox jumps over the lazy dog").digest();

    assert_eq!(hashed.to_string(), precomputed_hash);

    let test_key = "WHDQ9I4W5FZSCCI0".to_owned();
    let test_message = "1397552400".to_owned();

    let hmac_string = hmac_sha1(test_key,test_message).unwrap();

    assert_eq!(hmac_string, "206bfb33934df4f39580897444fa0371776bf97a");

    let otp_code = dynamic_truncation(hmac_string.clone()).unwrap();

    assert_eq!(otp_code,"098426".to_owned());

    for i in 0..3 {
        eprintln!("{}, {}", i, generate_totp().unwrap());
        thread::sleep(time::Duration::from_millis(15000));
    }
}

const SECRET_KEY : &str = "InsecureSecret1234";

fn main() -> Result<(), ()>{

    Ok(())
}
