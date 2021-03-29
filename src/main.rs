//use std::io::{Write, stdout};

//use crossterm::{execute, ExecutableCommand, cursor, Result};

use std::{mem::size_of, string};

fn str_to_vec_u8(key : &str) -> Vec<u8> {
    let mut message : Vec<u8> = vec![];
    for char in key.as_bytes() {
        message.push(char.clone());
    }
    message
}

fn rotate_left(x : u32, n : u32) -> u32 {
    let n = n%32;
    (x<<n) | (x>> (32-n) %32)
}

fn sha1(message : &str) -> Vec<u8> {
    let mut hash : Vec<u8> = vec![20; 0b00000000];
    let mut h0 : u32 = 0x67452301;
    let mut h1 : u32 = 0xEFCDAB89;
    let mut h2 : u32 = 0x98BADCFE;
    let mut h3 : u32 = 0x10325476;
    let mut h4 : u32 = 0xC3D2E1F0;

    let ml = message.len()*8;

    let mut mut_message : String = String::from(message);
    mut_message.push(0x80 as char);

    let mut append_k = ((mut_message.len()*8) % 512) as i64;
    while !(append_k == 0) {
        mut_message.push(0x00 as char);
        append_k = ((mut_message.len()*8) % 512) as i64;
    }

    //as the message will always be less than 512 bytes,
    //breaking the mutable message into 512 byte chunks is unnecessary

    let mut words : Vec<u32> = vec![0; 16];
    for word_index in 0..16{
        let mut word : u32 = 0;
        for x in 0..4{
            word += ((mut_message.as_bytes()[word_index*4+x]) as usize * x.pow(2)) as u32;
        }
        words[word_index] = word;
    }

    for i in 16..80 {
        words.push(rotate_left(words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16],1));
    }

    let mut a = h0.clone();
    let mut b = h1.clone();
    let mut c = h2.clone();
    let mut d = h3.clone();
    let mut e = h4.clone();


    for i in 0..80 {
        let mut f : u32;
        let mut k : u32;
        if 0<= i && i<= 19 {
            f = (b & c) | ((!b) & d);
            k  = 0x5A827999;
        }
        else if i <= 39 {
            f = b ^ c ^ d;
            k  = 0x6ED9EBA1;
        }
        else if i <= 59 {
            f = (b & c) | (b & d) | (c & d);
            k  = 0x8F1BBCDC;
        }
        else if i <= 79 {
            f = b ^ c ^ d;
            k  = 0xCA62C1D6;
        }
        else {
            unreachable!("i exceded 79 in hash function!");
        }

        let temp : usize = (rotate_left(a, 5) + f + e + k + words[i]) as usize;
        e = d;
        d = c;
        c = rotate_left(b, 30);
        b = a;
        a = temp as u32;
    }

    h0 = h0 + a;
    h1 = h1 + b;
    h2 = h2 + c;
    h3 = h3 + d;
    h4 = h4 + e;

    let h0_str = format!("{:X}", h0);
    let h1_str = format!("{:X}", h1);
    let h2_str = format!("{:X}", h2);
    let h3_str = format!("{:X}", h3);
    let h4_str = format!("{:X}", h4);
    let hex = "0x".to_string();

    let mut hash_str = hex.clone() + &h0_str + &h1_str + &h2_str + &h3_str + &h4_str;
    str_to_vec_u8(&hash_str)
}


fn sha1_test() {
    let key = "WHDQ9I4W5FZSCCI0";
    let time = "1397552400";

    let mut precomputed_hash : Vec<u8> = vec![0xf7, 0x70, 0x2a, 0xd6, 0x25, 0x4a, 0x06, 0xf3, 0x3f, 0x7d, 0xcb, 0x95, 0x20, 0x00, 0xcb, 0xff, 0xa8, 0xb3, 0xc7, 0x2e];

    assert_eq!(precomputed_hash[0], 0xf7);

    let m = time.to_owned()+key;
    let message = m.as_str();

    let hashed = sha1(message.clone());


    println!("{:?} {:?}", hashed.len(), precomputed_hash.len());
    assert_eq!(hashed, precomputed_hash)
}

fn main() -> Result<(), ()>{
    sha1_test();

    Ok(())
}
