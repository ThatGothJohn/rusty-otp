//use std::io::{Write, stdout};

//use crossterm::{execute, ExecutableCommand, cursor};

use std::string;


fn sha1(message : &str) -> String {
    let message_bytes : Vec<u8> = message.chars().collect::<Vec<char>>()
        .iter().map(|c| (*c as u8)).collect::<Vec<u8>>();

    let mut byte_str : String = message_bytes.iter()
        .map(|b| format!("{:08b}",*b)).collect();

    byte_str.push('1');

    while byte_str.len() % 512 != 448 {
        byte_str.push('0');
    }

    let message_len : u64 = (message.len()*8) as u64;

    let len_str : String = message_len.to_be_bytes()
        .iter().map(|b| format!("{:08b}",*b)).collect();

    byte_str.push_str(len_str.as_str());

    let mut chunks : Vec<String> = vec![byte_str.clone()];
    //todo! remove clone if last use

    while chunks[0].len() > 512 {
        let mut chunk = chunks[0].clone();
        let temp = chunk.split_at_mut(512);
        chunks[0] = temp.0.to_owned();
        chunks.push(temp.1.to_owned());
    }
    let mut words : Vec<Vec<u32>> = chunks.iter().map(|chunk| {
        chunk.chars().collect::<Vec<char>>()
            .chunks(32).map(|c| u32::from_str_radix(c.iter()
            .collect::<String>().as_str(), 2).unwrap())
            .collect::<Vec<u32>>()
    }).collect();

    let words_extended : Vec<Vec<u32>> = words.iter().map(|chunk| {
        let mut chunk_mut = chunk.clone();
        for i in 16..80 {
            let word_a = chunk_mut[i-3];
            let word_b = chunk_mut[i-8];
            let word_c = chunk_mut[i-14];
            let word_d = chunk_mut[i-16];

            let xor_a = word_a ^ word_b;
            let xor_b = xor_a ^ word_c;
            let xor_c = xor_b ^ word_d;

            let new_word = xor_c.rotate_left(1);

            chunk_mut.push(new_word);
        }
        chunk_mut
    }).collect();

    let mut h0 : u32 = 0x67452301;
    let mut h1 : u32 = 0xEFCDAB89;
    let mut h2 : u32 = 0x98BADCFE;
    let mut h3 : u32 = 0x10325476;
    let mut h4 : u32 = 0xC3D2E1F0;

    let mut a = h0.clone();
    let mut b = h1.clone();
    let mut c = h2.clone();
    let mut d = h3.clone();
    let mut e = h4.clone();

    for i in 0..words_extended.len() {
        for j in 0..80 {
            let f : u32;
            let k : u32;
            if j < 20 {
                let b_and_c = b & c;
                let d_and_not_b = d & !b;
                f = b_and_c | d_and_not_b;
                k = 0x5A827999;
            }
            else if i < 40 {
                let b_xor_c = b ^ c;
                f = b_xor_c ^ d;
                k = 0x5A827999;
            }
            else if i < 60 {
                let b_and_c = b & c;
                let b_and_d = b & d;
                let c_and_d = c & d;
                f = b_and_c | b_and_d | c_and_d;
                k = 0x5A827999;
            }
            else {
                let b_xor_c = b ^ c;
                f = b_xor_c ^ d;
                k = 0xCA62C1D6;
            }

            let word = words_extended[i][j];
            let temp_a = a.rotate_left(5).overflowing_add(f).0;
            let temp_b = temp_a.overflowing_add(e).0;
            let temp_c = temp_b.overflowing_add(k).0;
            let temp = temp_c.overflowing_add(word).0;

            e=d;
            d=c;
            c=b.rotate_left(30);
            b=a;
            a=temp;
        }
        h0 = h0.overflowing_add(a).0;
        h1 = h1.overflowing_add(b).0;
        h2 = h2.overflowing_add(c).0;
        h3 = h3.overflowing_add(d).0;
        h4 = h4.overflowing_add(e).0;
    }

    //println!("{:?}, {:?}, {:?}", words_extended, words_extended[0].len(), words_extended[0][0]);

    format!("{:x}{:x}{:x}{:x}{:x}", h0,h1,h2,h3,h4)
}

#[test]
fn sha1_test(){
    let precomputed_hash = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12";

    let hashed = sha1("The quick brown fox jumps over the lazy dog");

    assert_eq!(hashed, precomputed_hash);
}

fn main() -> Result<(), ()>{
    println!("{}",sha1("The quick brown fox jumps over the lazy dog"));
    println!("{}",sha1("The quick brown fox jumps over the lazy cog"));
    println!("{}",sha1("1397552400WHDQ9I4W5FZSCCI0"));

    Ok(())
}
