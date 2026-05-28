use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

fn base32_decode(string: &str) -> Option<Vec<u8>> {
    let code = string.trim_end_matches('=');
    let mut result = Vec::new();
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;

    for c in code.chars() {
        let value = match c {
            'A'..='Z' => c as u8 - b'A',
            'a'..='z' => c as u8 - b'a',
            '2'..='7' => c as u8 - b'2' + 26,
            _ => return None,
        };

        buffer = (buffer << 5) | value as u16;
        bits += 5;

        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
        }
    }

    Some(result)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: otp-gen <secret>");
        std::process::exit(1);
    }
    let secret = &args[1];

    const STEP: u64 = 30;
    const DIGITS: usize = 6;

    let counter = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / STEP;

    let key = base32_decode(&secret).expect("Invalid base32 secret");
    let mut mac: Hmac<Sha1> = Hmac::new_from_slice(&key).unwrap();
    mac.update(&counter.to_be_bytes());
    let hs = mac.finalize().into_bytes();

    let offset = (hs.last().unwrap() & 0x0f) as usize;

    let p = u32::from_be_bytes((hs[offset..offset + 4]).try_into().unwrap()) & 0x7FFFFFFF;

    println!("{:0DIGITS$}", p % 10_u32.pow(DIGITS as u32))
}
