use clap::Parser;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(about = "Generate google authenticator TOTPs")]
struct Args {
    #[arg(long, default_value_t = 30)]
    step: u64,

    #[arg(short, long, default_value_t = 6, value_parser = clap::value_parser!(u8).range(1..=31))]
    digits: u8,

    #[arg(short, long, default_value_t = 1)]
    count: usize,

    #[arg(short, long)]
    secret: String,
}

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
    let args = Args::parse();

    for i in 0..args.count {
        let counter = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / args.step)
            + i as u64;

        let key = base32_decode(&args.secret).expect("Secret is invalid base32");
        let mut mac: Hmac<Sha1> = Hmac::new_from_slice(&key).unwrap();
        mac.update(&counter.to_be_bytes());
        let hs = mac.finalize().into_bytes();

        let offset = (hs.last().unwrap() & 0x0f) as usize;

        let p = u32::from_be_bytes((hs[offset..offset + 4]).try_into().unwrap()) & 0x7FFFFFFF;

        print!(
            "{:0width$} ",
            p % 10_u32.pow(args.digits as u32),
            width = args.digits as usize
        );
    }
    println!();
}
