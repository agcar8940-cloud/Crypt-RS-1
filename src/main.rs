use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use base64::{Engine as _, engine::general_purpose};
use std::io::{self, Write};

fn banner() {
    println!(
        r###"
    ____________  ______  ______    ____  _____      ___
   / ____/ __ \ \/ / __ \/_  __/   / __ \/ ___/     <  /
  / /   / /_/ /\  / /_/ / / /_____/ /_/ /\__ \______/ /
 / /___/ _, _/ / / ____/ / /_____/ _, _/___/ /_____/ /
 \____/_/ |_| /_/_/     /_/     /_/ |_|/____/     /_/
    "###
    );
    println!("Crypt-RS-1 V~1.0");
    println!("Made by agcar8940-cloud");
}

fn input() -> String {
    let mut x = String::new();
    io::stdin().read_line(&mut x).expect("Failed");
    x.trim().to_string()
}

fn prompt(st: &str) {
    print!("{}", st);
    io::stdout().flush().expect("Failed");
}

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key_bytes = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
        .expect("Failed");
    key_bytes
}

fn help() {
    println!("Available commands:");
    println!("  encrypt          - encrypt text using AES-256-GCM");
    println!("  decrypt          - decrypt text using AES-256-GCM");
    println!("  encrypt-caesar   - encrypt text using a Caesar shift cipher");
    println!("  decrypt-caesar   - decrypt text using a Caesar shift cipher");
    println!("  ch-pwd           - change the password/key used for AES encryption");
    println!("  print-key        - print the current raw AES key bytes (be careful sharing this!)");
    println!("  help             - show this help message");
    println!("  exit             - quit the program");
}

fn encrypt_caesar(st: &mut String, offset: i32) {
    let encrypted: Vec<u8> = st
        .bytes()
        .map(|b| {
            let shifted = b as u16 + offset as u16;
            (shifted % 128) as u8
        })
        .collect();
    *st = String::from_utf8(encrypted).expect("Failed");
}

fn decrypt_caesar(st: &mut String, offset: i32) {
    let decrypted: Vec<u8> = st
        .bytes()
        .map(|b| {
            let shifted = (b as i32 - offset).rem_euclid(128);
            shifted as u8
        })
        .collect();
    *st = String::from_utf8(decrypted).expect("Failed");
}

fn main() {
    let mut key = Aes256Gcm::generate_key(&mut OsRng);
    let mut cipher = Aes256Gcm::new(&key);
    let mut current_password: Option<String> = None;

    banner();
    println!(
        "Welcome to Crypt-RS-1! This program will encrypt and decrypt texts, this is not a caesar encrypter"
    );
    println!("Enter <<help>> to see the commands");
    'main_loop: loop {
        prompt("crypt-rs1>> ");
        let rwinp = input();
        let inp: &str = &rwinp;
        match inp {
            "exit" => {
                println!("Exiting..");
                break 'main_loop;
            }

            "ch-pwd" => {
                prompt("enter password phrase: ");
                let inppp = input();
                let salt =
                    b"this-salt-is-awesome-and-to-get-this-you-will-have-to-check-the-source-code!";
                let key_bytes = derive_key(&inppp, salt);
                key = *Key::<Aes256Gcm>::from_slice(&key_bytes);
                let new_key = Key::<Aes256Gcm>::from_slice(&key_bytes);
                cipher = Aes256Gcm::new(new_key);
                current_password = Some(inppp);
                println!("Password changed successfully");
            }

            "print-key" => {
                let hex_key: String = key.iter().map(|b| format!("{:02x}", b)).collect();

                println!("key (raw bytes): {:?}", key);
                println!("key (hex):       {}", hex_key);
                match &current_password {
                    Some(pw) => println!("password:         {}", pw),
                    None => println!("password:        (none set, enter a password first)"),
                }
            }

            "encrypt" => {
                prompt("enter text to encrypt: ");
                let strinps = input();
                let mut nonce_bytes = [0u8; 12];
                OsRng.fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);
                let ciphertext = cipher.encrypt(nonce, strinps.as_bytes()).expect("Failed");
                let mut combined = nonce_bytes.to_vec();
                combined.extend(ciphertext);
                let encoded = general_purpose::STANDARD.encode(&combined);
                println!("Encrypted text: {}", encoded);
            }

            "decrypt" => {
                prompt("enter text to decrypt: ");
                let strinps = input();

                let combined = match general_purpose::STANDARD.decode(strinps.trim()) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        println!("Invalid base64 input");
                        continue 'main_loop;
                    }
                };

                if combined.len() < 12 {
                    println!("Too short!");
                    continue 'main_loop;
                }

                let (nonce_bytes, ciphertext) = combined.split_at(12);
                let nonce = Nonce::from_slice(nonce_bytes);

                match cipher.decrypt(nonce, ciphertext) {
                    Ok(plaintext) => match String::from_utf8(plaintext) {
                        Ok(text) => println!("Decrypted text: {}", text),
                        Err(_) => println!("Decrypted, but result wasnt a valid UTF-8"),
                    },
                    Err(_) => {
                        println!("Decryption failed");
                    }
                }
            }

            "encrypt-caesar" => {
                prompt("enter text to encrypt: ");
                let mut strinps = input();
                prompt("enter shift number: ");
                let shiftts = input();
                let shift: i32 = shiftts.trim().parse().expect("enter a valid number");

                encrypt_caesar(&mut strinps, shift);
                println!("Encrypted text: {}", strinps);
            }

            "help" => help(),

            "decrypt-caesar" => {
                prompt("enter text to decrypt: ");
                let mut strinps = input();
                prompt("enter shift number: ");
                let shiftts = input();
                let shift: i32 = shiftts.trim().parse().expect("enter a valid number");

                decrypt_caesar(&mut strinps, shift);
                println!("Decrypted text: {}", strinps);
            }

            _ => {
                println!("Command not found: {}", inp);
            }
        }
    }
}
