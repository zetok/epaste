/*
    Copyright © 2016 Zetok Zalbavar <zexavexxe@gmail.com>

    This file is part of Epaste.

    Epaste is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Epaste is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Epaste.  If not, see <http://www.gnu.org/licenses/>.
*/

/*!
    Currently just read stdin to the end, encrypt that with a `Key` derived from
    a supplied password, base64 concantenated `Nonce`, `Salt` and the payload
    and print it to stdout.
*/

use std::env;
use std::io;
use std::io::{Read, Write};

extern crate rustc_serialize;
use rustc_serialize::base64::*;

extern crate sodiumoxide;
use sodiumoxide::crypto::secretbox::*;
use sodiumoxide::crypto::pwhash::*;


/**
    Struct for the storing data that is needed for deriving `Key`, and
    decrypting encrypted payload.

    Consists of:

    * `Nonce`
    * `Salt`
*/
struct ToDecData {
    nonce: Nonce,
    salt: Salt,
}

/// Number of bytes of serialized [`ToDecData`](./struct.ToDecData.html).
const TO_DEC_DATA_BYTES: usize = NONCEBYTES + SALTBYTES;

impl ToDecData {
    /// Create new `ToDecBytes` with random `Nonce` and `Salt`.
    fn new() -> Self {
        ToDecData {
            nonce: gen_nonce(),
            salt: gen_salt(),
        }
    }

    /// Return its `Nonce`.
    fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Return its salt.
    fn salt(&self) -> &Salt {
        &self.salt
    }

    /// Decode bytes into the `ToDecData`.
    fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < TO_DEC_DATA_BYTES { return None }

        let nonce = match Nonce::from_slice(&bytes[..NONCEBYTES]) {
            Some(n) => n,
            None    => return None,
        };

        let salt = match Salt::from_slice(&bytes[NONCEBYTES..(NONCEBYTES + SALTBYTES)]) {
            Some(s) => s,
            None    => return None,
        };

        Some(ToDecData { nonce: nonce, salt: salt })
    }

    /// Encode `ToDecData` into bytes.
    fn as_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(TO_DEC_DATA_BYTES);
        let Nonce(n) = self.nonce;
        result.extend_from_slice(&n);
        let Salt(s) = self.salt;
        result.extend_from_slice(&s);
        result
    }
}

/// Number of bytes that an encrypted data should have.
const ENCRYPTED_MIN_SIZE: usize = TO_DEC_DATA_BYTES + MACBYTES;

/**
    Get bytes from stdin.

    Currently assumes that getting bytes can't fail. If failure were to happen,
    and empty message would be provided(!).
*/
fn get_bytes() -> Vec<u8> {
    let mut result = Vec::new();
    drop(io::stdin().read_to_end(&mut result));
    result
}


/**
    Decrypt bytes.

    Bytes should be de-base64d.

    Provided `&str` is used to derive key.

    Returns `None` if data could not have been decrypted.

    Panics if deriving key failed.
*/
fn decrypt(bytes: &[u8], passwd: &str) -> Option<Vec<u8>> {
    if bytes.len() < ENCRYPTED_MIN_SIZE { return None }
    let to_dec_data = match ToDecData::from_slice(&bytes) {
        Some(tdd) => tdd,
        None => return None,  // absolutely has no chances of happening
    };

    // derive key
    let mut keyb = [0; KEYBYTES];
    drop(derive_key(&mut keyb, passwd.as_bytes(), to_dec_data.salt(),
            OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE)
        .expect("Failed to derive key."));
    let key = Key(keyb);

    open(&bytes[TO_DEC_DATA_BYTES..], to_dec_data.nonce(), &key).ok()
        .and_then(|d| Some(d))
}


/**
    Encrypt bytes using provided `passwd`.

    Panics if deriving key failed.
*/
fn encrypt(bytes: &[u8], passwd: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(ENCRYPTED_MIN_SIZE + bytes.len());
    let to_dec_data = ToDecData::new();
    result.extend_from_slice(&to_dec_data.as_bytes());

    // derive key
    let mut keyb = [0; KEYBYTES];
    drop(derive_key(&mut keyb, passwd.as_bytes(), to_dec_data.salt(),
            OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE)
        .expect("Failed to derive key."));
    let key = Key(keyb);

    let encrypted = seal(&bytes, to_dec_data.nonce(), &key);
    result.extend_from_slice(&encrypted);
    result
}


/// Help message.
fn help() {
    let help_msg = String::from("Licensed under GNU GPLv3+ © 2016 Zetok Zalbavar.

`epaste` usage:

To encrypt:

    epaste <password> < <file>

To decrypt:

    epaste -d <password> < <file>

To decrypt raw bytes into a file:

    epaste -dr <password> < <file> > <output>");

    println!("{}", help_msg);
}


/**
    Parse command line args (perhaps opt to use some lib for it, or something).

    Returns `None` if number of args doesn't match.
*/
fn parse_args() -> Option<Switches> {
    let mut sw = Switches::new();
    match env::args().count() {
        2 | 3 => {
            sw.passwd = env::args().last().unwrap().to_string();
            match &*env::args().nth(1).unwrap() {
                "-d" => sw.decrypt = true,
                "-dr" => {
                    sw.decrypt = true;
                    sw.raw = true;
                },
                _ => {},
            }
        },
        _ => return None,
    }

    Some(sw)
}


/**
    Options to run with.
*/
#[derive(Clone, Debug)]
struct Switches {
    passwd: String,
    /// Whether to decrypt.
    decrypt: bool,
    ///// Provide raw bytes on output instead of text.
    raw: bool,
}

impl Switches {
    fn new() -> Self {
        Switches { passwd: String::new(), decrypt: false, raw: false }
    }
}



fn main() {
    let input = get_bytes();
    if let Some(sw) = parse_args() {
        if sw.decrypt {
            match input.from_base64() {
                Ok(bytes) => {
                    match decrypt(&bytes, &sw.passwd) {
                        None => panic!("Bytes couldn't be decrypted!"),
                        Some(decrypted) => {
                            if sw.raw {
                                drop(io::stdout().write_all(&decrypted));
                            } else {
                                let string = String::from_utf8(decrypted)
                                    .expect("Failed to parse bytes as UTF-8!");
                                println!("{}", string);
                            }
                        },
                    }
                },
                Err(e) => panic!("Failed to de-base64: {}", e),
            }
        } else {
            println!("{}", encrypt(&input, &sw.passwd).to_base64(MIME));
        }
    } else {
        help();
    }
}
