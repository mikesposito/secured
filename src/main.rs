use std::fs::{metadata, File};
use std::io::{Read, Write};
use text_io::read;

use clap::{Parser, Subcommand};
use enclave::{Enclave, EncryptionKey};

#[derive(Debug, Subcommand)]
enum Command {
  Encrypt {
    file: String,
    password: Option<String>,
  },
  Decrypt {
    file: String,
    password: Option<String>,
  },
}

#[derive(Parser, Debug)]
struct Args {
  #[command(subcommand)]
  command: Command,
}

fn main() {
  let args = Args::parse();

  match args.command {
    Command::Encrypt { file, password } => {
      let password = get_password_or_prompt(password);
      encrypt_file(&password, &file);
    }
    Command::Decrypt { file, password } => {
      let password = get_password_or_prompt(password);
      decrypt_file(&password, &file);
    }
  }
}

fn encrypt_file(password: &String, filename: &String) {
  let encryption_key = EncryptionKey::new(password.as_bytes(), 900_000);
  let enclave = Enclave::from_plain_bytes(
    encryption_key.salt,
    &encryption_key.pubk,
    get_file_as_byte_vec(filename),
  )
  .unwrap();
  let encrypted_bytes: Vec<u8> = enclave.into();

  File::create(format!("{}.secured", filename))
    .expect("Unable to create file")
    .write_all(&encrypted_bytes)
    .expect("Unable to write data");

  println!("Wrote encrypted file to {}.secured", filename);
}

fn decrypt_file(password: &String, filename: &String) {
  let encrypted_bytes = get_file_as_byte_vec(filename);
  let enclave = Enclave::try_from(encrypted_bytes).expect("Unable to deserialize enclave");
  let encryption_key = EncryptionKey::with_salt(password.as_bytes(), enclave.metadata, 900_000);
  let recovered_bytes = enclave
    .decrypt(&encryption_key.pubk)
    .expect("Wrong password or corrupted enclave");

  File::create(filename.replace(".secured", ""))
    .expect("Unable to create file")
    .write_all(&recovered_bytes)
    .expect("Unable to write data");

  println!(
    "Wrote decrypted file to {}",
    filename.replace(".enclave", "")
  );
}

fn get_file_as_byte_vec(filename: &String) -> Vec<u8> {
  let mut f = File::open(&filename).expect("no file found");
  let metadata = metadata(&filename).expect("unable to read metadata");
  let mut buffer = vec![0; metadata.len() as usize];
  f.read(&mut buffer).expect("buffer overflow");

  buffer
}

fn get_password_or_prompt(password: Option<String>) -> String {
  match password {
    Some(password) => password,
    None => {
      println!("Enter password: ");
      read!("{}\n")
    }
  }
}
