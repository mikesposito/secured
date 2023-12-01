use clap::{Parser, Subcommand};
use rpassword::prompt_password;
use std::fs::{metadata, File};
use std::io::{Read, Write};

use cipher::Key;
use enclave::Enclave;

/// Defines command line subcommands for the application.
#[derive(Debug, Subcommand)]
enum Command {
  /// Encrypts a specified file.
  Encrypt {
    /// Path to the file to be encrypted.
    file: String,

    /// Optional password. If not provided, it will be prompted for.
    password: Option<String>,
  },
  /// Decrypts a specified file.
  Decrypt {
    /// Path to the file to be decrypted.
    file: String,

    /// Optional password. If not provided, it will be prompted for.
    password: Option<String>,
  },
}

/// Defines the command line arguments structure.
#[derive(Parser, Debug)]
struct Args {
  /// The specific subcommand to execute (either Encrypt or Decrypt).
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

/// Encrypts a file with a given password.
///
/// # Arguments
/// * `password` - The password used for encryption.
/// * `filename` - The name of the file to be encrypted.
fn encrypt_file(password: &String, filename: &String) {
  let encryption_key: Key<32, 16> = Key::new(password.as_bytes(), 900_000);
  let enclave = Enclave::from_plain_bytes(
    encryption_key.salt,
    encryption_key.pubk,
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

/// Decrypts a file with a given password.
///
/// # Arguments
/// * `password` - The password used for decryption.
/// * `filename` - The name of the file to be decrypted.
fn decrypt_file(password: &String, filename: &String) {
  let encrypted_bytes = get_file_as_byte_vec(filename);
  let enclave = Enclave::try_from(encrypted_bytes)
    .expect("Unable to deserialize enclave");
  let encryption_key: Key<32, 16> = Key::with_salt(password.as_bytes(), enclave.metadata, 900_000);
  let recovered_bytes = enclave
    .decrypt(encryption_key.pubk)
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

/// Reads a file and returns its contents as a byte vector.
///
/// # Arguments
/// * `filename` - The name of the file to read.
///
/// # Returns
/// A `Vec<u8>` containing the contents of the file.
fn get_file_as_byte_vec(filename: &String) -> Vec<u8> {
  let mut f = File::open(&filename).expect("no file found");
  let metadata = metadata(&filename).expect("unable to read metadata");
  let mut buffer = vec![0; metadata.len() as usize];
  f.read(&mut buffer).expect("buffer overflow");

  buffer
}

/// Retrieves a password, either from an `Option` or by prompting the user.
///
/// # Arguments
/// * `password` - An `Option<String>` that may already contain the password.
///
/// # Returns
/// A `String` containing the password.
fn get_password_or_prompt(password: Option<String>) -> String {
  match password {
    Some(password) => password,
    None => prompt_password("Enter password: ").expect("Unable to read password"),
  }
}
