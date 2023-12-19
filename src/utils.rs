use glob::glob;
use indicatif::{ProgressBar, ProgressStyle};
use rpassword::prompt_password;
use std::fs::{metadata, File};
use std::io::{Read, Write};
use std::time::Duration;

use cipher::{Key, KeyDerivationStrategy};
use enclave::{Decryptable, Encryptable};

pub(crate) const LOADERS: [&str; 7] = [
  "▹▹▹▹▹",
  "▸▹▹▹▹",
  "▹▸▹▹▹",
  "▹▹▸▹▹",
  "▹▹▹▸▹",
  "▹▹▹▹▸",
  "▪▪▪▪▪",
];

pub enum Credentials {
  Password(String),
  HexKey(String),
}

/// Encrypts files with a given password.
///
/// # Arguments
/// * `credentials` - The password used for encryption.
/// * `path` - The path of the files to be encrypted.
pub fn encrypt_files(credentials: &Credentials, path: Vec<String>) {
  let plaintext_files = path
    .iter()
    .map(|p| glob(&p).expect("Invalid file pattern").collect::<Vec<_>>())
    .flatten()
    .collect::<Vec<_>>();

  match credentials {
    Credentials::Password(password) => {
      encrypt_multiple_with_password(password.to_string(), plaintext_files)
    }
    Credentials::HexKey(hex_key) => {
      encrypt_multiple_with_hex_key(hex_key.to_string(), plaintext_files)
    }
  };
}

fn encrypt_multiple_with_password(
  password: String,
  plaintext_files: Vec<Result<std::path::PathBuf, glob::GlobError>>,
) {
  let counter = std::time::Instant::now();
  let progress = ProgressBar::new_spinner();
  progress.set_style(
    ProgressStyle::with_template("{spinner:.yellow} {msg}")
      .unwrap()
      .tick_strings(&LOADERS),
  );

  let encryption_key = generate_encryption_key_with_progress(&password);

  for (i, entry) in plaintext_files.iter().enumerate() {
    match entry {
      Ok(path) => {
        let filename = path.to_str().unwrap().to_string();

        progress.set_message(format!(
          "[{}/{}] {}",
          i + 1,
          plaintext_files.len(),
          filename.clone()
        ));

        if metadata(path).unwrap().is_file() {
          let encrypted_bytes = get_file_as_byte_vec(&filename).encrypt_with_key(&encryption_key);
          File::create(format!("{}.secured", filename))
            .expect("Unable to create file")
            .write_all(&encrypted_bytes)
            .expect("Unable to write data");
        }

        progress.tick();
      }
      Err(e) => println!("{:?}", e),
    }
  }

  progress.finish_with_message(format!(
    "✅ > {} files secured in {}ms",
    plaintext_files.len(),
    counter.elapsed().as_millis()
  ));
}

fn encrypt_multiple_with_hex_key(
  hex_key: String,
  plaintext_files: Vec<Result<std::path::PathBuf, glob::GlobError>>,
) {
  let counter = std::time::Instant::now();
  let progress = ProgressBar::new_spinner();
  progress.set_style(
    ProgressStyle::with_template("{spinner:.yellow} {msg}")
      .unwrap()
      .tick_strings(&LOADERS),
  );

  let encryption_key: [u8; 32] = hex::decode(hex_key)
    .expect("Not a valid hex value")
    .try_into()
    .expect("Not a valid 32-byte key");

  for (i, entry) in plaintext_files.iter().enumerate() {
    match entry {
      Ok(path) => {
        let filename = path.to_str().unwrap().to_string();

        progress.set_message(format!(
          "[{}/{}] {}",
          i + 1,
          plaintext_files.len(),
          filename.clone()
        ));

        if metadata(path).unwrap().is_file() {
          let encrypted_bytes =
            get_file_as_byte_vec(&filename).encrypt_with_raw_key(encryption_key);
          File::create(format!("{}.secured", filename))
            .expect("Unable to create file")
            .write_all(&encrypted_bytes)
            .expect("Unable to write data");
        }

        progress.tick();
      }
      Err(e) => println!("{:?}", e),
    }
  }

  progress.finish_with_message(format!(
    "✅ > {} files secured in {}ms",
    plaintext_files.len(),
    counter.elapsed().as_millis()
  ));
}

/// Decrypts files with a given password.
///
/// # Arguments
/// * `password` - The password used for decryption.
/// * `path` - The path of the files to be decrypted.
pub fn decrypt_files(credentials: &Credentials, path: Vec<String>) {
  let encrypted_files = path
    .iter()
    .map(|p| glob(&p).expect("Invalid file pattern").collect::<Vec<_>>())
    .flatten()
    .collect::<Vec<_>>();

  let counter = std::time::Instant::now();
  let progress = ProgressBar::new_spinner();
  progress.set_style(
    ProgressStyle::with_template("{spinner:.yellow} {msg}")
      .unwrap()
      .tick_strings(&LOADERS),
  );

  for (i, entry) in encrypted_files.iter().enumerate() {
    match entry {
      Ok(path) => {
        let filename = path.to_str().unwrap().to_string();

        progress.set_message(format!(
          "[{}/{}] {}",
          i + 1,
          encrypted_files.len(),
          filename.clone()
        ));

        let encrypted_bytes = get_file_as_byte_vec(&filename);
        let recovered_bytes = match credentials {
          Credentials::Password(password) => {
            encrypted_bytes.decrypt(password.clone())
          }
          Credentials::HexKey(hex_key) => {
            let encryption_key: [u8; 32] = hex::decode(hex_key)
              .expect("Not a valid hex value")
              .try_into()
              .expect("Not a valid 32-byte key");

            encrypted_bytes.decrypt_with_key(encryption_key)
          }
        };

        File::create(filename.replace(".secured", ""))
          .expect("Unable to create file")
          .write_all(&recovered_bytes.unwrap())
          .expect("Unable to write data");

        progress.tick();
      }
      Err(e) => println!("{:?}", e),
    }
  }

  progress.finish_with_message(format!(
    "✅ > {} files decrypted in {}ms",
    encrypted_files.len(),
    counter.elapsed().as_millis()
  ));
}

/// Reads a file and returns its contents as a byte vector.
///
/// # Arguments
/// * `filename` - The name of the file to read.
///
/// # Returns
/// A `Vec<u8>` containing the contents of the file.
pub(crate) fn get_file_as_byte_vec(filename: &String) -> Vec<u8> {
  let mut f = File::open(filename).expect("no file found");
  let metadata = metadata(filename).expect("unable to read metadata");
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
pub(crate) fn get_password_or_prompt(password: Option<String>) -> String {
  match password {
    Some(password) => password,
    None => prompt_password("Enter password: ").expect("Unable to read password"),
  }
}

pub(crate) fn generate_encryption_key_with_progress(password: &String) -> Key<32, 16> {
  let counter = std::time::Instant::now();
  let derivation_progress = ProgressBar::new_spinner();

  derivation_progress.enable_steady_tick(Duration::from_millis(120));
  derivation_progress.set_style(
    ProgressStyle::with_template("{spinner:.yellow} {msg}")
      .unwrap()
      .tick_strings(&LOADERS),
  );
  derivation_progress.set_message("Deriving encryption key");

  let encryption_key: Key<32, 16> = Key::new(password.as_bytes(), KeyDerivationStrategy::default());
  derivation_progress.finish_with_message(format!(
    "{} {}ms",
    "🔑 > Key derived.",
    counter.elapsed().as_millis()
  ));

  encryption_key
}

pub(crate) fn generate_encryption_key_with_options(
  password: &String,
  iterations: usize,
  salt: Option<String>,
) {
  let counter = std::time::Instant::now();
  let derivation_progress = ProgressBar::new_spinner();

  derivation_progress.enable_steady_tick(Duration::from_millis(120));
  derivation_progress.set_style(
    ProgressStyle::with_template("{spinner:.yellow} {msg}")
      .unwrap()
      .tick_strings(&LOADERS),
  );
  derivation_progress.set_message("Deriving encryption key");

  let encryption_key: Key<32, 16> = match salt {
    None => Key::new(
      password.as_bytes(),
      KeyDerivationStrategy::PBKDF2(iterations),
    ),
    Some(salt) => Key::with_salt(
      password.as_bytes(),
      hex::decode(salt)
        .unwrap()
        .try_into()
        .expect("The salt is not of the right size"),
      KeyDerivationStrategy::PBKDF2(iterations),
    ),
  };
  derivation_progress.finish_with_message(format!(
    "{} {}ms",
    "🔑 > Key derived.",
    counter.elapsed().as_millis()
  ));

  println!("🔑 > Key: {}", hex::encode(encryption_key.pubk));
  println!("🧂 > Salt: {}", hex::encode(encryption_key.salt));
}
