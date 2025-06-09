use glob::glob;
use indicatif::{ProgressBar, ProgressStyle};
use rpassword::prompt_password;
use std::fs::{metadata, File};
use std::io::{Read, Write};
use std::time::Duration;

use cipher::{Key, KeyDerivationStrategy, SignedEnvelope};
use enclave::{Decryptable, Enclave, Encryptable};

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

enum CachedCredentials {
  Key(Key<32, 16>),
  KeyBytes([u8; 32]),
}

/// Encrypts files with a given password.
///
/// # Arguments
/// * `credentials` - The password used for encryption.
/// * `path` - The path of the files to be encrypted.
/// * `wipe` - Whether or not to wipe the original file after encryption.
pub fn encrypt_files(
  credentials: &Credentials,
  path: Vec<String>,
  wipe: bool,
) -> Result<(), String> {
  let plaintext_files = path
    .iter()
    .flat_map(|p| glob(p).expect("Invalid file pattern").collect::<Vec<_>>())
    .collect::<Vec<_>>();

  let encryption_key = match credentials {
    Credentials::Password(password) => {
      CachedCredentials::Key(generate_encryption_key_with_progress(password))
    }
    Credentials::HexKey(hex_key) => {
      let encryption_key: [u8; 32] = hex::decode(hex_key)
        .expect("Not a valid hex value")
        .try_into()
        .expect("Not a valid 32-byte key");

      CachedCredentials::KeyBytes(encryption_key)
    }
  };

  let counter = std::time::Instant::now();
  let mut bytes_counter: usize = 0;
  let progress = ProgressBar::new_spinner();
  progress.set_style(
    ProgressStyle::with_template("{spinner:.yellow} {msg}")
      .unwrap()
      .tick_strings(&LOADERS),
  );

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
          let file_contents = get_file_as_byte_vec(&filename);
          let encrypted_bytes = match &encryption_key {
            CachedCredentials::Key(key) => file_contents.encrypt_with_key(key),
            CachedCredentials::KeyBytes(key) => file_contents.encrypt_with_raw_key(*key),
          };
          bytes_counter += encrypted_bytes.len();
          File::create(format!("{}.secured", filename))
            .expect("Unable to create file")
            .write_all(&encrypted_bytes)
            .expect("Unable to write data");

          if wipe {
            std::fs::remove_file(filename).expect("Unable to remove file");
          }
        }

        progress.tick();
      }
      Err(e) => println!("{:?}", e),
    }
  }

  progress.finish_with_message(format!(
    "✅ > {} files secured ({}MB in {}ms)",
    plaintext_files.len(),
    bytes_counter / 1024 / 1024,
    counter.elapsed().as_millis()
  ));

  Ok(())
}

pub fn pack_and_encrypt_files(
  credentials: &Credentials,
  paths: Vec<String>,
  output: String,
  wipe: bool,
) -> Result<(), String> {
  let buffer = Vec::new();
  let cursor = std::io::Cursor::new(buffer);
  let mut archive = tar::Builder::new(cursor);

  let plaintext_files = paths
    .iter()
    .flat_map(|p| glob(p).expect("Invalid file pattern").collect::<Vec<_>>())
    .collect::<Vec<_>>();
  for path in plaintext_files.iter() {
    match path {
      Ok(path) if path.is_file() => {
        let filename = path.to_str().unwrap().to_string();
        archive
          .append_path(&filename)
          .map_err(|e| format!("Failed to append path {}: {}", &filename, e))?;
        if wipe {
          std::fs::remove_file(&filename)
            .map_err(|e| format!("Failed to remove file {}: {}", &filename, e))?;
        }
      }
      _ => continue, // Skip non-file entries
    }
  }

  let cursor = archive
    .into_inner()
    .map_err(|e| format!("Failed to finalize archive: {}", e))?;

  let archive_bytes = cursor.into_inner();

  let counter = std::time::Instant::now();
  let mut bytes_counter: usize = 0;
  let progress = ProgressBar::new_spinner();
  progress.set_style(
    ProgressStyle::with_template("{spinner:.yellow} {msg}")
      .unwrap()
      .tick_strings(&LOADERS),
  );

  let encryption_key = match credentials {
    Credentials::Password(password) => {
      CachedCredentials::Key(generate_encryption_key_with_progress(password))
    }
    Credentials::HexKey(hex_key) => {
      let encryption_key: [u8; 32] = hex::decode(hex_key)
        .expect("Not a valid hex value")
        .try_into()
        .expect("Not a valid 32-byte key");

      CachedCredentials::KeyBytes(encryption_key)
    }
  };

  let encrypted_bytes = match &encryption_key {
    CachedCredentials::Key(key) => archive_bytes.encrypt_with_key(key),
    CachedCredentials::KeyBytes(key) => archive_bytes.encrypt_with_raw_key(*key),
  };

  File::create(format!("{}.spack", output))
    .expect("Unable to create file")
    .write_all(&encrypted_bytes)
    .expect("Unable to write data");
  bytes_counter += encrypted_bytes.len();

  progress.finish_with_message(format!(
    "✅ > {} files packed ({}MB in {}ms)",
    paths.len(),
    bytes_counter / 1024 / 1024,
    counter.elapsed().as_millis()
  ));

  Ok(())
}

/// Decrypts files with a given password.
///
/// # Arguments
/// * `password` - The password used for decryption.
/// * `path` - The path of the files to be decrypted.
/// * `wipe` - Whether or not to wipe the encrypted file after decryption.
pub fn decrypt_files(
  credentials: &Credentials,
  path: Vec<String>,
  wipe: bool,
) -> Result<(), String> {
  let encrypted_files = path
    .iter()
    .flat_map(|p| glob(p).expect("Invalid file pattern").collect::<Vec<_>>())
    .collect::<Vec<_>>();

  let counter = std::time::Instant::now();
  let progress = ProgressBar::new_spinner();
  progress.set_style(
    ProgressStyle::with_template("{spinner:.yellow} {msg}")
      .unwrap()
      .tick_strings(&LOADERS),
  );

  let mut cached_encryption_key = match credentials {
    // we skip the password derivation step in this case
    // because we first need the key salt and iterations
    // from the enclave
    Credentials::Password(_) => [0u8; 32],
    // in this case we already have the key, super fast!
    Credentials::HexKey(hex_key) => {
      let encryption_key: [u8; 32] = hex::decode(hex_key)
        .expect("Not a valid hex value")
        .try_into()
        .expect("Not a valid 32-byte key");

      encryption_key
    }
  };

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

        if metadata(path).unwrap().is_file() {
          let encrypted_bytes = get_file_as_byte_vec(&filename);
          let enclave = Enclave::<Vec<u8>>::try_from(encrypted_bytes.clone()).or(Err(format!(
            "File {} is not a valid enclave",
            filename.clone()
          )))?;
          let recovered_bytes = match credentials {
            Credentials::Password(password) => {
              // we hope that the key is the same as the one used for the previous file
              let result = enclave.decrypt(cached_encryption_key);
              if result.is_ok() {
                result
              } else {
                // if the optimistic decryption fails, we try again with the password
                cached_encryption_key = enclave
                  .recover_key(password.as_bytes())
                  .or(Err(format!("Unable to recover encryption key")))?
                  .pubk;
                enclave.decrypt(cached_encryption_key)
              }
            }
            _ => encrypted_bytes.decrypt_with_key(cached_encryption_key),
          };

          File::create(filename.replace(".secured", ""))
            .expect("Unable to create file")
            .write_all(&recovered_bytes.unwrap())
            .or(Err(format!(
              "Unable to write decrypted data to file {}",
              filename.replace(".secured", "")
            )))?;

          if wipe {
            std::fs::remove_file(filename).or(Err(format!("Unable to remove file")))?;
          }
        }

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

  Ok(())
}

pub fn decrypt_and_unpack_files(
  credentials: &Credentials,
  paths: Vec<String>,
  output: String,
  wipe: bool,
) -> Result<(), String> {
  let encrypted_files = paths
    .iter()
    .flat_map(|p| glob(p).expect("Invalid file pattern").collect::<Vec<_>>())
    .collect::<Vec<_>>();

  let counter = std::time::Instant::now();
  let progress = ProgressBar::new_spinner();
  progress.set_style(
    ProgressStyle::with_template("{spinner:.yellow} {msg}")
      .unwrap()
      .tick_strings(&LOADERS),
  );

  let mut cached_encryption_key = match credentials {
    Credentials::Password(_) => [0u8; 32],
    Credentials::HexKey(hex_key) => {
      let encryption_key: [u8; 32] = hex::decode(hex_key)
        .expect("Not a valid hex value")
        .try_into()
        .expect("Not a valid 32-byte key");

      encryption_key
    }
  };

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

        if metadata(path).unwrap().is_file() {
          let encrypted_bytes = get_file_as_byte_vec(&filename);
          let enclave = Enclave::<Vec<u8>>::try_from(encrypted_bytes.clone()).or(Err(format!(
            "File {} is not a valid enclave",
            filename.clone()
          )))?;
          let recovered_bytes = match credentials {
            Credentials::Password(password) => {
              // we hope that the key is the same as the one used for the previous file
              let result = enclave.decrypt(cached_encryption_key);
              if result.is_ok() {
                result
              } else {
                // if the optimistic decryption fails, we try again with the password
                cached_encryption_key = enclave
                  .recover_key(password.as_bytes())
                  .or(Err(format!("Unable to recover encryption key")))?
                  .pubk;
                enclave.decrypt(cached_encryption_key)
              }
            }
            _ => encrypted_bytes.decrypt_with_key(cached_encryption_key),
          };

          let decrypted_data = recovered_bytes.unwrap();
          let mut archive = tar::Archive::new(std::io::Cursor::new(decrypted_data.clone()));
          archive.unpack(&output).or(Err(format!(
            "Unable to unpack archive from file {}",
            filename
          )))?;
          if wipe {
            std::fs::remove_file(filename).or(Err(format!("Unable to remove file")))?;
          }
        }
        progress.tick();
      }
      Err(e) => println!("{:?}", e),
    }
  }
  progress.finish_with_message(format!(
    "✅ > {} files unpacked in {}ms",
    encrypted_files.len(),
    counter.elapsed().as_millis()
  ));
  Ok(())
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
pub(crate) fn get_password_or_prompt(password: Option<String>, confirmation: bool) -> String {
  match password {
    Some(password) => password,
    None => {
      let password = prompt_password("Enter password: ").expect("Unable to read password");
      if !confirmation {
        return password;
      }

      let password_confirmation =
        prompt_password("Confirm password: ").expect("Unable to read password");

      if password != password_confirmation {
        panic!("Passwords do not match");
      }

      password
    }
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
) -> Result<(), String> {
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

  Ok(())
}

pub(crate) fn inspect_files(path: Vec<String>) -> Result<(), String> {
  let files = path
    .iter()
    .flat_map(|p| glob(p).expect("Invalid file pattern").collect::<Vec<_>>())
    .collect::<Vec<_>>();

  for entry in files {
    match entry {
      Ok(path) => {
        let filename = path.to_str().unwrap().to_string();
        let file_contents = get_file_as_byte_vec(&filename);

        let enclave: Result<Enclave<Vec<u8>>, _> = Enclave::try_from(file_contents);

        if enclave.is_err() {
          println!(" ------------------------------ ");
          println!("📦 > File\t\t\t {}", filename);
          println!("🚫 > Not a valid enclave.\n\n\n");
          continue;
        }

        let enclave = enclave.unwrap();
        let envelope =
          SignedEnvelope::try_from(enclave.encrypted_bytes.to_vec()).expect("Invalid envelope");

        println!(" ------------------------------ ");
        println!("📦 > File\t\t\t {}\n", filename);
        println!(
          "ℹ️  > Signed envelope headers\t\t\t {}",
          hex::encode(envelope.header)
        );
        println!("🤐 > Ciphertext\t\t\t {}", hex::encode(envelope.data));
        println!("✍️  > Signature\t\t\t {}", hex::encode(envelope.mac));
        println!("🎲 > Nonce\t\t\t {}", hex::encode(enclave.nonce));
        println!("👓 > Enclave Metadata\t {}", hex::encode(enclave.metadata));
      }
      Err(e) => println!("{:?}", e),
    }
  }

  Ok(())
}
