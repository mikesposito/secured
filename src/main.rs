use clap::{Parser, Subcommand};

mod utils;
pub use utils::{decrypt_files, encrypt_files};
use utils::{
  generate_encryption_key_with_options, get_password_or_prompt, inspect_files, Credentials,
};

/// Defines command line subcommands for the application.
#[derive(Debug, Subcommand)]
enum Command {
  /// Encrypts a specified file.
  Encrypt {
    /// Path to the files to be encrypted. Supports glob patterns.
    path: Vec<String>,

    /// Optional password. If not provided, it will be prompted for.
    #[arg(short, long)]
    password: Option<String>,

    /// Optional hex encoded encryption key. If not provided, it will be derived from the password.
    /// If provided, the password will be ignored.
    #[arg(short, long)]
    key: Option<String>,

    /// Wipe the original file after encryption.
    #[arg(short, long)]
    wipe: bool,
  },

  /// Decrypts a specified file.
  Decrypt {
    /// Path to the files to be decrypted. Supports glob patterns.
    path: Vec<String>,

    /// Optional password. If not provided, it will be prompted for.
    #[arg(short, long)]
    password: Option<String>,

    /// Optional hex encoded encryption key. If not provided, it will be derived from the password.
    /// If provided, the password will be ignored.
    #[arg(short, long)]
    key: Option<String>,

    /// Wipe the encrypted file after decryption.
    #[arg(short, long)]
    wipe: bool,
  },

  /// Derives a key from a given password.
  Key {
    /// Optional password. If not provided, it will be prompted for.
    #[arg(short, long)]
    password: Option<String>,

    /// Iterations to be used for key derivation.
    /// Defaults to 900,000.
    #[arg(short, long, default_value = "900000")]
    iterations: usize,

    /// Hex salt to be used for key derivation.
    /// Defaults to a random 16 byte array.
    #[arg(short, long)]
    salt: Option<String>,
  },

  /// Inspects a specified `.secured` file.
  Inspect {
    /// Path to the files to be inspected. Supports glob patterns.
    path: Vec<String>,
  },
}

/// Defines the command line arguments structure.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
  /// The specific subcommand to execute (either Encrypt or Decrypt).
  #[command(subcommand)]
  command: Command,
}

fn main() {
  let args = Args::parse();

  match args.command {
    Command::Encrypt {
      path,
      password,
      key,
      wipe,
    } => match key {
      Some(key) => encrypt_files(&Credentials::HexKey(key), path, wipe),
      None => {
        let password = get_password_or_prompt(password, true);
        encrypt_files(&Credentials::Password(password), path, wipe);
      }
    },
    Command::Decrypt {
      path,
      password,
      key,
      wipe,
    } => match key {
      Some(key) => decrypt_files(&Credentials::HexKey(key), path, wipe),
      None => {
        let password = get_password_or_prompt(password, false);
        decrypt_files(&Credentials::Password(password), path, wipe);
      }
    },
    Command::Key {
      password,
      iterations,
      salt,
    } => {
      let password = get_password_or_prompt(password, true);
      generate_encryption_key_with_options(&password, iterations, salt);
    }
    Command::Inspect { path } => inspect_files(path),
  }
}
