use clap::{Parser, Subcommand};

mod utils;
pub use utils::{decrypt_files, encrypt_files};
use utils::{generate_encryption_key_with_options, get_password_or_prompt};

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
  },
  /// Decrypts a specified file.
  Decrypt {
    /// Path to the files to be decrypted. Supports glob patterns.
    path: Vec<String>,

    /// Optional password. If not provided, it will be prompted for.
    #[arg(short, long)]
    password: Option<String>,
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
    Command::Encrypt { path, password } => {
      let password = get_password_or_prompt(password);
      encrypt_files(&password, path);
    }
    Command::Decrypt { path, password } => {
      let password = get_password_or_prompt(password);
      decrypt_files(&password, path);
    }
    Command::Key {
      password,
      iterations,
      salt,
    } => {
      let password = get_password_or_prompt(password);
      generate_encryption_key_with_options(&password, iterations, salt);
    }
  }
}
