use clap::Parser;
use enclave::Enclave;

#[derive(Parser, Debug)]
struct CliArgs {
  #[arg(short, long)]
  password: Option<String>,

  #[arg(short, long)]
  file: String,
}

fn main() {
  let args = CliArgs::parse();

  println!("{:?}", args);

  println!("Hello, world!");
}
