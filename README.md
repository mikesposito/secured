# secured

Secured is a versatile Rust package that provides robust encryption and decryption capabilities. It can be seamlessly integrated as a library in other Rust applications or used as a standalone command-line interface (CLI) tool.

## Features

- **Encryption and Decryption**: Easily encrypt and decrypt files with password, safely.
- **Cli & Library**: Use as a standalone CLI tool or integrate as a library in your Rust applications.

## Installation

To use **secured** as a CLI tool or integrate it into your Rust project, ensure you have Rust installed, then:

### As a CLI tool

```sh
cargo install secured
```

### As a Library

```sh
cargo add secured
```

## Usage

### As a CLI Tool

Secured is straightforward to use from the command line. Here are the basic commands:

1. **Encryption**
   ```sh
   secured encrypt <FILE> [PASSWORD]
   ```
   Encrypts the specified `<file>`. An optional `<password>` can be provided for extra security.

2. **Decryption**
   ```sh
   secured decrypt <FILE> [PASSWORD]
   ```
   Decrypts the specified `<file>`. If a `<password>` was used during encryption, the same must be provided for decryption.

### As a Library

To use Secured as a library in your Rust application, simply import the package and utilize its encryption and decryption functions as per your requirements.

## Examples

Here's a quick example of how to use Secured in your Rust code:

```rust
use secured::{encrypt, decrypt};

fn main() {
    let file_path = "path/to/your/file";
    let password = Some("your_password");

    // Encrypt a file
    encrypt(file_path, password).expect("Encryption failed");

    // Decrypt a file
    decrypt(file_path, password).expect("Decryption failed");
}
```

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

## License

Secured is distributed under the MIT License. See `LICENSE` for more information.
