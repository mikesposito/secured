# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.6.0]

### Changed
- Enhanced CLI capabilities with glob patterns and inspection commands

## [0.5.1]

### Added
- `process_in_line` to `AlgorithmProcessInLine` trait

### Changed
- Blocks are now computed in parallel
- `permutation` module has been changed to `algorithm`
- `Permutation` trait has been decomposed in multiple `Algorithm*` trait

### Removed
- `clear` function from chacha20 and poly1305

## [0.5.0]

### Added
- Added extension traits for vector of bytes, slices, strings, to encrypt and decrypt easily in `secured-enclave`.

## [0.4.0]

### Added
- **BREAKING** Added `Poly1305` AEAD as default authentication algorithm used by `Enclave`

## [0.3.0]

### Changed
- **BREAKING** Fixed `ChaCha20` implementation and added test vectors compliant with IETF RFC-7539

## [0.2.0]

### Added

- Added local implementation of the `ChaCha20` cipher, shipped with `secure-cipher` crate ([#9](https://github.com/mikesposito/secured/pull/9))

### Removed

- Removed `Cipher`, `ChaCha20Poly1305` and `EncryptionKey` from `secure-enclave` crate ([#9](https://github.com/mikesposito/secured/pull/9))
  - The `secure-cipher` crate should be used now.

## [0.1.2]

### Documentation

- Add inline documentation (([#6](https://github.com/mikesposito/secured/pull/6)))

### Fixed

- Hide password prompt ([#7](https://github.com/mikesposito/secured/pull/7))

## [0.1.1]

### Fixed

- Remove unsafe println ([#4](https://github.com/mikesposito/secured/pull/4))

## [0.1.0]

### Added

- Initial release

[Unreleased]: https://github.com/mikesposito/secured/compare/secured@0.6.0...HEAD
[0.6.0]: https://github.com/mikesposito/secured/compare/secured@0.5.1...secured@0.6.0
[0.5.1]: https://github.com/mikesposito/secured/compare/secured@0.5.0...secured@0.5.1
[0.5.0]: https://github.com/mikesposito/secured/compare/secured@0.4.0...secured@0.5.0
[0.4.0]: https://github.com/mikesposito/secured/compare/secured@0.3.0...secured@0.4.0
[0.3.0]: https://github.com/mikesposito/secured/compare/secured@0.2.0...secured@0.3.0
[0.2.0]: https://github.com/mikesposito/secured/compare/secured@0.1.2...secured@0.2.0
[0.1.2]: https://github.com/mikesposito/secured/compare/secured@0.1.1...secured@0.1.2
[0.1.1]: https://github.com/mikesposito/secured/compare/secured@0.1.0...secured@0.1.1
[0.1.0]: https://github.com/mikesposito/secured/releases/tag/secured@0.1.0
