# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-03-02

### Fixed

- Add underscore (`_`) to `EMAIL_ADDRESS_CHAR_TABLE` — previously rejected valid email addresses containing underscores

### Added

- CI check enforcing parity between JS and Noir `EMAIL_ADDRESS_CHAR_TABLE` definitions

### Breaking Changes

- **Verifier keys must be regenerated.** The char table change alters circuit constraints, so existing proofs and verifier keys are incompatible with this version.

## [1.0.1-beta.5] - 2025-10-15

_Released as git tag `v.1.0.1-beta.5`._

### Changed

- Make public key hash and nullifier output format compatible with circom circuits
- Implement Poseidon large for compatible hashing logic

## [1.0.0-beta.5] - 2025-05-15

_Released as git tag `v.1.0.0-beta.5`._

### Changed

- Change pubkey hash to use Poseidon
- Update to Noir `1.0.0-beta.5`

## [0.4.4] - 2025-05-08

### Changed

- Update dependencies for Noir `1.0.0-beta.3` compatibility
- Downgrade nodash to v0.40.2 for Noir stable compatibility

## [0.4.3] - 2025-04-24

### Changed

- Minor dependency updates and fixes

## [0.4.2] - 2025-02-04

### Fixed

- Minor fixes

[1.4.0]: https://github.com/zkemail/zkemail.nr/compare/v.1.0.1-beta.5...v1.4.0
[1.0.1-beta.5]: https://github.com/zkemail/zkemail.nr/compare/v.1.0.0-beta.5...v.1.0.1-beta.5
[1.0.0-beta.5]: https://github.com/zkemail/zkemail.nr/compare/v0.4.4...v.1.0.0-beta.5
[0.4.4]: https://github.com/zkemail/zkemail.nr/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/zkemail/zkemail.nr/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/zkemail/zkemail.nr/releases/tag/v0.4.2
