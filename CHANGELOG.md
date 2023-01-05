# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2023-01-05

### Added

- Intel add IP and URL services with lookup endpoint


## [1.0.2] - 2022-12-23

### Fixed

- Multiples bugs in audit tools used to dump and verify events


## [1.0.1] - 2022-12-19

### Added

- This CHANGELOG
- Test to search with dates as filter
- Functions to get token and domain according to test environment (PROD/DEV/STG)

### Fixed

- Fix audit verify tool according to last changes in audit log format
- Fix dates support in audit search

### Changed

- Move examples to root directory
- Unify token env var names on integration tests

### Removed

- References to config id
- Intel URL and IP services
- Save/load local data in audit (not used anymore)


## [1.0.0] - 2022-11-29

### Added

- Audit client
- Embargo client
- File Intel client
- Domain Intel client
- Redact client


[unreleased]: https://github.com/pangeacyber/pangea-python/compare/v1.0.3...main
[1.0.3]: https://github.com/pangeacyber/pangea-python/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/pangeacyber/pangea-python/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/pangeacyber/pangea-python/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/pangeacyber/pangea-python/releases/tag/v1.0.0
