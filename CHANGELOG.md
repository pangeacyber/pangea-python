# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2023-03-20

### Added

- Vault service support
- LICENSE
- Internal server exception support

### Changed

- Update services examples
- Improve docs
- Rename tools_util.py to tools.py

## [1.4.0] - 2023-03-01

### Added

- IP service add /geolocate, /vpn, /domain and /proxy endpoints support

### Fixed

- Support string as timestamp in Audit Search

## [1.3.0] - 2023-02-28

### Added

- Tenant ID support in Audit Service

## [1.2.2] - 2023-02-24

### Added

- Custom User-Agent support
- Logger to services

### Fixed

- Vulnerability on cryptography package


## [1.2.1] - 2023-02-15

### Fixed

- Timestamp handler in audit log

## [1.2.0] - 2023-02-03

### Added

- Rules parameter support on Redact service

### Fixed

- Readme examples
- Minors bugs

## [1.1.2] - 2023-01-27

### Changed
- Intel Domain and URL add reputation endpoint that will replace lookup endpoint
- Intel File add hashReputation() method. Lookup is deprecated deprecated.
- Intel File add filepathReputation() method. lookupFilepath is deprecated.


## [1.1.1] - 2023-01-25

### Changed

- Intel IP add reputation endpoint that will replace lookup endpoint
- Update User-Agent format


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

[unreleased]: https://github.com/pangeacyber/pangea-python/compare/v1.5.0...main
[1.5.0]: https://github.com/pangeacyber/pangea-python/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/pangeacyber/pangea-python/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/pangeacyber/pangea-python/compare/v1.2.2...v1.3.0
[1.2.2]: https://github.com/pangeacyber/pangea-python/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/pangeacyber/pangea-python/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/pangeacyber/pangea-python/compare/v1.1.2...v1.2.0
[1.1.2]: https://github.com/pangeacyber/pangea-python/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/pangeacyber/pangea-python/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/pangeacyber/pangea-python/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/pangeacyber/pangea-python/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/pangeacyber/pangea-python/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/pangeacyber/pangea-python/releases/tag/v1.0.0
