# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## 3.8.0beta1 - 2024-03-18

### Added

- Share service support
- Audit /download_results endpoint support

### Fixed

- AuthN list method's filter not being serialized properly.
- Incorrect docstrings positioning in `PangeaConfig`.
- Incorrect variable name in `Vault` docstring.
- Extraneous colons in `Vault.key_rotate()` docstrings.
- Put to presigned url. It should just put file in raw, not in form format.

### Changed

- AuthN ClientTokenCheckResult `token` field is optional

### Removed

- An unused binascii import.
- Unused os imports.

## [3.7.0] - 2024-02-26

### Added 

- Vault service. Post quantum signing algorithms support

### Removed

- Unused dependency on alive-progress.


## [3.6.1] - 2024-01-30

### Changed

- Rewrote `README.md`.
- Audit.search() `order_by` param also takes `str` now.


## [3.6.0] - 2024-01-12

### Added

- Vault encrypt structured support.

## [3.5.0] - 2023-12-18

### Added

- File Intel /v2/reputation support
- IP Intel /v2/reputation, /v2/domain, /v2/proxy, v2/vpn and /v2/geolocate support
- URL Intel /v2/reputation support
- Domain Intel /v2/reputation support
- User Intel /v2/user/breached and /v2/password/breached support


## [3.4.0] - 2023-12-07

### Changed

- 202 result format

### Removed

- accepted_status in 202 result

### Added

- put_url, post_url, post_form_data fields in 202 result


## [3.3.0] - 2023-11-28

### Added

- Authn unlock user support
- Redact multiconfig support
- File Scan post-url and put-url support


## [3.2.0] - 2023-11-15

### Added

- Support for audit /v2/log and /v2/log_async endpoints


## [3.1.0] - 2023-11-09

### Added

- Presigned URL upload support on FileScan service
- Folder settings support in Vault service


## [3.0.0] - 2023-10-23

### Added

- AuthN v2 support

### Removed

- AuthN v1 support


## [2.4.0] - 2023-09-29

### Added

Asyncio support. New Async Service classes are in /asyncio folder.


## [2.3.0] - 2023-09-26

### Added

- FileScan Reversinglabs provider example
- Domain WhoIs endpoint support

### Changed

- Deprecated config_id in PangeaConfig. Now is set in service initialization.

### Fixed

- HashType supported in File Intel


## [2.2.1] - 2023-09-06

### Fixed

- Disable multiconfig support in AuthN service


## [2.2.0] - 2023-09-05

### Added

- Redact rulesets field support
- FileScan service support


## [2.1.0] - 2023-07-14

### Added

- Vault /folder/create endpoint support


## [2.0.0] - 2023-07-06

### Added

- Custom schema support: Add Audit.log_event() to use custom schema

### Changed

- Custom schema support breaking change: event is a dict now
- Audit.log(): signing param rename to sign_local due to vault signing is set by token config
- Rename FileIntel.hashReputation to hash_reputation, and filepathReputation to filepath_reputation

### Removed

- Intel lookup deprecated methods.

## [1.10.0] - 2023-06-26

### Added
- Multiconfig support
- Instructions to setup token and domain in examples

## [1.9.1] - 2023-06-08

### Added

- Defang examples
- Intel IP /domain, /vpn and /proxy endpoint examples

### Changed

- Intel User password breached full workflow example
- Update requests package to fix vulnerability

### Fixed

- Audit search order. Enums were switched out


## [1.9.0] - 2023-05-25

### Added

- New algorithm support in Vault Service
- Algorithm field support in Audit Service
- Cymru IP Intel provider examples
- Support full url as domain in config for local use

## [1.8.0] - 2023-04-21

### Added

- AuthN service support


## [1.7.0] - 2023-04-10

### Added

- Audit-Vault signing integration support
- Intel User support
- Redact Service return_result field support
- Set custom user agent by config
- LICENSE

## [1.6.0] - 2023-03-27

### Added

- Algorithm support in Vault Service

### Changed

- Algorithm name in Vault Service


## [1.5.0] - 2023-03-20

### Added

- Vault service support
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

[unreleased]: https://github.com/pangeacyber/pangea-python/compare/v3.7.0...main
[3.7.0]: https://github.com/pangeacyber/pangea-python/compare/v3.6.1...v3.7.0
[3.6.1]: https://github.com/pangeacyber/pangea-python/compare/v3.6.0...v3.6.1
[3.6.0]: https://github.com/pangeacyber/pangea-python/compare/v3.5.0...v3.6.0
[3.5.0]: https://github.com/pangeacyber/pangea-python/compare/v3.4.0...v3.5.0
[3.4.0]: https://github.com/pangeacyber/pangea-python/compare/v3.3.0...v3.4.0
[3.3.0]: https://github.com/pangeacyber/pangea-python/compare/v3.2.0...v3.3.0
[3.2.0]: https://github.com/pangeacyber/pangea-python/compare/v3.1.0...v3.2.0
[3.1.0]: https://github.com/pangeacyber/pangea-python/compare/v3.0.0...v3.1.0
[3.0.0]: https://github.com/pangeacyber/pangea-python/compare/v2.4.0...v3.0.0
[2.4.0]: https://github.com/pangeacyber/pangea-python/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/pangeacyber/pangea-python/compare/v2.2.1...v2.3.0
[2.2.1]: https://github.com/pangeacyber/pangea-python/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/pangeacyber/pangea-python/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/pangeacyber/pangea-python/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/pangeacyber/pangea-python/compare/v1.10.0...v2.0.0
[1.10.0]: https://github.com/pangeacyber/pangea-python/compare/v1.9.1...v1.10.0
[1.9.1]: https://github.com/pangeacyber/pangea-python/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/pangeacyber/pangea-python/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/pangeacyber/pangea-python/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/pangeacyber/pangea-python/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/pangeacyber/pangea-python/compare/v1.5.0...v1.6.0
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
