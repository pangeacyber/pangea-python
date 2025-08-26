# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- AI Guard: `only_relevant_content` parameter which allows for sending only
  relevant messages to AI Guard.

### Changed

- IP Intel: modernized models.

## 6.5.0 - 2025-08-25

### Changed

- Made exports more explicit.
- Retries now include a request header `X-Pangea-Retried-Request-Ids` to track
  the request IDs of the retries.

### Fixed

- `PangeaResponse.http_status` being `None` when the response is not OK.

## 6.4.0 - 2025-07-28

### Changed

- AI Guard: updates to language and topic detectors.

## 6.3.0 - 2025-07-17

### Added

- AuthZ: bulk check endpoint.

### Changed

- AuthN: modernized models around token check.
- AuthZ: modernized models around tuples.
- Vault: simplified `metadata` and `tags`.

## 6.2.0 - 2025-06-25

### Changed

- AI Guard: `messages` parameter is no longer a generic. A new `Message` model
  has been introduced, and `messages` is now a `Sequence[Message]`.
- Audit: event data's `hash` is now optional.

## 6.1.1 - 2025-05-12

### Fixed

- Nested `BaseModel`s not excluding `None` values during serialization.

## 6.1.0 - 2025-04-25

### Added

- AuthZ: `expires_at` to tuples.
- AuthN: groups.

## 6.0.0 - 2025-04-21

### Added

- Redact: `fpe_context` on `StructuredResult`.
- AI Guard: detector overrides.
- AI Guard: topic detector.
- AI Guard: `ignore_recipe` in detector overrides.
- `base_url_template` has been added to `PangeaConfig` to allow for greater
  control over the complete API URL. This option may be a full URL with the
  optional `{SERVICE_NAME}` placeholder, which will be replaced by the slug of
  the respective service name. This supersedes `environment` and `insecure`.

### Changed

- The minimum supported version of Python is now v3.9.2.
- Updated cryptography to v44.0.2.
- Redact: `score` in `RecognizerResult` is now a float.

### Removed

- AI Guard: `llm_info` and `llm_input`.
- PangeaConfig: `config_id` field.

## 5.5.1 - 2025-02-17

### Changed

- Prompt Guard: `confidence` is now a float.

## 5.5.0 - 2025-02-16

### Added

- AI Guard and Prompt Guard services.

### Changed

- Clarified what `PangeaConfig.environment` affects.

## 5.4.0 - 2025-01-22

### Removed

- CDR and PDF support in Sanitize.

## 5.3.0 - 2025-01-13

### Added

- Support for `severity` field on `v1/user/breached` and `v2/user/breached` of `user-intel` service.
- `/v1/breach` endpoint support on `user-intel` service.
- `file_ttl` support in Secure Share.

## 5.2.1 - 2024-12-19

### Fixed

- Exposed `vault_parameters` and `llm_request` parameters in Redact.
- Added `fpe_context` to `RedactResult`.

## 5.2.0 - 2024-12-18

### Added

- Support for `cursor` field on `v1/user/breached` of `user-intel` service.
- `vault_parameters` and `llm_request` fields support on Redact service.

### Changed

- `Audit.fix_consistency_proofs` is now a private method.
- `pangea.deep_verify` error message to `warning` when `not_persisted` event.

### Fixed

- `pangea.audit_dump` only dump before events if the leaf_index is not None.


## 5.1.0 - 2024-10-16

### Added

- Secure Share service support.
- Multiple bucket ID support to Share.
- `metadata_protected` and `tags_protected` support to Share `ItemData`.
- `password` and `password_algorithm` support to Share.
- Filter fields to `filter_list` on Share service.
- `objects` field to Share `GetArchiveResult`.
- `title` and `message` to Share `ShareCreateLinkItem`.

## 5.0.0 - 2024-10-15

### Added

- Vault KEM export support.

### Changed

- Vault APIs have been updated to v2.

## 4.4.0 - 2024-10-15

### Added

- Support for `domains` field in `v2/user/breached` endpoint in User Intel service
- Detect-only Redact for Sanitize.

### Changed

- The minimum supported version of Python is now v3.9.

## 4.3.0 - 2024-09-25

### Added

- `attributes` field in `/list-resources` and `/list-subjects` endpoint
- Sanitize service support

### Changed

- `attributes` field in `/check` endpoint. Now it's a `Dict[str, Any]`

### Fixed

- The source-url transfer method now works with File Scan and Sanitize.

### Removed

- Dependency on the asyncio pypi package.
- Lingering beta tags on AuthZ `/list-resources` and `/list-subjects` endpoints.

## 4.2.0 - 2024-07-16

### Added

- AuthN user password expiration support.
- `"state"` and other new properties to AuthN's `Authenticator`.

### Changed

- `pangea.services.authn.models.Profile` has returned to being a
  `dict[str, str]`, and its `first_name`, `last_name`, and `phone` properties
  have been deprecated.

## 4.1.0 - 2024-06-19

### Added

- Vault `/export` support
- `exportable` field support in Vault `/key/store` and `/key/generate`

### Fixed

- Exception in `verify_audit` script when the event is not published

## 4.0.0 - 2024-06-14

### Added

- Improvements in `verify_audit` script

### Changed

- Support for Python v3.7 has been dropped. Python v3.8 is now the minimum
  supported version.
- Updated pydantic to v2.6.3.
- Updated aiohttp to v3.9.3.

### Removed

- `utils.dict_order_keys()` and `utils.dict_order_keys_recursive()`.

## 3.9.0 - 2024-06-07

### Added

- `fpe_context` field in Audit search events
- `return_context` support in Audit `/search`, `/results` and `/download` endpoints
- Redact `/unredact` endpoint support
- `redaction_method_overrides` field support in `/redact` and `redact_structured` endpoints
- AuthN usernames support.

### Removed

- Beta tags from AuthZ.

## 3.8.0 - 2024-05-10

Note that Sanitize and Secure Share did not make it into this release.

### Added

- Support for Secure Audit Log's log stream API.
- Support for Secure Audit Log's export API.
- AuthZ service support.

### Fixed

- Incorrect return types in Intel bulk APIs.
- `str2str_b64()` now supports non-ASCII strings.

## 3.7.1 - 2024-03-20

### Added

- Audit assert_search_restriction added as a keyword argument to the results method
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
