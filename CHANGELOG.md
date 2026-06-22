# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Optional per-entry `public_key` (base64 Ed25519) pinning a trusted
  `node_id` to a specific key. `IsTrustedWithKey(nodeID, pubKey)`
  enforces the pin with a constant-time compare when present, and falls
  back to `node_id`-only trust when absent (backward-compatible — every
  shipped entry is unpinned). `IsTrusted(nodeID)` is unchanged.
  Addresses audit finding H4.

## [v0.1.0]

Initial release.
