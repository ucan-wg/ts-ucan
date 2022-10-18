# Changelog

### v0.11.2

- Add `.js` suffixes to imports for ESM builds

### v0.11.0

- Refactors `ucans` to use a plugin system for DIDs & keys. It is now 3 packages in a monorepo:
  - `@ucans/core` - core functionality & logic around UCANs
  - `@ucans/default-plugins` - support for ed25519, NIST P-256, & RSA
  - `@ucans/ucans` - `core` with `default-plugins` injected
- Locked `uint8arrays` to `v3.0.0`
- Removed `KeyType` in favor of `jwtAlg`
- Removed `BaseKey` class


### v0.10.0

- Added a new verify function for checking UCANs  
- Removed `hasCapability` and chained interface in favor of verify  
- Added public key compression for NIST P-256 keys  
- Added re-delegation to capability checking  

### v0.9.1

Fixed ESM build.

### v0.9.0

- Adjusted implementation to the 0.8.x [specification](https://github.com/ucan-wg/spec#readme).
- Added Builder API
- Renamed Indexer to Store
- Capability semantics and validating
- Compatibility layer for 0.3 UCANs
- Better validation