# Changelog

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