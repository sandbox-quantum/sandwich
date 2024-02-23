# Changelog

## v0.3.0 (Feb 23, 2024)

### Major changes

 - Experimental [TurboTLS](https://cryptographycaffe.sandboxaq.com/posts/turbo-tls/) protocol implementation.

### Minor changes

 - Revamped Go Language binding to workaround restriction Golang places on accessing c types across packages.
 - Go helpers now always return blocking IOs.


## v0.2.0 (Feb 5, 2024)

### Major changes

 - Security fixes discovered by independent security research firm Trail of Bits.
 - Support for OpenSSL 3.2.0 coupled with oqs-provider as a cryptographic backend.
 - [Support for TLS 1.2](https://sandbox-quantum.github.io/sandwich/protobuf/api/v1/TLSv12Config.html)
 - New APIs on top of OpenTelemetry which traces internal stages of a TLS connection along with data collection.

### Minor changes

 - Fix an issue where protobuf versions did not match.
 - Update liboqs to its latest version to fix the `DIV` issue in Kyber implementation.
 - Accept standard Rust IO.


## v0.1.0 (Aug 8, 2023)

Initial public release
