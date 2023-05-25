# Configuration

## Description

All configuration are defined in `protobuf` files.
By default, our protobuf files provide predefined `*.proto` used in `Sandwich Backend`. Changing default `*.proto` also requires to change `Sandwich Backend`.


## Usage

For example, the `Configuration` prepared for [`Context`](./context.md) can be defined as two functions as follows,

<!-- TODO: Demonstrate how users can load configuration as .textproto instead of changing the source code -->

```python
from sandwich.proto.api import SandwichAPI

# Config Client options
conf = SandwichAPI.Configuration()
conf.impl = SandwichAPI.IMPL_OPENSSL1_1_1_OQS
conf.client.tls.common_options.kem.append("kyber512")

cert = conf.client.tls.common_options.x509_verifier.trusted_cas.add().static
cert.data.filename = "testdata/cert.pem"
cert.format = EncodingFormat.ENCODING_FORMAT_PEM

```
which matches the top level of the following `message Configuration`:

```go
syntax = "proto3";

import "compliance.proto";
import "tls.proto";

// Supported implementations.
enum Implementation {
  // Unspecified implementation.
  IMPL_UNSPECIFIED = 0;
  // OpenSSL 1.1.1.
  IMPL_OPENSSL1_1_1 = 1;
  // OpenSSL 1.1.1 with liboqs.
  IMPL_OPENSSL1_1_1_OQS = 2;
}

// Client options.
message ClientOptions {
  oneof opts {
    // TLS options.
    TLSClientOptions tls = 1;
  }
}

// Server options.
message ServerOptions {
  oneof opts {
    // TLS options.
    TLSServerOptions tls = 1;
  }
}

// A configuration for a sandwich tunnel (server or client).
message Configuration {
  // The implementation to use.
  Implementation impl = 1;

  // The option specific to the pair {protocol, impl}.
  oneof opts {
    // Client options.
    ClientOptions client = 2;
    // Server options.
    ServerOptions server = 3;
  }

  // Constraints applied on the choice of algorithms in the configuration.
  Compliance compliance = 4;
}
```
