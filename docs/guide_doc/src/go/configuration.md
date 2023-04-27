# Configuration

## Description

All configuration are defined in `protobuf` files.
By default, our protobuf files provide predefined `*.proto` used in `Sandwich Backend`. Changing default `*.proto` also requires to change `Sandwich Backend`.


## Usage

For example, the `Configuration` prepared for [`Context`](./context.md) can be defined as two functions as follows,

<!-- TODO: Demonstrate how users can load configuration as .textproto instead of changing the source code -->


```go

// createClientConfiguration creates the configuration for the client.
func createClientConfiguration() (*api.Configuration, error) {
	certfile := "testdata/cert.pem"

	return &api.Configuration{
		Impl: api.Implementation_IMPL_OPENSSL1_1_1_OQS,
		Opts: &api.Configuration_Client{
			Client: &api.ClientOptions{
				Opts: &api.ClientOptions_Tls{
					Tls: &api.TLSClientOptions{
						CommonOptions: &api.TLSOptions{
							Kem: []string{
								"kyber1024",
							},
						},
						TrustedCertificates: []*api.Certificate{
							{
								Source: &api.Certificate_Static{
									Static: &api.ASN1DataSource{
										Data: &api.DataSource{
											Specifier: &api.DataSource_Filename{
												Filename: certfile,
											},
										},
										Format: api.ASN1EncodingFormat_ENCODING_FORMAT_PEM,
									},
								},
							},
						},
					},
				},
			},
		},
	}, nil
}

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
