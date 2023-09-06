# Secure tunnel abstraction

## Introduction

Sandwich provides a secure tunnel abstraction. An example of such a
tunnel is TLS. Sandwich slices the concept of tunnels into two
different states:

* a handshake plane where a shared key between two peers is generated
* a record plane where actual protected data is exchanged


Sandwich uses a [protobuf-based
configuration](../protobuf/api/v1/Configuration.md) for setting up such
tunnels. Tunnels are either in client or server mode (from the underlying
protocol point of view), depending on whether a
[ClientOptions](../protobuf/api/v1/ClientOptions.md) or
[ServerOptions](../protobuf/api/v1/ServerOptions.md) object is used in the
overall [tunnel configuration](../protobuf/api/v1/Configuration.md). Data are
transported over an [I/O](io.md) object that must be initialised before
creating a tunnel.

The protobuf-based configuration provides various runtime agility:

* the cryptography backend that is used for protocol and cryptography
  implementation [can be changed](../protobuf/api/v1/Configuration.md#impl)
* the actual protocol ([client](../protobuf/api/v1/ClientOptions.md#oneof-opts) / [server](../protobuf/api/v1/ServerOptions.md#oneof-opts))

It provides runtime agility as only the protobuf-based configuration needs to
be changed (with no code modification), and that configuration can be provided
at runtime. Closing and relaunching existing tunnels is now not done directly
by Sandwich, and need to be handled by the users of the library.

## Verifiers

Verifiers are used to verify the identity of the peer a sandwich tunnel is
talking with. This is done by passing a
[TunnelVerifier](../protobuf/api/v1/TunnelVerifier.md) to the Sandwich tunnel
creation API through the [TunnelConfiguration](../protobuf/api/v1/TunnelConfiguration.md) message.

For TLS, only [SAN (Subject Alternative
Name)](https://en.wikipedia.org/wiki/Subject_Alternative_Name) can be verified
for now.

## Go example

Let's create a TLS server tunnel in Go. First, let's create a protobuf server configuration:

```go
import (
--8<-- "docs/examples/go/echo_tls_server/main.go:go_imports"
)

--8<-- "docs/examples/go/echo_tls_server/main.go:go_server_cfg"
```

That configuration uses a private key and public certificate that are stored on
disk, and accepts `kyber768`, `p256_kyber512` and `secp256k1` as key exchange
mechanisms.

Assuming we have a valid [Sandwich I/O object](io.md#go-api), we can then create a sandwich tunnel:

```go
import (
--8<-- "docs/examples/go/echo_tls_server/main.go:go_imports"
)

{
    swio := // ...
--8<-- "docs/examples/go/echo_tls_server/main.go:go_new_tunnel"
}
```

The underlying I/O object can come for instance from a TCP listener object that
has [accepted a new connection](https://pkg.go.dev/net#TCPListener.Accept). An
end-to-end example creating an echo TLS server is available in
`examples/go/echo_tls_server`.

## Python example

Let's create a TLS server tunnel in Python. First, let's create a protobuf server configuration:

```python
--8<-- "docs/examples/python/echo_tls_server/main.py:py_imports_proto"

--8<-- "docs/examples/python/echo_tls_server/main.py:py_server_cfg"
```

That configuration uses a private key and public certificate that are stored on
disk, and accepts `kyber768` and `prime256v1` as key exchange mechanisms.

Assuming we have a valid [Sandwich I/O object](io.md), we can then create a sandwich tunnel:

```python
def my_func():
    --8<-- "docs/examples/python/echo_tls_server/main.py:py_ctx"
        swio = # ...
--8<-- "docs/examples/python/echo_tls_server/main.py:py_new_tunnel"
```

An end-to-end example creating an echo TLS server is available in
`examples/python/echo_tls_server`.
