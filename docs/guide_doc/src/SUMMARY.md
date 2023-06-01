# Sandwich - A friendly wrapper for cryptography libraries

[Introduction](introduction.md)

[Architecture](architecture.md)

[Motivation](motivation.md)

[Features](features.md)

[Examples](examples.md)

# User Guide

- [Installation](install/installation.md)
  - [Python Sandwich Installation](install/python-installation.md)

# Tutorials

- [TLS connections made simple](tutorial/TLS-made-simple.md)
  - [Simple TLS connection with Pysandwich](tutorial/tls_connection.md)
  - [Let's write TLS with AsyncIO](tutorial/tls_asyncio.md)

# Sandwich Bindings API

## Go API

- [Go API](go/API.md)
  - [Context](go/context.md)
    - [Configuration](go/configuration.md)
  - [IO](go/io.md)
    - [Socket]()
  - [Tunnel](go/tunnel.md)
  - [Error](go/error.md)

## Python

- [Python API](python/API.md)
  - [Sandwich](python/sandwich.md)
  - [Context](python/context.md)
    - [Configuration](python/configuration.md)
  - [IO](python/io.md)
    - [Socket](python/socket.md)
  - [Tunnel](python/tunnel.md)
  - [Error](python/error.md)

## Rust API

- [Rust API](rust/API-doc.md)


<!-- # C/C++ -->

<!-- - [C/C++ API]() -->

# Sandwich Backend FFI

- [Rust FFI](rust/API.md)
  - [Context](rust/context.md)
    - [`sandwich_context_new`](rust/context_new.md)
    - [`sandwich_context_free`](rust/context_free.md)
  - [IO](rust/io.md)
  - [Tunnel](rust/tunnel.md)
      - [`sandwich_tunnel_new`](rust/tunnel_new.md)
      - [`sandwich_tunnel_handshake`](rust/tunnel_handshake.md)
      - [`sandwich_tunnel_read`](rust/tunnel_read.md)
      - [`sandwich_tunnel_write`](rust/tunnel_write.md)
      - [`sandwich_tunnel_state`](rust/tunnel_state.md)
      - [`sandwich_tunnel_io_release`](rust/tunnel_io_release.md)
      - [`sandwich_tunnel_close`](rust/tunnel_close.md)
      - [`sandwich_tunnel_free`](rust/tunnel_free.md)
  - [Error](rust/error.md)


---

[License](license.md)
[Disclamer](disclaimer.md)
