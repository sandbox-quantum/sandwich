# Echo TLS server example

The echo TLS server example implements a TLS server that echos every line it
is receiving.

## Go implementation

The server can be run with:

```
$ bazelisk run //examples/go/echo_tls_server:echo_tls_server -- -port 4444 -server_cert /path/to/cert.pem -server_key /path/to/key.pem
```

Its source code is the following (`examples/go/echo_tls_server/main.go`):

```go
--8<-- "docs/examples/go/echo_tls_server/main.go"
```

## Python implementation

The server can be run with:

```
$ bazelisk run //examples/python/echo_tls_server:echo_tls_server -- -p 4444 -c /path/to/cert.pem -k /path/to/key.pem
```

Its source code is the following (`examples/python/echo_tls_server/main.py`):

```python
--8<-- "docs/examples/python/echo_tls_server/main.py"
```

## Rust implementation

The server can be run with:

```
$ bazelisk run //examples/rust/echo_tls_server:echo_tls_server -- -p 4444 --certificate /path/to/cert.pem --private-key /path/to/key.pem
```

Its source code is the following (`examples/rust/echo_tls_server/main.rs`):

```rust
--8<-- "docs/examples/rust/echo_tls_server/main.rs"
```
