# TLS client example

This example creates a netcat-like client for TLS servers using Sandwich. It
does not validate any server-side certificates, and should be used for
educational purposes only.

## Go implementation

The Go version makes usage of Go channels for an efficient implementation. It
can be run with:

```
$ bazelisk run //examples/go/tls_client:tls_client -- -host 127.0.0.1 -port 4444
```

Its source code is the following (`examples/go/tls_client/main.go`):

```go
--8<-- "docs/examples/go/tls_client/main.go"
```

## Python implementation

The Python version can be run with:

```
$ bazelisk run //examples/python/tls_client:tls_client -- --host 127.0.0.1 -p 4444
```

Its source code is the following (`examples/python/tls_client/main.py`):

```python
--8<-- "docs/examples/python/tls_client/main.py"
```

## Rust implementation

The Rust version can be run with:

```
$ bazelisk run //examples/rust/tls_client:tls_client -- --hostname 127.0.0.1 --port 4444
```

It only works for Linux so far, as it's using the `epoll` API.

Its source code is the following (`examples/rust/tls_client/main.rs`):

```rust
--8<-- "docs/examples/rust/tls_client/main.rs"
```
