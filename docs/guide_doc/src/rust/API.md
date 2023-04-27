# Rust FFI

Sandwich Rust has two folders:

- [`Rust API`](Rust/API-doc.md): The actual Rust API provides to Rust developers. Link to Rust doc [is here]().
- [`Rust FFI`](Rust/ffi.md): Provide Sandwich high-level API from low-level `Sandwich Backend`. Its purpose is to provide stable binding to Go, Python, C/C++. If you use Rust, you should directly use Rust API. This following section describe Rust FFI.

This section describes stable Rust FFI API.
Rust FFI consists of 4 components:

- [`Context`](Rust/context.md): To build Context for Client and Server
- [`Tunnel`](Rust/tunnel.md): Tunnel API
- [`IO`](Rust/io.md): Responsible for Input/Output of Tunnel
- [`Error`](Rust/error.md): Meaningful error return from all of above
