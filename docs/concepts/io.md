# Input/Output (I/O) abstraction

When the Sandwich library needs to transport a stream of data, it does so
through a generic I/O interface. Said differently, Sandwich isn't opinionated
on the way data should be transported between the peers of a tunnel.

The I/O interface has three high-level API calls that are provided by the user:

* `read`: read a specified number of bytes for the underlying transport
* `write`: write a buffer to the underlying transport

It also contains a view of a generic object that can represent any state that
is needed to do the actual transport. I/O objects are always owned by a tunnel,
giving the ability to the I/O APIs to have access to their parent tunnel, and
for instance getting the current state of the tunnel.

The I/O interface also supports asynchronous operations, and can return
specific error codes for such a purpose.

## C API

The I/O interface is described in the C API through the
[SandwichCIOSettings](../cAPI/structSandwichCIOSettings.md) structure.

Here is an example of an I/O structure that would forward the data to a socket in C++:

```cpp
--8<-- "docs/sandwich_c/tunnels_test.cc:cio_socket"
```

## Go API

Go users need to implement the [sandwich.IO](https://pkg.go.dev/github.com/sandbox-quantum/sandwich/go/#IO) interface.

Here is an example wrapping an `io.ReadWrite` object, extracted from the Sandwich Go library:

```go
--8<-- "docs/go/io.go:go_io_rw"
```
