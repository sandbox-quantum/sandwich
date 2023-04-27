# I/O API

## Description

This API provides an I/O interface, wrapper of  to use with Sandwich .
It wraps a `struct SandwichCIO` and `struct SandwichCIOSettings`.

Sandwich I/O interface support following methods:

- `Read(b []byte, tunnel_state pb.State) (n int, err *IOError)`
- `Write(b []byte, tunne_state pb.State) (n int, err *IOError)`
- `Close()`

All methods should return the corresponding value (the number of bytes read
for `Read` and the amount of successfully written bytes for `Write`), and
error `IOError` if there is.

Users can build high-level IO functionalities base on `Read, Write, Close` provided in Sandwich.

## Usage

Client and Server communicate via `bytes.Buffer`

```go

// bufIO implements sandwich.IO, using a TX buffer and a
// remote peer.
type bufIO struct {
	tx     bytes.Buffer
	remote *bufIO
}

// newBufIO Creates a new buffer IO.
func newBufIO() *bufIO {
	return new(bufIO)
}

func createIOs() (sandwich.IO, sandwich.IO) {
	client := newBufIO()
	server := newBufIO()
	client.remote = server
	server.remote = client

    return client, server
}

client, server = createIOs()
```
