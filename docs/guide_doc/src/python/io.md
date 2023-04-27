# I/O API

## Description

This API provides an I/O interface in Python, it's a wrapper of
to use with Sandwich.
It wraps a `struct SandwichCIO` and `struct SandwichCIOSettings`.

Sandwich I/O interface support following methods:

- `read(n: int) -> bytes`
- `write(buf: bytes) -> int`
- `close()`

All methods should either return the corresponding value (the read bytes
for `read` and the amount of successfully written bytes for `write`), or
raise an exception of type `IOException`.

Users can build high-level IO functionalities base on `read, write, close` provided in Sandwich.

## Usage

Client and Server communicate via `socket`.

```Python

import sandwich.io as SandwichIO
import socket

def create_io() -> SandwichIO.IO:
    s = socket.socket(family=socket.AF_UNIX, type=SOCK_STREAM)
    return SandwichIO.Socket(s)

client_io = create_io()
server_io = create_io()
```
