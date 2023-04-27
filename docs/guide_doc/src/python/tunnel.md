# Tunnel

## Description

`Tunnel` class wraps a `struct SandwichTunnel` and exposes methods for using the `Sandwich Backend` API, such as:
-  `handshake`
-  `read`
-  `write`
-  `close`

Inputs:

- [`Context`](context.md): Context handle for creating the tunnel
- [`IO`](io.md): I/O interface to use

The destructor of this class is responsible for freeing memory.

## Usage

```python

from sandwich import Tunnel

client = Tunnel(client_ctx, client_io)
server = Tunnel(client_ctx, client_io)

try:
    client.handshake()
except Exception as e:
    AssertionError(f"expected no error, got {e}")

try:
    server.handshake()
except Exception as e:
    AssertionError(f"expected no error, got {e}")

assert state == client.State.STATE_HANDSHAKE_DONE, "Expected state HANDSHAKE_DONE"
assert state == server.State.STATE_HANDSHAKE_DONE, "Expected state HANDSHAKE_DONE"

client_msg = "Ping"
client.write(client_msg)

assert server.read(len(client_msg)) == client_msg

server_msg = "Pong"
server.write(server_msg)

assert client.read(len(server_msg)) == server_msg


client.close()
server.close()

```
