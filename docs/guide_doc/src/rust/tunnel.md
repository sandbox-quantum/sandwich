# Tunnel

## Description

`Tunnel API` is used for creating encrypted communication between client and server.

After a tunnel is created, it can:

- `handshake`: perform cryptographic handshake. If the handshake is success:
    - `read`: read data from tunnel
    - `write`: write data to tunnel
    - `state`: check the current state of tunnel
    - `io_release`: release io of the tunnel, give ownership of I/O back to the users
- `close`: close the tunnel, stop communication

## Functions

`Tunnel API` consists of 8 functions:

- [`sandwich_tunnel_new`](./tunnel_new.md): Create a tunnel
- [`sandwich_tunnel_handshake`](./tunnel_handshake.md): Perform handshake
- [`sandwich_tunnel_read`](./tunnel_read.md): Read data from the tunnel
- [`sandwich_tunnel_write`](./tunnel_write.md): Write data to the tunnel
- [`sandwich_tunnel_state`](./tunnel_state.md): Check the state of the tunnel
- [`sandwich_tunnel_io_release`](./tunnel_io_release.md): Release I/O interface of a tunnel
- [`sandwich_tunnel_close`](./tunnel_close.md): Close the tunnel
- [`sandwich_tunnel_free`](./tunnel_free.md): Free the tunnel
