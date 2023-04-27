# `sandwich_tunnel_io_release`

Release I/O interface, to continue to use tunnel, a new I/O interface need to be added.

```rust
/// Releases the underlying I/O.
/// This method is a no-op, as it is not safe.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_io_release(_tun: *mut std::ffi::c_void) {}
```

export to C header as:

```c
/// \brief Release the I/O interface from the tunnel.
///
/// When the I/O interface is released, the tunnel can no longer be used.
///
/// \param[in,out] tun The Sandwich tunnel
///
/// \return The I/O interface, or NULL if the I/O interface has already been
/// released from the tunnel.
SANDWICH_API struct SandwichCIO *sandwich_tunnel_io_release(
    struct SandwichTunnel *tun);
```
