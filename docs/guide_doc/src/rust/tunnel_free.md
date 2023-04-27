# `sandwich_tunnel_free`

Safely free the `tunnel` and I/O objects

```rust
/// Releases a tunnel.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_free(tun: *mut std::ffi::c_void) {
    if !tun.is_null() {
        let _: Box<Box<dyn crate::IO>> = unsafe { Box::from_raw(tun as *mut _) };
    }
}
```

export to C header as:

```c
/// \brief Free a Sandwich tunnel.
///
/// If the I/O interface is still owned by the tunnel, it will be freed too.
///
/// \param[in,out] tun Tunnel to free.
///
/// NULL for `tun` is allowed.
SANDWICH_API void sandwich_tunnel_free(struct SandwichTunnel *tun);
```
