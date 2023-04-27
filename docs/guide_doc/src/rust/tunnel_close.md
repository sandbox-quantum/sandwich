# `sandwich_tunnel_close`

Close the tunnel, stop communication.

```rust
/// Performs a close operation.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_close(tun: *mut std::ffi::c_void) {
    let mut b: Box<Box<dyn crate::tunnel::Tunnel>> = unsafe { Box::from_raw(tun as *mut _) };
    let _ = b.close();
    Box::into_raw(b);
}
```

export to C header as:

```c
/// \brief Close the tunnel.
///
/// \param[in,out] tun Tunnel to close.
SANDWICH_API void sandwich_tunnel_close(struct SandwichTunnel *tun);
```
