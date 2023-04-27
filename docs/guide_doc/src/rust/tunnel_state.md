# `sandwich_tunnel_state`

Check the current state of `tunnel` object.

Inputs:

- `tun: void`: pointer to `tunnel` object

Outputs:

- enum state of `tunnel` object


```rust
/// Returns the state of the tunnel.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_state(tun: *mut std::ffi::c_void) -> i32 {
    use protobuf::Enum;
    let b: Box<Box<dyn crate::tunnel::Tunnel>> = unsafe { Box::from_raw(tun as *mut _) };
    let r = b.state();
    Box::into_raw(b);
    r.value().value()
}
```

export to C header as:

```c
/// \brief Get the state of the tunnel.
///
/// \param[in] tun Tunnel.
///
/// \return The state of the tunnel.
SANDWICH_API enum SandwichTunnelState sandwich_tunnel_state(
    const struct SandwichTunnel *tun);
```
