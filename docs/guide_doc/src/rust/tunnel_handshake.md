# `sandwich_tunnel_handshake`

Perform cryptographic handshake, update the state of the tunnel

Input:

- `tun: void`: pointer to `tunnel` object

Output:

- `i32`: enum state of Handshake

```rust
/// Performs the handshake.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_handshake(tun: *mut std::ffi::c_void) -> i32 {
    use protobuf::Enum;
    let mut b: Box<Box<dyn crate::tunnel::Tunnel>> = unsafe { Box::from_raw(tun as *mut _) };
    let r = b.handshake();
    Box::into_raw(b);
    r.value().value()
}
```

export to C header as:

```c
/// \brief Perform the handshake.
///
/// \param[in,out] tun Tunnel.
///
/// \return The state of the handshake.
SANDWICH_API enum SandwichTunnelHandshakeState sandwich_tunnel_handshake(
    struct SandwichTunnel *tun);
```
