# `sandwich_tunnel_write`

Write data to `tunnel` object

Inputs:

- `src: void`: pointer to where to write data
- `n: usize`: number of bytes to write


Outputs:

- `tun: void`: pointer to `tunnel` object
- `w: usize`: number of byte _successfully_ write (`w <= n`)

```rust
/// Performs a write operation.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_write(
    tun: *mut std::ffi::c_void,
    src: *const std::ffi::c_void,
    n: usize,
    w: *mut usize,
) -> i32 {
    use protobuf::Enum;
    let mut b: Box<Box<dyn crate::tunnel::Tunnel>> = unsafe { Box::from_raw(tun as *mut _) };
    let res = b.write(unsafe { std::slice::from_raw_parts(src as *const u8, n) });
    Box::into_raw(b);
    match res {
        Ok(wn) => unsafe {
            *w = wn;
            pb::RecordError::RECORDERROR_OK
        },
        Err(e) => e.value(),
    }
    .value()
}
```

export to C header as:

```c
/// \brief Write some bytes to the record plane of the tunnel.
///
/// \param[in,out] tun Tunnel.
/// \param[in] src Source buffer.
/// \param n Amount of bytes to read.
/// \param[out] w Amount of bytes successfully written.
///
/// NULL for `w` is allowed.
///
/// \return An error code.
SANDWICH_API enum SandwichTunnelRecordError sandwich_tunnel_write(
    struct SandwichTunnel *tun, const void *src, size_t n, size_t *w);
```
