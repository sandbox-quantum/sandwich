# `sandwich_tunnel_read`

Read data from `tunnel` object

Inputs:

- `tun: void`: pointer to `tunnel` object
- `n: usize`: number of bytes read


Outputs:

- `dst: void`: pointer to where data is stored
- `r: usize`: number of byte _successfully_ read (`r <= n`)

```rust
/// Performs a read operation.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_read(
    tun: *mut std::ffi::c_void,
    dst: *mut std::ffi::c_void,
    n: usize,
    r: *mut usize,
) -> i32 {
    use protobuf::Enum;
    let mut b: Box<Box<dyn crate::tunnel::Tunnel>> = unsafe { Box::from_raw(tun as *mut _) };
    let res = b.read(unsafe { std::slice::from_raw_parts_mut(dst as *mut u8, n) });
    Box::into_raw(b);
    match res {
        Ok(rn) => unsafe {
            *r = rn;
            pb::RecordError::RECORDERROR_OK
        },
        Err(e) => e.value(),
    }
    .value()
}
```

export to C header as:

```c
/// \brief Read some bytes from the record plane of the tunnel.
///
/// \param[in,out] tun Tunnel..
/// \param[out] dst Destination buffer.
/// \param n Amount of bytes to read.
/// \param[out] r Amount of bytes successfully read.
///
/// NULL for `r` is allowed.
///
/// \return An error code.
SANDWICH_API enum SandwichTunnelRecordError sandwich_tunnel_read(
    struct SandwichTunnel *tun, void *dst, size_t n, size_t *r);
```
