# `sandwich_tunnel_new`

Create a new tunnel object from [`context`](./context.md) and [`io`](./io.md).


Inputs:

- `ctx: void`: Pointer to `context` struct
- `cio: void`: Poitner to `io` object

Outputs:

- `tun: void`: Pointer to `tunnel` object
- Error return struct

```rust
/// Instantiates a new tunnel from a serialized protobuf configuration message.
#[no_mangle]
pub extern "C" fn sandwich_tunnel_new(
    ctx: *mut std::ffi::c_void,
    cio: *mut super::io::Settings,
    tun: *mut *mut std::ffi::c_void,
) -> *mut super::Error {
    let mut b: Box<Box<dyn crate::context::Context>> = unsafe { Box::from_raw(ctx as *mut _) };
    let r = b.new_tunnel(unsafe { &mut *cio });
    Box::into_raw(b);
    match r {
        Ok(t) => {
            if !tun.is_null() {
                unsafe {
                    *tun = Box::into_raw(Box::new(t)) as *mut std::ffi::c_void;
                }
            }
            std::ptr::null_mut()
        }
        Err(e) => e.into(),
    }
}
```

export to C header as:

```c
/// \brief Create a tunnel.
///
/// A tunnel is created from an I/O interface. The tunnel takes the ownership
/// of the I/O interface. Therefore, when the tunnel is destroyed with
/// `sandwich_tunnel_free`, the I/O interface is also destroyed.
/// `sandwich_tunnel_io_release` take the ownership of the I/O interface back
/// to the user.
///
/// \param[in] ctx Sandwich context used for setting up the tunnel.
/// \param[in,out] cio I/O interface to use for creating the tunnel.
/// \param[out] tun The new Sandwich tunnel object.
///
/// \return NULL if no error occured, else a chain of errors.
SANDWICH_API struct SandwichError *sandwich_tunnel_new(
    struct SandwichContext *ctx, struct SandwichCIO *cio,
    struct SandwichTunnel **tun);
```
