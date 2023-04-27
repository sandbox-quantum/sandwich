# `sandwich_io_free`

Deallocate an I/O object.

```rust
/// Releases an I/O interface.
#[no_mangle]
pub extern "C" fn sandwich_io_free(io: *mut std::ffi::c_void) {
    if !io.is_null() {
        let _ = unsafe { Box::from_raw(io as *mut Settings) };
    }
}
```

export to C header as:

```c
/// \brief Free an I/O interface.
///
/// \param[in,out] cio I/O interface to free.
///
/// NULL for `cio` is allowed.
///
/// \return The I/O interface to free.
SANDWICH_API void sandwich_io_free(struct SandwichCIO *cio);
```
