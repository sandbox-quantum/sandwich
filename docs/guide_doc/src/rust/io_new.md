# `sandwich_io_new`

Allocate a new I/O object to serve I/O purpose.

Input:

- `set: *const Settings`: Pointer to struct `Settings`

Output:

- `io: void`: Pointer to allocated `io` object according to input struct `Settings`.

```rust
#[no_mangle]
pub extern "C" fn sandwich_io_new(
    set: *const Settings,
    io: *mut *mut std::ffi::c_void,
) -> *mut super::Error {
    let b = Box::new(unsafe { *set });
    unsafe {
        *io = Box::into_raw(b) as *mut std::ffi::c_void;
    }
    std::ptr::null_mut()
}
```

export to C header as:

```c
/// \brief Create an I/O interface.
///
/// \param[in] cioset Settings for the I/O interface.
/// \param[out] cio The new CIO object.
///
/// \return NULL if no error occured, else a chain of errors.
SANDWICH_API struct SandwichError *sandwich_io_new(
    const struct SandwichCIOSettings *cioset, struct SandwichCIO **cio);
```
