# Error

Struct `Error` in Rust constains information about error and translate them into readable languages.

```rust
#[repr(C)]
pub struct Error {
    pub(self) details: *mut Error,
    pub(self) kind: i32,
    pub(self) code: i32,
}
```

When Error is allocated, it should be deallocated with `sandwich_error_free`

```rust
/// Releases an [`Error`].
#[no_mangle]
pub extern "C" fn sandwich_error_free(mut ptr: *mut Error) {
    while !ptr.is_null() {
        let b = unsafe { Box::from_raw(ptr) };
        ptr = b.details;
    }
}
```

export to C header as:

```c
/// \brief Free an error chain.
///
/// \param chain Error chain.
SANDWICH_API void sandwich_error_free(struct SandwichError *chain);
```


## Portability

All errors are consistent since they are predefined in protobuf message.
