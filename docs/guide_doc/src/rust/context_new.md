# `sandwich_context_new`

Deserialize encoded protobuf message, allocate memory to store new `context` struct.

Inputs:

- `src: void`: Protobuf input as bytes
- `n : usize`: Size of input protobuf

Output:
- `out: void`: `Context` struct
- Error return struct

```rust
/// Instantiates a Sandwich context from a serialized configuration.
///
/// # Errors
///
/// See constructors of [`crate::Context`].
pub extern "C" fn sandwich_context_new(
    src: *const std::ffi::c_void,
    n: usize,
    out: *mut *mut std::ffi::c_void,
) -> *mut super::Error
```

export to C header as:

```c
/// \brief Create a context from an encoded protobuf message.
///
/// \param[in] src Source buffer containing the encoded protobuf message.
/// \param n Size of the source buffer.
/// \param[out] ctx The new Sandwich context object.
///
/// \return NULL if no error occured, else a chain of errors.
struct SandwichError *sandwich_context_new(const void *src, size_t n, struct SandwichContext **ctx);
```
