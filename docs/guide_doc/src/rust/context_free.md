# `sandwich_context_free`

Deallocate `context` struct

Inputs:

- `context` struct

Output:

- None


```rust
/// Releases a Sandwich context.
#[no_mangle]
pub extern "C" fn sandwich_context_free(ctx: *mut std::ffi::c_void) {
    if !ctx.is_null() {
        let _: Box<Box<dyn crate::context::Context>> = unsafe { Box::from_raw(ctx as *mut _) };
    }
}

```

export to C header as:

```c
/// \brief Free a Sandwich context.
///
/// \param[in,out] ctx Context to free.
///
/// NULL for `cio` is allowed.
void sandwich_context_free(struct SandwichContext *ctx);

```
