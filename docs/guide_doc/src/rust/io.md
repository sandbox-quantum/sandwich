# I/O

## Description

`I/O API` provide 3 basic operations:

- `read`: Read from an I/O handle
- `write`: Write to an I/O handle
- `close`: To close an I/O handle


## Functions

All 3 basic operations are packed into a default struct `Settings`.

```rust
/// Settings for a generic I/O interface, using pointers.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Settings {
    readfn: ReadFn,
    writefn: WriteFn,
    closefn: CloseFn,
    uarg: *mut std::ffi::c_void,
}
```

where `ReadFn, WriteFn, CloseFn` are predefined I/O functions in `Sandwich Backend` library.

`I/O API` consists of 2 functions:

- [`sandwich_io_new`](./io_new.md): Create an I/O object
- [`sandwich_io_free`](./io_free.md): Free an I/O object
