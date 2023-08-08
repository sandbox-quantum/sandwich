# Installation and integration

## C API

There are two ways to utilize the Sandwich C API: using prebuilt packages, or by
building from source.

### Using pre-built packages

Pre-built packages can be found on the [Sandwich releases Github
section](https://github.com/sandbox-quantum/sandwich/releases). It is
precompiled for Linux and MacOS, targetting both amd64 and aarch64 (arm64).

### Building from source

The Sandwich build system is based on [Bazel](https://bazel.build/). See [Installing Bazel](#installing-bazel) for more bazel setup information.

To build Sandwich, you must first install the necessary build-time dependencies. Platform specific dependency installation instructions are documented below, depending on whether you are building on [Linux](#linux-specific-build-dependencies) or [MacOS](#macos-specific-build-dependencies)


#### Installing Bazel

We recommend using [Bazelisk](https://github.com/bazelbuild/bazelisk/) to
install Bazel. You can use the [Bazelisk pre-built
releases](https://github.com/bazelbuild/bazelisk/releases), and add the `
bazelisk` binary in your `PATH`.

##### Linux-specific build dependencies

To install dependencies in Debian-like systems:

```
# apt install clang-13 lld-13 python3 python3-dev cmake ninja-build git
```

These environment variables need to be set:

* `export CC=clang-13`
* `export CXX=clang++-13`
* `export LD=lld-13`

##### MacOS-specific build dependencies

MacOS builds require installing [XCode](https://apps.apple.com/us/app/xcode/id497799835?mt=12).

#### Build sandwich

Use Bazel to build a release version of Sandwich:

```
bazelisk build //:export -c opt
```

This will generate an archive in `bazel-bin/sandwich_bin.tar.gz` that contains
the sandwich C API headers alongside a static and shared library version of
Sandwich:

```
$ tar tf /path/to/sandwich/bazel-bin/sandwich_bin.tar.gz
include/
include/sandwich_c/sandwich.h
[...]
lib/
lib/libsandwich_full.a
[...]
```

## Go API

The Sandwich Go bindings can be added in a project using `go get`:

```
$ go get github.com/sandbox-quantum/sandwich
```

The Go bindings rely on the Sandwich C API. In order to build a Go
project that is using Sandwich, some `cgo` environment variables need to be set
to tell the Go compiler where to find the Sandwich C headers and compiled static
library.

A compiled version of the Sandwich C API can be either [directly downloded from the Sandwich releases Github
section](https://github.com/sandbox-quantum/sandwich/releases), or [built from source](#building-from-source).

Assuming the Sandwich C API release has been extracted into `$SANDWICH_ROOT`, these environment variables need to be set at build time:

```
$ export CGO_CFLAGS="-I$SANDWICH_ROOT/include"
$ export CGO_LDFLAGS="-L$SANDWICH_ROOT/lib"
```

## Python API

The Python API can be installed with pip with:

```
$ pip install pysandwich
```

It can also be installed from source:
```
$ cd /path/to/sandwich
$ pip install .
```

At runtime, the Sandwich Python bindings will be looking for
`libsandwich_full.so`, which can be either [directly downloaded from the
Sandwich releases Github
section](https://github.com/sandbox-quantum/sandwich/releases), or [built from
source](#building-from-source).

The `SANDWICH_C_LIB` environment variable can point to the path where
`libsandwich_full.so` has been installed. The bindings will also look for the
library in standard operating system's paths.

## Rust API

### Using cargo

```toml
[dependencies]
sandwich = { git = "https://github.com/sandbox-quantum/sandwich.git" }
```

`cargo add` can also be used to append Sandwich into the _dependencies_ section
of an existing `Cargo.toml` file:

```sh
$ cargo add --git 'https://github.com/sandbox-quantum/sandwich.git' sandwich
```

### From source

The Rust API can be built and tested from source with `cargo`:

```sh
$ cargo build
$ cargo test
```

### Rust documentation

Use `cargo doc` to build the Rust documentation:

```sh
$ cargo doc
```

### Features

Sandwich has the following features:

| feature        | description                                          | enabled by default |
|----------------|------------------------------------------------------|--------------------|
| `openssl1_1_1` | Enable support for OpenSSL 1.1.1 built with `liboqs` | `true`             |
| `boringssl`    | Enable support for BoringSSL built with `liboqs`     | `true`             |
| `ffi`          | Enable the FFI interface                             | `false`            |


## Unit tests

Sandwich unit tests can be run directly using Bazel:

```
$ cd /path/to/sandwich && bazelisk test ...
```
