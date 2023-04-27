# Installation

## Prerequisites

You need to install these packages prior to installling Sandwich:

- [`bazelisk`](https://bazel.build/install/bazelisk)
- [`clang-13`](https://releases.llvm.org/download.html)
- `libncurses5`

### Install Bazelisk

#### macOS

To install `bazelisk`, on macOS, the easiest way is to use [`brew`](brew.sh):
```
brew install bazelisk
```

#### Windows

```
choco install bazelisk
```

Make sure to add `bazelisk, bazel` to your `PATH`.

#### Linux

You can download [Bazelisk Releases](https://github.com/bazelbuild/bazelisk/releases) and add it to your `PATH` manually.

### Install Clang-13

To install `clang-13` in Debian/Ubuntu:

```
apt-get install clang-13
```

### Install libncurses5

To install `libncurses5` in Debian/Ubuntu:

```
apt-get install libncurses5
```

## Build

First, we need Sandwich repository:

```
git clone https://github.com/sandbox-quantum/sandwich.git
```

Building with Bazel is easy, after Git clone Sandwich, run:


```
bazelisk build ...
```

Example output:

```
INFO: Build completed successfully, 34 total actions
```

## Test

To make sure Sandwich work properly in your system, run:

```
bazelisk test ...
```

Example output:

```
INFO: Analyzed 110 targets (0 packages loaded, 0 targets configured).
INFO: Found 102 targets and 8 test targets...
INFO: Elapsed time: 1.670s, Critical Path: 1.12s
INFO: 9 processes: 14 processwrapper-sandbox.
INFO: Build completed successfully, 9 total actions
//c:tunnels_test                                                         PASSED in 0.1s
//common/build/openssl:openssl_dep_link_test                             PASSED in 0.1s
//go:fuzz_test                                                           PASSED in 0.1s
//go:sandwich_test                                                       PASSED in 1.1s
//pysandwich:tunnel_test                                                 PASSED in 0.5s
//pysandwich:wheel_build_test                                            PASSED in 0.0s
//rust:clippy_build_test                                                 PASSED in 0.1s
//rust:sandwich_test                                                     PASSED in 0.1s
```

## Ready

You're good to create application with Sandwich.
