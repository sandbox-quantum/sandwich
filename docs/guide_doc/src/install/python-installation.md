## Python Sandwich Installation

### Sandwich Python Wheel

Sandwich officially supports `Python 3.11` and later, and many platforms:

- `x86_64-unknown-linux-gnu`
- `aarch64-apple-darwin`
- `aarch64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `x86_64-pc-windows-msvc`

After you cloned Sandwich Github repo, you can either install `Sandwich` via `pip` or build it from the source.

#### Install Sandwich via pip

`pip install pysandwich`

#### Build and Install Sandwich Python Wheel

After you clone the code, we can run Bazel command to build the Python wheel that fits to current platform.

`bazelisk build //pysandwich:wheel`

Here is the example output on `Linux x86_64`:

```
❯ bazelisk build //pysandwich:wheel

....
bazel-out/k8-fastbuild/bin/rust/libopenssl_bartleby_bartleby.a produced.
Target //pysandwich:wheel up-to-date:
  bazel-bin/pysandwich/pysandwich-0.0.1-cp310-abi3-manylinux2014_x86_64.whl
INFO: Elapsed time: 612.899s, Critical Path: 288.93s
INFO: 1479 processes: 251 internal, 1 local, 1227 processwrapper-sandbox.
INFO: Build completed successfully, 1479 total actions
```

On average, the build process takes 10 minutes on 8 cores for the first build.
The next time you build Python wheel, since most of the files are cached by Baze so the total build time is reduced to seconds.

To install the wheel to our system, at the root of our Github repository, run:

`pip install bazel-bin/pysandwich/pysandwich-0.0.1-cp310-abi3-manylinux2014_x86_64.whl`

You can add `--force-reinstall` after the `install` command to overwrite the old version of Sandwich package.
