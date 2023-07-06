<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./docs/guide_doc/src/images/sandwich_white.png">
  <source media="(prefers-color-scheme: light)" srcset="./docs/guide_doc/src/images/sandwich_black.png">
  <img alt="Sandwich logo" src="./docs/guide_doc/src/images/sandwich_black.png" align="center" height="100">
</picture>

# Sandwich
[rust-badge][go-badge][release-badge][etc][etc]

Sandwich is a multi-platform, multi-language, open-source library that provides a simple unified API for developers to use (multiple) cryptographic libraries in their applications. Find documentation at: [link to doc landing page].

## Contents

1. [Introduction](#introduction)
    1. [What is Sandwich?](#what-is-sandwich)
    2. [Why use Sandwich?](#why-sandwich)
2. [Current Version](#current-version)
3. [Getting Started](#installation)
4. [How to Contribute](#how-to-contribute)

## Introduction

<img src="./docs/guide_doc/src/images/architecture_sketch.png" align="right" width="325"/>

### What is Sandwich?
### (alt title) What are the main features of Sandwich?
- Sandwich is a **middleware** to interact with cryptographic libraries.
- Sandwich **unifies** cryptographic libraries under the Sandwich API.

### Why use Sandwich instead of `$LIBRARY`?

#### Sandwich provides **agility**

Consider these cases:

- If you need to use `$ANOTHER_CRYPTO_LIBRARY` instead of `$CURRENT_CRYPTO_LIBRARY` and worry about API differences?
- If you want have post-quantum cryptography and your `$CURRENT_CRYPTO_LIBRARY` does not have such features?
- If you want to support multiple `$LIBRARIES` instead of a single `$LIBRARY`?

**In all cases above, you don't have to reimplement your code**, the Sandwich API remains unchanged, you just need to point Sandwich to the your new choice of `$CRYPTO_LIBRARY` and recompile.

We have plan to support changing library at run-time on our roadmap.

#### Sandwich is a *thin wrapper*

Sandwich is a wrapper around cryptography libraries. Our objectives:

- **Minimal overhead**. You can see our benchmark between Sandwich and direct call to Crypto library [here](TODO).
- **Support multiple languages**. We provide binding to Go, Python, C/C++ via FFI and Rust API.

#### Sandwich is Simple

##### Simple to use
Using Sandwich will not collide with your current setup, we support domain separation by preventing symbol name collisions.

To do so, we develop open source tools to encounter problems while developing Sandwich:

- [`Bartleby`](https://github.com/sandbox-quantum/bartleby): Resolve symbols collision between shared crypto libraries. Which means a simple prefix `sandwich_crypto_@version_number` will isolate Sandwich with other libraries.

##### Simple to build

`Sandwich Backend` links to well-tested Cryptography libraries (e.g OpenSSL, BoringSSL). `Sandwich API` provides safe, high-level abstraction on top of `Sandwich Backend` to other programming languages.

Our build process is wrapped in Bazel build, which compiles the Sandwich cores and Cryptography libraries, plus all the bindings.

`Bazel` provides fast and parallel approaches, it's also support multiple platforms by predefined `Bazel rules`.
We think Bazel build system enhances build process experience for developers.

With Bazel, we simplify the build process to a few commands:

```
bazelisk build ... # Build everything
bazelisk test ...  # Test everything
```

## Current version

[Insert a versioned description of the library: timestamp this, describe what OS support there is, what languages (2 paragraphs max).]

e.g. "The last version is [1.0](https://github.com/sandbox-quantum/sandwich/releases/tag/v1.0), released on 2023-08-01, which offers support for [OpenSSL](https://github.com/sandbox-quantum/sandwich/tree/main/common/build/openssl) and [BoringSSL]() in [rust](), [python](https://github.com/sandbox-quantum/sandwich/blob/main/docs/guide_doc/src/install/python-installation.md), [go](), [C/C++](), [etc]()". Link these to landing pages (i.e., a how-to or install guide) for each language, e.g. for python the link above works.

[Add workflow status badges for ubuntu, macos, etc]

Our update and release cycle occurs at our GitHub repository. We ensure to stay on top of performance and security fixes.

## Getting Started

[Insert separate installation instructions for python, rust, go, etc.]

### Python

```sh
pip install pysandwich
```

Our documentation offers further python support for [installation](), [API](), [configuration](), [examples](), [etc](). [or we link to a unified homepage for Python, i.e. a Python-How-To, which itself links to installation, API, config, examples, etc.]

## Contributing
Any contributions towards this project, ranging from bug patches to library extensions, would be great appreciated. We have set out some instructions for contributors [here]().

## License

Sandwich is under [Apache 2.0 License](https://apache.org/licenses/LICENSE-2.0).

## Disclamer

The software and documentation are provided "as is" and SandboxAQ hereby disclaims all warranties, whether express, implied, statutory, or otherwise.
SandboxAQ specifically disclaims, without limitation, all implied warranties of merchantability, fitness for a particular purpose, title, and non-infringement, and all warranties arising from course of dealing, usage, or trade practice.
SandboxAQ makes no warranty of any kind that the software and documentation, or any products or results of the use thereof, will meet any person's requirements, operate without interruption, achieve any intended result, be compatible or work with any software, system or other services, or be secure, accurate, complete, free of harmful code, or error free.
