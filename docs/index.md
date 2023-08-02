# Introduction

<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./images/sandwich_architecture_white.png" width="666">
  <source media="(prefers-color-scheme: light)" srcset="./images/sandwich_architecture_black.png" width="666">
  <img alt="The architecture of Sandwich.">
</picture>
</p>

## What is Sandwich?

Sandwich provides a simple, unified, and hard to misuse API for developers to
use cryptographic algorithms and protocols of their choice in their
applications.  Sandwich is written in
[Rust](rust_api/sandwich_full_doc.rustdoc/sandwich/index.html), and provides a
[C API](cAPI/links.md) with bindings for [Python](TODO) and
[Go](https://pkg.go.dev/github.com/sandbox-quantum/sandwich). This API is
implemented through various cryptographic libraries (OpenSSL and BoringSSL),
and in particular supports
[libOQS](https://github.com/open-quantum-safe/liboqs), meaning **Sandwich
enables post-quantum cryptography**.

One goal of the library is to enable dynamic cryptographic agility, without the
necessity of having to recompile or redeploy updated software.

### The tunnel abstraction

Sandwich provides a secure tunnel abstraction. An example of such a tunnel is
TLS. Sandwich slices the concept of tunnels into two different dimensions:

* a handshake plane where a shared key between two peers is generated
* a record plane where actual protected data is exchanged

See [the documentation](concepts/tunnel.md) for more details.

### Runtime cryptographic agility

Utilizing Sandwich enables software to have dynamic cryptographic agility, meaning that the choice of which cryptographic library backend is used can be selected at runtime. See TODO for an example.

Sandwich implements the underlying cryptography functionality using existing cryptographic
libraries, namely OpenSSL or BoringSSL.

## Security fixes

Sandwich is keen to stay on top of performance and security fixes of the underlying libraries.

# License

Sandwich is under [Apache 2.0 License](https://apache.org/licenses/LICENSE-2.0).

# Disclaimer

The software and documentation are provided "as is" and SandboxAQ hereby disclaims all warranties, whether express, implied, statutory, or otherwise.
SandboxAQ specifically disclaims, without limitation, all implied warranties of merchantability, fitness for a particular purpose, title, and non-infringement, and all warranties arising from course of dealing, usage, or trade practice.
SandboxAQ makes no warranty of any kind that the software and documentation, or any products or results of the use thereof, will meet any person's requirements, operate without interruption, achieve any intended result, be compatible or work with any software, system or other services, or be secure, accurate, complete, free of harmful code, or error free.
