# Error

## Description

This API provides error types by inheriting the `Exception` class.
Error codes come from the predefined `*.proto` file.

All sandwich exceptions are based on `SandwichException`.

Sandwich `error.py` defines the following exception families:

- `SandwichGlobalException`: exceptions that can happen all across the
    library.
- `HandshakeException`: exceptions happening during the handshake stage
    (from `Tunnel.handshake()`).
- `RecordPlaneException`: exceptions happening in `Tunnel.read` or
    `Tunnel.write`.
- `IOException`: exceptions happening in the I/O interface (see `io.py`).

All exceptions are based on the error codes defined by the following protobuf:

- `errors.proto`: `SandwichGlobalException`
- `tunnel.proto`: `HandshakeException` and `RecordPlaneException`
- `io.proto`: `IOException`.

`SandwichException` exposes a `code` method to get the corresponding error code.

Here is a list of predefine protobuf error:


| proto        | ErrorMap             |
|--------------|----------------------|
| errors.proto | api                  |
|              | configuration        |
|              | openSSLConfiguration |
|              | certificate          |
|              | asn1                 |
|              | kEM                  |
|              | system               |
|              | socket               |

| proto        | ErrorMap             |
|--------------|----------------------|
| tunnel.proto | handshake            |
|              | recordPlane          |

| proto        | ErrorMap             |
|--------------|----------------------|
| io.proto     | io                   |

This error code is **compatible** with all others Sandwich binding languages.
