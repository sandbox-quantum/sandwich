# Error

## Description

This API provides error via `Error` interface.
Users have to check return error after each function call.

Error codes come from the predefined `*.proto` file.
Each error code are mapped to `string` for readability.

Sandwich `errors.go` defines the following `Error` interface:

```go
// Error represents the interface for all Sandwich errors.
type Error interface {
	// Error extends the builtin `error` interface.
	error
	// `Code` returns the error code, defined in the protobuf.
	Code() int32
	// `SetDetails` sets the encapsulated error.
	setDetails(e Error)
	// `Unwrap` unwraps the next error. It is meant to be used with the `errors`
	// package.
	Unwrap() error
}
```

All the error `map[int32]string{}` defined by the following protobuf:

---
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

---

The struct `BaseError` exposes `msg` and `details` fields to get verbose error code.

This error code is **compatible** with all others Sandwich binding languages.
