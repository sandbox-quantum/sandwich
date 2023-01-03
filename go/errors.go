// Copyright 2022 SandboxAQ
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Error defines all errors that may happen when using the Sandwich Go library.
// It uses the error codes defined in the protobuf.
package sandwich

import (
	"fmt"

	pb "github.com/sandbox-quantum/sandwich/proto/sandwich"
)

// Error represents the interface for all Sandwich errors.
type Error interface {
	// Error extends the builtin `error` interface.
	error
	// `Code` returns the error code, defined in the protobuf.
	Code() int32
}

// BaseError represents the base structure for all Sandwich errors.
type BaseError struct {
	// msg holds the error string.
	msg string
	// code holds the error code, which comes from the protobuf. It is compatible
	// with the C++ library.
	code int32
}

// Code implements the Error interface.
func (err *BaseError) Code() int32 {
	return err.code
}

// Error implements the error interface.
func (err *BaseError) Error() string {
	return err.msg
}

// globalErrorMap is a map code -> string for global errors defined in
// `errors.proto`.
var globalErrorMap = map[int32]string{
	int32(pb.Error_ERROR_OK):                               "no error",
	int32(pb.Error_ERROR_INVALID_ARGUMENT):                 "invalid argument",
	int32(pb.Error_ERROR_MEMORY):                           "memory error",
	int32(pb.Error_ERROR_IO):                               "i/O error",
	int32(pb.Error_ERROR_UNKNOWN):                          "unknown error",
	int32(pb.Error_ERROR_INVALID_CONFIGURATION):            "invalid configuration",
	int32(pb.Error_ERROR_UNSUPPORTED_IMPLEMENTATION):       "unsupported implementation",
	int32(pb.Error_ERROR_UNSUPPORTED_PROTOCOL):             "unsupported protocol",
	int32(pb.Error_ERROR_IMPLEMENTATION_PROTOCOL_MISMATCH): "implementation and protocol mismatch",
	int32(pb.Error_ERROR_PROTOBUF):                         "protobuf serialization or deserialization error",
	int32(pb.Error_ERROR_NETWORK_INVALID_ADDRESS):          "invalid network address",
	int32(pb.Error_ERROR_NETWORK_INVALID_PORT):             "invalid network port",
	int32(pb.Error_ERROR_INVALID_CONTEXT):                  "invalid context",
	int32(pb.Error_ERROR_BAD_FD):                           "bad file descriptor",
	int32(pb.Error_ERROR_UNSUPPORTED_TUNNEL_METHOD):        "unsupported tunnel method",
	int32(pb.Error_ERROR_INTEGER_OVERFLOW):                 "integer overflow",
	int32(pb.Error_ERROR_MEMORY_OVERFLOW):                  "memory overflow",
	int32(pb.Error_ERROR_IMPLEMENTATION):                   "implementation error",
	int32(pb.Error_ERROR_INVALID_TUNNEL):                   "invalid tunnel",
	int32(pb.Error_ERROR_INVALID_KEM):                      "invalid KEM",
	int32(pb.Error_ERROR_TIMEOUT):                          "tineout reached",
	int32(pb.Error_ERROR_NETWORK_ADDRESS_RESOLVE):          "failed to resolve network address",
	int32(pb.Error_ERROR_NETWORK_CONNECT):                  "failed to connect",
	int32(pb.Error_ERROR_SOCKET_FAILED):                    "failed to create socket",
	int32(pb.Error_ERROR_SOCKET_OPT_FAILED):                "`getsockopt`/`setsockopt` failed",
	int32(pb.Error_ERROR_SOCKET_INVALID_AI_FAMILY):         "invalid socket AI family",
	int32(pb.Error_ERROR_CONNECTION_REFUSED):               "connection refused",
	int32(pb.Error_ERROR_NETWORK_UNREACHABLE):              "network unreachable",
	int32(pb.Error_ERROR_SOCKET_POLL_FAILED):               "socket poll failed",
	int32(pb.Error_ERROR_INVALID_CERTIFICATE):              "invalid certificate",
	int32(pb.Error_ERROR_UNSUPPORTED_CERTIFICATE):          "unsupported certificate",
	int32(pb.Error_ERROR_INVALID_PRIVATE_KEY):              "invalid private key",
	int32(pb.Error_ERROR_UNSUPPORTED_PRIVATE_KEY):          "unsupported private key",
	int32(pb.Error_ERROR_UNSUPPORTED_PROTOCOL_VERSION):     "unsupported protocol version",
}

// GlobalError defines the global errors.
// These errors are defined by the enum `Error` in `errors.proto`.
// They are used all across the library.
type GlobalError struct {
	BaseError
}

// newGlobalError creates an error from an error code.
// The error code is supposed to match a key in `globalErrorMap`, defined above.
func newGlobalError(code int32) *GlobalError {
	if val, ok := globalErrorMap[code]; ok {
		return &GlobalError{
			BaseError{
				msg:  val,
				code: code,
			},
		}
	}
	return &GlobalError{
		BaseError{
			msg:  fmt.Sprintf("unknown GlobalError code %d", code),
			code: code,
		},
	}
}

// newGlobalErrorFromEnum creates an error from a value from the enum pb.Error.
func newGlobalErrorFromEnum(err pb.Error) *GlobalError {
	return newGlobalError(int32(err))
}

// handshakeErrorMap is a map code -> string for errors regarding the handshake
// stage. These errors are defined in `tunnel.proto` defined by `HandshakeState`.
var handshakeErrorMap = map[int32]string{
	int32(pb.HandshakeState_HANDSHAKESTATE_IN_PROGRESS): "the operation is still in progress",
	int32(pb.HandshakeState_HANDSHAKESTATE_WANT_READ):   "the implementation wants to read from the wire, but the underlying I/O is non-blocking",
	int32(pb.HandshakeState_HANDSHAKESTATE_WANT_WRITE):  "the implementation wants to write to the wire, but the underlying I/O is non-blocking",
	int32(pb.HandshakeState_HANDSHAKESTATE_ERROR):       "a critical error occurred",
}

// HandshakeError defines the error that can happens during the handshake stage.
// These errors are defined by the enum `HandshakeState` in `tunnel.proto`.
// They are used by `Tunnel.Handshake`.
type HandshakeError struct {
	BaseError
}

// NewHandshakeError creates an error from an error code.
// The error code is supposed to match a key in `handshakeErrorMap`, defined above.
func newHandshakeError(code int32) *HandshakeError {
	if val, ok := handshakeErrorMap[code]; ok {
		return &HandshakeError{
			BaseError{
				msg:  val,
				code: code,
			},
		}
	}
	return &HandshakeError{
		BaseError{
			msg:  fmt.Sprintf("unknown HandshakeError code %d", code),
			code: code,
		},
	}
}

// NewHandshakeErrorFromEnum creates an error from the enum pb.HandshakeState.
func newHandshakeErrorFromEnum(err pb.HandshakeState) *HandshakeError {
	return newHandshakeError(int32(err))
}

// recordPlaneErrorMap is a map code -> string for errors regarding the record
// plane. These errors ared defined in `tunnel.proto` defined by `RecordError`.
var recordPlaneErrorMap = map[int32]string{
	int32(pb.RecordError_RECORDERROR_WANT_READ):      "tunnel wants to read data, but the underlying I/O interface is non-blocking.",
	int32(pb.RecordError_RECORDERROR_WANT_WRITE):     "tunnel wants to write data, but the underlying I/O interface is non-blocking.",
	int32(pb.RecordError_RECORDERROR_BEING_SHUTDOWN): "tunnel is being closed",
	int32(pb.RecordError_RECORDERROR_CLOSED):         "tunnel is closed",
	int32(pb.RecordError_RECORDERROR_UNKNOWN):        "an unknown error occurred",
}

// RecordPlaneError defines the error that can happens during the record plane.
// These errors are defined by the enum `RecordError` in `tunnel.proto`.
// They are used by `Tunnel.Write` and `Tunnel.Read`.
type RecordPlaneError struct {
	BaseError
}

// NewRecordPlaneError creates an error from an error code.
// The error code is supposed to match a key in `recordPlaneErrorMap`, defined above.
func newRecordPlaneError(code int32) *RecordPlaneError {
	if val, ok := recordPlaneErrorMap[code]; ok {
		return &RecordPlaneError{
			BaseError{
				msg:  val,
				code: code,
			},
		}
	}
	return &RecordPlaneError{
		BaseError{
			msg:  fmt.Sprintf("unknown RecordPlaneError code %d", code),
			code: code,
		},
	}
}

// NewRecordPlaneErrorFromEnum creates an error from the enum pb.RecordError.
func newRecordPlaneErrorFromEnum(err pb.RecordError) *RecordPlaneError {
	return newRecordPlaneError(int32(err))
}

// ioErrorMap is a map code -> string for errors regarding the I/O interface.
// These errors ared defined in `io.proto` defined by `IOError`.
var ioErrorMap = map[int32]string{
	int32(pb.IOError_IOERROR_IN_PROGRESS): "the I/O interface is still connecting to the remote peer",
	int32(pb.IOError_IOERROR_WOULD_BLOCK): "the I/O operation would block, but the I/O interface is non-blocking",
	int32(pb.IOError_IOERROR_REFUSED):     "the I/O interface has been refused connection",
	int32(pb.IOError_IOERROR_CLOSED):      "this I/O interface is closed",
	int32(pb.IOError_IOERROR_INVALID):     "this I/O interface isn't valid",
	int32(pb.IOError_IOERROR_UNKNOWN):     "this I/O interface raised an unknown error",
}

// IOError defines the error that can happens during the i/o operations done by
// an I/O interface.
// These errors are defined by the enum `IOError` in `io.proto`.
type IOError struct {
	BaseError
}

// NewIOError creates an error from an error code.
// The error code is supposed to match a key in `ioErrorMap`, defined above.
// This function is publicly exposed, as it is meant to be used by the user
// to implement their own I/O interface.
func NewIOError(code int32) *IOError {
	if val, ok := ioErrorMap[code]; ok {
		return &IOError{
			BaseError{
				msg:  val,
				code: code,
			},
		}
	}
	return &IOError{
		BaseError{
			msg:  fmt.Sprintf("unknown IOError code %d", code),
			code: code,
		},
	}
}

// NewIOErrorFromEnum creates an error from the enum pb.IOError.
func NewIOErrorFromEnum(err pb.IOError) *IOError {
	return NewIOError(int32(err))
}
