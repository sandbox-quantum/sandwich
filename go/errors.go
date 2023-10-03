// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

// Error defines all errors that may happen when using the Sandwich Go library.
// It uses the error codes defined in the protobuf.
package sandwich

import "C"

import (
	"fmt"

	pb "github.com/sandbox-quantum/sandwich/go/proto/sandwich"
)

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

// BaseError represents the base structure for all Sandwich errors.
type BaseError struct {
	// details holds the encapsulated error.
	details Error
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

// SetDetails implements the Error interface.
func (err *BaseError) setDetails(e Error) {
	err.details = e
}

// Unwrap implements the Error interface.
func (err *BaseError) Unwrap() error {
	return err.details
}

// Error implements the error interface.
func (err *BaseError) Error() string {
	return err.msg
}

// handshakeStateErrorMap is a map code -> string for errors regarding the handshake
// state. These errors are defined in `tunnel.proto` defined by `HandshakeState`.
var handshakeStateErrorMap = map[int32]string{
	int32(pb.HandshakeState_HANDSHAKESTATE_IN_PROGRESS): "the operation is still in progress",
	int32(pb.HandshakeState_HANDSHAKESTATE_WANT_READ):   "the implementation wants to read from the wire, but the underlying I/O is non-blocking",
	int32(pb.HandshakeState_HANDSHAKESTATE_WANT_WRITE):  "the implementation wants to write to the wire, but the underlying I/O is non-blocking",
	int32(pb.HandshakeState_HANDSHAKESTATE_ERROR):       "a critical error occurred",
}

// HandshakeStateError defines errors that take place during the handshake stage.
// These states are defined by the enum `HandshakeState` in `tunnel.proto`.
// They are used by `Tunnel.Handshake`.
type HandshakeStateError struct {
	BaseError
}

// NewHandshakeStateError creates an error from an error code.
// The error code is supposed to match a key in `handshakeStateErrorMap`, defined above.
func newHandshakeStateError(code int32, msg string) *HandshakeStateError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	if val, ok := handshakeStateErrorMap[code]; ok {
		return &HandshakeStateError{
			BaseError{
				msg:  val + err_msg,
				code: code,
			},
		}
	}
	return &HandshakeStateError{
		BaseError{
			msg:  fmt.Sprintf("unknown HandshakeStateError code %d;", code),
			code: code,
		},
	}
}

// NewHandshakeErrorFromEnum creates an error from the enum pb.HandshakeState.
func newHandshakeStateErrorFromEnum(err pb.HandshakeState) *HandshakeStateError {
	return newHandshakeStateError(int32(err), "")
}

// recordPlaneErrorMap is a map code -> string for errors regarding the record
// plane. These errors are defined in `tunnel.proto` defined by `RecordError`.
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
func newRecordPlaneError(code int32, msg string) *RecordPlaneError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	if val, ok := recordPlaneErrorMap[code]; ok {
		return &RecordPlaneError{
			BaseError{
				msg:  val + err_msg,
				code: code,
			},
		}
	}
	return &RecordPlaneError{
		BaseError{
			msg:  fmt.Sprintf("unknown RecordPlaneError code %d;", code),
			code: code,
		},
	}
}

// NewRecordPlaneErrorFromEnum creates an error from the enum pb.RecordError.
func newRecordPlaneErrorFromEnum(err pb.RecordError) *RecordPlaneError {
	return newRecordPlaneError(int32(err), "")
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
func NewIOError(code int32, msg string) *IOError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	if val, ok := ioErrorMap[code]; ok {
		return &IOError{
			BaseError{
				msg:  val + err_msg,
				code: code,
			},
		}
	}
	return &IOError{
		BaseError{
			msg:  fmt.Sprintf("unknown IOError code %d;", code),
			code: code,
		},
	}
}

// NewIOErrorFromEnum creates an error from the enum pb.IOError.
func NewIOErrorFromEnum(err pb.IOError) *IOError {
	return NewIOError(int32(err), "")
}
