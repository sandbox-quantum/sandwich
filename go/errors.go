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

// createError creates a chain of errors, returned from Sandwich.
func createError(chain *C.struct_SandwichError) error {
	var root Error = nil
	var cur Error = nil
	for chain != nil {
		if _, ok := pb.ErrorKind_name[int32(chain.kind)]; ok {
			var e Error = nil
			var msg string = C.GoString(chain.msg)
			switch pb.ErrorKind(chain.kind) {
			case pb.ErrorKind_ERRORKIND_API:
				e = newAPIError(pb.APIError(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_CONFIGURATION:
				e = newConfigurationError(pb.ConfigurationError(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_TLS_CONFIGURATION:
				e = newTLSConfigurationError(pb.TLSConfigurationError(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_CERTIFICATE:
				e = newCertificateError(pb.CertificateError(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_SYSTEM:
				e = newSystemError(pb.SystemError(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_SOCKET:
				e = newSocketError(pb.SocketError(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_PROTOBUF:
				e = newProtobufError(pb.ProtobufError(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_PRIVATE_KEY:
				e = newPrivateKeyError(pb.PrivateKeyError(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_ASN1:
				e = newASN1Error(pb.ASN1Error(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_DATA_SOURCE:
				e = newDataSourceError(pb.DataSourceError(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_KEM:
				e = newKEMError(pb.KEMError(chain.code), msg)
			case pb.ErrorKind_ERRORKIND_HANDSHAKE:
				e = newHandshakeError(pb.HandshakeError(chain.code), msg)
			}
			if root == nil {
				root = e
				cur = e
			} else {
				cur.setDetails(e)
				cur = e
			}
			chain = chain.details
		}
	}
	return root
}

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

// errorKindMap is a map code -> string for error kinds, defined in
// `errors.proto`, enum `ErrorKind`.
var errorKindMap = map[pb.ErrorKind]string{
	pb.ErrorKind_ERRORKIND_API:               "API error",
	pb.ErrorKind_ERRORKIND_CONFIGURATION:     "configuration error",
	pb.ErrorKind_ERRORKIND_TLS_CONFIGURATION: "TLS configuration error",
	pb.ErrorKind_ERRORKIND_CERTIFICATE:       "certificate error",
	pb.ErrorKind_ERRORKIND_SYSTEM:            "system error",
	pb.ErrorKind_ERRORKIND_SOCKET:            "socket error",
	pb.ErrorKind_ERRORKIND_PROTOBUF:          "protobuf error",
	pb.ErrorKind_ERRORKIND_PRIVATE_KEY:       "private key error",
	pb.ErrorKind_ERRORKIND_ASN1:              "ASN.1 error",
	pb.ErrorKind_ERRORKIND_ALPN:              "ALPN error",
	pb.ErrorKind_ERRORKIND_DATA_SOURCE:       "DataSource error",
	pb.ErrorKind_ERRORKIND_KEM:               "KEM error",
}

// APIError defines the first-class API errors, such as Context errors,
// Socket errors and Tunnel errors.
type APIError struct {
	BaseError
}

// apiErrorMap is a map code -> string for API errors.
var apiErrorMap = map[pb.APIError]string{
	pb.APIError_APIERROR_CONFIGURATION: "invalid configuration",
	pb.APIError_APIERROR_SOCKET:        "socket error",
	pb.APIError_APIERROR_TUNNEL:        "tunnel error",
}

// newAPIError creates an APIError from an error code.
func newAPIError(code pb.APIError, msg string) *APIError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := apiErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf("unknown API error code %d", int32(code))
	}
	return &APIError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}

// ConfigurationError defines an error that may occur when a protobuf
// configuration is malformed.
type ConfigurationError struct {
	BaseError
}

// configurationErrorMap is a map code -> string for configuration errors.
var configurationErrorMap = map[pb.ConfigurationError]string{
	pb.ConfigurationError_CONFIGURATIONERROR_INVALID_IMPLEMENTATION:     "invalid implementation",
	pb.ConfigurationError_CONFIGURATIONERROR_UNSUPPORTED_IMPLEMENTATION: "unsupported implementation",
	pb.ConfigurationError_CONFIGURATIONERROR_INVALID:                    "invalid configuration",
}

// newConfigurationError creates a ConfigurationError from an error code.
func newConfigurationError(code pb.ConfigurationError, msg string) *ConfigurationError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := configurationErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf("unknown configuration error code %d", int32(code))
	}
	return &ConfigurationError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}

// TLSConfigurationError defines an error that may occur when a protobuf
// configuration using the TLS protocol is malformed.
type TLSConfigurationError struct {
	BaseError
}

// tlsConfigurationErrorMap is a map code -> string for TLS configuration errors.
var tlsConfigurationErrorMap = map[pb.TLSConfigurationError]string{
	pb.TLSConfigurationError_TLSCONFIGURATIONERROR_UNSUPPORTED_IMPLEMENTATION:                "unsupported implementation",
	pb.TLSConfigurationError_TLSCONFIGURATIONERROR_UNSUPPORTED_PROTOCOL_VERSION:              "invalid TLS version",
	pb.TLSConfigurationError_TLSCONFIGURATIONERROR_EMPTY:                                     "empty configuration",
	pb.TLSConfigurationError_TLSCONFIGURATIONERROR_INVALID_CASE:                              "invalid oneof case",
	pb.TLSConfigurationError_TLSCONFIGURATIONERROR_PRIVATE_KEY_INCONSISTENT_WITH_CERTIFICATE: "private key is not consistent with the provided certificate",
	pb.TLSConfigurationError_TLSCONFIGURATIONERROR_INVALID:                                   "invalid TLS configuration",
}

// newTLSConfigurationError creates a TLSConfigurationError from an error code.
func newTLSConfigurationError(code pb.TLSConfigurationError, msg string) *TLSConfigurationError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := tlsConfigurationErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf("unknown OpenSSL configuration error code %d", int32(code))
	}
	return &TLSConfigurationError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}

// CertificateError defines an error that may occur when a configuration supplies
// a certificate that is malformed.
type CertificateError struct {
	BaseError
}

// certificateErrorMap is a map code -> string for certificate errors.
var certificateErrorMap = map[pb.CertificateError]string{
	pb.CertificateError_CERTIFICATEERROR_MALFORMED:   "certificate malformed",
	pb.CertificateError_CERTIFICATEERROR_EXPIRED:     "certificate expired",
	pb.CertificateError_CERTIFICATEERROR_NOT_FOUND:   "certificate not found on disk",
	pb.CertificateError_CERTIFICATEERROR_UNKNOWN:     "unknown error",
	pb.CertificateError_CERTIFICATEERROR_UNSUPPORTED: "certificate not supported by underlying implementation",
}

// newCertificateError creates a CertificateError from an error code.
func newCertificateError(code pb.CertificateError, msg string) *CertificateError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := certificateErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf("unknown certificate error code %d", int32(code))
	}
	return &CertificateError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}

// PrivateKeyError defines an error that may occur when a configuration supplies
// a private key that is malformed.
type PrivateKeyError struct {
	BaseError
}

// privateKeyErrorMap is a map code -> string for private key errors.
var privateKeyErrorMap = map[pb.PrivateKeyError]string{
	pb.PrivateKeyError_PRIVATEKEYERROR_MALFORMED:   "private key malformed",
	pb.PrivateKeyError_PRIVATEKEYERROR_NOT_FOUND:   "private key not found on disk",
	pb.PrivateKeyError_PRIVATEKEYERROR_UNKNOWN:     "unknown error",
	pb.PrivateKeyError_PRIVATEKEYERROR_UNSUPPORTED: "private key not supported by underlying implementation",
	pb.PrivateKeyError_PRIVATEKEYERROR_NOT_SERVER:  "not a server configuration",
}

// newPrivateKeyError creates a PrivateKeyError from an error code.
func newPrivateKeyError(code pb.PrivateKeyError, msg string) *PrivateKeyError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := privateKeyErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf("unknown private key error code %d", int32(code))
	}
	return &PrivateKeyError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}

// ProtobufError defines an error that may occur when the protobuf message
// is malformed.
type ProtobufError struct {
	BaseError
}

// ErrorMap is a map code -> string for protobuf errors.
var protobufErrorMap = map[pb.ProtobufError]string{
	pb.ProtobufError_PROTOBUFERROR_EMPTY:            "empty message",
	pb.ProtobufError_PROTOBUFERROR_TOO_BIG:          "message too large",
	pb.ProtobufError_PROTOBUFERROR_PARSE_FAILED:     "message parsing failed",
	pb.ProtobufError_PROTOBUFERROR_NULLPTR:          "null pointer",
	pb.ProtobufError_PROTOBUFERROR_INVALID_ARGUMENT: "invalid argument",
}

// newProtobufError creates a ProtobufError from an error code.
func newProtobufError(code pb.ProtobufError, msg string) *ProtobufError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := protobufErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf("unknown protobuf error code %d", int32(code))
	}
	return &ProtobufError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}

// ASN1Error defines an error that may occur when a malformed ASN.1 document
// is provided.
type ASN1Error struct {
	BaseError
}

// ErrorMap is a map code -> string for ASN.1 errors.
var asn1ErrorMap = map[pb.ASN1Error]string{
	pb.ASN1Error_ASN1ERROR_INVALID_FORMAT: "invalid format",
}

// newASN1Error creates a ASN1Error from an error code.
func newASN1Error(code pb.ASN1Error, msg string) *ASN1Error {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := asn1ErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf("unknown ASN.1 error code %d", int32(code))
	}
	return &ASN1Error{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}

// ALPNError defines an error that may occur when ALPN Protocol is provided.
type ALPNError struct {
	BaseError
}

// ErrorMap is a map code -> string for ALPN errors.
var alpnErrorMap = map[pb.ALPNError]string{
	pb.ALPNError_ALPNERROR_LENGTH_ERROR:   "protocol length is longer than 255 bytes",
	pb.ALPNError_ALPNERROR_INVALID_STRING: "protocol contains NULL byte or invalid string",
}

// newALPNError creates a ALPNError from an error code.
func newALPNError(code pb.ALPNError, msg string) *ALPNError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := alpnErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf("unknown ALPN error code %d", int32(code))
	}
	return &ALPNError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}

// DataSourceError defines an error that may occur when a configuration
// provided a malformed DataSource.
type DataSourceError struct {
	BaseError
}

// ErrorMap is a map code -> string for DataSource errors.
var dataSourceErrorMap = map[pb.DataSourceError]string{
	pb.DataSourceError_DATASOURCEERROR_EMPTY:        "empty DataSource",
	pb.DataSourceError_DATASOURCEERROR_INVALID_CASE: "invalid oneof case",
	pb.DataSourceError_DATASOURCEERROR_NOT_FOUND:    "data not found on local filesystem",
}

// newDataSourceError creates a DataSourceError from an error code.
func newDataSourceError(code pb.DataSourceError, msg string) *DataSourceError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := dataSourceErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf("unknown DataSource error code %d", int32(code))
	}
	return &DataSourceError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}

// KEMError defines an error that may occur when a KEM is invalid or unsupported.
type KEMError struct {
	BaseError
}

// ErrorMap is a map code -> string for KEM errors.
var kEMErrorMap = map[pb.KEMError]string{
	pb.KEMError_KEMERROR_INVALID:  "invalid or unsupported KEM",
	pb.KEMError_KEMERROR_TOO_MANY: "too many KEMs",
}

// newKEMError creates a KEMError from an error code.
func newKEMError(code pb.KEMError, msg string) *KEMError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := kEMErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf("unknown KEM error code %d", int32(code))
	}
	return &KEMError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}

// SystemError defines an error that may occur when a system error is
// encountered, such as a memory allocation failure.
type SystemError struct {
	BaseError
}

// ErrorMap is a map code -> string for system errors.
var systemErrorMap = map[pb.SystemError]string{
	pb.SystemError_SYSTEMERROR_MEMORY:           "memory error",
	pb.SystemError_SYSTEMERROR_INTEGER_OVERFLOW: "integer overflow",
}

// newSystemError creates a SystemError from an error code.
func newSystemError(code pb.SystemError, msg string) *SystemError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := systemErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf("unknown system error code %d", int32(code))
	}
	return &SystemError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}

// SocketError defines an error that may occur in the I/O socket interface.
type SocketError struct {
	BaseError
}

// ErrorMap is a map code -> string for socket errors.
var socketErrorMap = map[pb.SocketError]string{
	pb.SocketError_SOCKETERROR_BAD_FD:             "bad file descriptor",
	pb.SocketError_SOCKETERROR_CREATION_FAILED:    "socket creation failed",
	pb.SocketError_SOCKETERROR_BAD_NETADDR:        "bad network address",
	pb.SocketError_SOCKETERROR_NETADDR_UNKNOWN:    "network address resolution failed",
	pb.SocketError_SOCKETERROR_FSTAT_FAILED:       "fstat failed",
	pb.SocketError_SOCKETERROR_NOT_SOCK:           "not a socket",
	pb.SocketError_SOCKETERROR_GETSOCKNAME_FAILED: "getsockname failed",
	pb.SocketError_SOCKETERROR_SETSOCKOPT_FAILED:  "setsockopt failed",
	pb.SocketError_SOCKETERROR_INVALID_AI_FAMILY:  "invalid AI family",
}

// newSocketError creates a SocketError from an error code.
func newSocketError(code pb.SocketError, msg string) *SocketError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := socketErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf("unknown socket error code %d", int32(code))
	}
	return &SocketError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
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

// handshakeErrorMap is a map code -> string for errors that take place during
// the handshake stage. These errors are defined in `errors.proto` defined by `HandshakeError`.
var handshakeErrorMap = map[int32]string{
	int32(pb.HandshakeError_HANDSHAKEERROR_INVALID_SERVER_NAME):                       "invalid server name",
	int32(pb.HandshakeError_HANDSHAKEERROR_CERTIFICATE_VERIFICATION_FAILED):           "certificate verification failed",
	int32(pb.HandshakeError_HANDSHAKEERROR_CERTIFICATE_EXPIRED):                       "certificate has expired",
	int32(pb.HandshakeError_HANDSHAKEERROR_CERTIFICATE_REVOKED):                       "certificate is revoked",
	int32(pb.HandshakeError_HANDSHAKEERROR_INVALID_CERTIFICATE):                       "certificate is invalid",
	int32(pb.HandshakeError_HANDSHAKEERROR_CERTIFICATE_SIGNATURE_VERIFICATION_FAILED): "certificate signature verification failed",
	int32(pb.HandshakeError_HANDSHAKEERROR_UNKNOWN_ERROR):                             "unknown handshake error",
}

// HandshakeError defines errors that can happen during the handshake stage.
// These errors are defined by the enum `HandshakeError` in `errors.proto`.
// They are used by `Tunnel.Handshake`.
type HandshakeError struct {
	BaseError
}

// NewHandshakeError creates an error from an error code.
// The error code is supposed to match a key in `handshakeErrorMap`, defined above.
func newHandshakeError(code pb.HandshakeError, msg string) *HandshakeError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	if val, ok := handshakeErrorMap[int32(code)]; ok {
		return &HandshakeError{
			BaseError{
				msg:  val + err_msg,
				code: int32(code),
			},
		}
	}
	return &HandshakeError{
		BaseError{
			msg:  fmt.Sprintf("unknown HandshakeError code %d;", code),
			code: int32(code),
		},
	}
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
