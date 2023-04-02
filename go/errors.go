// Copyright 2023 SandboxAQ
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

// errorKindMap is a map code -> string for error kinds, defined in
// `errors.proto`, enum `ErrorKind`.
var errorKindMap = map[pb.ErrorKind]string{
	pb.ErrorKind_ERRORKIND_API:                          "API error",
	pb.ErrorKind_ERRORKIND_CONFIGURATION:                "configuration error",
	pb.ErrorKind_ERRORKIND_OPENSSL_CONFIGURATION:        "OpenSSL configuration error",
	pb.ErrorKind_ERRORKIND_OPENSSL_CLIENT_CONFIGURATION: "OpenSSL client configuration error",
	pb.ErrorKind_ERRORKIND_OPENSSL_SERVER_CONFIGURATION: "OpenSSL server configuration error",
	pb.ErrorKind_ERRORKIND_CERTIFICATE:                  "certificate error",
	pb.ErrorKind_ERRORKIND_SYSTEM:                       "system error",
	pb.ErrorKind_ERRORKIND_SOCKET:                       "socket error",
	pb.ErrorKind_ERRORKIND_PROTOBUF:                     "protobuf error",
	pb.ErrorKind_ERRORKIND_PRIVATE_KEY:                  "private key error",
	pb.ErrorKind_ERRORKIND_ASN1:                         "ASN.1 error",
	pb.ErrorKind_ERRORKIND_DATA_SOURCE:                  "DataSource error",
	pb.ErrorKind_ERRORKIND_KEM:                          "KEM error",
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
func newAPIError(code pb.APIError) *APIError {
	var msg string
	if val, ok := apiErrorMap[code]; ok {
		msg = val
	} else {
		msg = fmt.Sprintf("unknown API error code %d", int32(code))
	}
	return &APIError{
		BaseError{
			msg:  msg,
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
func newConfigurationError(code pb.ConfigurationError) *ConfigurationError {
	var msg string
	if val, ok := configurationErrorMap[code]; ok {
		msg = val
	} else {
		msg = fmt.Sprintf("unknown configuration error code %d", int32(code))
	}
	return &ConfigurationError{
		BaseError{
			msg:  msg,
			code: int32(code),
		},
	}
}

// OpenSSLConfigurationError defines an error that may occur when a protobuf
// configuration using the OpenSSL implementation is malformed.
type OpenSSLConfigurationError struct {
	BaseError
}

// openSSLConfigurationErrorMap is a map code -> string for OpenSSL configuration errors.
var openSSLConfigurationErrorMap = map[pb.OpenSSLConfigurationError]string{
	pb.OpenSSLConfigurationError_OPENSSLCONFIGURATIONERROR_UNSUPPORTED_IMPLEMENTATION:   "unsupported implementation",
	pb.OpenSSLConfigurationError_OPENSSLCONFIGURATIONERROR_UNSUPPORTED_PROTOCOL_VERSION: "invalid TLS version",
	pb.OpenSSLConfigurationError_OPENSSLCONFIGURATIONERROR_EMPTY:                        "empty configuration",
	pb.OpenSSLConfigurationError_OPENSSLCONFIGURATIONERROR_INVALID_CASE:                 "invalid oneof case",
	pb.OpenSSLConfigurationError_OPENSSLCONFIGURATIONERROR_INVALID:                      "invalid OpenSSL configuration",
}

// newOpenSSLConfigurationError creates a OpenSSLConfigurationError from an error code.
func newOpenSSLConfigurationError(code pb.OpenSSLConfigurationError) *OpenSSLConfigurationError {
	var msg string
	if val, ok := openSSLConfigurationErrorMap[code]; ok {
		msg = val
	} else {
		msg = fmt.Sprintf("unknown OpenSSL configuration error code %d", int32(code))
	}
	return &OpenSSLConfigurationError{
		BaseError{
			msg:  msg,
			code: int32(code),
		},
	}
}

// OpenSSLClientConfigurationError defines an error that may occur when a
// protobuf configuration using the OpenSSL implementation in client mode
// is malformed.
type OpenSSLClientConfigurationError struct {
	BaseError
}

// openSSLClientConfigurationErrorMap is a map code -> string for OpenSSL client configuration errors.
var openSSLClientConfigurationErrorMap = map[pb.OpenSSLClientConfigurationError]string{
	pb.OpenSSLClientConfigurationError_OPENSSLCLIENTCONFIGURATIONERROR_EMPTY:          "empty configuration",
	pb.OpenSSLClientConfigurationError_OPENSSLCLIENTCONFIGURATIONERROR_CERTIFICATE:    "certificate error",
	pb.OpenSSLClientConfigurationError_OPENSSLCLIENTCONFIGURATIONERROR_SSL_CTX_FAILED: "SSL_CTX* creation failed",
	pb.OpenSSLClientConfigurationError_OPENSSLCLIENTCONFIGURATIONERROR_KEM:            "KEM error",
	pb.OpenSSLClientConfigurationError_OPENSSLCLIENTCONFIGURATIONERROR_FLAGS:          "flags error",
	pb.OpenSSLClientConfigurationError_OPENSSLCLIENTCONFIGURATIONERROR_SSL_FAILED:     "SSL* creation failed",
	pb.OpenSSLClientConfigurationError_OPENSSLCLIENTCONFIGURATIONERROR_BIO_FAILED:     "BIO* creation failed",
}

// newOpenSSLClientConfigurationError creates a OpenSSLClientConfigurationError from an error code.
func newOpenSSLClientConfigurationError(code pb.OpenSSLClientConfigurationError) *OpenSSLClientConfigurationError {
	var msg string
	if val, ok := openSSLClientConfigurationErrorMap[code]; ok {
		msg = val
	} else {
		msg = fmt.Sprintf("unknown OpenSSL client configuration error code %d", int32(code))
	}
	return &OpenSSLClientConfigurationError{
		BaseError{
			msg:  msg,
			code: int32(code),
		},
	}
}

// OpenSSLServerConfigurationError defines an error that may occur when a
// protobuf configuration using the OpenSSL implementation in server mode
// is malformed.
type OpenSSLServerConfigurationError struct {
	BaseError
}

// openSSLServerConfigurationErrorMap is a map code -> string for OpenSSL server configuration errors.
var openSSLServerConfigurationErrorMap = map[pb.OpenSSLServerConfigurationError]string{
	pb.OpenSSLServerConfigurationError_OPENSSLSERVERCONFIGURATIONERROR_EMPTY:          "empty configuration",
	pb.OpenSSLServerConfigurationError_OPENSSLSERVERCONFIGURATIONERROR_CERTIFICATE:    "certificate error",
	pb.OpenSSLServerConfigurationError_OPENSSLSERVERCONFIGURATIONERROR_SSL_CTX_FAILED: "SSL_CTX* creation failed",
	pb.OpenSSLServerConfigurationError_OPENSSLSERVERCONFIGURATIONERROR_KEM:            "KEM error",
	pb.OpenSSLServerConfigurationError_OPENSSLSERVERCONFIGURATIONERROR_FLAGS:          "flags error",
	pb.OpenSSLServerConfigurationError_OPENSSLSERVERCONFIGURATIONERROR_PRIVATE_KEY:    "private key error",
	pb.OpenSSLServerConfigurationError_OPENSSLSERVERCONFIGURATIONERROR_SSL_FAILED:     "SSL* creation failed",
	pb.OpenSSLServerConfigurationError_OPENSSLSERVERCONFIGURATIONERROR_BIO_FAILED:     "BIO* creation failed",
}

// newOpenSSLServerConfigurationError creates a OpenSSLServerConfigurationError from an error code.
func newOpenSSLServerConfigurationError(code pb.OpenSSLServerConfigurationError) *OpenSSLServerConfigurationError {
	var msg string
	if val, ok := openSSLServerConfigurationErrorMap[code]; ok {
		msg = val
	} else {
		msg = fmt.Sprintf("unknown OpenSSL server configuration error code %d", int32(code))
	}
	return &OpenSSLServerConfigurationError{
		BaseError{
			msg:  msg,
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
func newCertificateError(code pb.CertificateError) *CertificateError {
	var msg string
	if val, ok := certificateErrorMap[code]; ok {
		msg = val
	} else {
		msg = fmt.Sprintf("unknown certificate error code %d", int32(code))
	}
	return &CertificateError{
		BaseError{
			msg:  msg,
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
func newPrivateKeyError(code pb.PrivateKeyError) *PrivateKeyError {
	var msg string
	if val, ok := privateKeyErrorMap[code]; ok {
		msg = val
	} else {
		msg = fmt.Sprintf("unknown private key error code %d", int32(code))
	}
	return &PrivateKeyError{
		BaseError{
			msg:  msg,
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
	pb.ProtobufError_PROTOBUFERROR_EMPTY:        "empty message",
	pb.ProtobufError_PROTOBUFERROR_TOO_BIG:      "message too large",
	pb.ProtobufError_PROTOBUFERROR_PARSE_FAILED: "message parsing failed",
	pb.ProtobufError_PROTOBUFERROR_NULLPTR:      "null pointer",
}

// newProtobufError creates a ProtobufError from an error code.
func newProtobufError(code pb.ProtobufError) *ProtobufError {
	var msg string
	if val, ok := protobufErrorMap[code]; ok {
		msg = val
	} else {
		msg = fmt.Sprintf("unknown protobuf error code %d", int32(code))
	}
	return &ProtobufError{
		BaseError{
			msg:  msg,
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
func newASN1Error(code pb.ASN1Error) *ASN1Error {
	var msg string
	if val, ok := asn1ErrorMap[code]; ok {
		msg = val
	} else {
		msg = fmt.Sprintf("unknown ASN.1 error code %d", int32(code))
	}
	return &ASN1Error{
		BaseError{
			msg:  msg,
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
}

// newDataSourceError creates a DataSourceError from an error code.
func newDataSourceError(code pb.DataSourceError) *DataSourceError {
	var msg string
	if val, ok := dataSourceErrorMap[code]; ok {
		msg = val
	} else {
		msg = fmt.Sprintf("unknown DataSource error code %d", int32(code))
	}
	return &DataSourceError{
		BaseError{
			msg:  msg,
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
func newKEMError(code pb.KEMError) *KEMError {
	var msg string
	if val, ok := kEMErrorMap[code]; ok {
		msg = val
	} else {
		msg = fmt.Sprintf("unknown KEM error code %d", int32(code))
	}
	return &KEMError{
		BaseError{
			msg:  msg,
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
func newSystemError(code pb.SystemError) *SystemError {
	var msg string
	if val, ok := systemErrorMap[code]; ok {
		msg = val
	} else {
		msg = fmt.Sprintf("unknown system error code %d", int32(code))
	}
	return &SystemError{
		BaseError{
			msg:  msg,
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
func newSocketError(code pb.SocketError) *SocketError {
	var msg string
	if val, ok := socketErrorMap[code]; ok {
		msg = val
	} else {
		msg = fmt.Sprintf("unknown socket error code %d", int32(code))
	}
	return &SocketError{
		BaseError{
			msg:  msg,
			code: int32(code),
		},
	}
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
