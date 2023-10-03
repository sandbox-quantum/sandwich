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
      case pb.ErrorKind_ERRORKIND_PROTOBUF:
        e = newProtobufError(pb.ProtobufError(chain.code), msg)
      case pb.ErrorKind_ERRORKIND_TLS_CONFIGURATION:
        e = newTLSConfigurationError(pb.TLSConfigurationError(chain.code), msg)
      case pb.ErrorKind_ERRORKIND_CERTIFICATE:
        e = newCertificateError(pb.CertificateError(chain.code), msg)
      case pb.ErrorKind_ERRORKIND_PRIVATE_KEY:
        e = newPrivateKeyError(pb.PrivateKeyError(chain.code), msg)
      case pb.ErrorKind_ERRORKIND_ASN1:
        e = newASN1Error(pb.ASN1Error(chain.code), msg)
      case pb.ErrorKind_ERRORKIND_ALPN:
        e = newALPNError(pb.ALPNError(chain.code), msg)
      case pb.ErrorKind_ERRORKIND_DATA_SOURCE:
        e = newDataSourceError(pb.DataSourceError(chain.code), msg)
      case pb.ErrorKind_ERRORKIND_KEM:
        e = newKEMError(pb.KEMError(chain.code), msg)
      case pb.ErrorKind_ERRORKIND_SYSTEM:
        e = newSystemError(pb.SystemError(chain.code), msg)
      case pb.ErrorKind_ERRORKIND_SOCKET:
        e = newSocketError(pb.SocketError(chain.code), msg)
      case pb.ErrorKind_ERRORKIND_HANDSHAKE:
        e = newHandshakeError(pb.HandshakeError(chain.code), msg)
      case pb.ErrorKind_ERRORKIND_TUNNEL:
        e = newTunnelError(pb.TunnelError(chain.code), msg)
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

// errorKindMap is a map code -> string for error kinds, defined in
// `errors.proto`, enum `ErrorKind`.
var errorKindMap = map[pb.ErrorKind]string{
  pb.ErrorKind_ERRORKIND_API: `API errors.
 The following errors can occur during a call to the Context API.`,
  pb.ErrorKind_ERRORKIND_CONFIGURATION: `Errors regarding configurations.`,
  pb.ErrorKind_ERRORKIND_PROTOBUF: `Errors regarding protobuf.`,
  pb.ErrorKind_ERRORKIND_TLS_CONFIGURATION: `Errors regarding TLS configurations.`,
  pb.ErrorKind_ERRORKIND_CERTIFICATE: `Certificate errors.`,
  pb.ErrorKind_ERRORKIND_PRIVATE_KEY: `Private key errors.`,
  pb.ErrorKind_ERRORKIND_ASN1: `ASN.1 errors.`,
  pb.ErrorKind_ERRORKIND_ALPN: `ALPN errors.`,
  pb.ErrorKind_ERRORKIND_DATA_SOURCE: `DataSource errors.`,
  pb.ErrorKind_ERRORKIND_KEM: `KEM errors.`,
  pb.ErrorKind_ERRORKIND_SYSTEM: `System errors.`,
  pb.ErrorKind_ERRORKIND_SOCKET: `Socket errors.
 These errors are used in io/socket.`,
  pb.ErrorKind_ERRORKIND_HANDSHAKE: ``,
  pb.ErrorKind_ERRORKIND_TUNNEL: `Tunnel error.`,
}


type APIError struct {
  BaseError
}

var errAPIErrorMap = map[pb.APIError]string{
  pb.APIError_APIERROR_CONFIGURATION: `Configuration error.`,
  pb.APIError_APIERROR_SOCKET: `Socket error.`,
  pb.APIError_APIERROR_TUNNEL: `Tunnel error.`,
}

func newAPIError(code pb.APIError, msg string) *APIError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := errAPIErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf(`unknown 'API errors.
 The following errors can occur during a call to the Context API.' error code %d`, int32(code))
	}
	return &APIError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}
type ConfigurationError struct {
  BaseError
}

var errConfigurationErrorMap = map[pb.ConfigurationError]string{
  pb.ConfigurationError_CONFIGURATIONERROR_INVALID_IMPLEMENTATION: `The selected implementation is invalid.`,
  pb.ConfigurationError_CONFIGURATIONERROR_UNSUPPORTED_IMPLEMENTATION: `The selected implementation isn&#39;t supported.`,
  pb.ConfigurationError_CONFIGURATIONERROR_INVALID: `Invalid configuration.`,
  pb.ConfigurationError_CONFIGURATIONERROR_INVALID_LISTENER: `Invalid Listener configuration.`,
}

func newConfigurationError(code pb.ConfigurationError, msg string) *ConfigurationError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := errConfigurationErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf(`unknown 'Errors regarding configurations.' error code %d`, int32(code))
	}
	return &ConfigurationError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}
type ProtobufError struct {
  BaseError
}

var errProtobufErrorMap = map[pb.ProtobufError]string{
  pb.ProtobufError_PROTOBUFERROR_EMPTY: `The protobuf message is empty.`,
  pb.ProtobufError_PROTOBUFERROR_TOO_BIG: `The protobuf message is too large.`,
  pb.ProtobufError_PROTOBUFERROR_PARSE_FAILED: `Failed to parse the protobuf message.`,
  pb.ProtobufError_PROTOBUFERROR_NULLPTR: `A null pointer was supplied.
 This error is thrown by &#39;sandwich_context_new&#39;, when the given source
 buffer is a null pointer.`,
  pb.ProtobufError_PROTOBUFERROR_INVALID_ARGUMENT: `/ An invalid value was given.`,
}

func newProtobufError(code pb.ProtobufError, msg string) *ProtobufError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := errProtobufErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf(`unknown 'Errors regarding protobuf.' error code %d`, int32(code))
	}
	return &ProtobufError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}
type TLSConfigurationError struct {
  BaseError
}

var errTLSConfigurationErrorMap = map[pb.TLSConfigurationError]string{
  pb.TLSConfigurationError_TLSCONFIGURATIONERROR_UNSUPPORTED_IMPLEMENTATION: `The selected implementation isn&#39;t supported.`,
  pb.TLSConfigurationError_TLSCONFIGURATIONERROR_INVALID_CASE: `The configuration case (client/server) isn&#39;t valid.`,
  pb.TLSConfigurationError_TLSCONFIGURATIONERROR_EMPTY: `The configuration is empty.`,
  pb.TLSConfigurationError_TLSCONFIGURATIONERROR_UNSUPPORTED_PROTOCOL_VERSION: `Unsupported protocol version error.`,
  pb.TLSConfigurationError_TLSCONFIGURATIONERROR_PRIVATE_KEY_INCONSISTENT_WITH_CERTIFICATE: `/ Inconsistency between a private key and the corresponding certificate.`,
  pb.TLSConfigurationError_TLSCONFIGURATIONERROR_INVALID: `Invalid configuration.`,
}

func newTLSConfigurationError(code pb.TLSConfigurationError, msg string) *TLSConfigurationError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := errTLSConfigurationErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf(`unknown 'Errors regarding TLS configurations.' error code %d`, int32(code))
	}
	return &TLSConfigurationError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}
type CertificateError struct {
  BaseError
}

var errCertificateErrorMap = map[pb.CertificateError]string{
  pb.CertificateError_CERTIFICATEERROR_MALFORMED: `Malformed certificate.`,
  pb.CertificateError_CERTIFICATEERROR_EXPIRED: `Expired certificate.`,
  pb.CertificateError_CERTIFICATEERROR_NOT_FOUND: `Certificate not found.`,
  pb.CertificateError_CERTIFICATEERROR_UNKNOWN: `Unknown error. Can wrap a SystemError.`,
  pb.CertificateError_CERTIFICATEERROR_UNSUPPORTED: `Certificate not supported by the underlying implementation.`,
}

func newCertificateError(code pb.CertificateError, msg string) *CertificateError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := errCertificateErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf(`unknown 'Certificate errors.' error code %d`, int32(code))
	}
	return &CertificateError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}
type PrivateKeyError struct {
  BaseError
}

var errPrivateKeyErrorMap = map[pb.PrivateKeyError]string{
  pb.PrivateKeyError_PRIVATEKEYERROR_MALFORMED: `Malformed private key.`,
  pb.PrivateKeyError_PRIVATEKEYERROR_NOT_FOUND: `Private key not found.`,
  pb.PrivateKeyError_PRIVATEKEYERROR_UNKNOWN: `Unknown error. Can wrap a SystemError.`,
  pb.PrivateKeyError_PRIVATEKEYERROR_UNSUPPORTED: `Certificate not supported by the underlying implementation.`,
  pb.PrivateKeyError_PRIVATEKEYERROR_NOT_SERVER: `Not a server configuration.`,
}

func newPrivateKeyError(code pb.PrivateKeyError, msg string) *PrivateKeyError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := errPrivateKeyErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf(`unknown 'Private key errors.' error code %d`, int32(code))
	}
	return &PrivateKeyError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}
type ASN1Error struct {
  BaseError
}

var errASN1ErrorMap = map[pb.ASN1Error]string{
  pb.ASN1Error_ASN1ERROR_INVALID_FORMAT: `Invalid format.`,
  pb.ASN1Error_ASN1ERROR_MALFORMED: `Malformed ASN.1 document.`,
}

func newASN1Error(code pb.ASN1Error, msg string) *ASN1Error {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := errASN1ErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf(`unknown 'ASN.1 errors.' error code %d`, int32(code))
	}
	return &ASN1Error{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}
type ALPNError struct {
  BaseError
}

var errALPNErrorMap = map[pb.ALPNError]string{
  pb.ALPNError_ALPNERROR_LENGTH_ERROR: `Protocol length is longer than 255 bytes.`,
  pb.ALPNError_ALPNERROR_INVALID_STRING: `Protocol contains &#39;\x00&#39; byte or invalid string.`,
}

func newALPNError(code pb.ALPNError, msg string) *ALPNError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := errALPNErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf(`unknown 'ALPN errors.' error code %d`, int32(code))
	}
	return &ALPNError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}
type DataSourceError struct {
  BaseError
}

var errDataSourceErrorMap = map[pb.DataSourceError]string{
  pb.DataSourceError_DATASOURCEERROR_EMPTY: `Empty data source.`,
  pb.DataSourceError_DATASOURCEERROR_INVALID_CASE: `Invalid case for data source.`,
  pb.DataSourceError_DATASOURCEERROR_NOT_FOUND: `Data not found on local filesystem.`,
}

func newDataSourceError(code pb.DataSourceError, msg string) *DataSourceError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := errDataSourceErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf(`unknown 'DataSource errors.' error code %d`, int32(code))
	}
	return &DataSourceError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}
type KEMError struct {
  BaseError
}

var errKEMErrorMap = map[pb.KEMError]string{
  pb.KEMError_KEMERROR_INVALID: `Invalid or unsupported KEM.`,
  pb.KEMError_KEMERROR_TOO_MANY: `Too many KEMs.`,
}

func newKEMError(code pb.KEMError, msg string) *KEMError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := errKEMErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf(`unknown 'KEM errors.' error code %d`, int32(code))
	}
	return &KEMError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}
type SystemError struct {
  BaseError
}

var errSystemErrorMap = map[pb.SystemError]string{
  pb.SystemError_SYSTEMERROR_MEMORY: `Memory error (e.g. allocation failed).`,
  pb.SystemError_SYSTEMERROR_INTEGER_OVERFLOW: `Integer overflow.`,
}

func newSystemError(code pb.SystemError, msg string) *SystemError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := errSystemErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf(`unknown 'System errors.' error code %d`, int32(code))
	}
	return &SystemError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}
type SocketError struct {
  BaseError
}

var errSocketErrorMap = map[pb.SocketError]string{
  pb.SocketError_SOCKETERROR_BAD_FD: `Bad file descriptor.`,
  pb.SocketError_SOCKETERROR_CREATION_FAILED: `Socket creation failed.`,
  pb.SocketError_SOCKETERROR_BAD_NETADDR: `Invalid network address.`,
  pb.SocketError_SOCKETERROR_NETADDR_UNKNOWN: `Failed to resolve network address.`,
  pb.SocketError_SOCKETERROR_FSTAT_FAILED: `Syscall &#39;fstat&#39; failed.`,
  pb.SocketError_SOCKETERROR_NOT_SOCK: `File descriptor is not a socket.`,
  pb.SocketError_SOCKETERROR_GETSOCKNAME_FAILED: `Syscall getsockname failed.`,
  pb.SocketError_SOCKETERROR_SETSOCKOPT_FAILED: `Syscall setsockopt failed.`,
  pb.SocketError_SOCKETERROR_INVALID_AI_FAMILY: `Invalid AI family.`,
}

func newSocketError(code pb.SocketError, msg string) *SocketError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := errSocketErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf(`unknown 'Socket errors.
 These errors are used in io/socket.' error code %d`, int32(code))
	}
	return &SocketError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}
type HandshakeError struct {
  BaseError
}

var errHandshakeErrorMap = map[pb.HandshakeError]string{
  pb.HandshakeError_HANDSHAKEERROR_INVALID_SERVER_NAME: `Invalid Server Name.`,
  pb.HandshakeError_HANDSHAKEERROR_CERTIFICATE_VERIFICATION_FAILED: `Certficate verification failed.`,
  pb.HandshakeError_HANDSHAKEERROR_CERTIFICATE_EXPIRED: `Certificate has expired.`,
  pb.HandshakeError_HANDSHAKEERROR_CERTIFICATE_REVOKED: `Certificate was revoked.`,
  pb.HandshakeError_HANDSHAKEERROR_INVALID_CERTIFICATE: `Invalid Certificate.`,
  pb.HandshakeError_HANDSHAKEERROR_CERTIFICATE_SIGNATURE_VERIFICATION_FAILED: `Signature verification error.`,
  pb.HandshakeError_HANDSHAKEERROR_UNKNOWN_ERROR: `Unknown handshake error.`,
}

func newHandshakeError(code pb.HandshakeError, msg string) *HandshakeError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := errHandshakeErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf(`unknown '' error code %d`, int32(code))
	}
	return &HandshakeError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}
type TunnelError struct {
  BaseError
}

var errTunnelErrorMap = map[pb.TunnelError]string{
  pb.TunnelError_TUNNELERROR_INVALID: `Invalid tunnel configuration.`,
  pb.TunnelError_TUNNELERROR_VERIFIER: `Invalid tunnel verifier.`,
  pb.TunnelError_TUNNELERROR_UNKNOWN: `Unknown error.`,
}

func newTunnelError(code pb.TunnelError, msg string) *TunnelError {
	err_msg := ";"
	if msg != "" {
		err_msg = "; " + msg
	}
	var m string
	if val, ok := errTunnelErrorMap[code]; ok {
		m = val
	} else {
		m = fmt.Sprintf(`unknown 'Tunnel error.' error code %d`, int32(code))
	}
	return &TunnelError{
		BaseError{
			msg:  m + err_msg,
			code: int32(code),
		},
	}
}

