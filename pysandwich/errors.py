# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

"""Sandwich Error API.

This API provides error types by inheriting the `Exception` class.
Error codes come from the `.proto` file.

All sandwich exceptions are based on `SandwichException`.

This file defines the following exception families:
    * `SandwichGlobalException`: exceptions that can happen all across the
      library.
    * `HandshakeException`: exceptions happening during the handshake stage
      (from `Tunnel.handshake()`).
    * `HandshakeError`: exceptions relating to errors encountered by the implementation
    * `RecordPlaneException`: exceptions happening in `Tunnel.read` or
      `Tunnel.write`.
    * `IOException`: exceptions happening in the I/O interface (see `io.py`).
All exceptions are based on the error codes defined by the following protobuf:
    * `errors.proto`: `SandwichGlobalException`
    * `tunnel.proto`: `HandshakeException` and `RecordPlaneException`
    * `io.proto`: `IOException`.

`SandwichException` exposes a `code` method to get the corresponding error code.
This error code is compatible with the C++ library.

Author: thb-sb
"""

import pysandwich.proto.errors_pb2 as SandwichErrorProto
import pysandwich.proto.tunnel_pb2 as SandwichTunnelProto


class SandwichException(Exception):
    """Base class for Sandwich exceptions.

    This class wraps all errors defined in the `errors.proto` file, as well
    as the ones defined in `tunnel.proto` and `io.proto`.

    A Sandwich error lies on an error code.

    Attributes:
        _code: The error code.
    """

    def __init__(
        self,
        code: int,
        kind: SandwichErrorProto.ErrorKind = None,
        msg=None,
        *kargs,
        **kwargs,
    ):
        """Constructs a Sandwich exception from an error code.

        Arguments:
            code:
                Error code.
        """
        if not msg:
            super().__init__(self._resolve_error_string(code), *kwargs, **kwargs)
        else:
            super().__init__(msg.decode("ascii"), *kwargs, **kwargs)
        self._kind = kind
        self._code = code

    @property
    def kind(self) -> SandwichErrorProto.ErrorKind:
        """Returns the error kind.

        Returns:
            The error kind.
        """
        return self._kind

    @property
    def code(self) -> int:
        """Returns the error code.

        Returns:
            The error code.
        """
        return self._code

    def _resolve_error_string(self, code):
        errors_map = None
        try:
            errors_map = self._ERRORS_MAP
        except AttributeError:
            pass
        if (errors_map is not None) and (code in errors_map):
            return errors_map[code]["msg"]
        return f"Unknown error code {code}"

    @classmethod
    def new(
        cls,
        code: int,
        kind: SandwichErrorProto.ErrorKind = None,
        msg: str = None,
    ) -> "SandwichException":
        """Constructs an exception from an error code.

        Returns:
            The most appropriate exception object.
        """
        if target_cls := _ERROR_KIND_MAP.get(kind):
            return target_cls(code, kind, msg)
        errors_map = cls._ERRORS_MAP
        if (
            (errors_map is not None)
            and (code in errors_map)
            and ((target_cls := errors_map[code].get("cls")) is not None)
        ):
            return target_cls()(kind=kind)
        return SandwichException(code=code, kind=kind, msg=msg)


class APIError(SandwichException):
    """API errors.
    This exception defines the first-class API errors, such as Context errors,
    Socket errors and Tunnel errors.
    """

    _ERRORS_MAP = {
        SandwichErrorProto.APIERROR_CONFIGURATION: {
            "msg": "invalid configuration",
        },
        SandwichErrorProto.APIERROR_SOCKET: {
            "msg": "socket error",
        },
        SandwichErrorProto.APIERROR_TUNNEL: {
            "msg": "tunnel error",
        },
    }


class ConfigurationError(SandwichException):
    """Configuration errors.
    This exception may occur when a protobuf configuration is malformed.
    """

    _ERRORS_MAP = {
        SandwichErrorProto.CONFIGURATIONERROR_INVALID_IMPLEMENTATION: {
            "msg": "invalid implementation",
        },
        SandwichErrorProto.CONFIGURATIONERROR_UNSUPPORTED_IMPLEMENTATION: {
            "msg": "unsupported implementation",
        },
        SandwichErrorProto.CONFIGURATIONERROR_INVALID: {
            "msg": "invalid configuration",
        },
    }


class TLSConfigurationError(SandwichException):
    """TLS configuration errors.
    This exception may occur when a protobuf configuration using the TLS protocol
    is malformed.
    """

    _ERRORS_MAP = {
        SandwichErrorProto.TLSCONFIGURATIONERROR_UNSUPPORTED_IMPLEMENTATION: {
            "msg": "unsupported implementation",
        },
        SandwichErrorProto.TLSCONFIGURATIONERROR_UNSUPPORTED_PROTOCOL_VERSION: {
            "msg": "unsupported TLS version",
        },
        SandwichErrorProto.TLSCONFIGURATIONERROR_EMPTY: {
            "msg": "empty configuration",
        },
        SandwichErrorProto.TLSCONFIGURATIONERROR_INVALID_CASE: {
            "msg": "invalid oneof case",
        },
        SandwichErrorProto.TLSCONFIGURATIONERROR_PRIVATE_KEY_INCONSISTENT_WITH_CERTIFICATE: {
            "msg": "private key is not consistent with the provided certificate",
        },
        SandwichErrorProto.TLSCONFIGURATIONERROR_INVALID: {
            "msg": "invalid TLS configuration",
        },
    }


class CertificateError(SandwichException):
    """Certificate errors.

    This exception may occur when a configuration supplies a certificate
    that is malformed.
    """

    _ERRORS_MAP = {
        SandwichErrorProto.CERTIFICATEERROR_MALFORMED: {
            "msg": "certificate malformed",
        },
        SandwichErrorProto.CERTIFICATEERROR_EXPIRED: {
            "msg": "certificate expired",
        },
        SandwichErrorProto.CERTIFICATEERROR_NOT_FOUND: {
            "msg": "certificate not found on disk",
        },
        SandwichErrorProto.CERTIFICATEERROR_UNKNOWN: {
            "msg": "unknown error",
        },
        SandwichErrorProto.CERTIFICATEERROR_UNSUPPORTED: {
            "msg": "certificate not supported by underlying implementation",
        },
    }


class PrivateKeyError(SandwichException):
    """Private key errors.

    This exception may occur when a configuration supplies a private key
    that is malformed.
    """

    _ERRORS_MAP = {
        SandwichErrorProto.PRIVATEKEYERROR_MALFORMED: {
            "msg": "private key malformed",
        },
        SandwichErrorProto.PRIVATEKEYERROR_NOT_FOUND: {
            "msg": "private key not found on disk",
        },
        SandwichErrorProto.PRIVATEKEYERROR_UNKNOWN: {
            "msg": "unknown error",
        },
        SandwichErrorProto.PRIVATEKEYERROR_UNSUPPORTED: {
            "msg": "private key not supported by underlying implementation",
        },
        SandwichErrorProto.PRIVATEKEYERROR_NOT_SERVER: {
            "msg": "not a server configuration",
        },
    }


class ProtobufError(SandwichException):
    """Protobuf errors.

    This exception may occur when the protobuf message is malformed.
    """

    _ERRORS_MAP = {
        SandwichErrorProto.PROTOBUFERROR_EMPTY: {
            "msg": "empty message",
        },
        SandwichErrorProto.PROTOBUFERROR_TOO_BIG: {
            "msg": "message too large",
        },
        SandwichErrorProto.PROTOBUFERROR_PARSE_FAILED: {
            "msg": "message parsing failed",
        },
        SandwichErrorProto.PROTOBUFERROR_NULLPTR: {
            "msg": "null pointer",
        },
        SandwichErrorProto.PROTOBUFERROR_INVALID_ARGUMENT: {
            "msg": "invalid argument",
        },
    }


class ASN1Error(SandwichException):
    """ASN.1 errors.

    This exception may occur when a malformed ASN.1 document is provided.
    """

    _ERRORS_MAP = {
        SandwichErrorProto.ASN1ERROR_INVALID_FORMAT: {
            "msg": "invalid format",
        },
    }


class ALPNError(SandwichException):
    """ALPN errors.

    This exception may occur when an ALPN protocol is provided.
    """

    _ERRORS_MAP = {
        SandwichErrorProto.ALPNERROR_LENGTH_ERROR: {
            "msg": "protocol length is longer than 255 bytes",
        },
        SandwichErrorProto.ALPNERROR_INVALID_STRING: {
            "msg": "protocol contains NULL byte or invalid string",
        },
    }


class DataSourceError(SandwichException):
    """DataSource errors.

    This exception may occur when a configuration provided a malformed
    DataSource.
    """

    _ERRORS_MAP = (
        {
            SandwichErrorProto.DATASOURCEERROR_EMPTY: {
                "msg": "empty DataSource",
            },
            SandwichErrorProto.DATASOURCEERROR_INVALID_CASE: {
                "msg": "invalid oneof case",
            },
            SandwichErrorProto.DATASOURCEERROR_NOT_FOUND: {
                "msg": "data not found on local filesystem",
            },
        },
    )


class KEMError(SandwichException):
    """KEM errors.

    This exception may occur when a KEM is invalid or unsupported.
    """

    _ERRORS_MAP = {
        SandwichErrorProto.KEMERROR_INVALID: {
            "msg": "invalid or unsupported KEM",
        },
        SandwichErrorProto.KEMERROR_TOO_MANY: {
            "msg": "too many KEMs",
        },
    }


class SystemError(SandwichException):
    """System errors.

    This exception may occur when a system error is encountered, such as
    a memory allocation failure.
    """

    _ERRORS_MAP = {
        SandwichErrorProto.SYSTEMERROR_MEMORY: {
            "msg": "memory error",
        },
        SandwichErrorProto.SYSTEMERROR_INTEGER_OVERFLOW: {
            "msg": "integer overflow",
        },
    }


class SocketError(SandwichException):
    """Socket errors.

    This exception may occur in the I/O socket interface.
    """

    _ERRORS_MAP = {
        SandwichErrorProto.SOCKETERROR_BAD_FD: {
            "msg": "bad file descriptor",
        },
        SandwichErrorProto.SOCKETERROR_CREATION_FAILED: {
            "msg": "socket creation failed",
        },
        SandwichErrorProto.SOCKETERROR_BAD_NETADDR: {
            "msg": "bad network address",
        },
        SandwichErrorProto.SOCKETERROR_NETADDR_UNKNOWN: {
            "msg": "network address resolution failed",
        },
        SandwichErrorProto.SOCKETERROR_FSTAT_FAILED: {
            "msg": "fstat failed",
        },
        SandwichErrorProto.SOCKETERROR_NOT_SOCK: {
            "msg": "not a socket",
        },
        SandwichErrorProto.SOCKETERROR_GETSOCKNAME_FAILED: {
            "msg": "getsockname failed",
        },
        SandwichErrorProto.SOCKETERROR_SETSOCKOPT_FAILED: {
            "msg": "setsockopt failed",
        },
        SandwichErrorProto.SOCKETERROR_INVALID_AI_FAMILY: {
            "msg": "invalid AI family",
        },
    }


class HandshakeError(SandwichException):
    """Map from the protobuf enum 'HandshakeState" to error string."""

    _ERRORS_MAP = {
        SandwichErrorProto.HANDSHAKEERROR_INVALID_SERVER_NAME: {
            "msg": "invalid server name",
        },
        SandwichErrorProto.HANDSHAKEERROR_CERTIFICATE_VERIFICATION_FAILED: {
            "msg": "certificate verification failed"
        },
        SandwichErrorProto.HANDSHAKEERROR_CERTIFICATE_EXPIRED: {
            "msg": "certificate has expired",
        },
        SandwichErrorProto.HANDSHAKEERROR_CERTIFICATE_REVOKED: {
            "msg": "certificate is revoked",
        },
        SandwichErrorProto.HANDSHAKEERROR_INVALID_CERTIFICATE: {
            "msg": "certificate is invalid",
        },
        SandwichErrorProto.HANDSHAKEERROR_CERTIFICATE_SIGNATURE_VERIFICATION_FAILED: {
            "msg": "certificate signature verification failed",
        },
        SandwichErrorProto.HANDSHAKEERROR_UNKNOWN_ERROR: {
            "msg": "unknown handshake error",
        },
    }


_ERROR_KIND_MAP = {
    SandwichErrorProto.ERRORKIND_API: APIError,
    SandwichErrorProto.ERRORKIND_CONFIGURATION: ConfigurationError,
    SandwichErrorProto.ERRORKIND_TLS_CONFIGURATION: TLSConfigurationError,
    SandwichErrorProto.ERRORKIND_CERTIFICATE: CertificateError,
    SandwichErrorProto.ERRORKIND_SYSTEM: SystemError,
    SandwichErrorProto.ERRORKIND_SOCKET: SocketError,
    SandwichErrorProto.ERRORKIND_PROTOBUF: ProtobufError,
    SandwichErrorProto.ERRORKIND_PRIVATE_KEY: PrivateKeyError,
    SandwichErrorProto.ERRORKIND_ASN1: ASN1Error,
    SandwichErrorProto.ERRORKIND_ALPN: ALPNError,
    SandwichErrorProto.ERRORKIND_DATA_SOURCE: DataSourceError,
    SandwichErrorProto.ERRORKIND_KEM: KEMError,
    SandwichErrorProto.ERRORKIND_HANDSHAKE: HandshakeError,
}


class HandshakeException(SandwichException):
    """Exception base class for the handshake state.
    This exception handles the following cases:
        * HANDSHAKESTATE_IN_PROGRESS
        * HANDSHAKESTATE_WANT_READ
        * HANDSHAKESTATE_WANT_WRITE
        * HANDSHAKESTATE_ERROR
    """

    """The no-error error."""
    ERROR_OK = SandwichTunnelProto.HANDSHAKESTATE_DONE

    """Map from the protobuf enum 'HandshakeState" to error string."""
    _ERRORS_MAP = {
        SandwichTunnelProto.HANDSHAKESTATE_IN_PROGRESS: {
            "msg": "The operation is still in progress",
            "cls": lambda: HandshakeInProgressException,
        },
        SandwichTunnelProto.HANDSHAKESTATE_WANT_READ: {
            "msg": (
                "The implementation wants to read from the wire, "
                "but the underlying I/O is non-blocking"
            ),
            "cls": lambda: HandshakeWantReadException,
        },
        SandwichTunnelProto.HANDSHAKESTATE_WANT_WRITE: {
            "msg": (
                "The implementation wants to write data to the wire, "
                "but the underlying I/O is non-blocking"
            ),
            "cls": lambda: HandshakeWantWriteException,
        },
        SandwichTunnelProto.HANDSHAKESTATE_ERROR: {
            "msg": "A critical error occurred",
            "cls": lambda: HandshakeErrorStateException,
        },
    }


class HandshakeInProgressException(HandshakeException):
    """Handshake in progress"""

    def __init__(self, *kargs, **kwargs):
        super().__init__(
            code=SandwichTunnelProto.HANDSHAKESTATE_IN_PROGRESS, *kargs, **kwargs
        )


class HandshakeWantReadException(HandshakeException):
    """Handshake wants to read"""

    def __init__(self, *kargs, **kwargs):
        super().__init__(
            code=SandwichTunnelProto.HANDSHAKESTATE_WANT_READ, *kargs, **kwargs
        )


class HandshakeWantWriteException(HandshakeException):
    """Handshake wants to write"""

    def __init__(self, *kargs, **kwargs):
        super().__init__(
            code=SandwichTunnelProto.HANDSHAKESTATE_WANT_WRITE, *kargs, **kwargs
        )


class HandshakeErrorStateException(HandshakeException):
    """Handshake general error"""

    def __init__(self, *kargs, **kwargs):
        super().__init__(
            code=SandwichTunnelProto.HANDSHAKESTATE_ERROR, *kargs, **kwargs
        )


class RecordPlaneException(SandwichException):
    """Exception base class for the record plane.
    Errors are defined in the protobuf, `enum RecordError`.
    This exception handles the following cases:
        * HANDSHAKESTATE_IN_PROGRESS
        * HANDSHAKESTATE_WANT_READ
        * HANDSHAKESTATE_WANT_WRITE
        * HANDSHAKESTATE_ERROR
    """

    """The no-error error."""
    ERROR_OK = SandwichTunnelProto.RECORDERROR_OK

    """Map from the protobuf enum 'RecordError" to error string and subclass exception."""
    _ERRORS_MAP = {
        SandwichTunnelProto.RECORDERROR_WANT_READ: {
            "msg": (
                "Tunnel wants to read data, but the underlying "
                "I/O interface is non-blocking."
            ),
            "cls": lambda: RecordPlaneWantReadException,
        },
        SandwichTunnelProto.RECORDERROR_WANT_WRITE: {
            "msg": (
                "Tunnel wants to write data, but the underlying "
                "I/O interface is non-blocking."
            ),
            "cls": lambda: RecordPlaneWantWriteException,
        },
        SandwichTunnelProto.RECORDERROR_BEING_SHUTDOWN: {
            "msg": "Tunnel is being closed",
            "cls": lambda: RecordPlaneBeingShutdownException,
        },
        SandwichTunnelProto.RECORDERROR_CLOSED: {
            "msg": "Tunnel is closed.",
            "cls": lambda: RecordPlaneClosedException,
        },
        SandwichTunnelProto.RECORDERROR_UNKNOWN: {
            "msg": "An unknown error occurred.",
            "cls": lambda: RecordPlaneUnknownErrorException,
        },
    }


class RecordPlaneWantReadException(RecordPlaneException):
    """Record plane wants to read."""

    def __init__(self, *kargs, **kwargs):
        super().__init__(
            code=SandwichTunnelProto.RECORDERROR_WANT_READ, *kargs, **kwargs
        )


class RecordPlaneWantWriteException(RecordPlaneException):
    """Record plane wants to write."""

    def __init__(self, *kargs, **kwargs):
        super().__init__(
            code=SandwichTunnelProto.RECORDERROR_WANT_WRITE, *kargs, **kwargs
        )


class RecordPlaneBeingShutdownException(RecordPlaneException):
    """Record plane is being closed."""

    def __init__(self, *kargs, **kwargs):
        super().__init__(
            code=SandwichTunnelProto.RECORDERROR_BEING_SHUTDOWN, *kargs, **kwargs
        )


class RecordPlaneClosedException(RecordPlaneException):
    """Record plane is closed."""

    def __init__(self, *kargs, **kwargs):
        super().__init__(code=SandwichTunnelProto.RECORDERROR_CLOSED, *kargs, **kwargs)


class RecordPlaneUnknownErrorException(RecordPlaneException):
    """An unknown error occurred."""

    def __init__(self, *kargs, **kwargs):
        super().__init__(code=SandwichTunnelProto.RECORDERROR_UNKNOWN, *kargs, **kwargs)
