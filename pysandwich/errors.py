# Copyright 2022 SandboxAQ
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Sandwich Error API.

This API provides error types by inheriting the `Exception` class.
Error codes come from the `.proto` file.

All sandwich exceptions are based on `SandwichException`.

This file defines the following exception families:
    * `SandwichGlobalException`: exceptions that can happen all across the
      library.
    * `HandshakeException`: exceptions happening during the handshake stage
      (from `Tunnel.handshake()`).
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

import sys

import proto.errors_pb2 as SandwichErrorProto
import proto.io_pb2 as SandwichIOProto
import proto.tunnel_pb2 as SandwichTunnelProto


class SandwichException(Exception):
    """Base class for Sandwich exceptions.

    This class wraps all errors defined in the `errors.proto` file, as well
    as the ones defined in `tunnel.proto` and `io.proto`.

    A Sandwich error lies on an error code.

    Attributes:
        _code: The error code.
    """

    def __init__(self, code, *kargs, **kwargs):
        """Constructs a Sandwich exception from an error code.

        Arguments:
            code:
                Error code.
        """

        super().__init__(self._resolve_error_string(code), *kwargs, **kwargs)
        self._code = code

    @property
    def code(self):
        """Returns the error code.

        Returns:
            The error code.
        """
        return self._code

    def _resolve_error_string(self, code):
        errors_map = None
        try:
            errors_map = getattr(self, "_ERRORS_MAP")
        except AttributeError as e:
            pass
        if (errors_map != None) and (code in errors_map):
            return errors_map[code]["msg"]
        return f"Unknown error code {code}"

    @classmethod
    def new(cls, code: int) -> "SandwichException":
        """Constructs an exception from an error code.

        Returns:
            The most appropriate exception object.
        """
        errors_map = getattr(cls, "_ERRORS_MAP")
        if (
            (errors_map != None)
            and (code in errors_map)
            and (errors_map[code].get("cls") != None)
        ):
            return errors_map[code]["cls"]()()
        return SandwichException(code)


class SandwichGlobalException(SandwichException):
    """Sandwich global exceptions.

    Global exceptions are defined by the enum `Error` in `errors.proto`.
    They are used all across the library.
    """

    """The no-error error."""
    ERROR_OK = SandwichErrorProto.ERROR_OK

    """Map from the protobuf enum 'Error" to error string."""
    _ERRORS_MAP = {
        SandwichErrorProto.ERROR_OK: {
            "msg": "No error",
            "cls": None,
        },
        SandwichErrorProto.ERROR_INVALID_ARGUMENT: {
            "msg": "Invalid argument",
            "cls": None,
        },
        SandwichErrorProto.ERROR_MEMORY: {
            "msg": "Memory error",
            "cls": None,
        },
        SandwichErrorProto.ERROR_IO: {
            "msg": "I/O error",
            "cls": None,
        },
        SandwichErrorProto.ERROR_UNKNOWN: {
            "msg": "Unknown error",
            "cls": None,
        },
        SandwichErrorProto.ERROR_INVALID_CONFIGURATION: {
            "msg": "Invalid configuration",
            "cls": None,
        },
        SandwichErrorProto.ERROR_UNSUPPORTED_IMPLEMENTATION: {
            "msg": "Unsupported implementation",
            "cls": None,
        },
        SandwichErrorProto.ERROR_UNSUPPORTED_PROTOCOL: {
            "msg": "Unsupported protocol",
            "cls": None,
        },
        SandwichErrorProto.ERROR_IMPLEMENTATION_PROTOCOL_MISMATCH: {
            "msg": "Implementation and protocol mismatch",
            "cls": None,
        },
        SandwichErrorProto.ERROR_PROTOBUF: {
            "msg": "Protobuf serialization or deserialization error",
            "cls": None,
        },
        SandwichErrorProto.ERROR_NETWORK_INVALID_ADDRESS: {
            "msg": "Invalid network address",
            "cls": None,
        },
        SandwichErrorProto.ERROR_NETWORK_INVALID_PORT: {
            "msg": "Invalid network port",
            "cls": None,
        },
        SandwichErrorProto.ERROR_INVALID_CONTEXT: {
            "msg": "Invalid context",
            "cls": None,
        },
        SandwichErrorProto.ERROR_BAD_FD: {
            "msg": "Bad file descriptor",
            "cls": None,
        },
        SandwichErrorProto.ERROR_UNSUPPORTED_TUNNEL_METHOD: {
            "msg": "Unsupported tunnel method",
            "cls": None,
        },
        SandwichErrorProto.ERROR_INTEGER_OVERFLOW: {
            "msg": "Integer overflow",
            "cls": None,
        },
        SandwichErrorProto.ERROR_MEMORY_OVERFLOW: {
            "msg": "Memory overflow",
            "cls": None,
        },
        SandwichErrorProto.ERROR_IMPLEMENTATION: {
            "msg": "Implementation error",
            "cls": None,
        },
        SandwichErrorProto.ERROR_INVALID_TUNNEL: {
            "msg": "Invalid tunnel",
            "cls": None,
        },
        SandwichErrorProto.ERROR_INVALID_KEM: {
            "msg": "Invalid KEM",
            "cls": None,
        },
        SandwichErrorProto.ERROR_TIMEOUT: {
            "msg": "Timeout reached",
            "cls": None,
        },
        SandwichErrorProto.ERROR_NETWORK_ADDRESS_RESOLVE: {
            "msg": "Failed to resolve network address",
            "cls": None,
        },
        SandwichErrorProto.ERROR_NETWORK_CONNECT: {
            "msg": "Failed to connect",
            "cls": None,
        },
        SandwichErrorProto.ERROR_SOCKET_FAILED: {
            "msg": "Failed to create socket",
            "cls": None,
        },
        SandwichErrorProto.ERROR_SOCKET_OPT_FAILED: {
            "msg": "`getsockopt`/`setsockopt` failed",
            "cls": None,
        },
        SandwichErrorProto.ERROR_SOCKET_INVALID_AI_FAMILY: {
            "msg": "Invalid socket AI family",
            "cls": None,
        },
        SandwichErrorProto.ERROR_CONNECTION_REFUSED: {
            "msg": "Connection refused",
            "cls": None,
        },
        SandwichErrorProto.ERROR_NETWORK_UNREACHABLE: {
            "msg": "Network unreachable",
            "cls": None,
        },
        SandwichErrorProto.ERROR_SOCKET_POLL_FAILED: {
            "msg": "Socket poll failed",
            "cls": None,
        },
        SandwichErrorProto.ERROR_INVALID_CERTIFICATE: {
            "msg": "Invalid certificate",
            "cls": None,
        },
        SandwichErrorProto.ERROR_UNSUPPORTED_CERTIFICATE: {
            "msg": "Unsupported certificate",
            "cls": None,
        },
        SandwichErrorProto.ERROR_INVALID_PRIVATE_KEY: {
            "msg": "Invalid private key",
            "cls": None,
        },
        SandwichErrorProto.ERROR_UNSUPPORTED_PRIVATE_KEY: {
            "msg": "Unsupported private key",
            "cls": None,
        },
        SandwichErrorProto.ERROR_UNSUPPORTED_PROTOCOL_VERSION: {
            "msg": "Unsupported protocol version",
            "cls": None,
        },
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
            "msg": "The implementation wants to read from the wire, but the underlying I/O is non-blocking",
            "cls": lambda: HandshakeWantReadException,
        },
        SandwichTunnelProto.HANDSHAKESTATE_WANT_WRITE: {
            "msg": "The implementation wants to write data to the wire, but the underlying I/O is non-blocking",
            "cls": lambda: HandshakeWantWriteException,
        },
        SandwichTunnelProto.HANDSHAKESTATE_ERROR: {
            "msg": "A critical error occurred",
            "cls": lambda: HandshakeErrorException,
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


class HandshakeErrorException(HandshakeException):
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
            "msg": "Tunnel wants to read data, but the underlying I/O interface is non-blocking.",
            "cls": lambda: RecordPlaneWantReadException,
        },
        SandwichTunnelProto.RECORDERROR_WANT_WRITE: {
            "msg": "Tunnel wants to write data, but the underlying I/O interface is non-blocking.",
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


class IOException(SandwichException):
    """Exception base class for I/O interface.

    Errors are defined in the protobuf `io.proto`, `enum IOError`.

    This exception handles the following cases:
        * IOERROR_IN_PROGRESS
        * IOERROR_WOULD_BLOCK
        * IOERROR_REFUSED
        * IOERROR_CLOSED
        * IOERROR_INVALID
        * IOERROR_UNKNOWN
    """

    """The no-error error."""
    ERROR_OK = SandwichIOProto.IOERROR_OK

    """Map from the protobuf enum `IOError` to error string and subclass exception."""
    _ERRORS_MAP = {
        SandwichIOProto.IOERROR_IN_PROGRESS: {
            "msg": "The I/O interface is still connecting to the remote peer",
            "cls": lambda: IOInProgressException,
        },
        SandwichIOProto.IOERROR_WOULD_BLOCK: {
            "msg": "The I/O operation would block, but the I/O interface is non-blocking",
            "cls": lambda: IOWouldBlockException,
        },
        SandwichIOProto.IOERROR_REFUSED: {
            "msg": "The I/O interface has been refused connection",
            "cls": lambda: IORefusedException,
        },
        SandwichIOProto.IOERROR_CLOSED: {
            "msg": "This I/O interface is closed",
            "cls": lambda: IOClosedException,
        },
        SandwichIOProto.IOERROR_INVALID: {
            "msg": "This I/O interface isn't valid",
            "cls": lambda: IOInvalidException,
        },
        SandwichIOProto.IOERROR_UNKNOWN: {
            "msg": "This I/O interface raised an unknown error",
            "cls": lambda: IOUnknownException,
        },
    }


class IOInProgressException(IOException):
    """In progress exception."""

    def __init__(self, *kargs, **kwargs):
        super().__init__(code=SandwichIOProto.IOERROR_IN_PROGRESS, *kargs, **kwargs)


class IOWouldBlockException(IOException):
    """Would block exception."""

    def __init__(self, *kargs, **kwargs):
        super().__init__(code=SandwichIOProto.IOERROR_WOULD_BLOCK, *kargs, **kwargs)


class IORefusedException(IOException):
    """Connection refused exception."""

    def __init__(self, *kargs, **kwargs):
        super().__init__(code=SandwichIOProto.IOERROR_REFUSED, *kargs, **kwargs)


class IOClosedException(IOException):
    """Closed pipe exception."""

    def __init__(self, *kargs, **kwargs):
        super().__init__(code=SandwichIOProto.IOERROR_CLOSED, *kargs, **kwargs)


class IOInvalidException(IOException):
    """Invalid I/O interface exception."""

    def __init__(self, *kargs, **kwargs):
        super().__init__(code=SandwichIOProto.IOERROR_INVALID, *kargs, **kwargs)


class IOUnknownException(IOException):
    """Unknown I/O exception."""

    def __init__(self, *kargs, **kwargs):
        super().__init__(code=SandwichIOProto.IOERROR_UNKNOWN, *kargs, **kwargs)
