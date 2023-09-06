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

import pysandwich.proto.tunnel_pb2 as SandwichTunnelProto
from pysandwich.error_base import SandwichException
from pysandwich.generated_error_codes import *  # noqa: F403,F401


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
