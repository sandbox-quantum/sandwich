# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

"""Sandwich I/O API.

This API provides an I/O interface in Python, to use with Sandwich.
It wraps a `struct SandwichIO`.

An I/O interface is an object requiring the following methods:
    * read(n: int) -> bytes
    * write(buf: bytes) -> int

All methods should either return the corresponding value (the read bytes
for `read` and the amount of successfully written bytes for `write`), or
raise an exception of type `IOException`.

The user has to define a class extending `IO`.
An example can be found in `tunnel_test.py`.
"""

import abc
import ctypes

import pysandwich.proto.io_pb2 as SandwichIOProto
import pysandwich.proto.tunnel_pb2 as SandwichTunnelProto
from pysandwich import errors


class IOException(errors.SandwichException):
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
        super().__init__(*kargs, code=SandwichIOProto.IOERROR_IN_PROGRESS, **kwargs)


class IOWouldBlockException(IOException):
    """Would block exception."""

    def __init__(self, *kargs, **kwargs):
        super().__init__(*kargs, code=SandwichIOProto.IOERROR_WOULD_BLOCK, **kwargs)


class IORefusedException(IOException):
    """Connection refused exception."""

    def __init__(self, *kargs, **kwargs):
        super().__init__(*kargs, code=SandwichIOProto.IOERROR_REFUSED, **kwargs)


class IOClosedException(IOException):
    """Closed pipe exception."""

    def __init__(self, *kargs, **kwargs):
        super().__init__(*kargs, code=SandwichIOProto.IOERROR_CLOSED, **kwargs)


class IOInvalidException(IOException):
    """Invalid I/O interface exception."""

    def __init__(self, *kargs, **kwargs):
        super().__init__(*kargs, code=SandwichIOProto.IOERROR_INVALID, **kwargs)


class IOUnknownException(IOException):
    """Unknown I/O exception."""

    def __init__(self, *kargs, **kwargs):
        super().__init__(*kargs, code=SandwichIOProto.IOERROR_UNKNOWN, **kwargs)


class IO(abc.ABC):
    """Abstraction of a `struct SandwichIO` handle.

    The C handle is built by the tunnel, using the methods from this class.
    """

    Error = SandwichIOProto.IOError

    class Settings(ctypes.Structure):
        """The `struct SandwichIO`."""

        # typedef size_t(SandwichIOReadFunction)(void *uarg, void *buf, size_t count,
        # enum SandwichIOError *err);
        _READ_FN_TYPE = ctypes.CFUNCTYPE(
            ctypes.c_size_t,  # Return type
            ctypes.c_void_p,  # *uarg
            ctypes.c_void_p,  # *buf
            ctypes.c_size_t,  # count
            ctypes.POINTER(ctypes.c_int),  # *err
        )

        # typedef size_t(SandwichIOWriteFunction)(void *uarg, const void *buf,
        # size_t count,
        # enum SandwichIOError *err);
        _WRITE_FN_TYPE = ctypes.CFUNCTYPE(
            ctypes.c_size_t,  # Return type
            ctypes.c_void_p,  # *uarg
            ctypes.c_void_p,  # *buf
            ctypes.c_size_t,  # count
            ctypes.POINTER(ctypes.c_int),  # *err
        )

        # typedef enum SandwichIOError(SandwichIOFlushFunction)(void *uarg);
        _FLUSH_FN_TYPE = ctypes.CFUNCTYPE(
            ctypes.c_int,  # Return type
            ctypes.c_void_p,  # *uarg
        )

        _fields_ = [
            (
                "readfn",
                _READ_FN_TYPE,
            ),
            (
                "writefn",
                _WRITE_FN_TYPE,
            ),
            (
                "flushfn",
                _FLUSH_FN_TYPE,
            ),
            (
                "uarg",
                ctypes.c_void_p,
            ),
        ]

    @abc.abstractmethod
    def read(self, n: int) -> bytes:
        """Read function.

        Args:
            n:
                Amount of bytes to read.

        Raises:
            IOException: an error occured during reading

        Returns:
            Bytes successfully read.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def write(self, buf: bytes) -> int:
        """Write function.

        Args:
            buf:
                Buffer to write.

        Raises:
            IOException: an error occured during writing

        Returns:
            Amount of successfully written bytes.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def flush(self):
        """Flush function.

        Raises:
            IOException: an error occured while flushing
        """
        raise NotImplementedError


class OwnedIO(ctypes.Structure):
    """The `struct SandwichIO`."""

    _IO_TYPE = ctypes.POINTER(IO.Settings)

    # void(SandwhichIOOwnedFreeFunction)(struct SandwhichCIOSettings *cio)
    _FREE_PTR_TYPE = ctypes.CFUNCTYPE(
        None, ctypes.POINTER(IO.Settings)  # Return type  # cio
    )

    _fields_ = [
        (
            "io",
            _IO_TYPE,
        ),
        (
            "freeptr",
            _FREE_PTR_TYPE,
        ),
    ]


class TunnelIO(IO):
    """Abstraction of a `struct SandwichTunnelIO` handle.

    The C handle is built by the tunnel, using the methods from this class and
    `SandwichIO`.
    """

    class CTunnelIO(ctypes.Structure):
        """The `struct SandwichTunnelIO`."""

        # typedef void(SandwichTunnelIOSetStateFunction)(void *uarg, enum
        # SandwichTunnelState tunnel_state);
        _SET_STATE_FN_TYPE = ctypes.CFUNCTYPE(
            None,  # Return type
            ctypes.c_void_p,  # *uarg
            ctypes.c_int,  # tunnel_state
        )

        _fields_ = [
            (
                "base",
                IO.Settings,
            ),
            (
                "set_statefn",
                _SET_STATE_FN_TYPE,
            ),
        ]

    @abc.abstractmethod
    def set_state(self, tunnel_state: SandwichTunnelProto.State):
        """Set the state of the tunnel.

        Args:
            tunnel_state:
                Current state of the tunnel.

        It is guaranteed that the state of the tunnel will not change between
        two calls to set_state.
        """
        raise NotImplementedError
