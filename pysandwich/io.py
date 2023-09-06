# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

"""Sandwich I/O API.

This API provides an I/O interface in Python, to use with Sandwich.
It wraps a `struct SandwichCIOSettings`.

An I/O interface is an object requiring the following methods:
    * read(n: int) -> bytes
    * write(buf: bytes) -> int

All methods should either return the corresponding value (the read bytes
for `read` and the amount of successfully written bytes for `write`), or
raise an exception of type `IOException`.

The user has to define a class extending `IO`.
An example can be found in `tunnel_test.py`.

Author: thb-sb
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


class IO(abc.ABC):
    """Abstraction of a `struct SandwichCIO` handle.

    The C handle is built by the tunnel, using the methods from this class.
    """

    Error = SandwichIOProto.IOError

    class Settings(ctypes.Structure):
        """The `struct SandwichCIOSettings`."""

        # typedef size_t(SandwichCIOReadFunction)(void *uarg, void *buf, size_t count,
        # enum SandwichTunnelState tunnel_state,
        # enum SandwichIOError *err);
        _READ_FN_TYPE = ctypes.CFUNCTYPE(
            ctypes.c_size_t,  # Return type
            ctypes.c_void_p,  # *uarg
            ctypes.c_void_p,  # *buf
            ctypes.c_size_t,  # count
            ctypes.c_int,  # tunnel_state
            ctypes.POINTER(ctypes.c_int),  # *err
        )

        # typedef size_t(SandwichCIOWriteFunction)(void *uarg, const void *buf,
        # size_t count,
        # enum SandwichTunnelState tunnel_state,
        # enum SandwichIOError *err);
        _WRITE_FN_TYPE = ctypes.CFUNCTYPE(
            ctypes.c_size_t,  # Return type
            ctypes.c_void_p,  # *uarg
            ctypes.c_void_p,  # *buf
            ctypes.c_size_t,  # count
            ctypes.c_int,  # tunnel_state
            ctypes.POINTER(ctypes.c_int),  # *err
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
                "uarg",
                ctypes.c_void_p,
            ),
        ]

    @abc.abstractmethod
    def read(self, n: int, tunnel_state: SandwichTunnelProto.State) -> bytes:
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
    def write(self, buf: bytes, tunnel_state: SandwichTunnelProto.State) -> int:
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


class OwnedIO(ctypes.Structure):
    """The `struct SandwichCIOSettings`."""

    _IO_TYPE = ctypes.POINTER(IO.Settings)

    # typedef void(SandwhichIOOwnedFreeFunction)(struct SandwhichCIOSettings *cio)
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
