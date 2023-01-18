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

"""Sandwich I/O API.

This API provides an I/O interface in Python, to use with Sandwich.
It wraps a `struct SandwichCIO` and `struct SandwichCIOSettings`.

An I/O interface is an object requiring the following methods:
    * read(n: int) -> bytes
    * write(buf: bytes) -> int
    * close()

All methods should either return the corresponding value (the read bytes
for `read` and the amount of successfully written bytes for `write`), or
raise an exception of type `errors.IOException`.
See `errors.py` for more information about `IOException`.

The user has to define a class extending `IO`.
An example can be found in `tunnel_test.py`.

Author: thb-sb
"""

import abc
import ctypes

import proto.io_pb2 as SandwichIOProto
import proto.tunnel_pb2 as SandwichTunnelProto
from pysandwich import errors


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

        _CLOSE_FN_TYPE = ctypes.CFUNCTYPE(
            None,  # void,
            ctypes.c_void_p,  # uarg
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
                "closefn",
                _CLOSE_FN_TYPE,
            ),
            (
                "uarg",
                ctypes.c_void_p,
            ),
        ]

    @abc.abstractmethod
    def read(n, tunnel_state: SandwichTunnelProto.State) -> bytes:
        """Read function.

        Args:
            n:
                Amount of bytes to read.

        Raises:
            errors.IOException.

        Returns:
            Bytes successfully read.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def write(buf, tunnel_state: SandwichTunnelProto.State) -> int:
        """Write function.

        Args:
            buf:
                Buffer to write.

        Raises:
            errors.IOException.

        Returns:
            Amount of successfully written bytes.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def close():
        """Close function.

        Raises:
            errors.IOException.
        """
        pass


class _IOHandle:
    """Wrapper around a `struct SandwichCIO`."""

    def __init__(self, s: "Sandwich", handle=ctypes.c_void_p(0)):
        """Constructs an _IOHandle from a void pointer.

        Args:
            s:
                Sandwich handle.
            handle:
                Pointer to the `struct SandwichCIO` object.
        """
        self._s = s
        self._handle = handle

    def get(self):
        """Returns the handle.

        The handle is borrowed.

        Returns:
            The handle
        """
        return self._handle

    def ref(self):
        """Returns the pointer to the handle.


        Returns:
            Pointer to the handle
        """
        return ctypes.byref(self._handle)

    def release(self):
        """Releases the handle.

        When the handle is released, this object is no longer its owner.

        Returns:
            The handle
        """
        tmp, self._handle = self._handle, ctypes.c_void_p(0)
        return tmp

    def __del__(self):
        """Destructor."""
        self._s.c_call("sandwich_io_free", self._handle)