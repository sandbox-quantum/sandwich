# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

"""Sandwich Python API.

This API provides a way to use Sandwich from Python.

It wraps Sandwich primitives into classes for convenience.
It also provides the protobuf API for building Sandwich Contexts and Tunnels.

The following classes are defined:
    *   Context: wrapper around `struct SandwichContext*`.
    *   Tunnel: wrappers around `struct SandwichTunnel*`.

To be able to use this API, the user has to define its own I/O interface.
See `io.py` for more information.

Author: sb
"""
import ctypes

import pysandwich.proto.api.v1.configuration_pb2 as SandwichAPI
import pysandwich.proto.tunnel_pb2 as SandwichTunnelProto
import pysandwich.errors as errors
import pysandwich.io as SandwichIO
from pysandwich.proto.api.v1.tunnel_pb2 import TunnelConfiguration
from pysandwich import sandwich


class Context:
    """The `SandwichContext` handle.

    This class wraps a `struct SandwichContext *` and exposes few methods for
    convenience.

    Its destructor is responsible for freeing memory, by calling the relevant
    function(s):
        * `sandwich_tunnel_context_free`

    Attributes:
        _sandwich: Sandwich handle. See class `Sandwich`.
        _configuration: Configuration for Sandwich, using the protobuf definition.
        _handle : C pointer to a `struct SandwichContext`. This is the main handle.
    """

    def __init__(
        self,
        sandwich: "sandwich.Sandwich",
        configuration: SandwichAPI.Configuration,
        serialized_conf: bytes,
    ):
        """Inits Context with a Sandwich handle and a protobuf configuration.

        Args:
            sandwich:
                A Sandwich handle. See class `Sandwich`.
            configuration:
                Configuration for building a `SandwichContext` handle.

        Raises:
            errors.SandwichGlobalException: The call to `sandwich_tunnel_context_from_proto`
            returned an error.
        """

        self._sandwich = sandwich
        self._configuration = configuration
        self._handle = ctypes.c_void_p(None)
        self._serialized_conf = serialized_conf

        args = (
            self._serialized_conf,
            len(self._serialized_conf),
            ctypes.byref(self._handle),
        )
        err = self._sandwich.c_call("sandwich_tunnel_context_new", *args)
        if err is not None:
            excp = sandwich._error_code_to_exception(err)
            self._sandwich.c_call("sandwich_error_free", err)
            raise excp

    @classmethod
    def from_config(
        cls, sandwich: "sandwich.Sandwich", configuration: SandwichAPI.Configuration
    ):
        serialized_conf = configuration.SerializeToString()

        return Context(sandwich, configuration, serialized_conf)

    @classmethod
    def from_bytes(
        cls, sandwich: "sandwich.Sandwich", serialized_conf_bytestring: bytes
    ):
        configuration = SandwichAPI.Configuration()
        configuration.ParseFromString(serialized_conf_bytestring)

        return Context(sandwich, configuration, serialized_conf_bytestring)

    def implementation(self) -> SandwichAPI.Implementation:
        """The selected implementation."""

        return self._configuration.impl

    @property
    def serialized_config(self) -> bytes:
        """Return serialized configuration"""
        return self._serialized_conf

    @property
    def config(self) -> SandwichAPI.Implementation:
        """Return configuration"""
        return self._configuration

    def __del__(self):
        """Destructs the Context.

        This destructor is responsible for freeing the memory.
        """

        self._sandwich.c_call("sandwich_tunnel_context_free", self._handle)
        self._handle = ctypes.c_void_p(None)


class Tunnel:
    """A class representing a tunnel.

    This class wraps a `struct SandwichTunnel` and exposes methods for using
    the C frontend API, such as:
        * `handshake`
        * `read`
        * `write`
        * `close`

    The destructor of this class is responsible for freeing memory.

    WARNING: This class' destructor is not responsible for closing the tunnel.

    Attributes:
        _ctx: Context handle for creating the tunnel.
        _io: I/O interface to use.
    """

    State = SandwichTunnelProto.State
    HandshakeState = SandwichTunnelProto.HandshakeState
    RecordError = SandwichTunnelProto.RecordError

    def __init__(
        self,
        ctx: Context,
        io: SandwichIO.IO,
        configuration: TunnelConfiguration,
    ):
        """Initializes a tunnel.

        Args:
            ctx:
                Context handle to use to create the tunnel.
            io:
                IO interface to use to create the tunnel.
            configuration:
                Tunnel configuration.

        Raises:
            RuntimeError: The call to `sandwich_tunnel_new` failed.
        """
        self._ctx = ctx
        self._handle = ctypes.c_void_p(None)
        self._io = io

        conf_bytes = configuration.SerializeToString()
        conf = sandwich.Sandwich.TunnelConfigurationSerialized()
        conf.src = conf_bytes
        conf.n = len(conf_bytes)

        # WARNING: we have to keep a reference to this object, otherwise
        # the garbage collector will clean references to the ctypes.FUNCTYPE.
        self._settings = SandwichIO.IO.Settings()
        self._settings.readfn = SandwichIO.IO.Settings._READ_FN_TYPE(
            lambda uarg, buf, count, tunnel_state, err: self._io_read(
                buf, count, tunnel_state, err
            )
        )
        self._settings.writefn = SandwichIO.IO.Settings._WRITE_FN_TYPE(
            lambda uarg, buf, count, tunnel_state, err: self._io_write(
                buf, count, tunnel_state, err
            )
        )

        err = self._C.c_call(
            "sandwich_tunnel_new",
            self._ctx._handle,
            ctypes.byref(self._settings),
            conf,
            ctypes.byref(self._handle),
        )
        if err is not None:
            excp = sandwich._error_code_to_exception(err)
            self._C.c_call("sandwich_error_free", err)
            raise excp

    def state(self) -> State:
        """Returns the state of the tunnel.

        Returns:
            State of the tunnel.
        """
        return self._C.c_call("sandwich_tunnel_state", self._handle)

    def error(self) -> sandwich.Error:
        """Returns the last saved error.

        Returns:
            The last saved error.
        """
        return self._C.c_call("sandwich_tunnel_last_error", self._handle)

    @property
    def io(self) -> SandwichIO.IO:
        """Returns the underlying I/O interface.

        The returned I/O interface is borrowed.

        Returns:
            The I/O interface.
        """
        return self._io

    def handshake(self):
        """Performs the handshake step, for non-blocking tunnel.

        Raises:
            Tunnel.HandshakeInProgressException:
                The handshake is still in progress. The user has to call this
                function again.
            Tunnel.HandshakeWantReadException:
                The implementation wants to read data from the wire, but the
                underlying I/O interface is non-blocking.
            Tunnel.HandshakeWantWriteException:
                The implementation wants to write data to the wire, but the
                underlying I/O interface is non-blocking.
            Tunnel.HandshakeErrorException:
                The implementation experienced an error while performing the
                handshake. (e.g. expired or revoked certificates, bad signature, etc.)
        """

        handshake_state = ctypes.c_int32()
        err = self._C.c_call(
            "sandwich_tunnel_handshake",
            self._handle,
            ctypes.byref(handshake_state),
        )
        if err is not None:
            excp = sandwich._error_code_to_exception(err)
            self._C.c_call("sandwich_error_free", err)
            raise excp
        handshake_state = handshake_state.value
        if handshake_state != errors.HandshakeException.ERROR_OK:
            raise errors.HandshakeException.new(handshake_state)

    def read(self, n: int) -> bytes:
        """Reads bytes from the tunnel.

        Args:
            n:
                Maximum amount of bytes to read from the tunnel.

        Returns:
            Bytes successfully read.

        Raises:
            errors.RecordPlaneException.
        """

        read_n = ctypes.c_size_t(0)
        buf = (ctypes.c_uint8 * n)()
        err = self._C.c_call(
            "sandwich_tunnel_read",
            self._handle,
            buf,
            ctypes.c_size_t(n),
            ctypes.byref(read_n),
        )

        if err != errors.RecordPlaneException.ERROR_OK:
            raise errors.RecordPlaneException.new(err)

        return bytes(buf[0 : read_n.value])

    def write(self, src: bytes) -> int:
        """Writes bytes to the tunnel.

        Args:
            src:
                Buffer to write to the tunnel.

        Returns:
            Amount of bytes successfully written to the tunnel.

        Raises:
            errors.RecordPlaneException.
        """

        write_n = ctypes.c_size_t(0)
        err = self._C.c_call(
            "sandwich_tunnel_write",
            self._handle,
            src,
            ctypes.c_size_t(len(src)),
            ctypes.byref(write_n),
        )

        if err != errors.RecordPlaneException.ERROR_OK:
            raise errors.RecordPlaneException.new(err)

        return write_n.value

    def close(self):
        """Closes the tunnel."""

        self._C.c_call("sandwich_tunnel_close", self._handle)

    @property
    def _C(self):
        """Returns the ctypes handle to the Sandwich shared library.

        Returns:
            The ctypes handle to the Sandwich shared library.
        """
        return self._ctx._sandwich

    def _io_read(
        self,
        buf: ctypes.c_void_p,
        count: int,
        tunnel_state: ctypes.c_int,
        err: ctypes.POINTER(ctypes.c_int),
    ) -> int:
        """Trampoline routine for reading, between C and Python.

        Args:
            buf:
                ctypes void pointer buffer, where to store read bytes.
            count:
                Size of `buf`.
            tunnel_state:
                State of the tunnel.
            err:
                Pointer to an IOError, to set.

        Raises:
            SandwichIO.IOException

        Returns:
            Amount of bytes read from the I/O interface.
        """
        data = None
        try:
            data = self._io.read(count, tunnel_state)
        except SandwichIO.IOException as e:
            err[0] = e.code
            return 0
        err[0] = SandwichIO.IOException.ERROR_OK
        bytes_read = len(data)
        assert bytes_read <= count
        ctypes.memmove(buf, data, bytes_read)
        return bytes_read

    def _io_write(
        self,
        buf: ctypes.c_void_p,
        count: int,
        tunnel_state: ctypes.c_int,
        err: ctypes.POINTER(ctypes.c_int),
    ) -> int:
        """Trampoline routine for writing, between C and Python.

        Args:
            buf:
                ctypes void pointer buffer, source.
            count:
                Size of `buf`.
            tunnel_state:
                State of the tunnel.
            err:
                Pointer to an IOError, to set.

        Raises:
            SandwichIO.IOException

        Returns:
            Amount of bytes written to the I/O interface.
        """
        w = 0
        try:
            w = self._io.write(
                bytes(ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))[:count]),
                tunnel_state,
            )
        except SandwichIO.IOException as e:
            err[0] = e.code()
            return 0
        err[0] = SandwichIO.IOException.ERROR_OK
        return w

    def __del__(self):
        """Destructs the tunnel.

        This destructor is responsible for freeing the memory.
        """

        self._C.c_call("sandwich_tunnel_free", self._handle)
        self._handle = ctypes.c_void_p(None)
