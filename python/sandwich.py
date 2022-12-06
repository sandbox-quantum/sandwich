"""Sandwich Python API.

This API provides a way to use Sandwich from Python.

It wraps Sandwich primitives into classes for convenience.
It also provides the protobuf API for building Sandwich Contexts and Tunnels.

The following classes are defined:
    *   Sandwich: general handle responsible for ffi using ctypes.CDLL.
    *   Context: wrapper around `struct SandwichContext*`.
    *   Tunnel: wrappers around `struct SandwichTunnel*`.
    *   IO: abstract class to define an I/O interface.

To be able to use this API, the user has to define its own I/O interface.
See `io.py` for more information.

Here is an example of how to use Sandwich in Python:

```
from saq.pqc.sandwich.python.sandwich import (
    Context,
    Error,
    Sandwich,
    Tunnel,
    errors,
    io
)
import saq.pqc.sandwich.proto.sandwich_pb2 as SandwichProto

# Initialize a Sandwich handle
sandwich_handle = Sandwich()

# Create a Sandwich context, using a Sandwich Configuration from protobuf.
conf = SandwichProto.Configuration()
conf.protocol = SandwichProto.Protocol.PROTO_TLS_13
conf.impl = SandwichProto.Implementation.IMPL_OPENSSL_1_1_1

# Set KEM
conf.client.tls.common_options.kem.append("kyber512")

# Add certificate
cert = conf.client.tls.trusted_certificates.add()
cert.path = "cert.der"
cert.format = SandwichProto.EncodingFormat.ENCODING_FORMAT_DER

# Create the Sandwich context
ctx = None
try:
    ctx = Context(sandwich_handle, conf)
except Error as e:
    print(f"Failed to create a context: {e} (code: {e.code})")
    fail()

# Get an I/O.
io = create_custom_io()

# Create a tunnel.
tun = None
try:
    tun = Tunnel(ctx, io)
except Error as e:
    print(f"Failed to create the tunnel: {e} (code: {e.code})")
    fail()

# Perform the handshake.
try:
    tun.handshake()
except errors.HandshakeWantReadException as e:
    # Handle WANT_READ
except errors.HandshakeWantWriteException as e:
    # Handle WANT_WRITE
except errors.HandshakeErrorException as e:
    # Handle ERROR

# Do I/O.
data = None
try:
    data = tun.read(1337)
except errors.RecordPlaneException as e:
    print(f"Failed to read 1337 bytes: record plane error: {e} (code {e.code})")

tun.close()
```

Author: sb
"""

import abc
import ctypes
import os
import pathlib
import typing

from bazel_tools.tools.python.runfiles import runfiles

import saq.pqc.sandwich.proto.api.v1.configuration_pb2 as SandwichAPI
import saq.pqc.sandwich.proto.sandwich_pb2 as SandwichProto
import saq.pqc.sandwich.proto.tunnel_pb2 as SandwichTunnelProto
import saq.pqc.sandwich.python.errors as errors
import saq.pqc.sandwich.python.io as SandwichIO


def _find_sandwich_dll() -> typing.Optional[pathlib.Path]:
    """Finds the path to the libsandwich dll (`libsandwich_shared.so`).

    Finds the path to the file `libsandwich_shared.so`, using a list of default path.

    Returns:
        The path to `libsandwich_shared.so` if it was successfully found, else None.
    """
    r = runfiles.Create()
    libpath = "sandwich/c/libsandwich_shared.so"
    ret = r.Rlocation(libpath)
    return pathlib.Path(ret)


Error = errors.SandwichGlobalException


class Context:
    """The `SandwichContext` handle.

    This class wraps a `struct SandwichContext *` and exposes few methods for
    convenience.

    Its destructor is responsible for freeing memory, by calling the relevant
    function(s):
        * `sandwich_context_free`

    Attributes:
        _sandwich: Sandwich handle. See class `Sandwich`.
        _configuration: Configuration for Sandwich, using the protobuf definition.
        _handle : C pointer to a `struct SandwichContext`. This is the main handle.
    """

    def __init__(self, sandwich: "Sandwich", configuration: SandwichAPI.Configuration):
        """Inits Context with a Sandwich handle and a protobuf configuration.

        Args:
            sandwich:
                A Sandwich handle. See class `Sandwich`.
            configuration:
                Configuration for building a `SandwichContext` handle.

        Raises:
            errors.SandwichGlobalException: The call to `sandwich_context_from_proto` returned an error.
        """

        self._sandwich = sandwich
        self._configuration = configuration
        self._handle = ctypes.c_void_p(0)

        serialized_conf = configuration.SerializeToString()
        args: typing.Tuple[ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p] = (
            serialized_conf,
            ctypes.c_size_t(len(serialized_conf)),
            ctypes.byref(self._handle),
        )
        err = self._sandwich.c_call("sandwich_context_new", *args)
        if err != errors.SandwichGlobalException.ERROR_OK:
            raise errors.SandwichGlobalException.new(err)

    def protocol(self) -> SandwichAPI.Protocol:
        """The selected protocol."""

        return self._configuration.protocol

    def implementation(self) -> SandwichAPI.Implementation:
        """The selected implementation."""

        return self._configuration.impl

    def __del__(self):
        """Destructs the Context.

        This destructor is responsible for freeing the memory.
        """

        self._sandwich.c_call("sandwich_context_free", self._handle)
        self._handle = ctypes.c_void_p(0)


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

    def __init__(self, ctx: Context, io: SandwichIO.IO):
        """Initializes a tunnel.

        Args:
            ctx:
                Context handle to use to create the tunnel.
            io:
                IO interface to use to create the tunnel.

        Raises:
            IOError: The call to `sandwich_io_new` failed.
            RuntimeError: The call to `sandwich_tunnel_new` failed.
        """
        self._ctx = ctx
        self._handle = ctypes.c_void_p(0)
        self._io = io

        # WARNING: we have to keep a refrence to this object, otherwise
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
        self._settings.closefn = SandwichIO.IO.Settings._CLOSE_FN_TYPE(
            lambda uarg: self._io_close()
        )

        io_handle = SandwichIO._IOHandle(self._C)
        err = self._C.c_call(
            "sandwich_io_new", ctypes.byref(self._settings), io_handle.ref()
        )
        if err != errors.SandwichGlobalException.ERROR_OK:
            raise errors.SandwichGlobalException.new(err)

        ret = self._C.c_call(
            "sandwich_tunnel_new",
            self._ctx._handle,
            io_handle.release(),
            ctypes.byref(self._handle),
        )
        if err != 0:
            raise errors.SandwichGlobalException.new(
                err, f"Failed to construct a Sandwich tunnel"
            )

    def state(self) -> State:
        """Returns the state of the tunnel.

        Returns:
            State of the tunnel.
        """
        return self._C.c_call("sandwich_tunnel_state", self._handle)

    def error(self) -> Error:
        """Returns the last saved error.

        Returns:
            The last saved error.
        """
        return self._C.c_call("sandwich_tunnel_last_error", self._handle)

    def io_release(self) -> SandwichIO.IO:
        """Releases the underlying I/O interface.

        This function gives back the ownership of the I/O interface to the user.

        Returns:
            The I/O interface.
        """

        self._C.c_call("sandwich_tunnel_io_release", self._handle)
        return self._io

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
                An unknown error occurred during the handshake.
        """

        err = self._C.c_call("sandwich_tunnel_handshake", self._handle)

        if err != errors.HandshakeException.ERROR_OK:
            raise errors.HandshakeException.new(err)

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
            errors.IOException

        Returns:
            Amount of bytes read from the I/O interface.
        """
        data = None
        try:
            data = self._io.read(count, tunnel_state)
        except errors.IOException as e:
            err[0] = e.code
            return 0
        err[0] = errors.IOException.ERROR_OK
        l = len(data)
        assert l <= count
        ctypes.memmove(buf, data, len(data))
        return l

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
        except errors.IOException as e:
            err[0] = e.code()
            return 0
        err[0] = errors.IOException.ERROR_OK
        return w

    def __del__(self):
        """Destructs the tunnel.

        This destructor is responsible for freeing the memory.
        """

        self._C.c_call("sandwich_tunnel_free", self._handle)
        self._handle = ctypes.c_void_p(0)


class Sandwich:
    """A Sandwich handle.

    This handle is responsible for doing the glue with the C code.

    Attributes:
        lib: Handle to the Sandwich shared library.
        syms: Dictionary name -> native C function. Symbols are lazy-resolved.
    """

    lib: typing.Optional[ctypes.CDLL] = None
    syms: typing.Dict[str, typing.Callable] = {}

    def __init__(self, dllpath: typing.Optional[pathlib.Path] = None):
        """Inits a Sandwich handle, optionally with a path to `libsandwich.so`.

        Args:
            dllpath:
                Path to the Sandwich shared library. if None, common paths will
                be inspected.

        Raises:
            FileNotFoundError: The Sandwich shared library could not be found.
        """

        path: pathlib.Path = ""
        if (path := dllpath) == None and (dllpath := _find_sandwich_dll()) == None:
            raise FileNotFoundError("Failed to find `libsandwich.so`")

        if isinstance(dllpath, pathlib.Path):
            if dllpath.is_symlink():
                path = dllpath.readlink()
            else:
                path = dllpath.absolute()

        if Sandwich.lib == None:
            Sandwich.lib = ctypes.cdll.LoadLibrary(path)

        if Sandwich.syms == None:
            Sandwich.syms = {}

    @staticmethod
    def c_call(name: str, *kargs):
        """Calls a C function.

        Args:
            name:
                Name of the symbol.
            *kwargs:
                Arguments to forward to the C function.

        Returns:
            Any
        """

        f: typing.Callable
        if name in Sandwich.syms:
            f = Sandwich.syms[name]
        else:
            f = Sandwich.resolve(name)
            Sandwich.syms[name] = f
        return f(*kargs)

    @staticmethod
    def resolve(name: str) -> typing.Callable:
        """Resolves a symbol from the library.

        Args:
            name: Symbol's name.

        Returns:
            The handle to the symbol.

        Raises:
            AttributeError: The symbol was not found.
        """

        try:
            return getattr(Sandwich.lib, name)
        except AttributeError as e:
            raise AttributeError(f"Sandwich lib does not have symbol '{name}'")
