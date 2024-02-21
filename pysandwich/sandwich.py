# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

"""Sandwich Python API.

This API provides a way to use Sandwich from Python.

It wraps Sandwich primitives into classes for convenience.
It also provides the protobuf API for building Sandwich Contexts and Tunnels.

The following classes are defined:
    *   Sandwich: general handle responsible for ffi using ctypes.CDLL.
    *   IO: abstract class to define an I/O interface.

To be able to use this API, the user has to define its own I/O interface.
See `io.py` for more information.
"""

import ctypes
import pathlib
import platform
import typing
from collections import namedtuple
from types import MappingProxyType

import pysandwich.errors as errors
from pysandwich.io import OwnedIO, TunnelIO

_ext = {"Darwin": "dylib", "Windows": "dll"}.get(platform.system(), "so")


def _find_sandwich_dll() -> typing.Optional[pathlib.Path]:
    """Finds the path to the libsandwich dll (`libsandwich_full.so`, or
    `libsandwich_full.dylib`).

    Finds the path to the file `libsandwich_full.so` or
    `libsandwich_full.dylib`, using a list of default path.

    Args:
        extension:
            Library extension: `so` or `dylib`.
    Returns:
        The path to `libsandwich_shared.so` or `libsandwich_full.dylib` if
        it was successfully found, else None.
    """
    import os

    sandwich_c_lib = os.getenv("SANDWICH_C_LIB")
    if sandwich_c_lib is not None:
        return pathlib.Path(sandwich_c_lib)

    try:
        from bazel_tools.tools.python.runfiles import runfiles
    except ImportError:
        return None

    r = runfiles.Create()
    libpath = "sandwich/pysandwich/libsandwich_full.so"
    ret = r.Rlocation(libpath)
    return pathlib.Path(ret)


class _ErrorC(ctypes.Structure):
    """SandwichError structure."""

    _fields_ = [
        ("details", ctypes.c_void_p),
        ("msg", ctypes.c_char_p),
        ("kind", ctypes.c_int32),
        ("code", ctypes.c_int32),
    ]


def _error_code_to_exception(ptr: ctypes.c_void_p) -> errors.SandwichException | None:
    """Gather exceptions cause"""
    ec = ctypes.cast(ptr, ctypes.POINTER(_ErrorC))

    head_excp = None
    current_excp = None
    while ec:
        excp = errors.SandwichException.new(
            ec.contents.code, ec.contents.kind, ec.contents.msg
        )
        if head_excp is None:
            head_excp = excp
            current_excp = excp
        else:
            current_excp.__cause__ = excp
            current_excp = excp
        ec = ctypes.cast(ec.contents.details, ctypes.POINTER(_ErrorC))
    return head_excp


class TunnelContextConfigurationSerialized(ctypes.Structure):
    """The `struct SandwichContextTunnelConfigurationSerialized`."""

    _fields_ = [
        (
            "src",
            ctypes.c_char_p,
        ),
        (
            "n",
            ctypes.c_size_t,
        ),
    ]


class TunnelConfigurationSerialized(ctypes.Structure):
    """The `struct SandwichTunnelConfigurationSerialized`."""

    _fields_ = [
        (
            "src",
            ctypes.c_char_p,
        ),
        (
            "n",
            ctypes.c_size_t,
        ),
    ]


class _SandwichCLib:
    """A Sandwich handle.

    This handle is responsible for doing the glue with the C code.

    Attributes:
        lib: Handle to the Sandwich shared library.
        syms: Dictionary name -> native C function. Symbols are lazy-resolved.
    """

    lib: typing.Optional[ctypes.CDLL] = None
    syms: typing.Dict[str, typing.Callable] = {}

    __fs = namedtuple("function_signature", ["args", "ret"])

    func_dict = MappingProxyType(
        {
            # struct SandwichContext* sandwich_lib_context_new(void);
            "sandwich_lib_context_new": __fs(args=[], ret=ctypes.c_void_p),
            # void sandwich_lib_context_free(struct SandwichContext*);
            "sandwich_lib_context_free": __fs(args=[ctypes.c_void_p], ret=None),
            # void sandwich_error_free(struct SandwichError *chain)
            "sandwich_error_free": __fs(args=[ctypes.c_void_p], ret=None),
            # char* sandwich_error_stack_str_new(const struct SandwichError *chain)
            "sandwich_error_stack_str_new": __fs(
                args=[ctypes.c_void_p], ret=ctypes.c_char_p
            ),
            # void sandwich_error_stack_str_free(const char *err_str);
            "sandwich_error_stack_str_free": __fs(args=[ctypes.c_char_p], ret=None),
            # struct SandwichError * sandwich_tunnel_context_new(
            #       const struct SandwichContext *,
            #       struct SandwichTunnelContextConfigurationSerialized,
            #       struct SandwichTunnelContext **ctx);
            "sandwich_tunnel_context_new": __fs(
                args=[
                    ctypes.c_void_p,
                    TunnelContextConfigurationSerialized,
                    ctypes.c_void_p,
                ],
                ret=ctypes.c_void_p,
            ),
            # void sandwich_tunnel_context_free(struct SandwichTunnelContext *ctx);
            "sandwich_tunnel_context_free": __fs(args=[ctypes.c_void_p], ret=None),
            # struct SandwichError *sandwich_tunnel_new(
            #       struct SandwichTunnelContext *ctx,
            #       struct SandwichIO *cio,
            #       struct SandwichTunnelConfigurationSerialized configuration,
            #       struct SandwichTunnel **tun);
            "sandwich_tunnel_new": __fs(
                args=[
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    TunnelConfigurationSerialized,
                    ctypes.c_void_p,
                ],
                ret=ctypes.c_void_p,
            ),
            # struct SandwichError * sandwich_tunnel_handshake(
            #       struct SandwichTunnel *tun,
            #       enum SandwichTunnelHandshakeState *state);
            "sandwich_tunnel_handshake": __fs(
                args=[ctypes.c_void_p, ctypes.c_void_p],
                ret=ctypes.c_void_p,
            ),
            # enum SandwichTunnelRecordError sandwich_tunnel_read(
            #       struct SandwichTunnel *tun,
            #       void *dst,
            #       size_t n,
            #       size_t *r);
            "sandwich_tunnel_read": __fs(
                args=[
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_size_t,
                    ctypes.POINTER(ctypes.c_size_t),
                ],
                ret=ctypes.c_int32,
            ),
            # enum SandwichTunnelRecordError sandwich_tunnel_write(
            #       struct SandwichTunnel *tun,
            #       const void *src,
            #       size_t n,
            #       size_t *w);
            "sandwich_tunnel_write": __fs(
                args=[
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_size_t,
                    ctypes.POINTER(ctypes.c_size_t),
                ],
                ret=ctypes.c_int32,
            ),
            # void sandwich_tunnel_close(struct SandwichTunnel *tun);
            "sandwich_tunnel_close": __fs(args=[ctypes.c_void_p], ret=None),
            # enum SandwichTunnelState sandwich_tunnel_state(
            #       const struct SandwichTunnel *tun);
            "sandwich_tunnel_state": __fs(args=[ctypes.c_void_p], ret=ctypes.c_int32),
            # void sandwich_tunnel_free(struct SandwichTunnel *tun);
            "sandwich_tunnel_free": __fs(args=[ctypes.c_void_p], ret=None),
            # void sandwich_tunnel_add_tracer(
            #       struct SandwichTunnel *tun,
            #       const char *context_cstr,
            #       int fd);
            "sandwich_tunnel_add_tracer": __fs(
                args=[
                    ctypes.c_void_p,
                    ctypes.c_char_p,
                    ctypes.c_int,
                ],
                ret=None,
            ),
            # enum SandwichIOError sandwich_io_client_tcp_new(
            #       const char *hostname, const uint16_t port, bool async,
            #       struct SandwichIOOwned **ownedIO);
            "sandwich_io_client_tcp_new": __fs(
                args=[
                    ctypes.c_char_p,
                    ctypes.c_uint16,
                    ctypes.c_bool,
                    ctypes.POINTER(ctypes.POINTER(OwnedIO)),
                ],
                ret=ctypes.c_int32,
            ),
            # enum SandwichIOError sandwich_io_client_turbo_new(
            #       const char *udp_hostname, const uint16_t udp_port,
            #       const char *tcp_hostname, const uint16_t tcp_port,
            #       bool is_blocking, struct SandwichIOOwned **ownedIO);
            "sandwich_io_client_turbo_new": __fs(
                args=[
                    ctypes.c_char_p,
                    ctypes.c_uint16,
                    ctypes.c_char_p,
                    ctypes.c_uint16,
                    ctypes.c_bool,
                    ctypes.POINTER(ctypes.POINTER(OwnedIO)),
                ],
                ret=ctypes.c_int32,
            ),
            # enum SandwichIOError sandwich_io_socket_wrap_new(
            #       int fd, struct SandwichIOOwned **ownedIO);
            "sandwich_io_socket_wrap_new": __fs(
                args=[
                    ctypes.c_int,
                    ctypes.POINTER(ctypes.POINTER(OwnedIO)),
                ],
                ret=ctypes.c_int32,
            ),
            # void sandwich_io_owned_free(struct SandwichIOOwned *ownedIO)
            "sandwich_io_owned_free": __fs(args=[ctypes.c_void_p], ret=None),
            # struct SandwichError *sandwich_listener_new(const void *src,
            #       size_t n, struct SandwichListener **out);
            # strcut SandwichTunnelIO sandwich_owned_io_to_tunnel_io(
            #       struct SandwichIOOwned *ownedIO)
            "sandwich_owned_io_to_tunnel_io": __fs(
                args=[
                    ctypes.c_void_p,
                ],
                ret=TunnelIO.CTunnelIO,
            ),
            # struct SandwichError *sandwich_listener_new(const void *src,
            #       size_t n, struct SandwichListener **out);
            "sandwich_listener_new": __fs(
                args=[
                    ctypes.c_void_p,
                    ctypes.c_size_t,
                    ctypes.c_void_p,
                ],
                ret=ctypes.c_void_p,
            ),
            # enum SandwichIOError sandwich_listener_listen(
            #       struct SandwichListener *listener);
            "sandwich_listener_listen": __fs(
                args=[
                    ctypes.c_void_p,
                ],
                ret=ctypes.c_uint,
            ),
            # enum SandwichIOErrorsandwich_listener_accept(
            #       struct SandwichListener *listener,
            #       struct SandwichOwnedIO **owned_io);
            "sandwich_listener_accept": __fs(
                args=[
                    ctypes.c_void_p,
                    ctypes.POINTER(ctypes.POINTER(OwnedIO)),
                ],
                ret=ctypes.c_uint,
            ),
            # void sanwich_listener_close(struct SandwichListener *listener)
            "sandwich_listener_close": __fs(
                args=[
                    ctypes.c_void_p,
                ],
                ret=None,
            ),
            # void sanwich_listener_free(struct SandwichListener *listener)
            "sandwich_listener_free": __fs(
                args=[
                    ctypes.c_void_p,
                ],
                ret=None,
            ),
        }
    )

    def __init__(self, dllpath: typing.Optional[pathlib.Path | str] = None):
        """Inits a Sandwich handle, optionally with a path to `libsandwich.so`.

        Args:
            dllpath:
                Path to the Sandwich shared library. if None, common paths will
                be inspected.

        Raises:
            FileNotFoundError: The Sandwich shared library could not be found.
        """

        def __load_library(dllpath: pathlib.Path | str | None = None) -> ctypes.CDLL:
            dllpath = dllpath or _find_sandwich_dll() or "libsandwich_full.so"
            if isinstance(dllpath, pathlib.Path):
                dllpath = dllpath.resolve().__str__()
            return ctypes.cdll.LoadLibrary(dllpath)

        _SandwichCLib.lib = _SandwichCLib.lib or __load_library(dllpath)
        _SandwichCLib.syms = _SandwichCLib.syms or {}

    @staticmethod
    def c_call(name: str, *args: typing.Any) -> typing.Any:
        """Calls a C function.

        Args:
            name:
                Name of the symbol.
            *args:
                Arguments to forward to the C function.

        Returns:
            Any: ctypes-based value returned by the C function
        """

        f: typing.Callable
        if name in _SandwichCLib.syms:
            f = _SandwichCLib.syms[name]
        else:
            f = _SandwichCLib.resolve(name)
            _SandwichCLib.syms[name] = f

        # Extract function signature
        fs = _SandwichCLib.func_dict[name]
        f.argtypes = fs.args
        f.restype = fs.ret

        return f(*args)

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
            return getattr(_SandwichCLib.lib, name)
        except AttributeError:
            raise AttributeError(
                f"Sandwich lib does not have symbol {name!r}"
            ) from None


_sandwich_hdl = None


def sandwich() -> _SandwichCLib:
    """Returns the global handler to _SandwichCLib.
    This function performs a lazy initialization of the Sandwich handler.
    """
    global _sandwich_hdl
    if _sandwich_hdl is None:
        _sandwich_hdl = _SandwichCLib()
    return _sandwich_hdl


class Sandwich:
    """Top-level Sandwich context library."""

    _handle: ctypes.c_void_p

    def __init__(self):
        self._handle = sandwich().c_call("sandwich_lib_context_new")

    def _get_handle(self) -> ctypes.c_void_p:
        return self._handle

    def __del__(self):
        sandwich().c_call("sandwich_lib_context_free", self._handle)
        self._handle = ctypes.c_void_p(None)
