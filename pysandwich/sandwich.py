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

Author: sb
"""

import ctypes
import pathlib
import platform
import typing

import pysandwich.errors as errors
import pysandwich.io as SandwichIO

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


Error = errors.SandwichException


class _ErrorC(ctypes.Structure):
    """SandwichError structure."""

    _fields_ = [
        ("details", ctypes.c_void_p),
        ("msg", ctypes.c_char_p),
        ("kind", ctypes.c_int32),
        ("code", ctypes.c_int32),
    ]


def _error_code_to_exception(ptr: ctypes.c_void_p):
    """Gather exceptions cause"""
    ec = ctypes.cast(ptr, ctypes.POINTER(_ErrorC))

    head_excp = None
    current_excp = None
    while ec:
        excp = Error.new(ec.contents.code, ec.contents.kind, ec.contents.msg)
        if head_excp is None:
            head_excp = excp
            current_excp = excp
        else:
            current_excp.__cause__ = excp
            current_excp = excp
        ec = ctypes.cast(ec.contents.details, ctypes.POINTER(_ErrorC))
    return head_excp


class Sandwich:
    """A Sandwich handle.

    This handle is responsible for doing the glue with the C code.

    Attributes:
        lib: Handle to the Sandwich shared library.
        syms: Dictionary name -> native C function. Symbols are lazy-resolved.
    """

    lib: typing.Optional[ctypes.CDLL] = None
    syms: typing.Dict[str, typing.Callable] = {}

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

    func_types = {
        # void sandwich_error_free(struct SandwichError *chain)
        "sandwich_error_free": ([ctypes.c_void_p], None),
        # char * sandwich_error_stack_str_new(const struct SandwichError *chain)
        "sandwich_error_stack_str_new": ([ctypes.c_void_p], ctypes.c_char_p),
        # void sandwich_error_stack_str_free(const char *err_str);
        "sandwich_error_stack_str_free": ([ctypes.c_char_p], None),
        # struct SandwichError * sandwich_tunnel_context_new(
        #       const void *src,
        #       size_t n,
        #       struct SandwichTunnelContext **ctx);
        "sandwich_tunnel_context_new": (
            [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p],
            ctypes.c_void_p,
        ),
        # void sandwich_tunnel_context_free(struct SandwichTunnelContext *ctx);
        "sandwich_tunnel_context_free": ([ctypes.c_void_p], None),
        # struct SandwichError *sandwich_tunnel_new(
        #       struct SandwichTunnelContext *ctx,
        #       struct SandwichCIO *cio,
        #       struct SandwichTunnelConfigurationSerialized configuration,
        #       struct SandwichTunnel **tun);
        "sandwich_tunnel_new": (
            [
                ctypes.c_void_p,
                ctypes.c_void_p,
                TunnelConfigurationSerialized,
                ctypes.c_void_p,
            ],
            ctypes.c_void_p,
        ),
        # struct SandwichError * sandwich_tunnel_handshake(
        #       struct SandwichTunnel *tun,
        #       enum SandwichTunnelHandshakeState *state);
        "sandwich_tunnel_handshake": (
            [ctypes.c_void_p, ctypes.c_void_p],
            ctypes.c_void_p,
        ),
        # enum SandwichTunnelRecordError sandwich_tunnel_read(
        #       struct SandwichTunnel *tun,
        #       void *dst,
        #       size_t n,
        #       size_t *r);
        "sandwich_tunnel_read": (
            [
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_size_t),
            ],
            ctypes.c_int32,
        ),
        # enum SandwichTunnelRecordError sandwich_tunnel_write(
        #       struct SandwichTunnel *tun,
        #       const void *src,
        #       size_t n,
        #       size_t *w);
        "sandwich_tunnel_write": (
            [
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_size_t),
            ],
            ctypes.c_int32,
        ),
        # void sandwich_tunnel_close(struct SandwichTunnel *tun);
        "sandwich_tunnel_close": ([ctypes.c_void_p], None),
        # enum SandwichTunnelState sandwich_tunnel_state(
        #       const struct SandwichTunnel *tun);
        "sandwich_tunnel_state": ([ctypes.c_void_p], ctypes.c_int32),
        # void sandwich_tunnel_free(struct SandwichTunnel *tun);
        "sandwich_tunnel_free": ([ctypes.c_void_p], None),
        # enum SandwichCIOError sandwich_io_client_tcp_new(
        #       const char *hostname, const uint16_t port, bool async,
        #       struct SandwichCIOOwned **ownedIO);
        "sandwich_io_client_tcp_new": (
            [
                ctypes.c_char_p,
                ctypes.c_uint16,
                ctypes.c_bool,
                ctypes.POINTER(ctypes.POINTER(SandwichIO.OwnedIO)),
            ],
            ctypes.c_int32,
        ),
        # enum SandwichCIOError sandwich_io_socket_wrap_new(
        #       int fd, struct SandwichCIOOwned **ownedIO);
        "sandwich_io_socket_wrap_new": (
            [
                ctypes.c_int,
                ctypes.POINTER(ctypes.POINTER(SandwichIO.OwnedIO)),
            ],
            ctypes.c_int32,
        ),
        # void sandwich_io_owned_free(struct SandwichCIOOwned *ownedIO)
        "sandwich_io_owned_free": ([ctypes.c_void_p], None),
    }

    def __init__(self, dllpath: typing.Optional[pathlib.Path] = None):
        """Inits a Sandwich handle, optionally with a path to `libsandwich.so`.

        Args:
            dllpath:
                Path to the Sandwich shared library. if None, common paths will
                be inspected.

        Raises:
            FileNotFoundError: The Sandwich shared library could not be found.
        """

        if Sandwich.lib is None:
            if dllpath is None:
                dllpath = _find_sandwich_dll()

            if dllpath is None:
                dllpath = "libsandwich_full.so"

            if isinstance(dllpath, pathlib.Path):
                dllpath = dllpath.resolve()

            Sandwich.lib = ctypes.cdll.LoadLibrary(dllpath)

        if Sandwich.syms is None:
            Sandwich.syms = {}

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
        if name in Sandwich.syms:
            f = Sandwich.syms[name]
        else:
            f = Sandwich.resolve(name)
            Sandwich.syms[name] = f

        f.argtypes, f.restype = Sandwich.func_types[name]
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
            return getattr(Sandwich.lib, name)
        except AttributeError:
            raise AttributeError(
                f"Sandwich lib does not have symbol {name!r}"
            ) from None
