import ctypes
import socket

import pysandwich.proto.io_pb2 as SandwichIOProto
import pysandwich.proto.tunnel_pb2 as SandwichTunnelProto
from pysandwich import sandwich
from pysandwich.io import IO, IOException, OwnedIO

"""Sandwich I/O Helper API.

This API creates commonly used IO objects (such as TCP).

Author: jgoertzen-sb
"""


class SwOwnedIOWrapper(IO):
    """A SwOwnedIOWrapper to allow python to use rust created IO objects."""

    def __init__(self, owned_io):
        self._owned_io = owned_io
        self._sock = None

    @property
    def sock(self):
        return self._sock

    @sock.setter
    def sock(self, sock: socket.socket):
        if not isinstance(sock, socket.socket):
            raise ValueError("sock must be a socket type")
        self._sock = sock

    def read(self, n, tunnel_state: SandwichTunnelProto.State) -> bytes:
        buf = ctypes.create_string_buffer(n)
        err = ctypes.pointer(ctypes.c_int(0))
        bytes_read = self._owned_io.io.contents.readfn(
            self._owned_io.io.contents.uarg, buf, n, tunnel_state, err
        )
        if err.contents.value != SandwichIOProto.IOERROR_OK:
            raise IOException(err.contents.value)

        buf = buf[0:bytes_read]
        return bytes(buf)

    def write(self, buf, tunnel_state: SandwichTunnelProto.State) -> int:
        err = ctypes.pointer(ctypes.c_int(0))
        bytes_written = self._owned_io.io.contents.writefn(
            self._owned_io.io.contents.uarg, buf, len(buf), tunnel_state, err
        )
        if err.contents.value != SandwichIOProto.IOERROR_OK:
            raise IOException(err.contents.value)
        return bytes_written

    def __del__(self):
        sandwich.sandwich().c_call(
            "sandwich_io_owned_free", ctypes.pointer(self._owned_io)
        )


def io_client_tcp_new(hostname: str, port: int, is_blocking: bool) -> SwOwnedIOWrapper:
    if not isinstance(hostname, str):
        raise ValueError("hostname must be a str type")
    if not isinstance(port, int):
        raise ValueError("port must be an int type")

    owned_ptr = ctypes.POINTER(OwnedIO)()
    err = sandwich.sandwich().c_call(
        "sandwich_io_client_tcp_new",
        ctypes.c_char_p(hostname.encode("utf-8")),
        ctypes.c_ushort(port),
        ctypes.c_bool(is_blocking),
        ctypes.byref(owned_ptr),
    )
    if err != SandwichIOProto.IOERROR_OK:
        raise IOException(err)
    io = SwOwnedIOWrapper(owned_ptr.contents)
    return io


def io_socket_wrap(sock: socket.socket) -> SwOwnedIOWrapper:
    if not isinstance(sock, socket.socket):
        raise ValueError("sock must be a socket type")

    owned_ptr = ctypes.POINTER(OwnedIO)()
    err = sandwich.sandwich().c_call(
        "sandwich_io_socket_wrap_new",
        ctypes.c_int(sock.fileno()),
        ctypes.byref(owned_ptr),
    )
    if err != SandwichIOProto.IOERROR_OK:
        raise IOException(err)
    io = SwOwnedIOWrapper(owned_ptr.contents)
    # We need to keep a reference around to keep the garbage
    # collector happy.
    io.sock = sock
    return io
