import ctypes
import socket

import pysandwich.proto.io_pb2 as SandwichIOProto
import pysandwich.proto.tunnel_pb2 as SandwichTunnelProto
from pysandwich import sandwich
from pysandwich.io import IOException, OwnedIO, TunnelIO

"""Sandwich I/O Helper API.

This API creates commonly used IO objects (such as TCP).
"""


class SwTunnelIOWrapper(TunnelIO):
    """A SwTunnelIOWrapper to allow python to use rust created IO objects."""

    def __init__(self, owned_io):
        self._owned_io = owned_io
        self._tunnel_io = sandwich.sandwich().c_call(
            "sandwich_owned_io_to_tunnel_io",
            ctypes.byref(self._owned_io),
        )
        self._sock = None

    @property
    def sock(self):
        return self._sock

    @sock.setter
    def sock(self, sock: socket.socket):
        if not isinstance(sock, socket.socket):
            raise ValueError("sock must be a socket type")
        self._sock = sock

    def read(self, n) -> bytes:
        buf = ctypes.create_string_buffer(n)
        err = ctypes.pointer(ctypes.c_int(0))
        bytes_read = self._tunnel_io.base.readfn(self._tunnel_io.base.uarg, buf, n, err)
        if err.contents.value != SandwichIOProto.IOERROR_OK:
            raise IOException(err.contents.value)

        buf = buf[0:bytes_read]
        return bytes(buf)

    def write(self, buf) -> int:
        err = ctypes.pointer(ctypes.c_int(0))
        bytes_written = self._tunnel_io.base.writefn(
            self._tunnel_io.base.uarg, buf, len(buf), err
        )
        if err.contents.value != SandwichIOProto.IOERROR_OK:
            raise IOException(err.contents.value)
        return bytes_written

    def flush(self):
        err = self._tunnel_io.base.flushfn(
            self._tunnel_io.base.uarg,
        )
        if err != SandwichIOProto.IOERROR_OK:
            raise IOException(err)

    def set_state(self, tunnel_state: SandwichTunnelProto.State):
        if self._tunnel_io.set_statefn:
            self._tunnel_io.set_statefn(
                self._tunnel_io.base.uarg, ctypes.c_int(tunnel_state)
            )

    def __del__(self):
        sandwich.sandwich().c_call(
            "sandwich_io_owned_free", ctypes.pointer(self._owned_io)
        )


def io_client_tcp_new(hostname: str, port: int, is_blocking: bool) -> SwTunnelIOWrapper:
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
    io = SwTunnelIOWrapper(owned_ptr.contents)
    return io


def io_client_turbo_new(
    udp_hostname: str,
    udp_port: int,
    tcp_hostname: str,
    tcp_port: int,
    is_blocking: bool,
) -> SwTunnelIOWrapper:
    if not isinstance(udp_hostname, str):
        raise ValueError("udp_hostname must be a str type")
    if not isinstance(udp_port, int):
        raise ValueError("udp_port must be an int type")
    if not isinstance(tcp_hostname, str):
        raise ValueError("tcp_hostname must be a str type")
    if not isinstance(tcp_port, int):
        raise ValueError("tcp_port must be an int type")

    owned_ptr = ctypes.POINTER(OwnedIO)()
    err = sandwich.sandwich().c_call(
        "sandwich_io_client_turbo_new",
        ctypes.c_char_p(udp_hostname.encode("utf-8")),
        ctypes.c_ushort(udp_port),
        ctypes.c_char_p(tcp_hostname.encode("utf-8")),
        ctypes.c_ushort(tcp_port),
        ctypes.c_bool(is_blocking),
        ctypes.byref(owned_ptr),
    )
    if err != SandwichIOProto.IOERROR_OK:
        raise IOException(err)
    io = SwTunnelIOWrapper(owned_ptr.contents)
    return io


def io_socket_wrap(sock: socket.socket) -> SwTunnelIOWrapper:
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
    io = SwTunnelIOWrapper(owned_ptr.contents)
    # We need to keep a reference around to keep the garbage
    # collector happy.
    io.sock = sock
    return io
