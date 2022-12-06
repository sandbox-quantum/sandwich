#!/usr/bin/env python3

import errno
import pathlib
import socket
import sys
import threading
import typing

import saq.pqc.sandwich.proto.api.v1.configuration_pb2 as SandwichAPI
import saq.pqc.sandwich.proto.api.v1.encoding_format_pb2 as EncodingFormat
import saq.pqc.sandwich.proto.sandwich_pb2 as SandwichProto
import saq.pqc.sandwich.proto.tunnel_pb2 as SandwichTunnelProto
import saq.pqc.sandwich.python.errors as errors
import saq.pqc.sandwich.python.io as SandwichIO
from saq.pqc.sandwich.python.sandwich import Context, Sandwich, Tunnel

_LISTENING_ADDRESS = "127.0.0.1"
_LISTENING_PORT = 1339

_PING_MSG = b"PING"
_PONG_MSG = b"PONG"

_CERT_PATH = "testdata/cert.pem"
_KEY_PATH = "testdata/key.pem"

_DEFAULT_KEM = "kyber512"


class Socket(SandwichIO.IO):
    def __init__(self, sock: socket.socket):
        self._sock = sock

    _ERRNO_EXCEPTIONS_MAP = (
        (
            (
                errno.EINPROGRESS,
                errno.EINTR,
            ),
            errors.IOInProgressException,
        ),
        (
            (
                errno.EAGAIN,
                errno.EWOULDBLOCK,
            ),
            errors.IOWouldBlockException,
        ),
        (
            (
                errno.ENOTSOCK,
                errno.EPROTOTYPE,
                errno.EBADF,
            ),
            errors.IOInvalidException,
        ),
        (
            (
                errno.EACCES,
                errno.EPERM,
                errno.ETIMEDOUT,
                errno.ENETUNREACH,
                errno.ECONNREFUSED,
            ),
            errors.IORefusedException,
        ),
    )

    def _errno_to_exception(self, err):
        for val in Socket._ERRNO_EXCEPTIONS_MAP:
            if err in val[0]:
                return val[1]()
        return errors.IOUnknownException()

    def read(self, n, tunnel_state: SandwichTunnelProto.State) -> bytes:
        try:
            return self._sock.recv(n)
        except OSError as e:
            raise self._errno_to_exception(e.errno)

    def write(self, buf, tunnel_state: SandwichTunnelProto.State) -> int:
        try:
            return self._sock.send(buf)
        except Exception as e:
            raise self._errno_to_exception(e.errno)

    def close(self):
        self._sock.close()


def create_server_conf(s: Sandwich) -> Context:
    """Creates the configuration for the server.

    Returns:
        Configuration for the server.
    """
    conf = SandwichAPI.Configuration()
    conf.protocol = SandwichAPI.PROTO_TLS_13
    conf.impl = SandwichAPI.IMPL_OPENSSL1_1_1_OQS

    conf.server.tls.common_options.kem.append(_DEFAULT_KEM)
    conf.server.tls.certificate.static.data.filename = _CERT_PATH
    conf.server.tls.certificate.static.format = EncodingFormat.ENCODING_FORMAT_PEM

    conf.server.tls.private_key.static.data.filename = _KEY_PATH
    conf.server.tls.private_key.static.format = EncodingFormat.ENCODING_FORMAT_PEM

    return Context(s, conf)


def create_client_conf(s: Sandwich) -> Context:
    """Creates the configuration for the client.

    Returns:
        Configuration for the client.
    """
    conf = SandwichAPI.Configuration()
    conf.protocol = SandwichAPI.PROTO_TLS_13
    conf.impl = SandwichAPI.IMPL_OPENSSL1_1_1_OQS

    conf.client.tls.common_options.kem.append(_DEFAULT_KEM)

    cert = conf.client.tls.trusted_certificates.add().static
    cert.data.filename = _CERT_PATH
    cert.format = EncodingFormat.ENCODING_FORMAT_PEM

    return Context(s, conf)


def create_ios() -> (SandwichIO.IO, SandwichIO.IO):
    s1, s2 = socket.socketpair(
        family=socket.AF_UNIX, type=socket.SOCK_STREAM | socket.SOCK_NONBLOCK
    )
    return Socket(s1), Socket(s2)


def main():
    s = Sandwich()

    client_conf = create_client_conf(s)
    assert client_conf != None

    server_conf = create_server_conf(s)
    assert server_conf != None

    client_io, server_io = create_ios()
    assert client_io != None
    assert server_io != None

    server = Tunnel(server_conf, server_io)
    assert server != None

    client = Tunnel(client_conf, client_io)
    assert client != None

    e = None
    try:
        client.handshake()
        assert False, "expected  WANT_READ, got None"
    except errors.HandshakeException as e:
        assert isinstance(
            e, errors.HandshakeWantReadException
        ), f"expected WANT_READ, got {e}"
    except Exception as e:
        assert False, f"expected Tunnel.HandshakeWantReadException, got {e}"

    e = None
    try:
        server.handshake()
        assert False, "expected  WANT_READ, got None"
    except errors.HandshakeException as e:
        assert isinstance(
            e, errors.HandshakeWantReadException
        ), f"expected WANT_READ, got {e}"
    except Exception as e:
        assert False, f"expected Tunnel.HandshakeWantReadException, got {e}"

    e = None
    try:
        client.handshake()
    except Exception as e:
        assert False, f"expected no error, got {e}"

    e = None
    try:
        server.handshake()
    except Exception as e:
        assert False, f"expected no error, got {e}"

    state = client.state()
    assert (
        state == client.State.STATE_HANDSHAKE_DONE
    ), f"Expected state HANDSHAKE_DONE, got {state}"

    state = server.state()
    assert (
        state == client.State.STATE_HANDSHAKE_DONE
    ), f"Expected state HANDSHAKE_DONE, got {state}"

    w = 0
    try:
        w = client.write(_PING_MSG)
    except errors.RecordPlaneException as e:
        assert False, f"expected no error, got {e}"
    assert w == len(_PING_MSG), f"Expected {len(_PING_MSG)} bytes written, got {w}"

    try:
        data = server.read(len(_PING_MSG))
    except errors.RecordPlaneException as e:
        assert False, f"expected no error, got {e}"
    assert len(data) == len(_PING_MSG), f"Expected {len(_PING_MSG)} bytes read, got {w}"
    assert data == _PING_MSG, f"Expected msg {_PING_MSG} from client, got {data}"

    w = 0
    try:
        w = server.write(_PONG_MSG)
    except errors.RecordPlaneException as e:
        assert False, f"expected no error, got {e}"
    assert w == len(_PONG_MSG), f"Expected {len(_PING_MSG)} bytes written, got {w}"

    try:
        data = client.read(len(_PONG_MSG))
    except errors.RecordPlaneException as e:
        assert False, f"expected no error, got {e}"
    assert len(data) == len(_PONG_MSG), f"Expected {len(_PING_MSG)} bytes read, got {w}"
    assert data == _PONG_MSG, f"Expected msg {_PING_MSG} from client, got {data}"

    client.close()
    server.close()


if __name__ == "__main__":
    main()
