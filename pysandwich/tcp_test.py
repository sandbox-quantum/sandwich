# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

import random
import socket

import pysandwich.proto.api.v1.configuration_pb2 as SandwichAPI
import pysandwich.proto.api.v1.encoding_format_pb2 as EncodingFormat
import pysandwich.proto.api.v1.verifiers_pb2 as SandwichVerifiers
import pysandwich.errors as errors
import pysandwich.io as SandwichIO
from pysandwich.proto.api.v1.tunnel_pb2 import TunnelConfiguration
from pysandwich import tunnel
from pysandwich.io import io_client_tcp_new, io_socket_wrap
from pysandwich.sandwich import Sandwich

_LISTENING_ADDRESS = "127.0.0.1"
_LISTENING_PORT = random.randint(1226, 65535)

_PING_MSG = b"PING"
_PONG_MSG = b"PONG"

_CERT_PATH = "testdata/falcon1024.cert.pem"
_KEY_PATH = "testdata/falcon1024.key.pem"
_CERT_EXPIRED_PATH = "testdata/cert_expired.pem"
_PRIVATE_KEY_EXPIRED_PATH = "testdata/private_key_cert_expired.pem"

_DEFAULT_KEM = "kyber512"


def create_server_conf(s: Sandwich) -> tunnel.Context:
    """Creates the configuration for the server.

    Returns:
        Configuration for the server.
    """
    conf = SandwichAPI.Configuration()
    conf.impl = SandwichAPI.IMPL_OPENSSL1_1_1_OQS

    conf.server.tls.common_options.kem.append(_DEFAULT_KEM)
    conf.server.tls.common_options.empty_verifier.CopyFrom(
        SandwichVerifiers.EmptyVerifier()
    )
    conf.server.tls.common_options.identity.certificate.static.data.filename = (
        _CERT_PATH
    )
    conf.server.tls.common_options.identity.certificate.static.format = (
        EncodingFormat.ENCODING_FORMAT_PEM
    )

    conf.server.tls.common_options.identity.private_key.static.data.filename = _KEY_PATH
    conf.server.tls.common_options.identity.private_key.static.format = (
        EncodingFormat.ENCODING_FORMAT_PEM
    )

    return tunnel.Context.from_config(s, conf)


def create_client_conf(s: Sandwich) -> tunnel.Context:
    """Creates the configuration for the client.

    Returns:
        Configuration for the client.
    """
    conf = SandwichAPI.Configuration()
    conf.impl = SandwichAPI.IMPL_OPENSSL1_1_1_OQS

    conf.client.tls.common_options.kem.append(_DEFAULT_KEM)

    cert = conf.client.tls.common_options.x509_verifier.trusted_cas.add().static
    cert.data.filename = _CERT_PATH
    cert.format = EncodingFormat.ENCODING_FORMAT_PEM

    buf = conf.SerializeToString()
    return tunnel.Context.from_bytes(s, buf)


def create_expired_server_conf(s: Sandwich) -> tunnel.Context:
    """Creates the configuration for the server using an expired certificate.

    Returns:
        Configuration for the server.
    """
    conf = SandwichAPI.Configuration()
    conf.impl = SandwichAPI.IMPL_OPENSSL1_1_1_OQS

    conf.server.tls.common_options.kem.append(_DEFAULT_KEM)
    conf.server.tls.common_options.empty_verifier.CopyFrom(
        SandwichVerifiers.EmptyVerifier()
    )
    conf.server.tls.common_options.identity.certificate.static.data.filename = (
        _CERT_EXPIRED_PATH
    )
    conf.server.tls.common_options.identity.certificate.static.format = (
        EncodingFormat.ENCODING_FORMAT_PEM
    )

    conf.server.tls.common_options.identity.private_key.static.data.filename = (
        _PRIVATE_KEY_EXPIRED_PATH
    )
    conf.server.tls.common_options.identity.private_key.static.format = (
        EncodingFormat.ENCODING_FORMAT_PEM
    )

    return tunnel.Context.from_config(s, conf)


def create_expired_client_conf(s: Sandwich) -> tunnel.Context:
    """Creates the configuration for the client using an expired certificate.

    Returns:
        Configuration for the client.
    """
    conf = SandwichAPI.Configuration()
    conf.impl = SandwichAPI.IMPL_OPENSSL1_1_1_OQS

    conf.client.tls.common_options.kem.append(_DEFAULT_KEM)

    cert = conf.client.tls.common_options.x509_verifier.trusted_cas.add().static
    cert.data.filename = _CERT_EXPIRED_PATH
    cert.format = EncodingFormat.ENCODING_FORMAT_PEM

    buf = conf.SerializeToString()
    return tunnel.Context.from_bytes(s, buf)


def create_ios(s: "Sandwich", hostname, port) -> tuple[SandwichIO.IO, SandwichIO.IO]:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((hostname, port))
    server_socket.listen(1)
    client_io = io_client_tcp_new(s, hostname, port, False)
    server_socket, _ = server_socket.accept()
    server_socket.setblocking(0)
    return client_io, io_socket_wrap(s, server_socket)


def main():
    s = Sandwich()

    client_conf = create_client_conf(s)
    assert client_conf is not None

    server_conf = create_server_conf(s)
    assert server_conf is not None

    client_io, server_io = create_ios(s, _LISTENING_ADDRESS, _LISTENING_PORT)
    assert client_io is not None
    assert server_io is not None

    tunnel_configuration = TunnelConfiguration()
    tunnel_configuration.verifier.empty_verifier.CopyFrom(
        SandwichVerifiers.EmptyVerifier()
    )

    server = tunnel.Tunnel(server_conf, server_io, tunnel_configuration)
    assert server is not None

    client = tunnel.Tunnel(client_conf, client_io, tunnel_configuration)
    assert client is not None

    try:
        client.handshake()
        AssertionError("expected  WANT_READ, got None")
    except errors.HandshakeException as e:
        assert isinstance(
            e, errors.HandshakeWantReadException
        ), f"expected WANT_READ, got {e}"
    except Exception as e:
        raise AssertionError(
            f"expected Tunnel.HandshakeWantReadException, got {e}"
        ) from e

    try:
        server.handshake()
        AssertionError("expected  WANT_READ, got None")
    except errors.HandshakeException as e:
        assert isinstance(
            e, errors.HandshakeWantReadException
        ), f"expected WANT_READ, got {e}"
    except Exception as e:
        raise AssertionError(
            f"expected Tunnel.HandshakeWantReadException, got {e}"
        ) from e

    while True:
        try:
            client.handshake()
            break
        except errors.HandshakeWantReadException:
            pass
        except Exception as e:
            raise AssertionError(f"expected no error, got {e}") from e
    while True:
        try:
            server.handshake()
            break
        except errors.HandshakeWantReadException:
            pass
        except Exception as e:
            raise AssertionError(f"expected no error, got {e}") from e

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
        raise AssertionError(f"expected no error, got {e}") from e
    assert w == len(_PING_MSG), f"Expected {len(_PING_MSG)} bytes written, got {w}"

    while True:
        try:
            data = server.read(len(_PING_MSG))
            break
        except errors.RecordPlaneWantReadException:
            pass
        except errors.RecordPlaneException as e:
            raise AssertionError(f"expected no error, got {e}") from e
    assert len(data) == len(_PING_MSG), f"Expected {len(_PING_MSG)} bytes read, got {w}"
    assert data == _PING_MSG, f"Expected msg {_PING_MSG} from client, got {data}"

    w = 0
    try:
        w = server.write(_PONG_MSG)
    except errors.RecordPlaneException as e:
        raise AssertionError(f"expected no error, got {e}") from e
    assert w == len(_PONG_MSG), f"Expected {len(_PING_MSG)} bytes written, got {w}"

    while True:
        try:
            data = client.read(len(_PONG_MSG))
            break
        except errors.RecordPlaneWantReadException:
            pass
        except errors.RecordPlaneException as e:
            raise AssertionError(f"expected no error, got {e}") from e
    assert len(data) == len(_PONG_MSG), f"Expected {len(_PING_MSG)} bytes read, got {w}"
    assert data == _PONG_MSG, f"Expected msg {_PING_MSG} from client, got {data}"

    client.close()
    server.close()


if __name__ == "__main__":
    main()
