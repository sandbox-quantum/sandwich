# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

import pysandwich.proto.api.v1.configuration_pb2 as SandwichAPI
import pysandwich.proto.api.v1.encoding_format_pb2 as EncodingFormat
import pysandwich.proto.api.v1.listener_configuration_pb2 as ListenerAPI
import pysandwich.proto.api.v1.verifiers_pb2 as SandwichVerifiers
import pysandwich.errors as errors
from pysandwich.proto.api.v1.tunnel_pb2 import TunnelConfiguration
from pysandwich import listener, tunnel
from pysandwich.io_helpers import io_client_turbo_new
from pysandwich.sandwich import Sandwich

_LISTENING_ADDRESS = "127.0.0.1"
_LISTENING_PORT = 1339

_PING_MSG = b"PING"
_PONG_MSG = b"PONG"

_CERT_PATH = "testdata/falcon1024.cert.pem"
_KEY_PATH = "testdata/falcon1024.key.pem"
_CERT_EXPIRED_PATH = "testdata/cert_expired.pem"
_PRIVATE_KEY_EXPIRED_PATH = "testdata/private_key_cert_expired.pem"

_DEFAULT_KE = "kyber512"


def create_server_conf(sw: Sandwich) -> tunnel.Context:
    """Creates the configuration for the server.

    Returns:
        Configuration for the server.
    """
    conf = SandwichAPI.Configuration()
    conf.impl = SandwichAPI.IMPL_OPENSSL1_1_1_OQS

    # Sets TLS 1.3 Compliance and Key Establishment (KE)
    tls13 = conf.server.tls.common_options.tls13
    tls13.ke.append(_DEFAULT_KE)

    conf.server.tls.common_options.alpn_protocols.extend(
        ["http/1.1", "h2", "h2c", "h3"]
    )
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

    return tunnel.Context.from_config(sw, conf)


def create_client_conf(sw: Sandwich) -> tunnel.Context:
    """Creates the configuration for the client.

    Returns:
        Configuration for the client.
    """
    conf = SandwichAPI.Configuration()
    conf.impl = SandwichAPI.IMPL_OPENSSL1_1_1_OQS

    # Sets TLS 1.3 Compliance and Key Establishment (KE)
    tls13 = conf.client.tls.common_options.tls13
    tls13.ke.append(_DEFAULT_KE)

    conf.client.tls.common_options.alpn_protocols.extend(
        ["http/1.1", "h2", "h2c", "h3"]
    )

    cert = conf.client.tls.common_options.x509_verifier.trusted_cas.add().static
    cert.data.filename = _CERT_PATH
    cert.format = EncodingFormat.ENCODING_FORMAT_PEM

    buf = conf.SerializeToString()
    return tunnel.Context.from_bytes(sw, buf)


def create_turbo_listener(
    udp_hostname, udp_port, tcp_hostname, tcp_port
) -> listener.Listener:
    """Creates a Turbo listener.
    Returns:
        A Turbo listener which is listening on udp_hostname:udp_port and tcp_hostname:tcp_port.
    """
    conf = ListenerAPI.ListenerConfiguration()
    conf.turbo.udp.hostname = udp_hostname
    conf.turbo.udp.port = udp_port
    conf.turbo.tcp.hostname = tcp_hostname
    conf.turbo.tcp.port = tcp_port
    conf.turbo.blocking_mode = ListenerAPI.BLOCKINGMODE_NONBLOCKING

    return listener.Listener(conf)


def main():
    sw = Sandwich()
    client_conf = create_client_conf(sw)
    assert client_conf is not None

    server_conf = create_server_conf(sw)
    assert server_conf is not None

    tunnel_configuration = TunnelConfiguration()
    tunnel_configuration.verifier.empty_verifier.CopyFrom(
        SandwichVerifiers.EmptyVerifier()
    )
    listener = create_turbo_listener(
        _LISTENING_ADDRESS, _LISTENING_PORT, _LISTENING_ADDRESS, _LISTENING_PORT
    )
    listener.listen()

    client_io = io_client_turbo_new(
        _LISTENING_ADDRESS,
        _LISTENING_PORT,
        _LISTENING_ADDRESS,
        _LISTENING_PORT,
        False,
    )
    client = tunnel.Tunnel(client_conf, client_io, tunnel_configuration)
    assert client is not None

    try:
        client.handshake()
    except errors.HandshakeException as e:
        assert isinstance(
            e, errors.HandshakeWantReadException
        ), f"expected WANT_READ, got {e}"

    server_io = None
    while server_io is None:
        try:
            server_io = listener.accept()
        except Exception:
            pass

    server = tunnel.Tunnel(server_conf, server_io, tunnel_configuration)
    assert server is not None

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

    # Because of request-based fragmentation, we have to do this a few times.
    for _ in range(0, 10):
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
        except errors.HandshakeException as e:
            assert isinstance(
                e, errors.HandshakeWantReadException
            ), f"expected WANT_READ, got {e}"
        except Exception as e:
            raise AssertionError(f"expected no error, got {e}") from e

    while True:
        try:
            server.handshake()
            break
        except errors.HandshakeException as e:
            assert isinstance(
                e, errors.HandshakeWantReadException
            ), f"expected WANT_READ, got {e}"
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
        except errors.RecordPlaneException as e:
            if isinstance(e, errors.RecordPlaneWantReadException):
                continue
            else:
                print(type(e))
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
        except errors.RecordPlaneException as e:
            if isinstance(e, errors.RecordPlaneWantReadException):
                continue
            else:
                print(type(e))
                raise AssertionError(f"expected no error, got {e}") from e
    assert len(data) == len(_PONG_MSG), f"Expected {len(_PING_MSG)} bytes read, got {w}"
    assert data == _PONG_MSG, f"Expected msg {_PING_MSG} from client, got {data}"

    client.close()
    server.close()


if __name__ == "__main__":
    main()
