# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

import random
import socket
import time
from contextlib import nullcontext as does_not_raise

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import pysandwich.proto.api.v1.configuration_pb2 as SandwichAPI
import pysandwich.proto.api.v1.encoding_format_pb2 as EncodingFormat
import pysandwich.proto.api.v1.listener_configuration_pb2 as ListenerAPI
import pysandwich.proto.api.v1.verifiers_pb2 as SandwichVerifiers
import pysandwich.errors as errors
import pysandwich.io as SandwichIO
from pysandwich.proto.api.v1.tunnel_pb2 import TunnelConfiguration
from pysandwich import listener, tunnel
from pysandwich.io_helpers import io_client_tcp_new, io_socket_wrap
from pysandwich.sandwich import Sandwich

_LISTENING_ADDRESS = "127.0.0.1"
_LISTENING_PORT = random.randint(1226, 65535)
_DEFAULT_KE = "kyber512"

_PING_MSG = b"PING"
_PONG_MSG = b"PONG"

_CERT_PATH = "testdata/falcon1024.cert.pem"
_KEY_PATH = "testdata/falcon1024.key.pem"
_CERT_EXPIRED_PATH = "testdata/cert_expired.pem"
_PRIVATE_KEY_EXPIRED_PATH = "testdata/private_key_cert_expired.pem"

_DEFAULT_KEM = "kyber512"


@pytest.fixture
def good_server_ctx() -> tunnel.Context:
    """Creates the configuration for the server.

    Returns:
        Configuration for the server.
    """
    sw = Sandwich()
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


@pytest.fixture
def good_client_ctx() -> tunnel.Context:
    """Creates the configuration for the client.

    Returns:
        Configuration for the client.
    """
    sw = Sandwich()
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


@pytest.fixture
def expired_server_ctx() -> tunnel.Context:
    """Creates the configuration for the server using an expired certificate.

    Returns:
        Configuration for the server.
    """
    sw = Sandwich()
    conf = SandwichAPI.Configuration()
    conf.impl = SandwichAPI.IMPL_OPENSSL1_1_1_OQS

    # Sets TLS 1.3 Compliance and Key Establishment (KE)
    tls13 = conf.server.tls.common_options.tls13
    tls13.ke.append(_DEFAULT_KE)

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

    return tunnel.Context.from_config(sw, conf)


@pytest.fixture
def expired_client_ctx() -> tunnel.Context:
    """Creates the configuration for the client using an expired certificate.

    Returns:
        Configuration for the client.
    """
    sw = Sandwich()
    conf = SandwichAPI.Configuration()
    conf.impl = SandwichAPI.IMPL_OPENSSL1_1_1_OQS

    # Sets TLS 1.3 Compliance and Key Establishment (KE)
    tls13 = conf.client.tls.common_options.tls13
    tls13.ke.append(_DEFAULT_KE)

    cert = conf.client.tls.common_options.x509_verifier.trusted_cas.add().static
    cert.data.filename = _CERT_EXPIRED_PATH
    cert.format = EncodingFormat.ENCODING_FORMAT_PEM

    buf = conf.SerializeToString()
    return tunnel.Context.from_bytes(sw, buf)


@pytest.fixture
def make_io() -> tuple[SandwichIO.IO, SandwichIO.IO]:
    def _make_io() -> tuple[socket.socket, socket.socket]:
        s1, s2 = socket.socketpair(family=socket.AF_UNIX, type=socket.SOCK_STREAM)
        s1.setblocking(False)
        s2.setblocking(False)
        return s1, s2

    s1, s2 = _make_io()
    yield (io_socket_wrap(s1), io_socket_wrap(s2))


@pytest.fixture
def make_tcp_io() -> tuple[SandwichIO.IO, SandwichIO.IO]:
    print(f"{_LISTENING_ADDRESS}:{_LISTENING_PORT}")

    conf = ListenerAPI.ListenerConfiguration()
    conf.tcp.addr.hostname = _LISTENING_ADDRESS
    conf.tcp.addr.port = _LISTENING_PORT
    conf.tcp.blocking_mode = ListenerAPI.BLOCKINGMODE_NONBLOCKING

    server_listener = listener.Listener(conf)
    server_listener.listen()

    client_io = io_client_tcp_new(_LISTENING_ADDRESS, _LISTENING_PORT, False)
    server_io = server_listener.accept()

    yield (client_io, server_io)


@pytest.fixture
def tun_conf():
    tunnel_configuration = TunnelConfiguration()
    tunnel_configuration.verifier.empty_verifier.CopyFrom(
        SandwichVerifiers.EmptyVerifier()
    )
    return tunnel_configuration


@pytest.mark.parametrize(
    "client,server,io_type,expectation",
    [
        ("good_client_ctx", "good_server_ctx", "make_io", does_not_raise()),
        (
            "expired_client_ctx",
            "good_server_ctx",
            "make_io",
            pytest.raises(errors.HandshakeError),
        ),
        (
            "good_client_ctx",
            "expired_server_ctx",
            "make_io",
            pytest.raises(errors.HandshakeError),
        ),
        ("good_client_ctx", "good_server_ctx", "make_tcp_io", does_not_raise()),
    ],
)
def test_tunnel_handshake(client, server, io_type, expectation, request, tun_conf):
    with expectation:
        client_ctx = request.getfixturevalue(client)
        server_ctx = request.getfixturevalue(server)
        io_type = request.getfixturevalue(io_type)

        assert client_ctx is not None
        assert server_ctx is not None

        client_io, server_io = io_type

        assert client_io is not None
        assert server_io is not None

        server = tunnel.Tunnel(server_ctx, server_io, tun_conf)
        client = tunnel.Tunnel(client_ctx, client_io, tun_conf)
        assert server is not None
        assert client is not None

        assert client.state() == client.State.STATE_NOT_CONNECTED
        assert server.state() == server.State.STATE_NOT_CONNECTED

        trace.set_tracer_provider(TracerProvider())
        span_exporter = InMemorySpanExporter()
        span_processor = SimpleSpanProcessor(span_exporter)
        trace.get_tracer_provider().add_span_processor(span_processor)
        tracer = trace.get_tracer("Pytest")

        span_trace_id = None
        with tracer.start_as_current_span("TopLevelSpan") as span:
            span_trace_id = span._context.trace_id
            server.set_tracer(span_exporter)

        try:
            client.handshake()
        except errors.HandshakeException as e:
            assert isinstance(
                e, errors.HandshakeWantReadException
            ), f"expected WANT_READ, got {e}"

        try:
            server.handshake()
        except errors.HandshakeException as e:
            assert isinstance(
                e, errors.HandshakeWantReadException
            ), f"expected WANT_READ, got {e}"

        client.handshake()
        server.handshake()

        assert client.state() == client.State.STATE_HANDSHAKE_DONE
        assert server.state() == server.State.STATE_HANDSHAKE_DONE

        bytes_written = client.write(_PING_MSG)
        assert bytes_written == len(_PING_MSG)

        while True:
            try:
                bytes_read = server.read(len(_PING_MSG))
                break
            except errors.RecordPlaneWantReadException:
                pass

        assert len(bytes_read) == len(_PING_MSG)
        assert _PING_MSG == bytes_read

        bytes_written = server.write(_PONG_MSG)
        assert bytes_written == len(_PONG_MSG)

        while True:
            try:
                bytes_read = client.read(len(_PING_MSG))
                break
            except errors.RecordPlaneWantReadException:
                pass

        assert len(bytes_read) == len(_PONG_MSG)
        assert _PONG_MSG == bytes_read

        server.close()
        client.close()
        time.sleep(1)
        server.tracer.export_span_buffer()

        spans = span_exporter.get_finished_spans()
        finished_handshake = False
        last_span = spans[-1:][0]
        assert span_trace_id == last_span._context.trace_id

        for event in last_span.events:
            for attribute in event.attributes:
                if (
                    attribute.key == "Handshake"
                    and attribute.value.string_value == "Finished"
                ):
                    finished_handshake = True
                    break

        assert finished_handshake


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
