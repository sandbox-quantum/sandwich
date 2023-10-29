# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only
import random
import threading

import pysandwich.proto.api.v1.configuration_pb2 as SandwichAPI
import pysandwich.proto.api.v1.encoding_format_pb2 as EncodingFormat
import pysandwich.proto.api.v1.listener_configuration_pb2 as ListenerAPI
import pysandwich.proto.api.v1.verifiers_pb2 as SandwichVerifiers
import pysandwich.errors as errors
from pysandwich.proto.api.v1.tunnel_pb2 import TunnelConfiguration
from pysandwich import listener, tunnel
from pysandwich.io_helpers import io_client_tcp_new
from pysandwich.sandwich import Sandwich

_LISTENING_ADDRESS = "127.0.0.1"
_LISTENING_PORT = random.randint(1226, 65535)

_PING_MSG = b"PING"
_PONG_MSG = b"PONG"

_CERT_PATH = "testdata/falcon1024.cert.pem"
_KEY_PATH = "testdata/falcon1024.key.pem"

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

    cert = conf.client.tls.common_options.x509_verifier.trusted_cas.add().static
    cert.data.filename = _CERT_PATH
    cert.format = EncodingFormat.ENCODING_FORMAT_PEM

    buf = conf.SerializeToString()
    return tunnel.Context.from_bytes(sw, buf)


def create_tcp_listener(hostname, port) -> listener.Listener:
    """Creates the configuration for a TCP listener.
    Returns:
        A TCP listener which is listening on hostname:port.
    """
    conf = ListenerAPI.ListenerConfiguration()
    conf.tcp.addr.hostname = hostname
    conf.tcp.addr.port = port
    conf.tcp.blocking_mode = ListenerAPI.BLOCKINGMODE_BLOCKING

    return listener.Listener(conf)


def server_thread(hostname, port, server_conf, exceptions, server_ready):
    if server_conf is None:
        # prevent the other thread from hanging
        server_ready.set()
        exceptions.append(AssertionError("server_conf is None"))
        return

    tunnel_configuration = TunnelConfiguration()
    tunnel_configuration.verifier.empty_verifier.CopyFrom(
        SandwichVerifiers.EmptyVerifier()
    )
    try:
        listener = create_tcp_listener(hostname, port)
        listener.listen()
    except Exception as e:
        # prevent the other thread from hanging
        server_ready.set()
        exceptions.append(e)
        return
    server_ready.set()
    server_io = None
    try:
        server_io = listener.accept()
    except Exception as e:
        exceptions.append(e)
        return
    server = tunnel.Tunnel(server_conf, server_io, tunnel_configuration)
    if server is None:
        exceptions.append(AssertionError("server is None"))
        return
    try:
        server.handshake()
    except Exception as e:
        exceptions.append(e)
        server.close()
        return
    state = server.state()
    if state != server.State.STATE_HANDSHAKE_DONE:
        exceptions.append(AssertionError(f"Expected state HANDSHAKE_DONE, got {state}"))
        server.close()
        return
    try:
        data = server.read(len(_PING_MSG))
    except errors.RecordPlaneException as e:
        exceptions.append(e)
        server.close()
        return
    if len(data) != len(_PING_MSG):
        exceptions.append(
            AssertionError(f"Expected {len(_PING_MSG)} bytes read, got {len(data)}")
        )
        server.close()
        return
    if data != _PING_MSG:
        exceptions.append(
            AssertionError(f"Expected msg {_PING_MSG} from client, got {data}")
        )
        server.close()
        return

    w = 0
    try:
        w = server.write(_PONG_MSG)
    except errors.RecordPlaneException as e:
        exceptions.append(e)
        server.close()
        return
    if w != len(_PONG_MSG):
        exceptions.append(
            AssertionError(f"Expected {len(_PING_MSG)} bytes written, got {w}")
        )
    server.close()


def client_thread(hostname, port, client_conf, exceptions, server_ready):
    if client_conf is None:
        exceptions.append(AssertionError("client_conf is None"))
        return

    tunnel_configuration = TunnelConfiguration()
    tunnel_configuration.verifier.empty_verifier.CopyFrom(
        SandwichVerifiers.EmptyVerifier()
    )
    server_ready.wait()
    client_io = None
    try:
        client_io = io_client_tcp_new(hostname, port, True)
    except Exception as e:
        exceptions.append(AssertionError(f"failed to create client_io: {e}"))
        return
    client = tunnel.Tunnel(client_conf, client_io, tunnel_configuration)
    if client is None:
        exceptions.append(AssertionError("client is None"))
        return

    try:
        client.handshake()
    except Exception as e:
        client.close()
        exceptions.append(e)
        return

    state = client.state()
    if state != client.State.STATE_HANDSHAKE_DONE:
        exceptions.append(AssertionError(f"Expected state HANDSHAKE_DONE, got {state}"))
        client.close()
        return

    w = 0
    try:
        w = client.write(_PING_MSG)
    except errors.RecordPlaneException as e:
        exceptions.append(e)
        client.close()
        return
    if w != len(_PING_MSG):
        exceptions.append(
            AssertionError(f"Expected {len(_PING_MSG)} bytes written, got {w}")
        )
        client.close()
        return

    try:
        data = client.read(len(_PONG_MSG))
    except errors.RecordPlaneException as e:
        exceptions.append(e)
        client.close()
        return
    if len(data) != len(_PONG_MSG):
        exceptions.append(
            AssertionError(f"Expected {len(_PING_MSG)} bytes read, got {len(data)}")
        )
        client.close()
        return
    if data != _PONG_MSG:
        exceptions.append(
            AssertionError(f"Expected msg {_PING_MSG} from client, got {data}")
        )
    client.close()


def main():
    sw = Sandwich()
    threads = []
    client_conf = create_client_conf(sw)
    assert client_conf is not None
    server_conf = create_server_conf(sw)
    assert server_conf is not None
    server_ready = threading.Event()
    client_exceptions = []
    client_args = (
        _LISTENING_ADDRESS,
        _LISTENING_PORT,
        client_conf,
        client_exceptions,
        server_ready,
    )
    server_exceptions = []
    server_args = (
        _LISTENING_ADDRESS,
        _LISTENING_PORT,
        server_conf,
        server_exceptions,
        server_ready,
    )
    threads.append(threading.Thread(target=client_thread, args=client_args))
    threads.append(threading.Thread(target=server_thread, args=server_args))

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    if client_exceptions != []:
        print("===========Client thread exceptions===========")
    for e in client_exceptions:
        print(e)
    if server_exceptions != []:
        print("===========Server thread exceptions===========")
    for e in server_exceptions:
        print(e)
    if client_exceptions != [] or server_exceptions != []:
        print("==============================================", flush=True)
        raise AssertionError("A child thread threw an exception")


if __name__ == "__main__":
    main()
