#!/usr/bin/env python3
# Copyright 2023 SandboxAQ
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import socket

import pysandwich.proto.api.v1.configuration_pb2 as SandwichAPI
import pysandwich.proto.api.v1.encoding_format_pb2 as EncodingFormat
import pysandwich.errors as errors
import pysandwich.io as SandwichIO
from pysandwich.sandwich import Context, Sandwich, Tunnel

_LISTENING_ADDRESS = "127.0.0.1"
_LISTENING_PORT = 1339

_PING_MSG = b"PING"
_PONG_MSG = b"PONG"

_CERT_PATH = "testdata/cert.pem"
_KEY_PATH = "testdata/key.pem"

_DEFAULT_KEM = "kyber512"


def create_server_conf(s: Sandwich) -> Context:
    """Creates the configuration for the server.

    Returns:
        Configuration for the server.
    """
    conf = SandwichAPI.Configuration()
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
    conf.impl = SandwichAPI.IMPL_OPENSSL1_1_1_OQS

    conf.client.tls.common_options.kem.append(_DEFAULT_KEM)

    cert = conf.client.tls.trusted_certificates.add().static
    cert.data.filename = _CERT_PATH
    cert.format = EncodingFormat.ENCODING_FORMAT_PEM

    return Context(s, conf)


def create_ios() -> (SandwichIO.IO, SandwichIO.IO):
    s1, s2 = socket.socketpair(family=socket.AF_UNIX, type=socket.SOCK_STREAM)
    s1.setblocking(0)
    s2.setblocking(0)
    return SandwichIO.Socket(s1), SandwichIO.Socket(s2)


def main():
    s = Sandwich()

    client_conf = create_client_conf(s)
    assert client_conf is not None

    server_conf = create_server_conf(s)
    assert server_conf is not None

    client_io, server_io = create_ios()
    assert client_io is not None
    assert server_io is not None

    server = Tunnel(server_conf, server_io)
    assert server is not None

    client = Tunnel(client_conf, client_io)
    assert client is not None

    try:
        client.handshake()
        AssertionError("expected  WANT_READ, got None")
    except errors.HandshakeException as e:
        assert isinstance(
            e, errors.HandshakeWantReadException
        ), f"expected WANT_READ, got {e}"
    except Exception as e:
        AssertionError(f"expected Tunnel.HandshakeWantReadException, got {e}")

    try:
        server.handshake()
        AssertionError("expected  WANT_READ, got None")
    except errors.HandshakeException as e:
        assert isinstance(
            e, errors.HandshakeWantReadException
        ), f"expected WANT_READ, got {e}"
    except Exception as e:
        AssertionError(f"expected Tunnel.HandshakeWantReadException, got {e}")

    try:
        client.handshake()
    except Exception as e:
        AssertionError(f"expected no error, got {e}")

    try:
        server.handshake()
    except Exception as e:
        AssertionError(f"expected no error, got {e}")

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
        AssertionError(f"expected no error, got {e}")
    assert w == len(_PING_MSG), f"Expected {len(_PING_MSG)} bytes written, got {w}"

    try:
        data = server.read(len(_PING_MSG))
    except errors.RecordPlaneException as e:
        AssertionError(f"expected no error, got {e}")
    assert len(data) == len(_PING_MSG), f"Expected {len(_PING_MSG)} bytes read, got {w}"
    assert data == _PING_MSG, f"Expected msg {_PING_MSG} from client, got {data}"

    w = 0
    try:
        w = server.write(_PONG_MSG)
    except errors.RecordPlaneException as e:
        AssertionError(f"expected no error, got {e}")
    assert w == len(_PONG_MSG), f"Expected {len(_PING_MSG)} bytes written, got {w}"

    try:
        data = client.read(len(_PONG_MSG))
    except errors.RecordPlaneException as e:
        AssertionError(f"expected no error, got {e}")
    assert len(data) == len(_PONG_MSG), f"Expected {len(_PING_MSG)} bytes read, got {w}"
    assert data == _PONG_MSG, f"Expected msg {_PING_MSG} from client, got {data}"

    client.close()
    server.close()


if __name__ == "__main__":
    main()
