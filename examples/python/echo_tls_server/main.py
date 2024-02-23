# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only


# --8<-- [start:py_imports_proto]
import pysandwich.proto.api.v1.compliance_pb2 as Compliance
import pysandwich.proto.api.v1.configuration_pb2 as SandwichTunnelProto
import pysandwich.proto.api.v1.encoding_format_pb2 as EncodingFormat
import pysandwich.proto.api.v1.listener_configuration_pb2 as ListenerAPI
import pysandwich.proto.api.v1.verifiers_pb2 as SandwichVerifiers
import pysandwich.io_helpers as SandwichIOHelpers
import pysandwich.tunnel as SandwichTunnel
from pysandwich.proto.api.v1.tunnel_pb2 import TunnelConfiguration
from pysandwich import listener as SandwichListener
from pysandwich.sandwich import Sandwich

# --8<-- [end:py_imports_proto]


# --8<-- [start:py_server_cfg]
def create_server_conf(cert_path: str, key_path: str) -> SandwichTunnelProto:
    conf = SandwichTunnelProto.Configuration()
    conf.impl = SandwichTunnelProto.IMPL_OPENSSL1_1_1_OQS

    # Sets TLS 1.3 Compliance, Key Establishment (KE) and Ciphersuites.
    tls13 = conf.server.tls.common_options.tls13
    tls13.ke.append("X25519")
    tls13.compliance.classical_choice = Compliance.CLASSICAL_ALGORITHMS_ALLOW

    # Sets TLS 1.2 Ciphersuite.
    tls12 = conf.server.tls.common_options.tls12
    ciphers = [
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
    ]
    tls12.ciphersuite.extend(ciphers)

    conf.server.tls.common_options.empty_verifier.CopyFrom(
        SandwichVerifiers.EmptyVerifier()
    )
    conf.server.tls.common_options.identity.certificate.static.data.filename = cert_path
    conf.server.tls.common_options.identity.certificate.static.format = (
        EncodingFormat.ENCODING_FORMAT_PEM
    )

    conf.server.tls.common_options.identity.private_key.static.data.filename = key_path
    conf.server.tls.common_options.identity.private_key.static.format = (
        EncodingFormat.ENCODING_FORMAT_PEM
    )

    return conf


def create_server_tun_conf() -> TunnelConfiguration:
    tun_conf = TunnelConfiguration()
    tun_conf.verifier.empty_verifier.CopyFrom(SandwichVerifiers.EmptyVerifier())
    return tun_conf


def create_tcp_listener(hostname: str, port: int) -> SandwichListener.Listener:
    """Creates the configuration for a TCP listener.
    Returns:
        A TCP listener which is listening on hostname:port.
    """
    conf = ListenerAPI.ListenerConfiguration()
    conf.tcp.addr.hostname = hostname
    conf.tcp.addr.port = port
    conf.tcp.blocking_mode = ListenerAPI.BLOCKINGMODE_BLOCKING

    return SandwichListener.Listener(conf)


# --8<-- [end:py_server_cfg]
sw = Sandwich()


def server_to_client(server_ctx_conf, swio: SandwichIOHelpers.SwTunnelIOWrapper):
    # --8<-- [start:py_ctx]
    server_tun_conf = create_server_tun_conf()
    server = SandwichTunnel.Tunnel(server_ctx_conf, swio, server_tun_conf)

    server.handshake()
    state = server.state()
    assert (
        state == server.State.STATE_HANDSHAKE_DONE
    ), f"Expected state HANDSHAKE_DONE, got {state}"

    while True:
        data = b""
        while True:
            c = server.read(1)
            data += c
            if c == b"\n":
                break
        server.write(data)

    server.close()
    # --8<-- [end:py_ctx]


def main(hostname: str, port: int, cert: str, key: str):
    server_ctx_conf = SandwichTunnel.Context.from_config(
        sw, create_server_conf(cert, key)
    )
    listener = create_tcp_listener(hostname, port)
    listener.listen()

    while True:
        server_io = listener.accept()
        server_to_client(server_ctx_conf, server_io)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(prog="Echo TLS server using Sandwich")
    parser.add_argument("-p", "--port", type=int, help="Listening port", required=True)
    parser.add_argument("--host", type=str, help="Listening host", default="127.0.0.1")
    parser.add_argument(
        "-k", "--key", type=str, help="Path to the server private key", required=True
    )
    parser.add_argument(
        "-c",
        "--cert",
        type=str,
        help="Path to the server public certificate",
        required=True,
    )
    args = parser.parse_args()

    main(args.host, args.port, args.cert, args.key)
