# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

import selectors
import socket
import sys
from multiprocessing.connection import Connection
from typing import BinaryIO

import pysandwich.proto.api.v1.compliance_pb2 as Compliance
import pysandwich.proto.api.v1.configuration_pb2 as SandwichTunnelProto
import pysandwich.proto.api.v1.verifiers_pb2 as SandwichVerifiers
import pysandwich.errors as SandwichErrors
import pysandwich.io_helpers as SandwichIOHelpers
import pysandwich.tunnel as SandwichTunnel
from pysandwich.proto.api.v1.tunnel_pb2 import TunnelConfiguration
from pysandwich.sandwich import Sandwich


def create_client_conf(tls: str) -> SandwichTunnelProto:
    """Create Client configuration."""
    conf = SandwichTunnelProto.Configuration()
    conf.impl = SandwichTunnelProto.IMPL_BORINGSSL_OQS

    tls_config = conf.client.tls.common_options.tls_config
    match tls:
        case "tls13":
            # Sets TLS 1.3 Compliance, Key Establishment (KE), and Ciphersuite.
            tls_config.tls13.ke.append("X25519")
            tls_config.tls13.compliance.classical_choice = (
                Compliance.CLASSICAL_ALGORITHMS_ALLOW
            )
            tls_config.tls13.ciphersuite.extend(["TLS_CHACHA20_POLY1305_SHA256"])
        case "tls12":
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
            tls_config.tls12.ciphersuite.extend(ciphers)
        case _:
            raise NotImplementedError("TLS version is not supported")

    conf.client.tls.common_options.empty_verifier.CopyFrom(
        SandwichVerifiers.EmptyVerifier()
    )

    return conf


def is_localhost(hostname: str):
    try:
        # Get the IP address for the given hostname
        ip_address = socket.gethostbyname(hostname)

        # Check if the IP address is a localhost IP address
        return ip_address in ("127.0.0.1", "::1")
    except socket.gaierror:
        # If the hostname cannot be resolved, it's not localhost
        return False


def create_client_tun_conf(hostname: str) -> TunnelConfiguration:
    tun_conf = TunnelConfiguration()
    if not is_localhost(hostname):
        tun_conf.server_name_indication = hostname
    tun_conf.verifier.empty_verifier.CopyFrom(SandwichVerifiers.EmptyVerifier())

    return tun_conf


def run_client(
    host: str,
    port: int,
    input_r: Connection | BinaryIO,
    output_w: Connection | BinaryIO,
    client_ctx_conf: SandwichTunnel.Context,
):
    """Connect to server with a Context"""
    client_io = socket.create_connection((host, port))
    swio = SandwichIOHelpers.io_socket_wrap(client_io)
    client_tun_conf = create_client_tun_conf(host)

    client = SandwichTunnel.Tunnel(
        client_ctx_conf,
        swio,
        client_tun_conf,
    )
    assert client is not None

    client.handshake()
    state = client.state()
    assert (
        state == client.State.STATE_HANDSHAKE_DONE
    ), f"Expected state HANDSHAKE_DONE, got {state}"

    sel = selectors.DefaultSelector()
    sel.register(input_r, selectors.EVENT_READ, data=None)
    sel.register(client_io, selectors.EVENT_READ, data=None)

    client_io.setblocking(False)

    while True:
        events = sel.select(timeout=None)

        for key, _ in events:
            if key.fileobj is client_io:
                try:
                    data = client.read(1024)
                except SandwichErrors.RecordPlaneWantReadException:
                    continue

                if not data:
                    sel.unregister(client_io)
                else:
                    if isinstance(output_w, Connection):
                        output_w.send_bytes(data)
                    else:
                        output_w.write(b">")
                        output_w.write(data)
                        output_w.flush()

            elif key.fileobj is input_r:
                if isinstance(input_r, Connection):
                    data = input_r.recv_bytes(16)
                else:
                    data = input_r.readline()

                if not data:
                    sel.unregister(input_r)
                else:
                    client_io.setblocking(True)
                    client.write(data)
                    client_io.setblocking(False)

    client.close()


def main(
    hostname: str,
    port: int,
    tls: str,
    input_r: Connection | BinaryIO,
    output_w: Connection | BinaryIO,
):
    sw = Sandwich()
    client_conf = create_client_conf(tls)
    client_ctx = SandwichTunnel.Context.from_config(sw, client_conf)

    run_client(hostname, port, input_r, output_w, client_ctx)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(prog="TLS client using Sandwich")
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        help="Port to connect to (defaults to 443)",
        default=443,
        required=True,
    )
    parser.add_argument("--host", type=str, help="Host to connect to", required=True)
    parser.add_argument(
        "--tls_version",
        type=str,
        help="TLS version: --tls_version tls13 or tls12",
        required=True,
    )
    args = parser.parse_args()

    main(args.host, args.port, args.tls_version, sys.stdin.buffer, sys.stdout.buffer)
