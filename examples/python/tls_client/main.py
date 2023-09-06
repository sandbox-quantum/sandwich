# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

import selectors
import socket
import sys

import pysandwich.proto.api.v1.compliance_pb2 as Compliance
import pysandwich.proto.api.v1.configuration_pb2 as SandwichTunnelProto
import pysandwich.proto.api.v1.verifiers_pb2 as SandwichVerifiers
import pysandwich.errors as SandwichErrors
import pysandwich.io_helpers as SandwichIOHelpers
import pysandwich.tunnel as SandwichTunnel
from pysandwich.proto.api.v1.tunnel_pb2 import TunnelConfiguration


def create_client_conf() -> SandwichTunnelProto:
    """Create Client configuration"""
    conf = SandwichTunnelProto.Configuration()
    # conf.impl = SandwichTunnelProto.IMPL_OPENSSL1_1_1_OQS
    conf.impl = SandwichTunnelProto.IMPL_BORINGSSL_OQS

    conf.compliance.classical_choice = Compliance.CLASSICAL_ALGORITHMS_ALLOW
    conf.client.tls.common_options.kem.append("prime256v1")

    conf.client.tls.common_options.empty_verifier.CopyFrom(
        SandwichVerifiers.EmptyVerifier()
    )

    return conf


def is_localhost(hostname):
    try:
        # Get the IP address for the given hostname
        ip_address = socket.gethostbyname(hostname)

        # Check if the IP address is a localhost IP address
        return ip_address in ("127.0.0.1", "::1")
    except socket.gaierror:
        # If the hostname cannot be resolved, it's not localhost
        return False


def create_client_tun_conf(hostname) -> TunnelConfiguration:
    tun_conf = TunnelConfiguration()
    if not is_localhost(hostname):
        tun_conf.server_name_indication = hostname
    tun_conf.verifier.empty_verifier.CopyFrom(SandwichVerifiers.EmptyVerifier())

    return tun_conf


def run_client(host, port, input_r, output_w, client_ctx_conf: SandwichTunnel.Context):
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
                    if isinstance(output_w, type(sys.stdout.buffer)):
                        output_w.write(b">")
                        output_w.write(data)
                        output_w.flush()
                    else:
                        output_w.send_bytes(data)

            elif key.fileobj is input_r:
                if isinstance(input_r, type(sys.stdin.buffer)):
                    data = input_r.readline()
                else:
                    data = input_r.recv_bytes(16)

                if not data:
                    sel.unregister(input_r)
                else:
                    client_io.setblocking(True)
                    client.write(data)
                    client_io.setblocking(False)

    client.close()


def main(hostname, port, input_r, output_w):
    client_conf = create_client_conf()
    client_ctx = SandwichTunnel.Context.from_config(client_conf)

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
    args = parser.parse_args()

    main(args.host, args.port, sys.stdin.buffer, sys.stdout.buffer)
