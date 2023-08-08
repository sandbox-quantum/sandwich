# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

import array
import fcntl
import select
import socket
import termios

import pysandwich.proto.api.v1.compliance_pb2 as Compliance
import pysandwich.proto.api.v1.configuration_pb2 as SandwichTunnelProto
import pysandwich.proto.api.v1.verifiers_pb2 as SandwichVerifiers
import pysandwich.errors as SandwichErrors
import pysandwich.io as SandwichIO
import pysandwich.tunnel as SandwichTunnel
from pysandwich.proto.api.v1.tunnel_pb2 import TunnelConfiguration
from pysandwich.sandwich import Sandwich


def create_client_conf() -> SandwichTunnelProto:
    """Create Client configuration"""
    conf = SandwichTunnelProto.Configuration()
    # conf.impl = SandwichTunnelProto.IMPL_OPENSSL1_1_1_OQS
    conf.impl = SandwichTunnelProto.IMPL_BORINGSSL_OQS

    conf.compliance.classical_choice = Compliance.CLASSICAL_ALGORITHMS_ALLOW
    conf.client.tls.common_options.kem.append("kyber768")
    conf.client.tls.common_options.kem.append("prime256v1")

    conf.client.tls.common_options.empty_verifier.CopyFrom(
        SandwichVerifiers.EmptyVerifier()
    )

    return conf


def run_client(peer_address, input_, output, client_ctx: SandwichTunnel.Context):
    """Connect to server with a Context"""
    client_io = socket.create_connection(peer_address)
    tunnel_configuration = TunnelConfiguration()
    tunnel_configuration.verifier.empty_verifier.CopyFrom(
        SandwichVerifiers.EmptyVerifier()
    )

    client = SandwichTunnel.Tunnel(
        client_ctx,
        SandwichIO.io_socket_wrap(Sandwich(), client_io),
        tunnel_configuration,
    )
    assert client is not None

    client.handshake()
    state = client.state()
    assert (
        state == client.State.STATE_HANDSHAKE_DONE
    ), f"Expected state HANDSHAKE_DONE, got {state}"

    client_io.setblocking(False)
    inputs = [client_io, input_]
    outputs = []

    avail_arr = array.array("i", [0])
    while inputs:
        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for r in readable:
            if r is client_io:
                try:
                    data = client.read(1024)
                except SandwichErrors.RecordPlaneWantReadException:
                    continue

                if not data:
                    inputs.remove(r)
                else:
                    output.write(data)
                    output.flush()
            elif r is input_:
                fcntl.ioctl(input_.fileno(), termios.FIONREAD, avail_arr)
                data = input_.read(avail_arr[0])
                if not data:
                    inputs.remove(r)
                else:
                    client_io.setblocking(True)
                    client.write(data)
                    client_io.setblocking(False)

    client.close()


def main(host, port, input_, output):
    client_conf = create_client_conf()
    client_ctx = SandwichTunnel.Context.from_config(Sandwich(), client_conf)

    run_client((host, port), input_, output, client_ctx)


if __name__ == "__main__":
    import argparse
    import sys

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
