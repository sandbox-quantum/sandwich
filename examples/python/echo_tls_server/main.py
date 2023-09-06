# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

import socketserver

# --8<-- [start:py_imports_proto]
import pysandwich.proto.api.v1.compliance_pb2 as Compliance
import pysandwich.proto.api.v1.configuration_pb2 as SandwichTunnelProto
import pysandwich.proto.api.v1.encoding_format_pb2 as EncodingFormat
import pysandwich.proto.api.v1.verifiers_pb2 as SandwichVerifiers
import pysandwich.io_helpers as SandwichIOHelpers
import pysandwich.tunnel as SandwichTunnel
from pysandwich.proto.api.v1.tunnel_pb2 import TunnelConfiguration

# --8<-- [end:py_imports_proto]


# --8<-- [start:py_server_cfg]
def create_server_conf(cert_path: str, key_path: str) -> SandwichTunnelProto:
    conf = SandwichTunnelProto.Configuration()
    conf.impl = SandwichTunnelProto.IMPL_OPENSSL1_1_1_OQS

    conf.compliance.classical_choice = Compliance.CLASSICAL_ALGORITHMS_ALLOW
    conf.server.tls.common_options.kem.append("prime256v1")

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


# --8<-- [end:py_server_cfg]


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        swio = SandwichIOHelpers.io_socket_wrap(self.request)
        server_ctx_conf = self.ctx_conf
        # --8<-- [start:py_new_tunnel]
        server_tun_conf = create_server_tun_conf()
        server = SandwichTunnel.Tunnel(server_ctx_conf, swio, server_tun_conf)
        # --8<-- [end:py_new_tunnel]

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


def tcp_handler(key, cert):
    # --8<-- [start:py_ctx]
    server_ctx_conf = SandwichTunnel.Context.from_config(create_server_conf(cert, key))
    # --8<-- [end:py_ctx]
    EchoHandler.ctx_conf = server_ctx_conf
    return EchoHandler


def main(host, port, key, cert):
    handler = tcp_handler(key, cert)
    server = socketserver.TCPServer((host, port), handler)
    server.serve_forever()


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

    main(args.host, args.port, args.key, args.cert)
