import socketserver

import pysandwich.proto.api.v1.compliance_pb2 as Compliance
import pysandwich.proto.api.v1.configuration_pb2 as SandwichAPI
import pysandwich.proto.api.v1.encoding_format_pb2 as EncodingFormat
import pysandwich.proto.api.v1.verifiers_pb2 as SandwichVerifiers
import pysandwich.io as SandwichIO
from pysandwich.sandwich import Context, Sandwich, Tunnel

_PING_MSG = b"PING"
_PONG_MSG = b"PONG"

_CIPHER = "prime256v1"
_CERT_PATH = "testdata/falcon1024.cert.pem"
_KEY_PATH = "testdata/falcon1024.key.pem"


def create_server_conf(cipher_opts: str) -> SandwichAPI:
    """Create Server configuration"""

    conf = SandwichAPI.Configuration()
    conf.impl = SandwichAPI.IMPL_OPENSSL1_1_1_OQS

    conf.compliance.classical_choice = Compliance.CLASSICAL_ALGORITHMS_ALLOW
    conf.server.tls.common_options.kem.append(cipher_opts)
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

    return conf


class MyTCPSandwich(socketserver.BaseRequestHandler):
    # The context is shared and immutable
    s = Sandwich()
    server_conf = create_server_conf(_CIPHER)
    server_ctx = Context.from_config(s, server_conf)
    verifier = SandwichVerifiers.TunnelVerifier()
    verifier.empty_verifier.CopyFrom(SandwichVerifiers.EmptyVerifier())

    def handle(self):
        # self.request is the TCP socket connected to the client
        server = Tunnel(self.server_ctx, SandwichIO.Socket(self.request), self.verifier)

        # 1. Handshake
        server.handshake()
        state = server.state()
        assert (
            state == server.State.STATE_HANDSHAKE_DONE
        ), f"Expected state HANDSHAKE_DONE, got {state}"

        # 2. Expect PING
        data = server.read(len(_PING_MSG))
        assert data == _PING_MSG, f"Expected msg {_PING_MSG} from server, got {data}"

        # 3. Send PONG
        w = server.write(_PONG_MSG)

        assert w == len(_PONG_MSG), f"Expected {len(_PONG_MSG)} bytes written, got {w}"

        # 4. Close tunnel
        server.close()


def main(server_address):
    server = socketserver.TCPServer(server_address, MyTCPSandwich)
    server.serve_forever()


if __name__ == "__main__":
    server_address = "127.0.0.1", 7652
    main(server_address)
