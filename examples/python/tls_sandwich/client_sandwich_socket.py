import socket
from time import process_time

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


def create_client_conf(cipher_opts: str) -> SandwichAPI:
    """Create Client configuration"""
    conf = SandwichAPI.Configuration()
    conf.impl = SandwichAPI.IMPL_OPENSSL1_1_1_OQS

    conf.compliance.classical_choice = Compliance.CLASSICAL_ALGORITHMS_ALLOW
    conf.client.tls.common_options.kem.append(cipher_opts)

    cert = conf.client.tls.common_options.x509_verifier.trusted_cas.add().static
    cert.data.filename = _CERT_PATH
    cert.format = EncodingFormat.ENCODING_FORMAT_PEM

    return conf


def sandwich_client_to_server(server_address, client_ctx: Context):
    """Connect to server with a Context"""
    client_io = socket.create_connection(server_address)
    verifier = SandwichVerifiers.TunnelVerifier()
    verifier.empty_verifier.CopyFrom(SandwichVerifiers.EmptyVerifier())

    client = Tunnel(client_ctx, SandwichIO.Socket(client_io), verifier)
    assert client is not None

    # Here is the plan:
    # 1. Handshake
    # 2. Client sends: PING
    # 3. Client expects: PONG
    # 4. Closes tunnel

    # 1. Handshake
    client.handshake()
    state = client.state()
    assert (
        state == client.State.STATE_HANDSHAKE_DONE
    ), f"Expected state HANDSHAKE_DONE, got {state}"

    # 2. Send PING
    w = client.write(_PING_MSG)
    assert w == len(_PING_MSG), f"Expected {len(_PING_MSG)} bytes written, got {w}"

    # 3. Expect PONG
    data = client.read(len(_PONG_MSG))
    assert data == _PONG_MSG, f"Expected msg {_PONG_MSG} from server, got {data}"

    # 4. Close tunnel
    client.close()


def main(count):
    server_address = "127.0.0.1", 7652
    client_conf = create_client_conf(_CIPHER)
    # Prepare the client context
    s = Sandwich()
    client_ctx = Context.from_config(s, client_conf)

    start = process_time()
    for _ in range(count):
        sandwich_client_to_server(server_address, client_ctx=client_ctx)
    elapsed = process_time() - start
    return elapsed


if __name__ == "__main__":
    for count in range(200, 2_000, 200):
        create_time = main(count)
        create_per_second = 1 / (create_time / count)
        print(f"{count:,} connections \t {create_per_second:0,.0f} conns per/s")
