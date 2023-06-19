import asyncio
from time import process_time

import pysandwich.proto.api.v1.configuration_pb2 as SandwichAPI
import pysandwich.proto.api.v1.encoding_format_pb2 as EncodingFormat
import pysandwich.proto.api.v1.verifiers_pb2 as SandwichVerifiers
import pysandwich.sandwich_async as stream
from pysandwich.sandwich import Context, Sandwich

_PING_MSG = b"PING"
_PONG_MSG = b"PONG"

_CERT_PATH = "testdata/falcon1024.cert.pem"


def create_client_conf(cipher_opts: str) -> SandwichAPI:
    """Create Client configuration"""
    conf = SandwichAPI.Configuration()
    conf.impl = SandwichAPI.IMPL_OPENSSL1_1_1_OQS
    conf.client.tls.common_options.kem.append(cipher_opts)

    cert = conf.client.tls.common_options.x509_verifier.trusted_cas.add().static
    cert.data.filename = _CERT_PATH
    cert.format = EncodingFormat.ENCODING_FORMAT_PEM

    return conf


client_config = create_client_conf("kyber512")
client_ctx = Context.from_config(Sandwich(), client_config)
client_verifier = SandwichVerifiers.TunnelVerifier()
client_verifier.empty_verifier.CopyFrom(SandwichVerifiers.EmptyVerifier())


async def client_to_server(reader, writer):
    """Connect to a server with a Context"""

    # Upgrade to TLS
    await writer.start_tls(
        sandwich_context=client_ctx,
        sandwich_verifier=client_verifier,
    )

    # Here is the plan:
    # 2. Client sends: PING
    # 3. Client expects: PONG
    # 4. Closes tunnel

    # 2. Send PING
    writer.write(_PING_MSG)
    await writer.drain()

    # 3. Expect PONG
    data = await reader.read(len(_PONG_MSG))
    assert data == _PONG_MSG, f"Expected msg {_PONG_MSG} from server, got {data}"

    # 4. Close tunnel
    writer.close()
    await writer.wait_closed()


async def tls_client_to_server(server_host: int, server_port: int):
    # Establish connection then upgrade to tls
    reader, writer = await stream.open_connection(host=server_host, port=server_port)

    await client_to_server(reader, writer)


async def main(count, server_address):
    server_host, server_port = server_address

    # Start benchmark
    start = process_time()

    tasks = [
        asyncio.create_task(
            tls_client_to_server(server_host=server_host, server_port=server_port)
        )
        for _ in range(count)
    ]
    await asyncio.wait(tasks)

    # Wait for all tasks to complete
    elapsed = process_time() - start
    return elapsed


if __name__ == "__main__":
    server_address = "127.0.0.1", 7653

    for count in range(2_00, 1_000, 200):
        create_time = asyncio.run(main(count, server_address))
        create_per_second = 1 / (create_time / count)
        print(f"{count:,} connections \t {create_per_second:0,.0f} conns per/s")
