import asyncio
import logging

import pysandwich.proto.api.v1.configuration_pb2 as SandwichAPI
import pysandwich.proto.api.v1.encoding_format_pb2 as EncodingFormat
import pysandwich.proto.api.v1.verifiers_pb2 as SandwichVerifiers
import pysandwich.sandwich_async as stream
from pysandwich.sandwich import Context, Sandwich

_PING_MSG = b"PING"
_PONG_MSG = b"PONG"

_CERT_PATH = "testdata/falcon1024.cert.pem"
_KEY_PATH = "testdata/falcon1024.key.pem"
_CERT_EXPIRED_PATH = "testdata/cert_expired.pem"
_PRIVATE_KEY_EXPIRED_PATH = "testdata/private_key_cert_expired.pem"

# Disable logging message
# "returning true from eof_received() has no effect when using ssl"
asyncio.log.logger.setLevel(logging.ERROR)


def create_server_conf(cipher_opts: str) -> SandwichAPI:
    """Create Server configuration"""

    conf = SandwichAPI.Configuration()
    conf.impl = SandwichAPI.IMPL_OPENSSL1_1_1_OQS

    conf.server.tls.common_options.kem.append(cipher_opts)
    conf.server.tls.common_options.empty_verifier.CopyFrom(
        SandwichVerifiers.EmptyVerifier()
    )

    conf.server.tls.common_options.identity.certificate.static.data.filename = (
        _CERT_PATH
    )
    conf.server.tls.common_options.identity.private_key.static.data.filename = _KEY_PATH

    conf.server.tls.common_options.identity.certificate.static.format = (
        EncodingFormat.ENCODING_FORMAT_PEM
    )

    conf.server.tls.common_options.identity.private_key.static.format = (
        EncodingFormat.ENCODING_FORMAT_PEM
    )

    return conf


server_config = create_server_conf("kyber512")
server_ctx = Context.from_config(Sandwich(), server_config)
server_verifier = SandwichVerifiers.TunnelVerifier()
server_verifier.empty_verifier.CopyFrom(SandwichVerifiers.EmptyVerifier())


async def server_to_client(reader, writer):
    """Handle a connection from client with Context"""

    # Upgrade to TLS
    await writer.start_tls(
        sandwich_context=server_ctx,
        sandwich_verifier=server_verifier,
    )

    # Here is the plan:
    # 2. Server expects: PING
    # 3. Server sends: PONG
    # 4. Closes tunnel

    # 2. Expect PING
    data = await reader.read(len(_PING_MSG))
    assert data == _PING_MSG, f"Expected msg {_PING_MSG} from server, got {data}"

    # 3. Send PONG
    writer.write(_PONG_MSG)
    await writer.drain()

    # 4. Close tunnel
    writer.close()
    await writer.wait_closed()


async def main(server_host: str, server_port: int):
    server = await stream.start_server(
        server_to_client,
        server_host,
        server_port,
        reuse_address=True,
        reuse_port=True,
    )

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    server_host, server_port = "127.0.0.1", 7653

    asyncio.run(main(server_host, server_port))
