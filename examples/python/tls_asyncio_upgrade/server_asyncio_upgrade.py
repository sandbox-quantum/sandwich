import asyncio
import ssl


server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
server_ctx.load_cert_chain(_CERT_EXPIRED_PATH, _PRIVATE_KEY_EXPIRED_PATH)


async def server_to_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Handle a connection from client with Context"""
    # Upgrade connection to TLS
    # start_tls available since Python 3.11
    await writer.start_tls(server_ctx)

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
    server = await asyncio.start_server(
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
