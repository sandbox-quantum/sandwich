import asyncio
import ssl
from time import process_time

_PING_MSG = b"PING"
_PONG_MSG = b"PONG"

_CERT_PATH = "testdata/cert.pem"


async def client_to_server(
    server_host: str, server_port: int, ssl_context: ssl.SSLContext
):
    """Connect to a server with a Context"""
    reader, writer = await asyncio.open_connection(
        server_host, server_port, ssl=ssl_context
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


async def main(count, server_address):
    server_host, server_port = server_address

    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.load_verify_locations(_CERT_PATH)
    client_ctx.verify_mode = ssl.CERT_REQUIRED
    client_ctx.check_hostname = False

    # Start benchmark
    start = process_time()

    tasks = [
        asyncio.create_task(
            client_to_server(
                server_host=server_host, server_port=server_port, ssl_context=client_ctx
            )
        )
        for _ in range(count)
    ]
    await asyncio.wait(tasks)

    # Wait for all tasks to complete
    elapsed = process_time() - start
    return elapsed


if __name__ == "__main__":
    server_address = "127.0.0.1", 7653

    for count in range(1_000, 3_000, 500):
        create_time = asyncio.run(main(count, server_address))
        create_per_second = 1 / (create_time / count)
        print(f"{count:,} connections \t {create_per_second:0,.0f} conns per/s")