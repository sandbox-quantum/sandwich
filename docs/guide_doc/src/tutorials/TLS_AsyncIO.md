# TLS Sandwich and AsyncIO

## TLS with AsyncIO + SSL

Do you know that in Python we can have `asyncio` together with `ssl` to make TLS connection?
Let's follow the 4 steps plan in [TLS with SSL](#tls-with-ssl).

### Client

Here is the code for the client. The handshake is performed when the connection is initiated, so we only need to write steps 2 to 4.

```python
import asyncio
import ssl

_PING_MSG = b"PING"
_PONG_MSG = b"PONG"

async def client_to_server(
    server_host: str, server_port: int, ssl_context: ssl.SSLContext
):
    """Make a connection to server with Context"""
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
```

and here is the rest of the program:

1. We setup the client context, that uses certificate we supply.
2. We run on localhost, thus set `ssl.CERT_REQUIRED` to use the provided certificate, we don't want the hostname to be checked so we set `client_ctx.check_hostname = False`.

```python
from time import process_time

_CERT_PATH = "testdata/cert.pem"

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
```

### Server

Similar to the plan of Client, server expects to see PING message and sends back PONG, then closes the TLS connection.


```python
import asyncio

_PING_MSG = b"PING"
_PONG_MSG = b"PONG"

async def server_to_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Receive a connection from client with Context"""
    # Here is the plan:
    # 2. Server expects: PING
    # 3. Server sends: PONG
    # 4. Closes tunnel

    # 2. Expects PING
    data = await reader.read(len(_PING_MSG))
    assert data == _PING_MSG, f"Expected msg {_PING_MSG} from server, got {data}"

    # 3. Sends PONG
    writer.write(_PONG_MSG)
    await writer.drain()

    # 4. Closes tunnel
    writer.close()
    await writer.wait_closed()
```

At Client side, we setup the Client to use `cert.pem`. On the Server side it needs an additional `key.pem`.

```python

_CERT_PATH = "testdata/cert.pem"
_KEY_PATH = "testdata/key.pem"

async def main(server_host: str, server_port: int):
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(_CERT_PATH, _KEY_PATH)

    server = await asyncio.start_server(
        server_to_client,
        server_host,
        server_port,
        ssl=server_ctx,
        reuse_address=True,
        reuse_port=True,
    )

    async with server:
        await server.serve_forever()
```

With the server and client ready, Let's see the cost of encryption.

### Benchmark results

This time, we set up the benchmark in remote connection from an Apple M1 laptop to a Google Cloud server.

```python
❯ python3 examples/python/client_asyncio_ssl.py
1,000 connections        2,153 conns per/s
1,500 connections        2,055 conns per/s
2,000 connections        2,127 conns per/s
2,500 connections        2,132 conns per/s
```

So, we are seeing a huge increase in the number of connections per second.

The **average** connections per second for AsyncIO is about `2100` conns per/s.

You can find the source code of this experiment in the `example/python/tls_asyncio/` directory.
