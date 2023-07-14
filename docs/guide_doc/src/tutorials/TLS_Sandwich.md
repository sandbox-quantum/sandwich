# TLS connection with Sandwich

## Unencrypted connections

```python
❯ python3 examples/python/client_plain_socket.py
1,000 connections        11,284 conns per/s
1,500 connections        14,610 conns per/s
2,000 connections        15,757 conns per/s
2,500 connections        16,403 conns per/s
3,000 connections        14,890 conns per/s
3,500 connections        15,361 conns per/s
4,000 connections        16,080 conns per/s
4,500 connections        16,281 conns per/s
5,000 connections        15,062 conns per/s
5,500 connections        15,211 conns per/s
6,000 connections        15,894 conns per/s
6,500 connections        15,870 conns per/s
7,000 connections        15,787 conns per/s
7,500 connections        15,808 conns per/s
8,000 connections        15,621 conns per/s
8,500 connections        15,741 conns per/s
9,000 connections        15,414 conns per/s
9,500 connections        15,437 conns per/s
```

On the left side, it's the total number of connections we issue.
On the right side, it's the number of connections it can make per second.

In an experiment to send plain PING and PONG between client and server, the unencrypted connection is at about `15,000` connections per second.
You can find the source code of this experiment in the `example/python/plaintext_socket` directory.

## TLS with Python `ssl` library

Let's write one and let's see the cost of encryption.

The overall plan is:

1. Client handshakes with Server
2. Client sends PONG
3. Client receives PING
4. Closes connection


Out of courisity, we rewrite the experiment above with TLS connections using the `ssl` Python library.

You can find the source code of this experiment in the `example/python/tls_socket/` directory.

For short, the result of TLS connection is:

```python
❯ python3 examples/python/client_ssl_socket.py
200 connections          1,509 conns per/s
400 connections          1,534 conns per/s
600 connections          1,515 conns per/s
800 connections          1,559 conns per/s
1,000 connections        1,582 conns per/s
1,200 connections        1,573 conns per/s
1,400 connections        1,560 conns per/s
1,600 connections        1,596 conns per/s
1,800 connections        1,582 conns per/s
```

As expected, with encryption it is much slower than plaintext.

## TLS with Pysandwich

It's time for Pysandwich to shine, let's follow the mental model of Sandwich: **Context**, but this time, we want to compare the performance of Sandwich with the built-in TLS implementation.

Here is the plan, same as the previous experiment:

1. Client handshakes Server
2. Client sends PING
3. Client receives PONG
4. Closes connection

### Client

First of all, let's import all ingredients of Sandwich to create a configuration:

```python
import pysandwich.proto.api.v1.configuration_pb2 as SandwichAPI
import pysandwich.proto.api.v1.encoding_format_pb2 as EncodingFormat
import pysandwich.proto.api.v1.compliance_pb2 as Compliance
import pysandwich.io as SandwichIO
from pysandwich.sandwich import Context, Sandwich, Tunnel

_CERT_PATH = "testdata/cert.pem"

def create_client_conf(cipher_opts: str) -> SandwichAPI:
    """Create Client configuration"""
    conf = SandwichAPI.Configuration()
    conf.impl = SandwichAPI.IMPL_OPENSSL1_1_1_OQS
    # To use classical public-key cryptography, we have to explicitly enable it
    conf.compliance.classical_choice = Compliance.CLASSICAL_ALGORITHMS_ALLOW
    conf.client.tls.common_options.kem.append(cipher_opts)

    cert = conf.client.tls.common_options.x509_verifier.trusted_cas.add().static
    cert.data.filename = _CERT_PATH
    cert.format = EncodingFormat.ENCODING_FORMAT_PEM

    return conf

```

Now let's have steps 1 to 4 demonstate the connection to server given a context as input:

```python
import socket

_PING_MSG = b"PING"
_PONG_MSG = b"PONG"

def sandwich_client_to_server(server_address, client_ctx: Context):
    """Make a connection to server with Context"""
    client_io = socket.create_connection(server_address)

    client = Tunnel(client_ctx, SandwichIO.Socket(client_io))
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
```

Consistently with the [TLS with SSL](#tls-with-ssl) section, we explicitly use `secp256r1` (also known as `prime256v1` in OpenSSL).


### Server

Now let's write the Server. Inspired from **Context** model, server and client will share the same Context setting.

Let's generate the configuration under the same context for Server.

```python
import pysandwich.proto.api.v1.configuration_pb2 as SandwichAPI
import pysandwich.proto.api.v1.encoding_format_pb2 as EncodingFormat
import pysandwich.proto.api.v1.compliance_pb2 as Compliance
import pysandwich.io as SandwichIO
from pysandwich.sandwich import Context, Sandwich, Tunnel

_CERT_PATH = "testdata/cert.pem"
_KEY_PATH = "testdata/key.pem"

def create_server_conf(cipher_opts: str) -> SandwichAPI:
    """Create Server configuration"""

    conf = SandwichAPI.Configuration()
    conf.impl = SandwichAPI.IMPL_OPENSSL1_1_1_OQS
    # To use classical public-key cryptography, we have to explicitly enable it
    conf.compliance.classical_choice = Compliance.CLASSICAL_ALGORITHMS_ALLOW
    conf.server.tls.common_options.kem.append(cipher_opts)
    conf.server.tls.certificate.static.data.filename = _CERT_PATH
    conf.server.tls.certificate.static.format = EncodingFormat.ENCODING_FORMAT_PEM

    conf.server.tls.private_key.static.data.filename = _KEY_PATH
    conf.server.tls.private_key.static.format = EncodingFormat.ENCODING_FORMAT_PEM

    return conf
```

Let's write a server using `socketserver.TCPServer` in Python.

```python
import socketserver

_PING_MSG = b"PING"
_PONG_MSG = b"PONG"

CIPHER = "prime256v1"

class MyTCPSandwich(socketserver.BaseRequestHandler):
    # The context is share and immutable
    s = Sandwich()
    server_conf = create_server_conf(CIPHER)
    server_ctx = Context.from_config(s, server_conf)

    def handle(self):
        # self.request is the TCP socket connected to the client
        server = Tunnel(self.server_ctx, SandwichIO.Socket(self.request))

        # 1. Handshake
        server.handshake()
        state = server.state()
        assert (
            state == server.State.STATE_HANDSHAKE_DONE
        ), f"Expected state HANDSHAKE_DONE, got {state}"

        # 2. Expects PING
        data = server.read(len(_PING_MSG))
        assert data == _PING_MSG, f"Expected msg {_PING_MSG} from server, got {data}"

        # 3. Sends PONG
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

```

We can measure the performance by running Client and Server in separate terminals, the expected output in Client side is:

```python

❯ python3 examples/python/client_socket.py
200 connections          1,045 conns per/s
400 connections          1,123 conns per/s
600 connections          1,090 conns per/s
800 connections          1,066 conns per/s
1,000 connections        1,042 conns per/s
1,200 connections        1,048 conns per/s
1,400 connections        1,069 conns per/s
1,600 connections        1,041 conns per/s
1,800 connections        1,061 conns per/s
```

So now we are having about 1000 connections per second.

You can find the source code of this experiment in the `example/python/tls_sandwich` directory.


# Benchmark Platform

We use `AMD EPYC 7B13` CPU as Server, `Apple M1` as Client, using `prime256v1` as our public signature.
One CPU dedicates for Client and Server.
