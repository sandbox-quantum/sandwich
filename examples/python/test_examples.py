# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

import signal
import sys
from functools import partial
from multiprocessing import Pipe, Process
from multiprocessing.connection import Connection

from echo_tls_server.main import main as server_main
from tls_client.main import main as client_main

hello = b"hello\n"
world = b"world\n"

TLS13_CERT_PATH = "testdata/dilithium5.cert.pem"
TLS13_KEY_PATH = "testdata/dilithium5.key.pem"

TLS12_CERT_PATH = "testdata/rsa.cert.pem"
TLS12_KEY_PATH = "testdata/rsa.key.pem"

SERVER_PORT = 54089


def thread_server(cert: str, key: str) -> None:
    server_main("127.0.0.1", SERVER_PORT, cert, key)


def thread_client(
    input_r: Connection,
    output_w: Connection,
    tls_version: str = "tls13",
) -> None:
    client_main("127.0.0.1", SERVER_PORT, tls_version, input_r, output_w)


def killme(sig, handle, client: Process, server: Process):
    client.terminate()
    server.terminate()

    client.join()
    server.join()

    sys.exit(1)


def test_server_client(thread_client, thread_server):
    input_r, input_w = Pipe(duplex=False)
    output_r, output_w = Pipe(duplex=False)

    server = Process(target=thread_server, args=())
    client = Process(target=thread_client, args=(input_r, output_w))

    killme_wrapped = partial(killme, client=server, server=client)

    signal.signal(signal.SIGCHLD, killme_wrapped)

    server.start()
    client.start()

    input_w.send_bytes(hello)
    assert output_r.recv_bytes() == hello

    input_w.send_bytes(world)
    assert output_r.recv_bytes() == world

    signal.signal(signal.SIGCHLD, signal.SIG_DFL)

    client.terminate()
    server.terminate()

    client.join()
    server.join()


if __name__ == "__main__":
    tls13_client = partial(thread_client, tls_version="tls13")
    tls13_server = partial(thread_server, cert=TLS13_CERT_PATH, key=TLS13_KEY_PATH)

    test_server_client(
        thread_client=tls13_client,
        thread_server=tls13_server,
    )
    tls12_client = partial(thread_client, tls_version="tls12")
    tls12_server = partial(thread_server, cert=TLS12_CERT_PATH, key=TLS12_KEY_PATH)
    test_server_client(
        thread_client=tls12_client,
        thread_server=tls12_server,
    )
