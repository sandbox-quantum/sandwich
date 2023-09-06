# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

import signal
import socketserver
import sys
from multiprocessing import Pipe, Process

from echo_tls_server.main import tcp_handler as server_tcp_handler
from tls_client.main import main as client_main


def thread_server(port_w: Pipe) -> None:
    CERT_PATH = "testdata/dilithium5.cert.pem"
    KEY_PATH = "testdata/dilithium5.key.pem"

    server_handler = server_tcp_handler(KEY_PATH, CERT_PATH)

    server = socketserver.TCPServer(("127.0.0.1", 0), server_handler)

    port_w.send_bytes(server.server_address[1].to_bytes(2, "big"))

    server.serve_forever()


def thread_client(port_r: Pipe, input_r: Pipe, output_w: Pipe) -> None:
    port = int.from_bytes(port_r.recv_bytes(), "big")

    client_main("127.0.0.1", port, input_r, output_w)


def killme(sig, handle):
    pclient.terminate()
    pserver.terminate()

    pclient.join()
    pserver.join()
    sys.exit(1)


if __name__ == "__main__":
    port_r, port_w = Pipe(duplex=False)
    input_r, input_w = Pipe(duplex=False)
    output_r, output_w = Pipe(duplex=False)

    signal.signal(signal.SIGCHLD, killme)

    pserver = Process(target=thread_server, args=(port_w,))
    pclient = Process(target=thread_client, args=(port_r, input_r, output_w))

    pserver.start()
    pclient.start()

    hello = b"hello\n"
    world = b"world\n"

    input_w.send_bytes(hello)
    assert output_r.recv_bytes() == hello

    input_w.send_bytes(world)
    assert output_r.recv_bytes() == world

    signal.signal(signal.SIGCHLD, signal.SIG_DFL)

    pclient.terminate()
    pserver.terminate()
    pclient.join()
    pserver.join()
