# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

import os
import signal
import socketserver
import sys
from multiprocessing import Process

from echo_tls_server.main import tcp_handler as server_tcp_handler
from tls_client.main import main as client_main


def thread_server(server):
    server.serve_forever()


def thread_client(port, input_, output):
    client_main("127.0.0.1", port, os.fdopen(input_, "rb"), os.fdopen(output, "wb"))


def killme(sig, handler):
    pserver.terminate()
    pclient.terminate()
    pserver.join()
    pclient.join()
    sys.exit(1)


input_r, input_w = os.pipe()
output_r, output_w = os.pipe()

CERT_PATH = "testdata/dilithium5.cert.pem"
KEY_PATH = "testdata/dilithium5.key.pem"

server_handler = server_tcp_handler(KEY_PATH, CERT_PATH)
server = socketserver.TCPServer(("127.0.0.1", 0), server_handler)
port = server.server_address[1]

signal.signal(signal.SIGCHLD, killme)

pserver = Process(target=thread_server, args=(server,))
pclient = Process(target=thread_client, args=(port, input_r, output_w))

pserver.start()
pclient.start()

input_w = os.fdopen(input_w, "wb")
output_r = os.fdopen(output_r, "rb")

input_w.write(b"HELLO\n")
input_w.flush()
assert output_r.read(6) == b"HELLO\n"

input_w.write(b"WORLD\n")
input_w.flush()
assert output_r.read(6) == b"WORLD\n"

signal.signal(signal.SIGCHLD, signal.SIG_DFL)

pclient.terminate()
pserver.terminate()
pserver.join()
pclient.join()
