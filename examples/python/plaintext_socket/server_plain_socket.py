import socketserver

_PING_MSG = b"PING"
_PONG_MSG = b"PONG"


class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        server_io = self.request

        # 2. Expect PING
        # data = server_io.recv(len(_PING_MSG))
        data = server_io.recv(len(_PING_MSG))
        assert data == _PING_MSG, f"Expected msg {_PING_MSG} from server, got {data}"

        # 3. Send PONG
        w = server_io.send(_PONG_MSG)
        assert w == len(_PONG_MSG), f"Expected {len(_PONG_MSG)} bytes written, got {w}"

        # 4. Close tunnel
        server_io.close()


def main(server_address):
    server = socketserver.TCPServer(server_address, MyTCPHandler)
    server.allow_reuse_address = True

    with server:
        server.serve_forever()


if __name__ == "__main__":
    server_address = "127.0.0.1", 7654
    main(server_address)
