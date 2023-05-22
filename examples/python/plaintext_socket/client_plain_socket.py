import socket
from time import process_time

_PING_MSG = b"PING"
_PONG_MSG = b"PONG"


def client_to_server(server_address):
    client_io = socket.create_connection(server_address)

    # 2. Send PING
    w = client_io.send(_PING_MSG)
    assert w == len(_PING_MSG), f"Expected {len(_PING_MSG)} bytes written, got {w}"

    # 3. Expect PONG
    data = client_io.recv(len(_PONG_MSG))
    assert data == _PONG_MSG, f"Expected msg {_PONG_MSG} from server, got {data}"

    # 4. Close socket
    client_io.close()


def main(count, server_address):
    start = process_time()
    for _ in range(count):
        client_to_server(server_address)
    elapsed = process_time() - start
    return elapsed


if __name__ == "__main__":
    server_address = "127.0.0.1", 7654
    for count in range(200, 1_000, 200):
        create_time = main(count, server_address)
        create_per_second = 1 / (create_time / count)
        print(f"{count:,} connections \t {create_per_second:0,.0f} conns per/s")
