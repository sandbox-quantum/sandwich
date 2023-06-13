import socket
import ssl
from time import process_time

_PING_MSG = b"PING"
_PONG_MSG = b"PONG"

_CERT_EXPIRED_PATH = "testdata/cert_expired.pem"


def client_to_server(server_address, client_ssl_io: ssl.SSLSocket):
    client_ssl_io.connect(server_address)

    w = client_ssl_io.write(_PING_MSG)
    assert w == len(_PING_MSG)

    data = client_ssl_io.read(len(_PONG_MSG))
    assert data == _PONG_MSG

    client_ssl_io.close()


def main(count):
    server_adress = "127.0.0.1", 7651

    # Set up the client SSL context
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.load_verify_locations(_CERT_EXPIRED_PATH)
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE
    client_ctx.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384")

    start = process_time()
    for _ in range(count):
        client_ssl_io = client_ctx.wrap_socket(
            socket.socket(socket.AF_INET), server_hostname=server_adress[0]
        )
        client_to_server(server_address=server_adress, client_ssl_io=client_ssl_io)
    elapsed = process_time() - start
    return elapsed


if __name__ == "__main__":
    for count in range(200, 2_000, 200):
        create_time = main(count)
        create_per_second = 1 / (create_time / count)
        print(f"{count:,} connections \t {create_per_second:0,.0f} conns per/s")
