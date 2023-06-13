import socket
import ssl

_PING_MSG = b"PING"
_PONG_MSG = b"PONG"

_CERT_EXPIRED_PATH = "testdata/cert_expired.pem"
_PRIVATE_KEY_EXPIRED_PATH = "testdata/private_key_cert_expired.pem"


def server_handler(client_ssl_socket: ssl.SSLSocket):
    client_ssl_io, _ = client_ssl_socket.accept()

    data = client_ssl_io.recv(len(_PING_MSG))
    assert data == _PING_MSG, f"Expect to see {_PING_MSG} but got {data}"

    w = client_ssl_io.send(_PONG_MSG)
    assert w == len(_PONG_MSG)

    client_ssl_io.close()


def main():
    server_address = "127.0.0.1", 7651

    # Setup the server SSL context
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(_CERT_EXPIRED_PATH, _PRIVATE_KEY_EXPIRED_PATH)
    server_ctx.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.bind(server_address)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.listen(5)
    ssock = server_ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=True)

    while True:
        server_handler(ssock)


if __name__ == "__main__":
    main()
