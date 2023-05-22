import argparse
import subprocess
import sys
import threading


def run_client(client_bin):
    proc = subprocess.run([client_bin], capture_output=True, timeout=5, check=True)
    sys.stdout.buffer.write(proc.stdout)
    if proc.returncode != 0:
        return False
    return True


def run_server(server_bin):
    try:
        proc = subprocess.run([server_bin], capture_output=True, timeout=5, check=True)
        if proc.returncode != 0:
            return False
        return True
    except subprocess.TimeoutExpired:
        return True


def test_client_server(args: argparse.Namespace):
    server_thread = threading.Thread(target=run_server, args=[args.server_bin])
    client_thread = threading.Thread(target=run_client, args=[args.client_bin])

    server_thread.start()
    client_thread.start()

    client_thread.join()
    server_thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="2 Threads Tester",
        description="Execute two binaries in two threads",
        epilog="",
    )
    parser.add_argument("--server_bin", action="store", required=True)
    parser.add_argument("--client_bin", action="store", required=True)

    args = parser.parse_args()
    test_client_server(args)
