#!/usr/bin/env python3
# client.py - simple bidirectional TCP client (newline-delimited messages)

import socket
import sys
import threading


def send_all(sock: socket.socket, data: bytes) -> bool:
    """Send all bytes, return False if the connection breaks."""
    try:
        sock.sendall(data)
        return True
    except (BrokenPipeError, ConnectionResetError, OSError):
        return False


def receiver_loop(sock: socket.socket, running: threading.Event):
    buffer = b""
    try:
        while running.is_set():
            chunk = sock.recv(512)
            if chunk == b"":
                print("Peer closed connection.")
                running.clear()
                break

            buffer += chunk

            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                text = line.decode("utf-8", errors="replace")
                print(f"received: {{{text}}}")
    except (ConnectionResetError, OSError) as e:
        print(f"recv() failed: {e}")
        running.clear()


def sender_loop(sock: socket.socket, running: threading.Event):
    try:
        while running.is_set():
            line = sys.stdin.readline()
            if line == "":  # EOF
                break

            # Ensure exactly one newline like C++ line + "\n"
            line = line.rstrip("\n") + "\n"

            if not send_all(sock, line.encode("utf-8")):
                print("send() failed or peer closed.")
                running.clear()
                break
    finally:
        running.clear()
        # Equivalent to shutdown(sock, SHUT_WR)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def main():
    if len(sys.argv) < 2:
        print("Usage: client.py <server_ip> [port]", file=sys.stderr)
        return 1

    host = sys.argv[1]
    port = 12345

    if len(sys.argv) >= 3:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print("Invalid port, using default 12345", file=sys.stderr)
            port = 12345
    else:
        try:
            portline = input("Enter port [12345]: ").strip()
            if portline:
                port = int(portline)
        except ValueError:
            print("Invalid port input, using default 12345", file=sys.stderr)
            port = 12345
        except EOFError:
            # If stdin is closed, just keep default
            pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect((host, port))
    except OSError as e:
        print(f"connect() failed: {e}", file=sys.stderr)
        sock.close()
        return 1

    print(f"Connected to {host}:{port}")

    running = threading.Event()
    running.set()

    rx = threading.Thread(target=receiver_loop, args=(sock, running), daemon=True)
    tx = threading.Thread(target=sender_loop, args=(sock, running), daemon=True)

    rx.start()
    tx.start()

    tx.join()
    rx.join()

    sock.close()
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nShutting down...")