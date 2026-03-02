#!/usr/bin/env python3
# server.py - simple bidirectional TCP server (newline-delimited messages)

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


def receiver_loop(conn: socket.socket, running: threading.Event):
    buffer = b""
    try:
        while running.is_set():
            chunk = conn.recv(512)
            if chunk == b"":
                print("Peer closed connection.")
                running.clear()
                break

            buffer += chunk

            # Split by newline, print complete lines
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                try:
                    text = line.decode("utf-8", errors="replace")
                except Exception:
                    text = str(line)
                print(f"received: {{{text}}}")
    except (ConnectionResetError, OSError) as e:
        print(f"recv() failed: {e}")
        running.clear()


def sender_loop(conn: socket.socket, running: threading.Event):
    try:
        while running.is_set():
            line = sys.stdin.readline()
            if line == "":  # EOF
                break

            # Match C++ behavior: send line + "\n"
            # readline includes newline already; normalize to exactly one newline.
            line = line.rstrip("\n") + "\n"
            if not send_all(conn, line.encode("utf-8")):
                print("send() failed or peer closed.")
                running.clear()
                break
    finally:
        running.clear()
        # Equivalent to shutdown(conn_fd, SHUT_WR)
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage: server2.py <bind_ip> [port]")
        return 0

    bind_ip = sys.argv[1]
    port = 12345
    if len(sys.argv) >= 3:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print("Invalid port, using default 12345")

    # Create listening socket
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind (Python handles "0.0.0.0" naturally)
    try:
        listen_sock.bind((bind_ip, port))
    except OSError as e:
        print(f"bind() failed: {e}")
        listen_sock.close()
        return 1

    try:
        listen_sock.listen(1)
    except OSError as e:
        print(f"listen() failed: {e}")
        listen_sock.close()
        return 1

    print(f"Server listening on port {port}...")

    try:
        conn, peer = listen_sock.accept()
    except OSError as e:
        print(f"accept() failed: {e}")
        listen_sock.close()
        return 1

    peer_ip, peer_port = peer[0], peer[1]
    print(f"Connection from {peer_ip}:{peer_port}")

    running = threading.Event()
    running.set()

    rx = threading.Thread(target=receiver_loop, args=(conn, running), daemon=True)
    tx = threading.Thread(target=sender_loop, args=(conn, running), daemon=True)

    rx.start()
    tx.start()

    # Wait until sender finishes (stdin EOF or error), then receiver finishes
    tx.join()
    rx.join()

    try:
        conn.close()
    finally:
        listen_sock.close()

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nShutting down...")