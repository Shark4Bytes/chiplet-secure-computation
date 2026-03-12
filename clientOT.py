#!/usr/bin/env python3
# client.py - dummy Oblivious Transfer receiver over TCP
#
# Protocol:
#   Client -> HELLO|<session_id>|receiver
#   Server -> HELLO_ACK|<session_id>|sender
#   Client -> OT_CHOICE|<session_id>|0_or_1
#   Server -> OT_RESULT|<session_id>|<selected_message>
#
# This is a DEMO FLOW ONLY.
# It is NOT cryptographically secure OT yet.
# It is the first step toward replacing manual chat with an OT-style protocol.

import socket
import sys
import threading
from typing import Optional

class OTReceiverState:
    """Simple state container for the dummy OT receiver."""
    def __init__(self, choice_bit: str):
        self.session_id: str = "sess1"
        self.choice_bit: str = choice_bit   # must be "0" or "1"
        self.phase: str = "WAIT_HELLO_ACK"
        self.received_message: Optional[str] =None


def send_all(sock: socket.socket, data: bytes) -> bool:
    """Send all bytes, return False if the connection breaks."""
    try:
        sock.sendall(data)
        return True
    except (BrokenPipeError, ConnectionResetError, OSError):
        return False


def send_message(conn: socket.socket, msg_type: str, *fields: str) -> bool:
    """
    Build a pipe-delimited protocol message and send it with exactly one newline.
    Example:
        HELLO|sess1|receiver\n
    """
    line = "|".join([msg_type, *fields]) + "\n"
    print(f"[SEND] {line.rstrip()}")
    return send_all(conn, line.encode("utf-8"))


def handle_message(conn: socket.socket, running: threading.Event, state: OTReceiverState, text: str):
    """
    Parse one complete incoming message and react based on the current protocol phase.
    """
    parts = text.split("|")
    msg_type = parts[0] if parts else ""

    print(f"[STATE] Current phase: {state.phase}")

    if msg_type == "HELLO_ACK":
        # Expected format: HELLO_ACK|session_id|sender
        if len(parts) != 3:
            print("[ERROR] Bad HELLO_ACK format. Expected: HELLO_ACK|<session_id>|sender")
            running.clear()
            return

        session_id = parts[1]
        claimed_role = parts[2]

        if state.phase != "WAIT_HELLO_ACK":
            print("[ERROR] Received HELLO_ACK in wrong phase.")
            running.clear()
            return

        if session_id != state.session_id:
            print(f"[ERROR] Session mismatch. Expected '{state.session_id}', got '{session_id}'")
            running.clear()
            return

        if claimed_role != "sender":
            print(f"[ERROR] Expected role 'sender', got '{claimed_role}'")
            running.clear()
            return

        print(f"[INFO] HELLO_ACK received for session '{state.session_id}'")

        if not send_message(conn, "OT_CHOICE", state.session_id, state.choice_bit):
            print("[ERROR] Failed to send OT_CHOICE")
            running.clear()
            return

        state.phase = "WAIT_RESULT"
        print(f"[STATE] Transitioned to: {state.phase}")

    elif msg_type == "OT_RESULT":
        # Expected format: OT_RESULT|session_id|selected_message
        if len(parts) != 3:
            print("[ERROR] Bad OT_RESULT format. Expected: OT_RESULT|<session_id>|<selected_message>")
            running.clear()
            return

        session_id = parts[1]
        selected_message = parts[2]

        if state.phase != "WAIT_RESULT":
            print("[ERROR] Received OT_RESULT in wrong phase.")
            running.clear()
            return

        if session_id != state.session_id:
            print(f"[ERROR] Session mismatch. Expected '{state.session_id}', got '{session_id}'")
            running.clear()
            return

        state.received_message = selected_message
        state.phase = "DONE"

        print(f"[STATE] Transitioned to: {state.phase}")
        print(f"[RESULT] Choice bit = {state.choice_bit}")
        print(f"[RESULT] Received message = {state.received_message}")

        running.clear()

    else:
        print(f"[ERROR] Unknown message type: '{msg_type}'")
        running.clear()


def receiver_loop(conn: socket.socket, running: threading.Event, state: OTReceiverState):
    """
    Receive bytes, split complete newline-delimited messages, and pass them
    to the OT protocol handler.
    """
    buffer = b""

    try:
        while running.is_set():
            chunk = conn.recv(512)
            if chunk == b"":
                print("[INFO] Peer closed connection.")
                running.clear()
                break

            buffer += chunk

            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)

                try:
                    text = line.decode("utf-8", errors="replace")
                except Exception:
                    text = str(line)

                print(f"[RECV] {text}")
                handle_message(conn, running, state, text)

    except (ConnectionResetError, OSError) as e:
        print(f"[ERROR] recv() failed: {e}")
        running.clear()


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage: client.py <server_ip> [port] [choice_bit]")
        print("Example: client.py 192.168.1.50 12345 1")
        return 0

    server_ip = sys.argv[1]
    port = 12345
    choice_bit = "1"   # default receiver choice

    if len(sys.argv) >= 3:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print("Invalid port, using default 12345")
            port = 12345

    if len(sys.argv) >= 4:
        if sys.argv[3] in ("0", "1"):
            choice_bit = sys.argv[3]
        else:
            print("Invalid choice_bit, using default 1")
            choice_bit = "1"

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        conn.connect((server_ip, port))
    except OSError as e:
        print(f"connect() failed: {e}")
        conn.close()
        return 1

    print(f"[INFO] Connected to server {server_ip}:{port}")

    running = threading.Event()
    running.set()

    state = OTReceiverState(choice_bit)

    # Start receiver thread first so it is ready for HELLO_ACK
    rx = threading.Thread(target=receiver_loop, args=(conn, running, state), daemon=True)
    rx.start()

    # Kick off the protocol automatically
    if not send_message(conn, "HELLO", state.session_id, "receiver"):
        print("[ERROR] Failed to send HELLO")
        running.clear()

    rx.join()

    try:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()
    finally:
        pass

    print("[INFO] Client shut down cleanly.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down...")