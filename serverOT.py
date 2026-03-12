# server.py - dummy Oblivious Transfer sender over TCP
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


class OTSenderState:
    """Simple state container for the dummy OT sender."""
    def __init__(self):
        self.session_id = "sess1"
        self.m0 = "WIRE_LABEL_0"
        self.m1 = "WIRE_LABEL_1"
        self.phase = "WAIT_HELLO"


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
        HELLO_ACK|sess1|sender\n
    """
    line = "|".join([msg_type, *fields]) + "\n"
    print(f"[SEND] {line.rstrip()}")
    return send_all(conn, line.encode("utf-8"))


def handle_message(conn: socket.socket, running: threading.Event, state: OTSenderState, text: str):
    """
    Parse one complete incoming message and react based on the current protocol phase.
    """
    parts = text.split("|")
    msg_type = parts[0] if parts else ""

    print(f"[STATE] Current phase: {state.phase}")

    if msg_type == "HELLO":
        # Expected format: HELLO|session_id|receiver
        if len(parts) != 3:
            print("[ERROR] Bad HELLO format. Expected: HELLO|<session_id>|receiver")
            running.clear()
            return

        session_id = parts[1]
        claimed_role = parts[2]

        if state.phase != "WAIT_HELLO":
            print("[ERROR] Received HELLO in wrong phase.")
            running.clear()
            return

        if claimed_role != "receiver":
            print(f"[ERROR] Expected role 'receiver', got '{claimed_role}'")
            running.clear()
            return

        state.session_id = session_id
        print(f"[INFO] HELLO received for session '{state.session_id}'")

        if not send_message(conn, "HELLO_ACK", state.session_id, "sender"):
            print("[ERROR] Failed to send HELLO_ACK")
            running.clear()
            return

        state.phase = "WAIT_CHOICE"
        print(f"[STATE] Transitioned to: {state.phase}")

    elif msg_type == "OT_CHOICE":
        # Expected format: OT_CHOICE|session_id|0_or_1
        if len(parts) != 3:
            print("[ERROR] Bad OT_CHOICE format. Expected: OT_CHOICE|<session_id>|0_or_1")
            running.clear()
            return

        session_id = parts[1]
        choice = parts[2]

        if state.phase != "WAIT_CHOICE":
            print("[ERROR] Received OT_CHOICE in wrong phase.")
            running.clear()
            return

        if session_id != state.session_id:
            print(f"[ERROR] Session mismatch. Expected '{state.session_id}', got '{session_id}'")
            running.clear()
            return

        if choice == "0":
            selected = state.m0
        elif choice == "1":
            selected = state.m1
        else:
            print(f"[ERROR] Invalid choice bit '{choice}'. Expected 0 or 1.")
            running.clear()
            return

        print(f"[INFO] Receiver chose bit {choice}")
        print(f"[INFO] Sending selected message: {selected}")

        if not send_message(conn, "OT_RESULT", state.session_id, selected):
            print("[ERROR] Failed to send OT_RESULT")
            running.clear()
            return

        state.phase = "DONE"
        print(f"[STATE] Transitioned to: {state.phase}")

        # End demo after one OT exchange
        running.clear()

    else:
        print(f"[ERROR] Unknown message type: '{msg_type}'")
        running.clear()


def receiver_loop(conn: socket.socket, running: threading.Event, state: OTSenderState):
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

            # Process complete lines only
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
        print("Usage: server.py <bind_ip> [port]")
        return 0

    bind_ip = sys.argv[1]
    port = 12345

    if len(sys.argv) >= 3:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print("Invalid port, using default 12345")
            port = 12345

    # Create listening socket
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

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

    print(f"[INFO] Server listening on {bind_ip}:{port} ...")

    try:
        conn, peer = listen_sock.accept()
    except OSError as e:
        print(f"accept() failed: {e}")
        listen_sock.close()
        return 1

    peer_ip, peer_port = peer[0], peer[1]
    print(f"[INFO] Connection from {peer_ip}:{peer_port}")

    running = threading.Event()
    running.set()

    state = OTSenderState()

    rx = threading.Thread(target=receiver_loop, args=(conn, running, state), daemon=True)
    rx.start()
    rx.join()

    try:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()
    finally:
        listen_sock.close()

    print("[INFO] Server shut down cleanly.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down...")