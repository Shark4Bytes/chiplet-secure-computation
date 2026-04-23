#!/usr/bin/env python3
# serverOT.py - staged OT-style sender over TCP
#
# Protocol:
#   Client -> HELLO|<session_id>|receiver
#   Server -> HELLO_ACK|<session_id>|sender
#   Client -> OT_INIT|<session_id>|<receiver_token>
#   Server -> OT_MASKS|<session_id>|<sender_nonce>|<mask0>|<mask1>|<enc0>|<enc1>
#   Client -> OT_DONE|<session_id>|ok
#
# This is STILL a DEMO FLOW.
# It is not cryptographically secure oblivious transfer.
# It is a better protocol structure that hides the direct choice bit from the sender
# and prepares the codebase for a real OT implementation later.

import hashlib
import secrets
import socket
import sys
import threading
from typing import Optional


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def xor_hex(hex_a: str, hex_b: str) -> str:
    a = bytes.fromhex(hex_a)
    b = bytes.fromhex(hex_b)
    return xor_bytes(a, b).hex()


def pad_message_to_32(message: str) -> bytes:
    raw = message.encode("utf-8")
    if len(raw) > 32:
        raise ValueError("Message too long; keep demo messages at 32 bytes or fewer.")
    return raw.ljust(32, b"\x00")


def derive_pad(sender_nonce: str, mask_value: str) -> str:
    return sha256_hex(f"{sender_nonce}|{mask_value}")


class OTSenderState:
    """State for sender-side OT demo."""
    def __init__(self):
        self.session_id: str = "sess1"
        self.phase: str = "WAIT_HELLO"

        # Demo payloads
        self.m0: str = "WIRE_LABEL_0"
        self.m1: str = "WIRE_LABEL_1"

        # OT-related state
        self.sender_nonce: Optional[str] = None
        self.receiver_token: Optional[str] = None
        self.mask0: Optional[str] = None
        self.mask1: Optional[str] = None
        self.enc0: Optional[str] = None
        self.enc1: Optional[str] = None


def send_all(sock: socket.socket, data: bytes) -> bool:
    try:
        sock.sendall(data)
        return True
    except (BrokenPipeError, ConnectionResetError, OSError):
        return False


def send_message(conn: socket.socket, msg_type: str, *fields: Optional[str]) -> bool:
    parts = [msg_type] + [f if f is not None else "" for f in fields]
    line = "|".join(parts) + "\n"
    print(f"[SEND] {line.rstrip()}")
    return send_all(conn, line.encode("utf-8"))


def build_mask_pair(receiver_token: str):
    """
    Demo idea:
    - sender receives one opaque receiver_token
    - sender deterministically derives two masks from it
    - receiver will only know how to reconstruct one of them later
    """
    mask0 = sha256_hex(receiver_token + "|0")
    mask1 = sha256_hex(receiver_token + "|1")
    return mask0, mask1


def build_ciphertexts(state: OTSenderState):
    if state.sender_nonce is None or state.mask0 is None or state.mask1 is None:
        raise ValueError("Missing OT state for ciphertext construction.")

    pad0 = derive_pad(state.sender_nonce, state.mask0)
    pad1 = derive_pad(state.sender_nonce, state.mask1)

    msg0_hex = pad_message_to_32(state.m0).hex()
    msg1_hex = pad_message_to_32(state.m1).hex()

    state.enc0 = xor_hex(msg0_hex, pad0)
    state.enc1 = xor_hex(msg1_hex, pad1)


def handle_message(conn: socket.socket, running: threading.Event, state: OTSenderState, text: str):
    parts = text.split("|")
    msg_type = parts[0] if parts else ""

    print(f"[STATE] Current phase: {state.phase}")

    if msg_type == "HELLO":
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

        state.phase = "WAIT_OT_INIT"
        print(f"[STATE] Transitioned to: {state.phase}")

    elif msg_type == "OT_INIT":
        if len(parts) != 3:
            print("[ERROR] Bad OT_INIT format. Expected: OT_INIT|<session_id>|<receiver_token>")
            running.clear()
            return

        session_id = parts[1]
        receiver_token = parts[2]

        if state.phase != "WAIT_OT_INIT":
            print("[ERROR] Received OT_INIT in wrong phase.")
            running.clear()
            return

        if session_id != state.session_id:
            print(f"[ERROR] Session mismatch. Expected '{state.session_id}', got '{session_id}'")
            running.clear()
            return

        state.receiver_token = receiver_token
        state.sender_nonce = secrets.token_hex(16)
        state.mask0, state.mask1 = build_mask_pair(receiver_token)

        try:
            build_ciphertexts(state)
        except ValueError as e:
            print(f"[ERROR] {e}")
            running.clear()
            return

        print("[INFO] Built masked payloads for both branches.")
        print("[INFO] Sender does not receive an explicit choice bit anymore.")

        if not send_message(
            conn,
            "OT_MASKS",
            state.session_id,
            state.sender_nonce,
            state.mask0,
            state.mask1,
            state.enc0,
            state.enc1,
        ):
            print("[ERROR] Failed to send OT_MASKS")
            running.clear()
            return

        state.phase = "WAIT_DONE"
        print(f"[STATE] Transitioned to: {state.phase}")

    elif msg_type == "OT_DONE":
        if len(parts) != 3:
            print("[ERROR] Bad OT_DONE format. Expected: OT_DONE|<session_id>|ok")
            running.clear()
            return

        session_id = parts[1]
        status = parts[2]

        if state.phase != "WAIT_DONE":
            print("[ERROR] Received OT_DONE in wrong phase.")
            running.clear()
            return

        if session_id != state.session_id:
            print(f"[ERROR] Session mismatch. Expected '{state.session_id}', got '{session_id}'")
            running.clear()
            return

        print(f"[INFO] Receiver reported completion status: {status}")
        state.phase = "DONE"
        print(f"[STATE] Transitioned to: {state.phase}")
        running.clear()

    else:
        print(f"[ERROR] Unknown message type: '{msg_type}'")
        running.clear()


def receiver_loop(conn: socket.socket, running: threading.Event, state: OTSenderState):
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
        print("Usage: serverOT.py <bind_ip> [port]")
        print("Example: serverOT.py 0.0.0.0 12345")
        return 0

    bind_ip = sys.argv[1]
    port = 12345

    if len(sys.argv) >= 3:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print("Invalid port, using default 12345")
            port = 12345

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