#!/usr/bin/env python3
# clientOT.py - staged OT-style receiver over TCP
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
# It is a better structural step than sending the choice bit directly.

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


def derive_pad(sender_nonce: str, mask_value: str) -> str:
    return sha256_hex(f"{sender_nonce}|{mask_value}")


def strip_zero_padding(raw: bytes) -> str:
    return raw.rstrip(b"\x00").decode("utf-8", errors="replace")


class OTReceiverState:
    """State for receiver-side OT demo."""
    def __init__(self, choice_bit: str):
        self.session_id: str = "sess1"
        self.choice_bit: str = choice_bit
        self.phase: str = "WAIT_HELLO_ACK"

        # Receiver OT state
        self.choice_secret: str = secrets.token_hex(16)
        self.receiver_token: Optional[str] = None
        self.sender_nonce: Optional[str] = None

        # Output
        self.received_message: Optional[str] = None


def send_all(sock: socket.socket, data: bytes) -> bool:
    try:
        sock.sendall(data)
        return True
    except (BrokenPipeError, ConnectionResetError, OSError):
        return False


def send_message(conn: socket.socket, msg_type: str, *fields: str) -> bool:
    line = "|".join([msg_type, *fields]) + "\n"
    print(f"[SEND] {line.rstrip()}")
    return send_all(conn, line.encode("utf-8"))


def build_receiver_token(state: OTReceiverState) -> str:
    """
    Demo trick:
    receiver embeds its choice into a token that does not literally transmit '0' or '1'.
    This is not secure OT, but it removes the explicit choice field from the wire format.
    """
    token = sha256_hex(f"{state.choice_secret}|{state.choice_bit}")
    state.receiver_token = token
    return token


def reconstruct_selected_mask(receiver_token: str, choice_bit: str) -> str:
    """
    Mirrors sender-side deterministic construction.
    """
    return sha256_hex(receiver_token + f"|{choice_bit}")


def recover_message(sender_nonce: str, selected_mask: str, enc_value: str) -> str:
    pad = derive_pad(sender_nonce, selected_mask)
    msg_hex = xor_hex(enc_value, pad)
    msg_bytes = bytes.fromhex(msg_hex)
    return strip_zero_padding(msg_bytes)


def handle_message(conn: socket.socket, running: threading.Event, state: OTReceiverState, text: str):
    parts = text.split("|")
    msg_type = parts[0] if parts else ""

    print(f"[STATE] Current phase: {state.phase}")

    if msg_type == "HELLO_ACK":
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

        token = build_receiver_token(state)
        print("[INFO] HELLO_ACK validated.")
        print("[INFO] Built receiver token without sending raw choice bit.")

        if not send_message(conn, "OT_INIT", state.session_id, token):
            print("[ERROR] Failed to send OT_INIT")
            running.clear()
            return

        state.phase = "WAIT_MASKS"
        print(f"[STATE] Transitioned to: {state.phase}")

    elif msg_type == "OT_MASKS":
        if len(parts) != 7:
            print("[ERROR] Bad OT_MASKS format. Expected: OT_MASKS|<session_id>|<sender_nonce>|<mask0>|<mask1>|<enc0>|<enc1>")
            running.clear()
            return

        session_id = parts[1]
        sender_nonce = parts[2]
        mask0 = parts[3]
        mask1 = parts[4]
        enc0 = parts[5]
        enc1 = parts[6]

        if state.phase != "WAIT_MASKS":
            print("[ERROR] Received OT_MASKS in wrong phase.")
            running.clear()
            return

        if session_id != state.session_id:
            print(f"[ERROR] Session mismatch. Expected '{state.session_id}', got '{session_id}'")
            running.clear()
            return

        if state.receiver_token is None:
            print("[ERROR] Missing receiver token.")
            running.clear()
            return

        state.sender_nonce = sender_nonce

        selected_mask = reconstruct_selected_mask(state.receiver_token, state.choice_bit)

        expected_other = reconstruct_selected_mask(
            state.receiver_token,
            "1" if state.choice_bit == "0" else "0"
        )

        print(f"[INFO] Receiver choice is hidden from wire format.")
        print(f"[INFO] Locally reconstructing only branch {state.choice_bit}.")

        if state.choice_bit == "0":
            if selected_mask != mask0:
                print("[ERROR] Selected mask did not match mask0.")
                running.clear()
                return
            if expected_other != mask1:
                print("[WARN] Non-selected mask check failed.")
            enc_value = enc0
        else:
            if selected_mask != mask1:
                print("[ERROR] Selected mask did not match mask1.")
                running.clear()
                return
            if expected_other != mask0:
                print("[WARN] Non-selected mask check failed.")
            enc_value = enc1

        try:
            state.received_message = recover_message(sender_nonce, selected_mask, enc_value)
        except ValueError as e:
            print(f"[ERROR] Failed to recover message: {e}")
            running.clear()
            return

        state.phase = "DONE"
        print(f"[STATE] Transitioned to: {state.phase}")
        print(f"[RESULT] Choice bit = {state.choice_bit}")
        print(f"[RESULT] Recovered message = {state.received_message}")

        if not send_message(conn, "OT_DONE", state.session_id, "ok"):
            print("[WARN] Failed to send OT_DONE")

        running.clear()

    else:
        print(f"[ERROR] Unknown message type: '{msg_type}'")
        running.clear()


def receiver_loop(conn: socket.socket, running: threading.Event, state: OTReceiverState):
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
        print("Usage: clientOT.py <server_ip> [port] [choice_bit]")
        print("Example: clientOT.py 192.168.1.50 12345 1")
        return 0

    server_ip = sys.argv[1]
    port = 12345
    choice_bit = "1"

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

    rx = threading.Thread(target=receiver_loop, args=(conn, running, state), daemon=True)
    rx.start()

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