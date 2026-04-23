#!/usr/bin/env python3
"""clientOT.py - reusable OT receiver/evaluator over TCP.

Protocol:
  Client -> HELLO|<session_id>|receiver
  Server -> HELLO_ACK|<session_id>|sender

  Repeated per evaluator-owned wire:
    Server -> OT_INIT|<session_id>|<wire_id>|<Ax_hex>|<Ay_hex>|<label_len>
    Client -> OT_RESPONSE|<session_id>|<wire_id>|<Bx_hex>|<By_hex>
    Server -> OT_RESULT|<session_id>|<wire_id>|<C0_hex>|<C1_hex>

  Server -> OT_DONE|<session_id>|<num_wires>

Library entry point:
  receive_evaluator_wire_labels_ot(conn, evaluator_bits, session_id='sess1')
"""

import hashlib
import secrets
import socket
import sys
from typing import List, Sequence, Tuple

from ecdsa import curves, ellipticcurve

CURVE = curves.SECP256k1
GENERATOR = CURVE.generator
ORDER = CURVE.order


# =========================
# Basic transport helpers
# =========================

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


# =========================
# EC helpers
# =========================

def rand_scalar() -> int:
    return secrets.randbelow(ORDER - 1) + 1


def point_to_hex(P: ellipticcurve.Point) -> Tuple[str, str]:
    return format(P.x(), "064x"), format(P.y(), "064x")


def hex_to_point(x_hex: str, y_hex: str) -> ellipticcurve.Point:
    x = int(x_hex, 16)
    y = int(y_hex, 16)
    if not CURVE.curve.contains_point(x, y):
        raise ValueError("Point is not on curve")
    return ellipticcurve.Point(CURVE.curve, x, y, ORDER)


def point_to_bytes(P: ellipticcurve.Point) -> bytes:
    x_hex, y_hex = point_to_hex(P)
    return bytes.fromhex(x_hex + y_hex)


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def derive_pad(P: ellipticcurve.Point, out_len: int) -> bytes:
    seed = sha256_bytes(point_to_bytes(P))
    pad = b""
    counter = 0
    while len(pad) < out_len:
        pad += sha256_bytes(seed + counter.to_bytes(4, "big"))
        counter += 1
    return pad[:out_len]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# =========================
# Core evaluator OT function
# =========================

def receive_evaluator_wire_labels_ot(
    conn: socket.socket,
    evaluator_bits: Sequence[int],
    session_id: str = "sess1",
) -> List[bytes]:
    """Run OT as evaluator/receiver over an existing connected socket.

    evaluator_bits contains one bit per evaluator-owned input wire.
    Returns the selected garbled labels in wire order.
    """
    for bit in evaluator_bits:
        if bit not in (0, 1):
            raise ValueError("Evaluator bits must all be 0 or 1")

    if not send_message(conn, "HELLO", session_id, "receiver"):
        raise ConnectionError("Failed to send HELLO")

    buffer = b""  # Buffer for accumulating incoming data until we get a full line

    def recv_line() -> str:
        nonlocal buffer
        while b"\n" not in buffer:
            chunk = conn.recv(4096)
            if chunk == b"":
                raise ConnectionError("Peer closed connection")
            buffer += chunk
        line, buffer = buffer.split(b"\n", 1)
        text = line.decode("utf-8", errors="replace")
        print(f"[RECV] {text}")
        return text

    text = recv_line()
    parts = text.split("|")
    if len(parts) != 3 or parts[0] != "HELLO_ACK":
        raise ValueError("Expected HELLO_ACK|<session_id>|sender")
    _, ack_session, ack_role = parts
    if ack_session != session_id:
        raise ValueError("Session mismatch in HELLO_ACK")
    if ack_role != "sender":
        raise ValueError("Expected sender role in HELLO_ACK")

    selected_labels: List[bytes] = []

    while True:
        text = recv_line()
        parts = text.split("|")
        msg_type = parts[0] if parts else ""

        if msg_type == "OT_DONE":
            if len(parts) != 3:
                raise ValueError("Expected OT_DONE|<session_id>|<num_wires>")
            _, done_session, num_wires_str = parts
            if done_session != session_id:
                raise ValueError("Session mismatch in OT_DONE")
            if int(num_wires_str) != len(evaluator_bits):
                raise ValueError("Wire count mismatch in OT_DONE")
            break

        if msg_type != "OT_INIT" or len(parts) != 6:
            raise ValueError("Expected OT_INIT|<session_id>|<wire_id>|<Ax>|<Ay>|<label_len>")

        _, init_session, wire_id_str, ax_hex, ay_hex, label_len_str = parts
        if init_session != session_id:
            raise ValueError("Session mismatch in OT_INIT")

        wire_id = int(wire_id_str)
        if wire_id < 0 or wire_id >= len(evaluator_bits):
            raise ValueError("wire_id out of range")

        A = hex_to_point(ax_hex, ay_hex)
        label_len = int(label_len_str)
        choice_bit = evaluator_bits[wire_id]
        b = rand_scalar()

        if choice_bit == 0:
            B = b * GENERATOR
        else:
            B = A + (b * GENERATOR)

        bx_hex, by_hex = point_to_hex(B)
        if not send_message(conn, "OT_RESPONSE", session_id, str(wire_id), bx_hex, by_hex):
            raise ConnectionError("Failed to send OT_RESPONSE")

        text = recv_line()
        parts = text.split("|")
        if len(parts) != 5 or parts[0] != "OT_RESULT":
            raise ValueError("Expected OT_RESULT|<session_id>|<wire_id>|<C0>|<C1>")

        _, result_session, result_wire_str, c0_hex, c1_hex = parts
        if result_session != session_id:
            raise ValueError("Session mismatch in OT_RESULT")
        if int(result_wire_str) != wire_id:
            raise ValueError("Wire mismatch in OT_RESULT")

        kc = b * A
        pad = derive_pad(kc, label_len)
        if choice_bit == 0:
            label = xor_bytes(bytes.fromhex(c0_hex), pad)
        else:
            label = xor_bytes(bytes.fromhex(c1_hex), pad)

        while len(selected_labels) <= wire_id:
            selected_labels.append(b"")
        selected_labels[wire_id] = label

    return selected_labels


# Alias name that reads naturally from evaluator code.
run_evaluator_ot = receive_evaluator_wire_labels_ot


# =========================
# Demo CLI wrapper
# =========================

def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage: clientOT.py <server_ip> [port] [bits]")
        print("Example: clientOT.py 192.168.1.50 12345 10")
        return 0

    server_ip = sys.argv[1]
    port = 12345
    bit_string = "10"

    if len(sys.argv) >= 3:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print("Invalid port, using default 12345")

    if len(sys.argv) >= 4:
        bit_string = sys.argv[3]
        if any(ch not in "01" for ch in bit_string):
            print("Invalid bits string, using default 10")
            bit_string = "10"

    evaluator_bits = [int(ch) for ch in bit_string]

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        conn.connect((server_ip, port))
        print(f"[INFO] Connected to server {server_ip}:{port}")
        labels = receive_evaluator_wire_labels_ot(conn, evaluator_bits)
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down...")
        return 1
    except Exception as exc:
        print(f"[ERROR] {exc}")
        return 1
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()

    print("[INFO] Evaluator received labels:")
    for index, label in enumerate(labels):
        print(f"  wire {index}: {label.hex()} ({label!r})")
    print("[INFO] Client shut down cleanly.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
