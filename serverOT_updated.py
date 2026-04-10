#!/usr/bin/env python3
"""serverOT.py - reusable OT sender/garbler over TCP.

This refactors the old demo so the garbler can call a function from another
program to perform the OT stage for evaluator-owned wires.

Protocol:
  Client -> HELLO|<session_id>|receiver
  Server -> HELLO_ACK|<session_id>|sender

  Repeated per evaluator-owned wire:
    Server -> OT_INIT|<session_id>|<wire_id>|<Ax_hex>|<Ay_hex>|<label_len>
    Client -> OT_RESPONSE|<session_id>|<wire_id>|<Bx_hex>|<By_hex>
    Server -> OT_RESULT|<session_id>|<wire_id>|<C0_hex>|<C1_hex>

  Server -> OT_DONE|<session_id>|<num_wires>

Library entry point:
  send_evaluator_wire_labels_ot(conn, wire_label_pairs, session_id='sess1')
"""

import hashlib
import secrets
import socket
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from ecdsa import curves, ellipticcurve

CURVE = curves.SECP256k1
GENERATOR = CURVE.generator
ORDER = CURVE.order

LabelPair = Tuple[bytes, bytes]


@dataclass
class OTSenderState:
    """State container for OT sender / garbler."""

    session_id: str = "sess1"
    phase: str = "WAIT_HELLO"
    active_wire_id: int = -1
    wire_label_pairs: List[LabelPair] = field(default_factory=list)


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
# Core garbler OT function
# =========================

def send_evaluator_wire_labels_ot(
    conn: socket.socket,
    wire_label_pairs: Sequence[LabelPair],
    session_id: str = "sess1",
) -> None:
    """Run OT as the garbler/sender over an existing connected socket.

    wire_label_pairs is one (L0, L1) pair per evaluator-owned input wire.
    Each label must be bytes and both labels for the same wire must have the
    same length.
    """
    state = OTSenderState(session_id=session_id, wire_label_pairs=list(wire_label_pairs))

    buffer = b""

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

    # Handshake
    text = recv_line()
    parts = text.split("|")
    if len(parts) != 3 or parts[0] != "HELLO":
        raise ValueError("Expected HELLO|<session_id>|receiver")
    _, their_session, their_role = parts
    if their_role != "receiver":
        raise ValueError("Expected receiver role in HELLO")

    state.session_id = their_session
    if not send_message(conn, "HELLO_ACK", state.session_id, "sender"):
        raise ConnectionError("Failed to send HELLO_ACK")
    state.phase = "OT_TRANSFER"

    for wire_id, pair in enumerate(state.wire_label_pairs):
        if len(pair) != 2:
            raise ValueError(f"wire {wire_id}: expected (L0, L1)")

        m0, m1 = pair
        if not isinstance(m0, (bytes, bytearray)) or not isinstance(m1, (bytes, bytearray)):
            raise TypeError("Wire labels must be bytes")
        if len(m0) != len(m1):
            raise ValueError(f"wire {wire_id}: label lengths differ")

        state.active_wire_id = wire_id

        a = rand_scalar()
        A = a * GENERATOR
        ax_hex, ay_hex = point_to_hex(A)

        if not send_message(conn, "OT_INIT", state.session_id, str(wire_id), ax_hex, ay_hex, str(len(m0))):
            raise ConnectionError("Failed to send OT_INIT")

        text = recv_line()
        parts = text.split("|")
        if len(parts) != 5 or parts[0] != "OT_RESPONSE":
            raise ValueError("Expected OT_RESPONSE|<session_id>|<wire_id>|<Bx>|<By>")

        _, resp_session, resp_wire_id, bx_hex, by_hex = parts
        if resp_session != state.session_id:
            raise ValueError("Session mismatch in OT_RESPONSE")
        if int(resp_wire_id) != wire_id:
            raise ValueError("Wire mismatch in OT_RESPONSE")

        B = hex_to_point(bx_hex, by_hex)
        K0 = a * B
        K1 = a * (B + (-A))

        c0 = xor_bytes(bytes(m0), derive_pad(K0, len(m0))).hex()
        c1 = xor_bytes(bytes(m1), derive_pad(K1, len(m1))).hex()

        if not send_message(conn, "OT_RESULT", state.session_id, str(wire_id), c0, c1):
            raise ConnectionError("Failed to send OT_RESULT")

    state.phase = "DONE"
    if not send_message(conn, "OT_DONE", state.session_id, str(len(state.wire_label_pairs))):
        raise ConnectionError("Failed to send OT_DONE")


# Alias name that reads naturally from garbler code.
run_garbler_ot = send_evaluator_wire_labels_ot


# =========================
# Demo CLI wrapper
# =========================

def _demo_label_pairs() -> List[LabelPair]:
    return [
        (b"WIRE0_LABEL_FOR_0", b"WIRE0_LABEL_FOR_1"),
        (b"WIRE1_LABEL_FOR_0", b"WIRE1_LABEL_FOR_1"),
    ]


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage: serverOT.py <bind_ip> [port]")
        return 0

    bind_ip = sys.argv[1]
    port = 12345
    if len(sys.argv) >= 3:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print("Invalid port, using default 12345")

    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        listen_sock.bind((bind_ip, port))
        listen_sock.listen(1)
        print(f"[INFO] Server listening on {bind_ip}:{port} ...")
        conn, peer = listen_sock.accept()
        print(f"[INFO] Connection from {peer[0]}:{peer[1]}")

        with conn:
            send_evaluator_wire_labels_ot(conn, _demo_label_pairs())

    except KeyboardInterrupt:
        print("\n[INFO] Shutting down...")
    except Exception as exc:
        print(f"[ERROR] {exc}")
        return 1
    finally:
        listen_sock.close()

    print("[INFO] Server shut down cleanly.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
