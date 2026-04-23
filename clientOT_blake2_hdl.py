#!/usr/bin/env python3
"""clientOT_blake2_hdl.py - OT receiver/evaluator with BLAKE2 and HDL endpoints.

Network OT protocol (evaluator <-> garbler):
  Client -> HELLO|<session_id>|receiver
  Server -> HELLO_ACK|<session_id>|sender|<label_len>

  Repeated per evaluator-owned wire:
    Server -> OT_INIT|<session_id>|<wire_id>|<Ax_hex>|<Ay_hex>|<label_len>
    Client -> OT_RESPONSE|<session_id>|<wire_id>|<Bx_hex>|<By_hex>
    Server -> OT_RESULT|<session_id>|<wire_id>|<C0_hex>|<C1_hex>

  Server -> OT_DONE|<session_id>|<num_wires>

HDL control endpoint (local sidecar or direct HDL connection):
  LOAD_BITS|<session_id>|<bitstring>
  STATUS

When LOAD_BITS is received, the next outgoing OT session uses that exact bitstring,
so the evaluator HDL program can push any number of input bits into the Python OT service.
"""

import hashlib
import secrets
import socket
import sys
import threading
from dataclasses import dataclass, field
from typing import List, Sequence, Tuple


# Pure-Python secp256k1 helpers so the file runs without third-party ecdsa.
P_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A_CURVE = 0
B_CURVE = 7
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 55066263022277343669578718895168534326250603453777594175500187360389116729240
GY = 32670510020758816978083085130507043184471273380659243275938904335757337482424
PERSON_PAD = b"GCOTPAD1"
PERSON_TAG = b"GCOTTAG1"


class Point:
    __slots__ = ("x", "y", "inf")

    def __init__(self, x: int = 0, y: int = 0, inf: bool = False):
        self.x = x
        self.y = y
        self.inf = inf

    def __neg__(self):
        if self.inf:
            return self
        return Point(self.x, (-self.y) % P_FIELD)

    def __add__(self, other):
        return point_add(self, other)

    def __rmul__(self, k: int):
        return scalar_mult(k, self)


INF = Point(inf=True)
GENERATOR = Point(GX, GY)


def inv_mod(a: int, n: int) -> int:
    return pow(a % n, -1, n)


def is_on_curve(Pt: Point) -> bool:
    if Pt.inf:
        return True
    return (Pt.y * Pt.y - (Pt.x * Pt.x * Pt.x + A_CURVE * Pt.x + B_CURVE)) % P_FIELD == 0


def point_add(P1: Point, P2: Point) -> Point:
    if P1.inf:
        return P2
    if P2.inf:
        return P1
    if P1.x == P2.x and (P1.y != P2.y or P1.y == 0):
        return INF
    if P1.x == P2.x:
        lam = (3 * P1.x * P1.x + A_CURVE) * inv_mod(2 * P1.y, P_FIELD) % P_FIELD
    else:
        lam = (P2.y - P1.y) * inv_mod(P2.x - P1.x, P_FIELD) % P_FIELD
    x3 = (lam * lam - P1.x - P2.x) % P_FIELD
    y3 = (lam * (P1.x - x3) - P1.y) % P_FIELD
    return Point(x3, y3)


def scalar_mult(k: int, Pt: Point) -> Point:
    if k % ORDER == 0 or Pt.inf:
        return INF
    if k < 0:
        return scalar_mult(-k, -Pt)
    result = INF
    addend = Pt
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


@dataclass
class EvaluatorJob:
    session_id: str = "sess1"
    evaluator_bits: List[int] = field(default_factory=list)
    ready: bool = False

    def __post_init__(self):
        if self.evaluator_bits is None:
            self.evaluator_bits = []


JOB = EvaluatorJob()
JOB_LOCK = threading.Lock()
JOB_READY = threading.Event()
LAST_LABELS: List[bytes] = []
LAST_LOCK = threading.Lock()


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
# EC + BLAKE2 helpers
# =========================

def rand_scalar() -> int:
    return secrets.randbelow(ORDER - 1) + 1



def point_to_hex(P: Point) -> Tuple[str, str]:
    if P.inf:
        raise ValueError("Cannot serialize point at infinity")
    return format(P.x, "064x"), format(P.y, "064x")



def hex_to_point(x_hex: str, y_hex: str) -> Point:
    x = int(x_hex, 16)
    y = int(y_hex, 16)
    P = Point(x, y)
    if not is_on_curve(P):
        raise ValueError("Point is not on curve")
    return P



def point_to_bytes(P: Point) -> bytes:
    x_hex, y_hex = point_to_hex(P)
    return bytes.fromhex(x_hex + y_hex)



def blake2s_bytes(data: bytes, out_len: int = 32, *, key: bytes = b"", person: bytes = b"") -> bytes:
    h = hashlib.blake2s(digest_size=out_len, key=key, person=person)
    h.update(data)
    return h.digest()



def derive_pad(P: Point, out_len: int, *, wire_id: int, session_id: str) -> bytes:
    seed = blake2s_bytes(
        point_to_bytes(P),
        out_len=32,
        person=PERSON_PAD,
        key=session_id.encode("utf-8")[:32],
    )
    pad = b""
    counter = 0
    while len(pad) < out_len:
        material = wire_id.to_bytes(4, "big") + counter.to_bytes(4, "big")
        pad += blake2s_bytes(material, out_len=32, key=seed, person=PERSON_PAD)
        counter += 1
    return pad[:out_len]



def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))



def compute_line_tag(msg_without_tag: str, session_id: str) -> str:
    tag = blake2s_bytes(
        msg_without_tag.encode("utf-8"),
        out_len=16,
        key=session_id.encode("utf-8")[:32],
        person=PERSON_TAG,
    )
    return tag.hex()


# =========================
# Core evaluator OT function
# =========================

def receive_evaluator_wire_labels_ot(
    conn: socket.socket,
    evaluator_bits: Sequence[int],
    session_id: str = "sess1",
) -> List[bytes]:
    for bit in evaluator_bits:
        if bit not in (0, 1):
            raise ValueError("Evaluator bits must all be 0 or 1")

    if not send_message(conn, "HELLO", session_id, "receiver"):
        raise ConnectionError("Failed to send HELLO")

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

    text = recv_line()
    parts = text.split("|")
    if len(parts) != 4 or parts[0] != "HELLO_ACK":
        raise ValueError("Expected HELLO_ACK|<session_id>|sender|<label_len>")
    _, ack_session, ack_role, _label_len = parts
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
        pad = derive_pad(kc, label_len, wire_id=wire_id, session_id=session_id)
        if choice_bit == 0:
            label = xor_bytes(bytes.fromhex(c0_hex), pad)
        else:
            label = xor_bytes(bytes.fromhex(c1_hex), pad)

        while len(selected_labels) <= wire_id:
            selected_labels.append(b"")
        selected_labels[wire_id] = label

    return selected_labels


run_evaluator_ot = receive_evaluator_wire_labels_ot


# =========================
# HDL control endpoint
# =========================

def handle_hdl_client(conn: socket.socket) -> None:
    with conn:
        buffer = b""
        while True:
            while b"\n" not in buffer:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buffer += chunk
            line, buffer = buffer.split(b"\n", 1)
            text = line.decode("utf-8", errors="replace").strip()
            print(f"[HDL RECV] {text}")
            parts = text.split("|", 2)
            cmd = parts[0] if parts else ""

            if cmd == "STATUS":
                with JOB_LOCK, LAST_LOCK:
                    last = ";".join(label.hex() for label in LAST_LABELS)
                    status = (
                        f"STATUS|ready={int(JOB.ready)}|session={JOB.session_id}|bits={len(JOB.evaluator_bits)}"
                        f"|last_labels={last}\n"
                    )
                conn.sendall(status.encode("utf-8"))
                continue

            if cmd == "LOAD_BITS" and len(parts) == 3:
                session_id = parts[1]
                bit_string = parts[2].strip()
                if any(ch not in "01" for ch in bit_string):
                    conn.sendall(b"ERR|bits_must_be_binary\n")
                    continue
                bits = [int(ch) for ch in bit_string]
                with JOB_LOCK:
                    JOB.session_id = session_id
                    JOB.evaluator_bits = bits
                    JOB.ready = True
                    JOB_READY.set()
                conn.sendall(f"OK|loaded|{len(bits)}\n".encode("utf-8"))
                continue

            conn.sendall(b"ERR|unknown_command\n")



def hdl_listener(bind_ip: str, hdl_port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_ip, hdl_port))
    sock.listen(5)
    print(f"[INFO] HDL endpoint listening on {bind_ip}:{hdl_port}")
    while True:
        conn, peer = sock.accept()
        print(f"[INFO] HDL connection from {peer[0]}:{peer[1]}")
        threading.Thread(target=handle_hdl_client, args=(conn,), daemon=True).start()


# =========================
# OT network runner
# =========================

def wait_for_job() -> Tuple[str, List[int]]:
    JOB_READY.wait()
    with JOB_LOCK:
        session_id = JOB.session_id
        bits = list(JOB.evaluator_bits)
        JOB.ready = False
        JOB_READY.clear()
    return session_id, bits



def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage: clientOT_blake2_hdl.py <server_ip> [ot_port] [hdl_port] [bits]")
        print("Example: clientOT_blake2_hdl.py 192.168.1.50 12345 12346 1011")
        return 0

    server_ip = sys.argv[1]
    ot_port = int(sys.argv[2]) if len(sys.argv) >= 3 else 12345
    hdl_port = int(sys.argv[3]) if len(sys.argv) >= 4 else 12346
    bit_string = sys.argv[4] if len(sys.argv) >= 5 else "10"

    if any(ch not in "01" for ch in bit_string):
        print("Invalid bits string, using default 10")
        bit_string = "10"

    with JOB_LOCK:
        JOB.session_id = "sess1"
        JOB.evaluator_bits = [int(ch) for ch in bit_string]
        JOB.ready = True
        JOB_READY.set()

    threading.Thread(target=hdl_listener, args=("0.0.0.0", hdl_port), daemon=True).start()

    try:
        while True:
            session_id, evaluator_bits = wait_for_job()
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                conn.connect((server_ip, ot_port))
                print(f"[INFO] Connected to garbler {server_ip}:{ot_port}")
                labels = receive_evaluator_wire_labels_ot(conn, evaluator_bits, session_id=session_id)
                with LAST_LOCK:
                    LAST_LABELS.clear()
                    LAST_LABELS.extend(labels)
                print("[INFO] Evaluator received labels:")
                for index, label in enumerate(labels):
                    print(f"  wire {index}: {label.hex()}")
            finally:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                conn.close()
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down...")
        return 0
    except Exception as exc:
        print(f"[ERROR] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
