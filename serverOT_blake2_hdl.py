#!/usr/bin/env python3
"""serverOT_blake2_hdl.py - OT sender/garbler with BLAKE2 and HDL endpoints.

Network OT protocol (garbler <-> evaluator):
  Client -> HELLO|<session_id>|receiver
  Server -> HELLO_ACK|<session_id>|sender|<label_len>

  Repeated per evaluator-owned wire:
    Server -> OT_INIT|<session_id>|<wire_id>|<Ax_hex>|<Ay_hex>|<label_len>
    Client -> OT_RESPONSE|<session_id>|<wire_id>|<Bx_hex>|<By_hex>
    Server -> OT_RESULT|<session_id>|<wire_id>|<C0_hex>|<C1_hex>

  Server -> OT_DONE|<session_id>|<num_wires>

HDL control endpoint (local sidecar or direct HDL connection):
  LOAD_LABELS|<session_id>|<hex_label0,hex_label1;hex_label0,hex_label1;...>
  STATUS

When LOAD_LABELS is received, the next evaluator connection can run the OT for all
provided wires. This lets an HDL-side garbler program push an arbitrary number of
input-wire label pairs into the Python OT service.
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

LabelPair = Tuple[bytes, bytes]


@dataclass
class OTSenderState:
    session_id: str = "sess1"
    phase: str = "WAIT_HELLO"
    active_wire_id: int = -1
    wire_label_pairs: List[LabelPair] = field(default_factory=list)


@dataclass
class SharedJob:
    session_id: str = "sess1"
    wire_label_pairs: List[LabelPair] = field(default_factory=list)
    ready: bool = False


JOB = SharedJob()
JOB_LOCK = threading.Lock()
JOB_READY = threading.Event()


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
# Core garbler OT function
# =========================

def send_evaluator_wire_labels_ot(
    conn: socket.socket,
    wire_label_pairs: Sequence[LabelPair],
    session_id: str = "sess1",
) -> None:
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

    text = recv_line()
    parts = text.split("|")
    if len(parts) != 3 or parts[0] != "HELLO":
        raise ValueError("Expected HELLO|<session_id>|receiver")
    _, their_session, their_role = parts
    if their_role != "receiver":
        raise ValueError("Expected receiver role in HELLO")

    state.session_id = their_session
    if state.wire_label_pairs:
        expected_len = len(state.wire_label_pairs[0][0])
    else:
        expected_len = 16
    if not send_message(conn, "HELLO_ACK", state.session_id, "sender", str(expected_len)):
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

        c0 = xor_bytes(bytes(m0), derive_pad(K0, len(m0), wire_id=wire_id, session_id=state.session_id)).hex()
        c1 = xor_bytes(bytes(m1), derive_pad(K1, len(m1), wire_id=wire_id, session_id=state.session_id)).hex()

        if not send_message(conn, "OT_RESULT", state.session_id, str(wire_id), c0, c1):
            raise ConnectionError("Failed to send OT_RESULT")

    state.phase = "DONE"
    if not send_message(conn, "OT_DONE", state.session_id, str(len(state.wire_label_pairs))):
        raise ConnectionError("Failed to send OT_DONE")


run_garbler_ot = send_evaluator_wire_labels_ot


# =========================
# HDL control endpoint
# =========================

def parse_label_pairs_blob(blob: str) -> List[LabelPair]:
    blob = blob.strip()
    if not blob:
        return []
    pairs: List[LabelPair] = []
    for entry in blob.split(";"):
        left_right = entry.split(",")
        if len(left_right) != 2:
            raise ValueError("Each label pair must be hex0,hex1")
        left_hex, right_hex = left_right
        left = bytes.fromhex(left_hex)
        right = bytes.fromhex(right_hex)
        if len(left) != len(right):
            raise ValueError("Labels in a pair must have the same length")
        pairs.append((left, right))
    return pairs



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
                with JOB_LOCK:
                    status = f"STATUS|ready={int(JOB.ready)}|session={JOB.session_id}|wires={len(JOB.wire_label_pairs)}\n"
                conn.sendall(status.encode("utf-8"))
                continue

            if cmd == "LOAD_LABELS" and len(parts) == 3:
                session_id = parts[1]
                pairs = parse_label_pairs_blob(parts[2])
                with JOB_LOCK:
                    JOB.session_id = session_id
                    JOB.wire_label_pairs = pairs
                    JOB.ready = True
                    JOB_READY.set()
                conn.sendall(f"OK|loaded|{len(pairs)}\n".encode("utf-8"))
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
# OT network listener
# =========================

def wait_for_job() -> Tuple[str, List[LabelPair]]:
    JOB_READY.wait()
    with JOB_LOCK:
        session_id = JOB.session_id
        pairs = list(JOB.wire_label_pairs)
        JOB.ready = False
        JOB_READY.clear()
    return session_id, pairs



def _demo_label_pairs() -> List[LabelPair]:
    return [
        (b"WIRE0_LABEL_FOR_0", b"WIRE0_LABEL_FOR_1"),
        (b"WIRE1_LABEL_FOR_0", b"WIRE1_LABEL_FOR_1"),
        (b"WIRE2_LABEL_FOR_0", b"WIRE2_LABEL_FOR_1"),
        (b"WIRE3_LABEL_FOR_0", b"WIRE3_LABEL_FOR_1"),
    ]



def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage: serverOT_blake2_hdl.py <bind_ip> [ot_port] [hdl_port]")
        print("Example: serverOT_blake2_hdl.py 0.0.0.0 12345 12346")
        return 0

    bind_ip = sys.argv[1]
    ot_port = int(sys.argv[2]) if len(sys.argv) >= 3 else 12345
    hdl_port = int(sys.argv[3]) if len(sys.argv) >= 4 else 12346

    # preload a demo job so terminal testing still works before HDL is attached
    with JOB_LOCK:
        if not JOB.wire_label_pairs:
            JOB.session_id = "sess1"
            JOB.wire_label_pairs = _demo_label_pairs()
            JOB.ready = True
            JOB_READY.set()

    threading.Thread(target=hdl_listener, args=(bind_ip, hdl_port), daemon=True).start()

    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        listen_sock.bind((bind_ip, ot_port))
        listen_sock.listen(1)
        print(f"[INFO] OT server listening on {bind_ip}:{ot_port} ...")

        while True:
            session_id, pairs = wait_for_job()
            print(f"[INFO] Loaded job session={session_id} wires={len(pairs)}")
            conn, peer = listen_sock.accept()
            print(f"[INFO] Evaluator connection from {peer[0]}:{peer[1]}")
            with conn:
                send_evaluator_wire_labels_ot(conn, pairs, session_id=session_id)
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down...")
    except Exception as exc:
        print(f"[ERROR] {exc}")
        return 1
    finally:
        listen_sock.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
