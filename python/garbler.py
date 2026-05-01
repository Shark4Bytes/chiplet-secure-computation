from pynq import Overlay, MMIO
import socket
import secrets
import time
import json
import csv
import hashlib

PORT = 6761


# ---------------------------
# OT group parameters
# ---------------------------
# This is a 2048-bit prime modulus used for the OT modular arithmetic group.
# The value comes from a standard MODP group and lets both sides compute values like g^x mod p. 
OT_P_HEX = """
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08
8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B
302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9
A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6
49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8
FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C
180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718
3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
""".replace("\n", "")
OT_P = int(OT_P_HEX, 16) # Convert the Hex to Python Int for actual math operations
OT_G = 2                 # Sets the generator value used in modular arithmetic group such as g^x mod p
LABEL_BYTES = 16         # 128 -bits for one wire-label



# ---------------------------
# Utility functions
# ---------------------------

# Function Explanation: 
# finds the boards loack IP
def get_local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    finally:
        sock.close()

# Function Explanation: 
# receives one newline message from evaluator
def recv_line(conn):
    data = bytearray()

    while True:
        byte = conn.recv(1)

        if not byte:
            raise ConnectionError("Client disconnected")

        if byte == b"\n":
            break

        data.extend(byte)

    message = data.decode().strip()
    print("[RX]", message)
    return message

# Function Explanation: 
# sends one newline-terminated message to the evaluator
def send_line(conn, message):
    print("[TX]", message)
    conn.sendall((message + "\n").encode())

# Function Explanation: 
# Recieve one line from socket, parse it into JSON dict
def recv_json(conn):
    return json.loads(recv_line(conn))


# Function Explanation: 
# sends a python dict as a JSON line
def send_json(conn, payload):
    send_line(conn, json.dumps(payload))


# ---------------------------
# Crypto / OT helpers
# ---------------------------

# Function Explanation: 
# used to generate a random private value for OT
def random_scalar():
    return secrets.randbelow(OT_P - 2) + 1

# Function Explanation: 
# computes modular inverse of a value
# exists for symmetry with the evaluator although we dont use it right now in garbler
def mod_inverse(value):
    return pow(value, OT_P - 2, OT_P)

# Function Explanation: 
# turns OT shared secret into 128-bit mask
# garbler uses this mask to hide each label
def ot_kdf(shared_secret, row, input_name, choice):
    """Derive a 128-bit mask from the OT shared secret and transfer context."""
    hasher = hashlib.blake2s(digest_size=LABEL_BYTES)
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")
    hasher.update(secret_bytes)
    hasher.update(row.to_bytes(4, "big"))
    hasher.update(input_name.encode())
    hasher.update(choice.to_bytes(1, "big"))
    return int.from_bytes(hasher.digest(), "big")

# Function Explanation: 
# hashes two input labels plus gate coordinates
# garbler stores these checksums so evaluator can identify the right garbled row.
def compute_checksum(label_a, label_b, column, row):
    hasher = hashlib.blake2s(digest_size=16)

    hasher.update(label_a.to_bytes(16, "big"))
    hasher.update(label_b.to_bytes(16, "big"))
    hasher.update(column.to_bytes(4, "big"))
    hasher.update(row.to_bytes(4, "big"))

    return int.from_bytes(hasher.digest(), "big")

# Function Explanation: 
# rejects obviously invalid OT public keys
# this prevents values like 0, 1, or p-1 from being used
def validate_group_element(value):
    return 1 < value < OT_P - 1

# Function Explanation: 
# Selects the two possible labels for one input wire.
# A uses labels[0] and labels[1]; B uses labels[2] and labels[3]
def get_input_label_pair(gate, input_name):
    if input_name == "A":
        return gate["labels"][0], gate["labels"][1]
    if input_name == "B":
        return gate["labels"][2], gate["labels"][3]
    raise ValueError(f"Unknown input name: {input_name}")

# Function Explanation: 
# garbler/sender side of 1-out-of-2 OT
# it has both labels, sends masked versions of both, and lets evaluator recover only one.
def handle_ot_init(conn, gates, request):
    row_number = int(request["ROW"])
    input_name = request["INPUT"]

    gate = find_gate_by_row(gates, row_number)
    if gate is None:
        send_line(conn, "BAD INPUT")
        return

    m0, m1 = get_input_label_pair(gate, input_name)

    # Compute C = q^x mod p and send to evaluator
    x = random_scalar()
    C = pow(OT_G, x, OT_P)

    send_json(conn, {
        "TYPE": "OT_SETUP",
        "ROW": row_number,
        "INPUT": input_name,
        "C": hex(C),
    })

    keys = recv_json(conn)
    if keys.get("TYPE") != "OT_KEYS":
        raise RuntimeError(f"Expected OT_KEYS, got {keys}")

    pk0 = int(keys["PK0"], 16)
    pk1 = int(keys["PK1"], 16)

    if not validate_group_element(pk0) or not validate_group_element(pk1):
        send_line(conn, "BAD OT KEY")
        return

    if (pk0 * pk1) % OT_P != C:
        send_line(conn, "BAD OT KEY")
        return

    r0 = random_scalar()
    r1 = random_scalar()

    gr0 = pow(OT_G, r0, OT_P)
    gr1 = pow(OT_G, r1, OT_P)

    pad0 = ot_kdf(pow(pk0, r0, OT_P), row_number, input_name, 0)
    pad1 = ot_kdf(pow(pk1, r1, OT_P), row_number, input_name, 1)

    ct0 = m0 ^ pad0
    ct1 = m1 ^ pad1

    send_json(conn, {
        "TYPE": "OT_RESPONSE",
        "ROW": row_number,
        "INPUT": input_name,
        "GR0": hex(gr0),
        "GR1": hex(gr1),
        "CT0": hex(ct0),
        "CT1": hex(ct1),
    })

    print(f"[STEP] Completed OT for row {row_number} input {input_name}")


# ---------------------------
# Hardware helpers
# ---------------------------

# Function Explanation: 
# polls FPGA control register until the DONE bit is set
def wait_for_done(ctrl):
    while True:
        status = ctrl.read(0x04)
        if status & (1 << 3):
            return
        time.sleep(0.001)

# Function Explanation: 
# writes 128-bit seed into four 32-bit hardware registers
def write_seed(ctrl, seed):
    ctrl.write(0x10, seed & 0xFFFFFFFF)
    ctrl.write(0x14, (seed >> 32) & 0xFFFFFFFF)
    ctrl.write(0x18, (seed >> 64) & 0xFFFFFFFF)
    ctrl.write(0x1C, (seed >> 96) & 0xFFFFFFFF)

# Function Explanation: 
# seeds and starts garbler hardware
def initialize_garbler(ctrl, seed):
    print(f"[STEP] Initializing garbler with seed {hex(seed)}")
    write_seed(ctrl, seed)
    ctrl.write(0x00, 1)
    wait_for_done(ctrl)

# Function Explanation: 
# tells hardware to generate six 128-bit labels
def generate_labels(ctrl, bram):
    ctrl.write(0x00, 2)
    wait_for_done(ctrl)

    labels = []

    for i in range(6):
        words = []

        for j in range(4):
            word = bram.read((i * 4 + j) * 4)
            words.append(word)

        value = (
            words[0]
            | (words[1] << 32)
            | (words[2] << 64)
            | (words[3] << 96)
        )

        labels.append(value)

    return labels

# Function Explanation: 
# sends the reset command to the hardware
def reset_garbler(ctrl):
    print("[STEP] Resetting garbler")
    ctrl.write(0x00, 4)
    wait_for_done(ctrl)


# ---------------------------
# Circuit building
# ---------------------------

# Function Explanation: 
# reads circuit description from CSV file
def load_rows_from_csv(csv_path):
    rows = []

    with open(csv_path) as file:
        reader = csv.DictReader(file)

        for row in reader:
            rows.append({
                "row": int(row["GATE_ROW"]),
                "column": int(row["GATE_CLMN"]),
                "mapping": [
                    int(row["OUT_1"]),
                    int(row["OUT_2"]),
                    int(row["OUT_3"]),
                    int(row["OUT_4"]),
                ]
            })

    rows.sort(key=lambda item: item["row"])
    return rows

# Function Explanation: 
# generates labels and checksums for each gate
# creates garbled table information for evaluator to use
def build_gates(ctrl, bram, rows):
    gates = []

    for row in rows:
        print(f"[STEP] Building gate for row {row['row']}")

        labels = generate_labels(ctrl, bram)

        input_pairs = [
            (labels[0], labels[2]),
            (labels[0], labels[3]),
            (labels[1], labels[2]),
            (labels[1], labels[3]),
        ]

        checksums = []

        for label_a, label_b in input_pairs:
            checksum = compute_checksum(label_a, label_b, row["column"], row["row"])
            checksums.append(checksum)

        gate = {
            "row": row["row"],
            "column": row["column"],
            "labels": labels,
            "checksums": checksums,
            "mapping": row["mapping"],
        }

        gates.append(gate)

    return gates

# Function Explanation: 
# resets/initializes hardware and builds all garbled gates for one round
def prepare_gates(ctrl, bram, rows):
    try:
        reset_garbler(ctrl)
    except Exception:
        print("[STEP] Reset failed, continuing anyway")

    seed = secrets.randbits(128) or 1
    initialize_garbler(ctrl, seed)
    gates = build_gates(ctrl, bram, rows)
    return gates

# Function Explanation: 
# converts one internal gate dict into the JSON payload sent to the evaluator
# it sends checksums and output labels, but not input labels
def make_gate_payload(gate):
    labels = gate["labels"]
    mapping = gate["mapping"]

    return {
        "GATE_ROW_NUM": gate["row"],
        "GATE_COLUMN_NUM": gate["column"],
        "CHECKSUM_1": hex(gate["checksums"][0]),
        "CHECKSUM_2": hex(gate["checksums"][1]),
        "CHECKSUM_3": hex(gate["checksums"][2]),
        "CHECKSUM_4": hex(gate["checksums"][3]),
        "OUTPUT_1": hex(labels[4 if mapping[0] == 0 else 5]),
        "OUTPUT_2": hex(labels[4 if mapping[1] == 0 else 5]),
        "OUTPUT_3": hex(labels[4 if mapping[2] == 0 else 5]),
        "OUTPUT_4": hex(labels[4 if mapping[3] == 0 else 5]),
    }

# Function Explanation: 
# Searches current gate list for specific row number
def find_gate_by_row(gates, row_number):
    for gate in gates:
        if gate["row"] == row_number:
            return gate
    return None

# Function Explanation: 
# sends every garbled gate payload to the evaluator
def send_gate_stream(conn, gates):
    request = recv_line(conn)

    if request != "GATE INFO":
        send_line(conn, "BAD INPUT")
        return False

    for gate in gates:
        payload = make_gate_payload(gate)
        send_line(conn, json.dumps(payload))

        response = recv_line(conn)
        if response != "READY":
            send_line(conn, "BAD INPUT")
            return False

    send_line(conn, "DONE")
    return True

# Function Explanation: 
# evaluator requests after the gate stream is sent
# This is where OT_INIT request are handled
def serve_round(conn, gates):
    while True:
        raw_request = recv_line(conn)

        try:
            request = json.loads(raw_request)
        except json.JSONDecodeError:
            request = None

        if isinstance(request, dict) and request.get("TYPE") == "OT_INIT":
            handle_ot_init(conn, gates, request)
            continue

        # Legacy path intentionally disabled: do not send both input labels anymore.
        if raw_request.startswith("INPUTS ROW"):
            send_line(conn, "USE OT_INIT")
            continue

        if raw_request.startswith("OUTPUTS ROW"):
            row_number = int(raw_request.split()[2])
            gate = find_gate_by_row(gates, row_number)

            if gate is None:
                send_line(conn, "BAD INPUT")
                continue

            payload = {
                "0": hex(gate["labels"][4]),
                "1": hex(gate["labels"][5]),
            }

            send_line(conn, json.dumps(payload))
            continue

        if raw_request == "READY_NEW":
            print("[STEP] Client requested another round")
            return "READY_NEW"

        if raw_request == "EXIT":
            print("[STEP] Client requested exit")
            return "EXIT"

        send_line(conn, "BAD INPUT")


# ---------------------------
# Main
# ---------------------------

# Function Explanation: 
# Main function:
# loads FPGA overlya, opens MMIO, listens for evaluator, serves circuit rounds
def main():
    csv_path = input("CSV path [./circuit.csv]: ").strip() or "./circuit.csv"

    print("[STEP] Loading overlay")
    overlay = Overlay("garbler.bit")

    ctrl_name = [name for name in overlay.ip_dict if name.startswith("garbler")][0]

    ctrl = MMIO(
        overlay.ip_dict[ctrl_name]["phys_addr"],
        overlay.ip_dict[ctrl_name]["addr_range"]
    )

    bram = MMIO(
        overlay.mem_dict["axi_bram_ctrl_0"]["phys_addr"],
        overlay.mem_dict["axi_bram_ctrl_0"]["addr_range"]
    )

    rows = load_rows_from_csv(csv_path)

    server = socket.socket()
    server.bind(("0.0.0.0", PORT))
    server.listen(1)

    ip = get_local_ip()
    print(f"IP: {ip}")
    print(f"Listening on port {PORT}")
    print("Waiting for client connection...")

    conn, _ = server.accept()

    with conn:
        print("[STEP] Client connected")

        while True:
            request = recv_line(conn)

            if request != "START":
                send_line(conn, "BAD INPUT")
                continue

            gates = prepare_gates(ctrl, bram, rows)
            send_line(conn, "DONE")

            stream_ok = send_gate_stream(conn, gates)
            if not stream_ok:
                return

            round_result = serve_round(conn, gates)

            if round_result == "EXIT":
                return

            if round_result == "READY_NEW":
                continue


if __name__ == "__main__":
    main()
