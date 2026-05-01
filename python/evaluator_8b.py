import socket
import json
import hashlib
import secrets


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
OT_G = 2                 # Sets the generator value used in modular arithmetic group
LABEL_BYTES = 16         # 128 -bits for one wire-label


# ---------------------------
# Utility functions
# ---------------------------

# Function explanation:
# reads one complete newline-terminated message from the socket.
# this keeps the protocol simple: every message ends with "\n".
def recv_line(sock):
    data = bytearray()

    while True:
        byte = sock.recv(1)

        if not byte:
            raise ConnectionError("Server disconnected")

        if byte == b"\n":
            break

        data.extend(byte)

    message = data.decode().strip()
    print("[RX]", message)
    return message

# Function explanation:
# sends one complete newline-terminated message over the socket
def send_line(sock, message):
    print("[TX]", message)
    sock.sendall((message + "\n").encode())

#Function used for receiving one socket line and parsing it as JSON, as OT messages are dictionaries, JSON makes protocol simpler
def recv_json(sock):
    return json.loads(recv_line(sock))

# Function used for sending one socket line after converting to JSON
def send_json(sock, payload):
    send_line(sock, json.dumps(payload))

# Function explanation:
# prompt_bit prompts the evaluator for 1 or 0
# once input source provides bits automatically we need this function
def prompt_bit(prompt_text):
    while True:
        value = input(prompt_text).strip()

        if value in ("0", "1"):
            return int(value)

        print("Enter 0 or 1.")


def prompt_8b_num(prompt_text):
    while True:
        value = int(input(prompt_text).strip())

        if 0 <= value <= 255:
            return value

        print("Enter 8 bit value.")
# ---------------------------
# Crypto / OT helpers
# ---------------------------

# # Function explanation:
# creates a random secret number used in OT math
# both eval and garble need random private values.
def random_scalar():
    return secrets.randbelow(OT_P - 2) + 1

# Function explanation:
# computes modular division
# in OT the eval needs to calculate C / pk_choice mod p, which is done using an inverse...
def mod_inverse(value):
    return pow(value, OT_P - 2, OT_P)

# converts OT shared secret into 128-bit mask
# we send ct0 = m0 ^ pad0
# ct1 = m1 ^ pad0
# m0 = label for 0, m1 = label for 1
# pad0 = hash mask for label 0, pad1 = hash mask for label 1
def ot_kdf(shared_secret, row, input_name, choice):
    """Derive a 128-bit mask from the OT shared secret and transfer context."""
    hasher = hashlib.blake2s(digest_size=LABEL_BYTES)
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")
    hasher.update(secret_bytes)
    hasher.update(row.to_bytes(4, "big"))
    hasher.update(input_name.encode())
    hasher.update(choice.to_bytes(1, "big"))
    return int.from_bytes(hasher.digest(), "big")


# Function explanation:
# recreates the garbled-table checksum for two input labels.
# evaluator uses it to find which encrypted table row matches its two labels
def compute_checksum(label_a, label_b, column, row):
    hasher = hashlib.blake2s(digest_size=16)

    hasher.update(label_a.to_bytes(16, "big"))
    hasher.update(label_b.to_bytes(16, "big"))
    hasher.update(column.to_bytes(4, "big"))
    hasher.update(row.to_bytes(4, "big"))

    return int.from_bytes(hasher.digest(), "big")


# Function explanation:
# this is the evaluator/receiver side of 1-out-of-2 OT.
# The evaluator chooses either label 0 or label 1, but the Garbler shouldn't know which
# evaluator should only be able to decrypt one selected label.
def ot_receive_label(sock, row, input_name, choice):
    send_json(sock, {
        "TYPE": "OT_INIT",
        "ROW": row,
        "INPUT": input_name,
    })

    setup = recv_json(sock)
    if setup.get("TYPE") != "OT_SETUP":
        raise RuntimeError(f"Expected OT_SETUP, got {setup}")

    C = int(setup["C"], 16)

    # Calculate the evaluator private random secret k
    k = random_scalar()
    
    # compute the public key for the choice the evaluator actually knows
    pk_choice = pow(OT_G, k, OT_P)

    # compute other pk so that pk0 * pk1 = C mod OT_P
    pk_other = (C * mod_inverse(pk_choice)) % OT_P

    if choice == 0:
        pk0, pk1 = pk_choice, pk_other
    else:
        pk0, pk1 = pk_other, pk_choice

    send_json(sock, {
        "TYPE": "OT_KEYS",
        "ROW": row,
        "INPUT": input_name,
        "PK0": hex(pk0),
        "PK1": hex(pk1),
    })

    response = recv_json(sock)
    if response.get("TYPE") != "OT_RESPONSE":
        raise RuntimeError(f"Expected OT_RESPONSE, got {response}")

    gr = int(response[f"GR{choice}"], 16)
    ciphertext = int(response[f"CT{choice}"], 16)

    shared_secret = pow(gr, k, OT_P)

    # Derive the 128-bit mask from the shared secret and OT label.
    pad = ot_kdf(shared_secret, row, input_name, choice)

    # XOR the ciphertext with the pad to recover the selected wire label.
    label = ciphertext ^ pad

    # print the label 
    print(f"[STEP] OT received only input {input_name} label for choice {choice}: {hex(label)}")

    #return 128-bit wire label
    return label


# ---------------------------
# Parsing helpers
# ---------------------------

# Function explanation:
# parses one garbled gate JSON payload from the garbler.
# extracts row, column, four checksums, and four encrypted output labels. 
def parse_gate_payload(message):
    payload = json.loads(message)

    gate = {
        "row": int(payload["GATE_ROW_NUM"]),
        "column": int(payload["GATE_COLUMN_NUM"]),
        "checksums": [
            int(payload["CHECKSUM_1"], 16),
            int(payload["CHECKSUM_2"], 16),
            int(payload["CHECKSUM_3"], 16),
            int(payload["CHECKSUM_4"], 16),
        ],
        "outputs": [
            int(payload["OUTPUT_1"], 16),
            int(payload["OUTPUT_2"], 16),
            int(payload["OUTPUT_3"], 16),
            int(payload["OUTPUT_4"], 16),
        ],
    }

    return gate

# Function explanation:
# Parse a pair of labels from JSON.
# in this OT version, this is only used for final output decoding, not evaluator input labels...
def parse_label_pair(message):
    payload = json.loads(message)

    return {
        0: int(payload["0"], 16),
        1: int(payload["1"], 16),
    }


# ---------------------------
# Protocol helpers
# ---------------------------

# Function explanation:
# ask the garbler to send garbled table data
def request_gate_stream(sock):
    gates = []

    send_line(sock, "GATE INFO")

    while True:
        response = recv_line(sock)

        if response == "DONE":
            break

        gate = parse_gate_payload(response)
        gates.append(gate)

        print(f"[STEP] Received gate for row {gate['row']}, column {gate['column']}")
        send_line(sock, "READY")

    return gates

# Function explanation:
# readability wrapper around ot_recieve_label()
# requests only one selected label through OT
def request_input_label_ot(sock, row, input_name, choice):
    return ot_receive_label(sock, row, input_name, choice)

# Function explanation:
# asks garbler for final output labels so eval can decode...
def request_output_labels(sock, row):
    send_line(sock, f"OUTPUTS ROW {row}")
    response = recv_line(sock)
    return parse_label_pair(response)


def to_bit_list(n):
    binary_string = format(n, "08b")

    bits = []
    for character in binary_string:
        bits.append(int(character))

    return bits

# ---------------------------
# Evaluation
# ---------------------------

# Function explanation:
# uses the two selected input labels to find the matching garbled table row
# matching row gives output label for this gate.
def evaluate_gate(gate, label_a, label_b):
    checksum = compute_checksum(label_a, label_b, gate["column"], gate["row"])

    print(f"[STEP] Computed checksum for row {gate['row']}: {hex(checksum)}")

    try:
        match_index = gate["checksums"].index(checksum)
    except ValueError as exc:
        raise RuntimeError(
            "No garbled-table row matched. This usually means OT returned the wrong label, "
            "the row/column context differs, or labels/checksums were generated for a different round."
        ) from exc

    output_label = gate["outputs"][match_index]

    print(f"[STEP] Matched case {match_index + 1}")
    print(f"[STEP] Output label: {hex(output_label)}")

    return output_label

# Function explanation:
# evaluates every recieved gate
# For each gate, it uses OT to recieve only chosen A or B input labels
def evaluate_circuit(sock, gates):
    gates = sorted(gates, key=lambda gate: gate["row"])
    results = []

    valA = prompt_8b_num(f"Input A: ")
    valB = prompt_8b_num(f"Input B: ")
    arrayA = to_bit_list(valA)
    arrayB = to_bit_list(valB)
    
    for gate in gates:
        row = gate["row"]

        print(f"[STEP] Evaluating gate in row {row}")

        label_a = request_input_label_ot(sock, row, "A", arrayA[row])

        label_b = request_input_label_ot(sock, row, "B", arrayB[row])

        output_label = evaluate_gate(gate, label_a, label_b)

        results.append({
            "row": row,
            "column": gate["column"],
            "output_label": output_label,
        })

    return results

# Function explanation:
# compares output labels against garbler's final output label pair.
# this converts the final wire label back into a 0 or 1
def decode_outputs(sock, results):
    print("[STEP] Decoding outputs")

    for result in results:
        row = result["row"]
        output_label = result["output_label"]

        output_labels = request_output_labels(sock, row)

        if output_label == output_labels[0]:
            boolean_value = 0
        elif output_label == output_labels[1]:
            boolean_value = 1
        else:
            boolean_value = None

        print(f"[RESULT] Row {row} = {boolean_value}")


# Function explanation:
# performs one full circuit eval round
def run_round(sock):
    send_line(sock, "START")
    response = recv_line(sock)

    if response != "DONE":
        raise RuntimeError(f"Unexpected START response: {response}")

    gates = request_gate_stream(sock)
    results = evaluate_circuit(sock, gates)
    decode_outputs(sock, results)


# ---------------------------
# Main
# ---------------------------

def main():
    garbler_ip = input("Garbler IP: ").strip()
    garbler_port = int(input("Port: ").strip())

    print("[STEP] Connecting to garbler")

    sock = socket.create_connection((garbler_ip, garbler_port))

    with sock:
        print("[STEP] Connected")

        while True:
            run_round(sock)
            usr_input = input("[N]ew inputs or [E]xit: ").strip().lower()

            if usr_input == "n":
                send_line(sock, "READY_NEW")
                continue

            elif usr_input == "e":
                send_line(sock, "EXIT")
                break

            else:
                print("Invalid input.")

    print("[STEP] Evaluator finished")


if __name__ == "__main__":
    main()
