from pynq import Overlay, MMIO
import secrets
import sys
import time

# Register offsets
REG_CMD    = 0x00
REG_STATUS = 0x04
REG_ERROR  = 0x08
REG_DBG    = 0x0C
REG_SEED0  = 0x10
REG_SEED1  = 0x14
REG_SEED2  = 0x18
REG_SEED3  = 0x1C

# Command bits
CMD_START    = 0x1
CMD_GENERATE = 0x2
CMD_RESET    = 0x4

# Status bits
STS_SEED_VALID  = 1 << 0
STS_INITIALIZED = 1 << 1
STS_BUSY        = 1 << 2
STS_DONE        = 1 << 3
STS_SUCCESS     = 1 << 4
STS_ERROR       = 1 << 5
STS_DATA_VALID  = 1 << 6


def find_ip_names(overlay):
    ctrl_name = next(name for name in overlay.ip_dict if name.startswith("garbler"))
    bram_name = "axi_bram_ctrl_0"
    if bram_name not in overlay.mem_dict:
        raise KeyError("Could not find axi_bram_ctrl_0 in mem_dict.")
    return ctrl_name, bram_name


def write_seed(ctrl, seed128: int) -> None:
    ctrl.write(REG_SEED0, (seed128 >> 0) & 0xFFFFFFFF)
    ctrl.write(REG_SEED1, (seed128 >> 32) & 0xFFFFFFFF)
    ctrl.write(REG_SEED2, (seed128 >> 64) & 0xFFFFFFFF)
    ctrl.write(REG_SEED3, (seed128 >> 96) & 0xFFFFFFFF)


def read_status(ctrl) -> int:
    return ctrl.read(REG_STATUS)


def read_error(ctrl) -> int:
    return ctrl.read(REG_ERROR)


def wait_done(ctrl, timeout_s: float = 2.0) -> tuple[int, int]:
    t0 = time.time()
    while True:
        status = read_status(ctrl)
        error = read_error(ctrl)
        if status & STS_DONE:
            return status, error
        if time.time() - t0 > timeout_s:
            raise TimeoutError("Timed out waiting for operation to complete.")
        time.sleep(0.001)


def initialize(ctrl, seed128: int) -> None:
    write_seed(ctrl, seed128)
    ctrl.write(REG_CMD, CMD_START)
    status, error = wait_done(ctrl)

    if not (status & STS_SUCCESS):
        raise RuntimeError(f"Initialization failed. Error code: {error}")

    if not (status & STS_INITIALIZED):
        raise RuntimeError("Initialization completed without initialized bit set.")


def generate(ctrl, bram) -> list[int]:
    ctrl.write(REG_CMD, CMD_GENERATE)
    status, error = wait_done(ctrl)

    if not (status & STS_SUCCESS):
        raise RuntimeError(f"Generate failed. Error code: {error}")

    if not (status & STS_DATA_VALID):
        raise RuntimeError("Generate completed without data_valid bit set.")

    values = []
    for i in range(6):
        w0 = bram.read((i * 4 + 0) * 4)
        w1 = bram.read((i * 4 + 1) * 4)
        w2 = bram.read((i * 4 + 2) * 4)
        w3 = bram.read((i * 4 + 3) * 4)
        v = w0 | (w1 << 32) | (w2 << 64) | (w3 << 96)
        values.append(v)

    return values


def reset_garbler(ctrl) -> None:
    ctrl.write(REG_CMD, CMD_RESET)
    status, error = wait_done(ctrl)

    if not (status & STS_SUCCESS):
        raise RuntimeError(f"Reset failed. Error code: {error}")


def prompt_seed() -> int:
    while True:
        choice = input("Choose seed type: [c]ustom or [r]andom: ").strip().lower()

        if choice == "r":
            seed128 = secrets.randbits(128)
            if seed128 == 0:
                seed128 = 1
            print(f"Using random seed: 0x{seed128:032x}")
            return seed128

        if choice == "c":
            seed_hex = input("Enter 128-bit seed (32 hex chars, optional 0x prefix): ").strip().lower()
            if seed_hex.startswith("0x"):
                seed_hex = seed_hex[2:]

            if len(seed_hex) != 32:
                print("Seed must be exactly 32 hex characters.")
                continue

            try:
                seed128 = int(seed_hex, 16)
            except ValueError:
                print("Invalid hexadecimal seed.")
                continue

            if seed128 == 0:
                print("Seed cannot be zero.")
                continue

            print(f"Using custom seed: 0x{seed128:032x}")
            return seed128

        print("Please enter 'c' or 'r'.")


def print_values(values: list[int]) -> None:
    print("\nGenerated values:")
    for i, v in enumerate(values):
        print(f"  value[{i}] = 0x{v:032x}")


def main():
    print("Loading overlay...", flush=True)
    ol = Overlay("garbler.bit")
    print("Overlay loaded.", flush=True)

    ctrl_name, bram_name = find_ip_names(ol)

    ctrl_desc = ol.ip_dict[ctrl_name]
    bram_desc = ol.mem_dict[bram_name]

    ctrl = MMIO(ctrl_desc["phys_addr"], ctrl_desc["addr_range"])
    bram = MMIO(bram_desc["phys_addr"], bram_desc["addr_range"])

    print(f"Control IP: {ctrl_name}")
    print(f"BRAM IP:    {bram_name}")
    print(f"Control base: 0x{ctrl_desc['phys_addr']:08x}")
    print(f"BRAM base:    0x{bram_desc['phys_addr']:08x}\n")

    try:
        seed128 = prompt_seed()
        initialize(ctrl, seed128)
        print("Initialization successful.\n")

        while True:
            choice = input("[g]enerate values, [s]elect new seed, e[x]it: ").strip().lower()

            if choice == "g":
                values = generate(ctrl, bram)
                print_values(values)
                print()
                continue

            if choice == "s":
                reset_garbler(ctrl)
                print("Reset complete.\n")
                seed128 = prompt_seed()
                initialize(ctrl, seed128)
                print("Initialization successful.\n")
                continue

            if choice == "x":
                try:
                    reset_garbler(ctrl)
                    print("Reset complete.")
                except Exception as e:
                    print(f"Warning: reset on exit failed: {e}")
                print("Exiting.")
                break

            print("Please enter 'g', 's', or 'x'.\n")

    except (RuntimeError, TimeoutError, KeyError) as e:
        print(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(1)


if __name__ == "__main__":
    main()
