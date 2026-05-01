# Garbler Register Map

AXI4-Lite control interface for `garbler_0`.

Base address is assigned in Vivado Address Editor.

## Register Offsets

| Offset | Name    | Access | Description |
|--------|---------|--------|-------------|
| `0x00` | CMD     | W      | Command register |
| `0x04` | STATUS  | R      | Status bits |
| `0x08` | ERROR   | R      | Error code |
| `0x0C` | DBG     | R      | Sticky BRAM debug info |
| `0x10` | SEED0   | R/W    | Seed bits `[31:0]` |
| `0x14` | SEED1   | R/W    | Seed bits `[63:32]` |
| `0x18` | SEED2   | R/W    | Seed bits `[95:64]` |
| `0x1C` | SEED3   | R/W    | Seed bits `[127:96]` |

## CMD Register (`0x00`)

Write-only pulse-style command register.

### Bits

- bit 0: `START`
- bit 1: `GENERATE`
- bit 2: `RESET`

### Notes

- Writing `0x1` initializes the core from the current seed.
- Writing `0x2` generates 6 x 128-bit values and writes them into BRAM.
- Writing `0x4` clears state and zeroes the 24 BRAM words.

## STATUS Register (`0x04`)

### Bits

- bit 0: seed valid (`seed != 0`)
- bit 1: initialized
- bit 2: busy
- bit 3: done
- bit 4: success
- bit 5: error
- bit 6: data valid
- bits `[31:7]`: reserved, zero

### Typical values

- `0x0` : no seed, uninitialized
- `0x1` : seed written but not initialized
- `0x1B`: initialization succeeded
- `0x5B`: generation succeeded and data valid is set

## ERROR Register (`0x08`)

### Codes

- `0`: no error
- `2`: zero seed
- `3`: generate requested before initialization

## DBG Register (`0x0C`)

Sticky debug register capturing the last BRAM write-side activity seen from `garbler_core`.

### Bits

- bit 0: `dbg_last_en`
- bits `[4:1]`: `dbg_last_we`
- bits `[9:5]`: `dbg_last_addr`
- bits `[31:10]`: reserved, zero

### Interpretation

This register is useful for confirming that the core is actively driving BRAM write cycles.

## Seed Registers (`0x10` to `0x1C`)

Together form a 128-bit seed:

```text
seed = {SEED3, SEED2, SEED1, SEED0}