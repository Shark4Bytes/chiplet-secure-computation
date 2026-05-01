# Block Design Notes

## Working Topology

The validated system uses:

- Zynq PS
- AXI Interconnect
- custom `garbler_0` AXI-Lite IP
- AXI BRAM Controller
- Block Memory Generator
- Processor System Reset

## BRAM Architecture

### Port A
Used for software read/write through AXI BRAM Controller.

Connection:

- `axi_bram_ctrl_0/BRAM_PORTA` -> `blk_mem_gen_0/BRAM_PORTA`

This should be connected interface-to-interface only.

Do not manually wire Port A sub-pins such as:

- `addra`
- `dina`
- `wea`
- `ena`

## Port B
Used by `garbler_0` / `garbler_core` to write generated data.

Connections:

- `bram_din` -> `dinb`
- `bram_we` -> `web`
- `bram_en` -> `enb`
- `FCLK_CLK0` -> `clkb`
- constant `0` -> `rstb`

### Address mapping
Port B address must be mapped as:

```text
addrb = {25'b0, bram_addr[4:0], 2'b00}