# Garbled Circuit Project

## Python Files
The primary part of this project was the python code, designed to run on the PYNQ-Z2. It implements a basic garbled circuit protocol, reading circuit infomation from a CSV and generating gates

Currently, it is not able to handle inputting outputs from other gates.

The evaluator was meant to be in hardware, but we ran out of time.

### Note on Python Files
Always run with the .hwh and .bit files in the same directory as the python script you're trying to run.

## Garbler IP for PYNQ-Z2

This repository also contains a custom AXI4-Lite peripheral and BRAM-backed generator IP for the PYNQ-Z2.

The design lets software:

- provide a 128-bit seed
- initialize the core
- generate 6 x 128-bit values
- store the generated values into BRAM
- read the BRAM contents back from software

## Repository Layout

```text
garbler/
  garbler.v
  garbler_core.v
  garbler_slave_lite_v0_1_S00_AXI.v
  
python/
	bram_test.py
	garbler.py
	evaluator.py
	evaluator_8b.py
	
examples_circuits/
	circuit.csv
	
docs/
	block_design_notes.md
	garbler_register_info.md
