Quick test for bidirectional TCP comms between two boards (or VMs).

Build:
  make

Run:
- Terminal A (server):
  ./server <ip address> <port>

- Terminal B (client, connect to server IP):
  ./client <ip address> <port>

Usage:
- Type `hello` (or any text) on either side and press Enter.
- The remote side will print: received: {hello}