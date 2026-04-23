Quick test for bidirectional TCP comms between two boards (or VMs).

Connect to the PYNQ Z2 boards

From there 
python3 serverOT_updated.py <ip addr> <port>

Then
python3 clientOT_updated.py <server_ip> <port> <wirechoices>

Currently coded for just 2 wire labels.  Uses independent tokens for each wire label.  However, will be expanded once we combine OT and Garbled Circuit.  