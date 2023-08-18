# rs-wbiq
This repository contains sample code for IQ data reception and processing for an MSR4.
IQ data is received using up to 4 10G ethernet interfaces. After validating the incoming data stream it is either written to disk or forwarded using an ZMQ PUB pattern.
Using the PUB/SUB pattern the data can be processed by GNUradio or other receivers.

# Dependencies
* dpdk (tested with 21.02.0)
* zmq (optional, only when forwarding is desired)

# Setup
The NICs must load the DPDK drivers prior to running the application. See [rs-jerry-setup](https://github.com/Rohde-Schwarz/rs-jerry-setup) for additional information.