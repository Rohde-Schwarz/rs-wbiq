# rs-wbiq
This repository contains sample code for IQ data reception and processing for an MSR4.
IQ data is received using up to 4 10G ethernet interfaces. After validating the incoming data stream it is either written to disk or forwarded using an ZMQ PUB pattern.
Using the PUB/SUB pattern the data can be processed by GNUradio or other receivers.

# Dependencies
* dpdk (tested with 21.02.0)
* zmq (optional, only when forwarding is desired)


# Building
Project can be build using CMake.
```console
$ mkdir build && cd build
$ cmake ..
```
## Configuration Options
Use the CMake option
```console
-DUSE_ZMQ:STRING=ON
```
to forward data using ZMQ instead of dumping the IQ files.
# Setup
The NICs must load the DPDK drivers prior to running the application. See [rs-jerry-setup](https://github.com/Rohde-Schwarz/rs-jerry-setup) for additional information.

# Settings
Most of the settings are located in [dpdk_ms4r_rx.h](include/dpdk_ms4r_rx.h).
The most important ones are probably.
```c
#define NB_PORTS 1                          //Number of network ports to receive data from.
#define IQ_FILES_BASE_PATH "/tmp/iq_dump/"  //where to store the iq dumps
```