#pragma once

#include <vector>
#include <mutex>
#include <signal.h>
#include <complex>
#include <net/ethernet.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

#define NB_PORTS 1 //Number of network ports to receive data from.

// MSR4 related defines
#define MSR4_PAYLOAD_SIZE 1464                                              // Standard payload size
#define MSR4_PAYLOAD_SIZE_WITH_ADDITIONAL_TIMESTAMP MSR4_PAYLOAD_SIZE - 8   // Standard payload size

#define WRITE_BUFFER_SIZE (size_t)0x20000000                                //512 Mebi
#define NUM_CAPTURE_BUFFERS 2

#define IQ_FILES_BASE_PATH "/tmp/iq_dump/" //where to store the iq dumps

#define CHUNK_SIZE 131072 //this is the size of a buffer that gets forwarded using zmq. WRITE_BUFFER_SIZE % CHUNK_SIZE should 0.

// DPDK related defines
#define RTE_MAX_PKT_BURST 32
#define RTE_MEMPOOL_CACHE_SIZE 512
#define RTE_RX_DESC_DEFAULT 4096
#define RTE_TX_DESC_DEFAULT 256
#define PRINT_RATE

// Header definitions
struct msr4hdr
{
  struct ether_header ether_hdr;
  struct rte_ipv4_hdr ipv4_hdr;
  struct rte_udp_hdr udp_hdr;
  uint64_t hrzr_hdr;
} __attribute__((packed));

// Header definitions
struct msr4hdrWithTimestamp
{
  struct msr4hdr ether_hdr;
  uint64_t unix_ts_ns;
} __attribute__((packed));
