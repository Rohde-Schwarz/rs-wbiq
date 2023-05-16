#include <vector>
#include <mutex>
#include <signal.h>
#include <complex>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

// Activate calibration
#define ENABLE_CALIBRATION 0

// Enable/Disable debugging of time alignment calibration
#define DEBUG_CALIBRATION 

// General defines
#define NB_PORTS 4
#define SLOTS_PER_SECOND 60  // Target petformance
#define SLOT_DURATION 0.5e-3 // 0.5 ms

// MSR4 related defines
#define MSR4_PAYLOAD_SIZE 1464                        // All packets have max size
#define MSR4_SAMPLES_PER_PACKET MSR4_PAYLOAD_SIZE / 4 // complex valued samples are 4 bytes long
#define MSR4_UDP_PORT 5000                            // Port number on which packets are received
#define MSR4_METADATA_SIZE 40                         // Size of metadata packet
#define MSR4_SAMPLING_FREQUENCY 122880000             // 122.88MHz

#define PACKETS_TO_BUFFER  0x50000
#define WRITE_BUFFER_SIZE (size_t)MSR4_PAYLOAD_SIZE*PACKETS_TO_BUFFER
#define NUM_CAPTURE_BUFFERS 2

// Calibration settings
#define CALIB_CAP_DURATION 12.1e-6 // 12.1 us capture duration. USE MATCHING ARB FILE IN SIG GEN!
#define CALIB_SKIP_DURATION 1      // 1s, give calibration enough time to finish before processing packets again

// DPDK related defines
#define RTE_MAX_PKT_BURST 32
#define RTE_MEMPOOL_CACHE_SIZE 512
#define RTE_RX_DESC_DEFAULT 4096
static uint16_t nb_rxd = RTE_RX_DESC_DEFAULT;
#define RTE_TX_DESC_DEFAULT 256
static uint16_t nb_txd = RTE_TX_DESC_DEFAULT;
#define PRINT_RATE

// Memory pool
struct rte_mempool *mbuf_pool = NULL;

// Port configuration
struct rte_eth_conf port_conf = {
/*
    .rxmode =
        {
            .split_hdr_size = 0,
        },
*/
};

// Quit flag
static bool force_quit;

// Header definitions
struct msr4hdr
{
  struct rte_ether_hdr ether_hdr;
  struct rte_ipv4_hdr ipv4_hdr;
  struct rte_udp_hdr udp_hdr;
  uint64_t hrzr_hdr;
} __attribute__((__packed__));

// Timestamp when capturing on all four cores should start
static uint64_t ts_capture_start = 0;

// Mutex to lock capture start timestamp
static std::mutex ts_caputure_start_mutex;

// Ring buffers holding capture buffer pointers being exchanged between cores
static struct rte_ring *rings[4];

// Ring buffer holding pointer to calibration data exchanged between cores
static struct rte_ring *ring_calib;

// Per-port boolean flag indicating whether data is currently being dumped
static bool fwrite_active[NB_PORTS];

// Calibration Data
struct calib_data
{
  uint8_t port_id;
  uint32_t *capbuf;
};

// Number of samples to be discared per port due to calibration
static uint64_t nb_samples_calib_discard[NB_PORTS];

// Flag indicating whether calibration completed for all ports. + a mutex to
// enable thread-safe access
static bool calib_done_global = false;
struct std::mutex calib_done_global_mutex;
