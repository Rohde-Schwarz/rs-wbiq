#include <assert.h>
#include "dpdk_ms4r_rx.h"
#include "hrzrHeaderParser.h"
#include <iostream>
#include <rte_memcpy.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "util.h"

#ifdef FORWARD_ZMQ
  #include <zmq.h>
#endif

// Ring buffers holding capture buffer pointers being exchanged between cores
static struct rte_ring *rings[NB_PORTS];

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

static void signal_handler(int signum)
{
  if (signum == SIGINT || signum == SIGTERM)
    force_quit = true;
}

static void lcore_rx()
{
  //This thread is dequeuing arriving network packets from the NIC, checks for validity and copies the IQ data on a ring buffer for further processing in a different thread.
  int ret;
  unsigned lcore_id;
  unsigned port_id;
  unsigned ring_id;
  unsigned nb_rx;
  unsigned i;
  struct rte_mbuf *mbufs[RTE_MAX_PKT_BURST];
  struct rte_mbuf *mbuf;
  struct msr4hdr *hdr;
  HrzrHeaderParser::PacketType hrzr_packet_type;
  uint8_t *payload;

  // Keep track of number of samples in capture buffer
  uint32_t nb_samples_capbuf = 0;

  // Ring to enqueue capture buffer pointer
  rte_ring *ring;

  // Get lcore id
  lcore_id = rte_lcore_id();

  // Get port id (lcores 1 through NB_PORTS are running the rx threads)
  port_id = lcore_id - 1;

  // Initialize memory to hold capture buffer
  uint8_t *capbuf[NUM_CAPTURE_BUFFERS];
  for (int i = 0; i < NUM_CAPTURE_BUFFERS; i++)
  {
    capbuf[i] = (uint8_t *)rte_malloc(NULL, WRITE_BUFFER_SIZE, 0);
    if (capbuf[i] == NULL)
      rte_exit(EXIT_FAILURE, "Port %d :: Could not allocate memory.\n", port_id);
  }
  uint8_t current_buffer_idx = 0;

  // Get ring id
  ring_id = port_id;

  // Get ring that is used to transfer capture buffer pointers to cores dumping
  // them to files
  ring = rings[ring_id];

  // Print out that we are ready to receive
  rte_log(RTE_LOG_INFO, 0, "%lu - Port %d - Ready to receive data!\n", std::time(NULL), port_id);
  struct timespec tic, toc; 
  clock_gettime (CLOCK_REALTIME, &tic);
  bool once = false;
  size_t rx_bytes = 0;

  while (!force_quit)
  {
    clock_gettime (CLOCK_REALTIME, &toc);
    #ifdef PRINT_RATE
    if (toc.tv_sec - tic.tv_sec == 1) {
        printf("Port %d rate: %f Gbit/s\n", port_id, ((float)rx_bytes*8.0f)/1e9f);
        tic = toc;
        rx_bytes = 0;
    }
    #endif

    // Read burst of packets
    nb_rx = rte_eth_rx_burst(port_id, 0, mbufs, RTE_MAX_PKT_BURST);

    // Loop over packets to be processed
    for (i = 0; i < nb_rx; i++)
    {
      // Get mbuf
      mbuf = mbufs[i];

      // Get header
      hdr = rte_pktmbuf_mtod(mbuf, struct msr4hdr *);

      // Discard irrelevant packets.
      if (!pkt_is_relevant(hdr))
      {
        rte_pktmbuf_free(mbuf);
        continue;
      }

      // Get packet type
      hrzr_packet_type = HrzrHeaderParser::getControlFromHeader(hdr->hrzr_hdr);

      if (hrzr_packet_type == HrzrHeaderParser::PacketType::METADATA)
      {
        rte_pktmbuf_free(mbuf);
        continue;
      }
      else if (hrzr_packet_type == HrzrHeaderParser::PacketType::DATA)
      {
        //get offset to payload
        size_t offset_to_payload = sizeof(struct msr4hdr);
        size_t payload_size = MSR4_PAYLOAD_SIZE;

        if (HrzrHeaderParser::hasExtendedTimestamp(hdr->hrzr_hdr))
        {
          offset_to_payload =  sizeof(struct msr4hdrWithTimestamp);
          payload_size = MSR4_PAYLOAD_SIZE_WITH_ADDITIONAL_TIMESTAMP;
        }

        // Get payload
        payload = rte_pktmbuf_mtod_offset(mbuf, uint8_t *, offset_to_payload);
        //printf("Samples in capbuf %d\n", nb_samples_capbuf);
        size_t samples_to_write = payload_size;
        size_t remainder = 0;
        if (nb_samples_capbuf + payload_size > WRITE_BUFFER_SIZE)
        {
          remainder = (nb_samples_capbuf + payload_size) - WRITE_BUFFER_SIZE;
          samples_to_write = WRITE_BUFFER_SIZE - nb_samples_capbuf;
        }
        // Write samples to capture buffer
        copy_to_ringbuf(capbuf[current_buffer_idx], nb_samples_capbuf, payload, samples_to_write);

        rx_bytes += payload_size;
        // Trigger dump of capture buffer to file when it's full
        if (nb_samples_capbuf == WRITE_BUFFER_SIZE)
        {
          #ifdef VERBOSE
          rte_log(RTE_LOG_INFO, 0, "Buffer %d is full. Ring_cnt %d\n", current_buffer_idx, rte_ring_count(ring));
          #endif

          if (rte_ring_count(ring) == 2)
            rte_exit(EXIT_FAILURE, "Port %d :: Exceeded number of available buffers in ring.!\n", port_id);
          // Do the enqueueing
          ret = rte_ring_enqueue(ring, capbuf[current_buffer_idx]);
          if (ret != 0)
          {
            rte_exit(EXIT_FAILURE, "Port %d :: Unable to insert capture buffer pointer into ring!\n", port_id);
          }
          //flip buffer
          current_buffer_idx += 1;
          if (current_buffer_idx == NUM_CAPTURE_BUFFERS)
            current_buffer_idx = 0;

          nb_samples_capbuf = 0;

          if (remainder != 0) {
            copy_to_ringbuf(capbuf[current_buffer_idx], nb_samples_capbuf, payload, samples_to_write);
          }

          if (!once) {
            rte_log(RTE_LOG_INFO, 0, "%lu - Port %d - First capture buffer available\n", std::time(NULL), port_id);
            once = true;
          }
        }
      }
      else
      {
        throw std::runtime_error("Invalid packet type!");
      }

      // Packet processed. Discard.
      rte_pktmbuf_free(mbuf);
    }
  }

  for (int i = 0; i < NUM_CAPTURE_BUFFERS; i++)
    rte_free(capbuf[i]);
}

static void lcore_dump()
{
  int lcore_id;
  int ring_id;
  int port_id;
  struct rte_ring *ring;
  int ret;
  #ifndef FORWARD_ZMQ

  std::string fname_capture;
  std::string path_capture;

  // File index
  uint32_t idx_file = 0;
  // Amount of data that has been written to file
  size_t size_fwrite;
  int fd = -1;
  #endif
  // Pointer to capture buffer that will be obtained from queue
  uint8_t *capbuf[1];

  // Get lcore id
  lcore_id = rte_lcore_id();

  // Determine port id (lcores 5 to 8 are running the dump threads)
  port_id = lcore_id - (NB_PORTS + 1);

  // Determine ring id
  ring_id = port_id;

  // Get ring that triggers the data dump once an element is inserted
  ring = rings[ring_id];

  // Print out that we are ready to dump
  rte_log(RTE_LOG_INFO, 0, "%lu - Port %d - Ready to dump data!\n", std::time(NULL), port_id);

  // Allocate sample buffer
  //std::complex<float> *samples =(std::complex<float> *)rte_malloc(NULL, nb_samples_per_capture * sizeof(std::complex<float>), 0);
  bool once = false;

  int n_chunks = 0;
  #ifdef FORWARD_ZMQ
  void *context = zmq_ctx_new();
  void *publisher = zmq_socket(context, ZMQ_PUB);
  int rc = zmq_bind(publisher, "ipc:///tmp/feed0");

  if (rc != 0)
  {
    printf("ZMQ error!");
    return;
  }
  #endif
  while (!force_quit)
  {
    // Dequeue one element from the ring
    ret = rte_ring_sc_dequeue(ring, (void **)capbuf);
    if (ret != 0)
    {
      // Nothing dequeued
      continue;
    }

    n_chunks++;
    #ifdef FORWARD_ZMQ
    zmq_msg_t msg;

    for (unsigned i = 0; i < WRITE_BUFFER_SIZE/CHUNK_SIZE; i++)
    {
      rc = zmq_msg_init_data (&msg, capbuf[0] + i*CHUNK_SIZE, CHUNK_SIZE, NULL, NULL); 
      assert (rc == 0);

      if (i == WRITE_BUFFER_SIZE/CHUNK_SIZE-1)
        rc = zmq_msg_send(&msg, publisher, ZMQ_SNDMORE);
      else
        rc = zmq_msg_send(&msg, publisher, 0);
      if (rc < 0)
      {
        printf("ZMQ error it %d err %d!\n", i, zmq_errno());
        return;
      }

      assert(rc == CHUNK_SIZE);
    }
    #else
    // Assemble capture filename
    fname_capture = "capture_" + std::to_string(port_id) + "_" + std::to_string(idx_file) + ".bin";

    // Assemble file path
    path_capture = IQ_FILES_BASE_PATH + fname_capture;

    // Open capture file for writing
    fd = open(path_capture.c_str(),O_WRONLY | O_CREAT);

    if (fd < 0)
    {
      throw std::runtime_error("Could not open file for writing!");
    }

    // Write samples to file
    size_fwrite = write(fd, capbuf[0], WRITE_BUFFER_SIZE);
    if (size_fwrite != WRITE_BUFFER_SIZE)
    {
      throw std::runtime_error("Failed to write to file!");
    }

    // Close capture file
    close(fd);

    // Increment file index
    idx_file = (idx_file + 1) % 10000;

    #endif
    if (!once) {
      rte_log(RTE_LOG_INFO, 0, "%lu - Port %d - First capture buffer written\n", std::time(NULL), port_id);
      once = true;
    }
  }
  #ifdef FORWARD_ZMQ
  zmq_close(publisher);
  zmq_ctx_destroy(context);
  #endif
  rte_log(RTE_LOG_INFO, 0, "%lu - Port %d - %d chunks received.\n", std::time(NULL), port_id, n_chunks);
}

static int launch_lcores(__rte_unused void *dummy)
{
  // Get lcore id
  int lcore_id = rte_lcore_id();

  if (lcore_id > 0 && lcore_id < NB_PORTS + 1)
  {
    // Lcores for packet RX
    lcore_rx();
  }
  else if (lcore_id > NB_PORTS && lcore_id < 2 * NB_PORTS + 1)
  {
    // Lcores for file dump
    lcore_dump();
  }
  else
  {
    
  }
  return 0;
}

static void setup_dpdk()
{
  int ret;
  unsigned port_id;
  unsigned nb_mbufs;
  struct rte_eth_dev_info dev_info;
  struct rte_eth_rxconf rxq_conf;
  struct rte_eth_txconf txq_conf = {};
  struct rte_eth_link link = {};
  char ring_name[16];

  // Register signal handler
  force_quit = false;
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  int nb_ports = NB_PORTS;

  // Assemble command line arguments. Using 2 lcores per port
  std::vector<const char *> argv{"dpdk", "-l", "1,2,3,4,5,6,7,8"};

  // Initialize EAL
  ret = rte_eal_init(argv.size(), (char **)argv.data());
  if (ret < 0)
    rte_exit(EXIT_FAILURE, ":: RTE init failed\n");
 
  // Determine size of mbuf pool
  nb_mbufs = RTE_MAX(nb_ports * (RTE_RX_DESC_DEFAULT + RTE_MAX_PKT_BURST +
                                 nb_ports * RTE_MEMPOOL_CACHE_SIZE),
                     8192U);

  // Create mbuf pool
  mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs, RTE_MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  if (mbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, ":: Unable to init membuf pool\n");

  for(port_id = 0; port_id < NB_PORTS; port_id++)
  {
    // Get port info
    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0)
      rte_exit(EXIT_FAILURE, ":: Unable to get dev info\n");

    // Enable offloads
    port_conf.txmode.offloads &= dev_info.tx_offload_capa;

    // Configure device (E810 needs a TX queue, even though we will not use it!)
    ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    if (ret != 0)
      rte_exit(EXIT_FAILURE, ":: Unable to configure dev\n");

    // Set default RX queue conf, enable all offloads
    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = port_conf.rxmode.offloads;

    // Configure RX queue
    ret = rte_eth_rx_queue_setup(port_id, 0, RTE_RX_DESC_DEFAULT, rte_eth_dev_socket_id(port_id), &rxq_conf, mbuf_pool);
    if (ret != 0)
      rte_exit(EXIT_FAILURE, ":: Uanble to configure RX queue\n");

    // Configure TX queue (E810 needs this, we will not actually use it!)
    ret = rte_eth_tx_queue_setup(port_id, 0, RTE_TX_DESC_DEFAULT, rte_eth_dev_socket_id(port_id), &txq_conf);
    if (ret != 0)
      rte_exit(EXIT_FAILURE, ":: Unable to configure TX queue\n");

    // Enable promisuous mode
    ret = rte_eth_promiscuous_enable(port_id);
    if (ret != 0)
      rte_exit(EXIT_FAILURE, ":: Unable to enable promisc mode\n");

    // Create one ring per port. This ring is used for lockless
    // communication between cores. When an RX core processed enough data to
    // be written to files by a dump core, this is notified by inserting the
    // capture buffer pointer into the ring.
    sprintf(ring_name, "ring_%d", port_id);
    rings[port_id] = rte_ring_create(ring_name, 8, rte_eth_dev_socket_id(port_id), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (rings[port_id] == NULL)
      rte_exit(EXIT_FAILURE, ":: Unable to create ring\n");
  }

  for(port_id = 0; port_id < NB_PORTS; port_id++)
  {
    // Start the device
    ret = rte_eth_dev_start(port_id);
    if (ret != 0)
      rte_exit(EXIT_FAILURE, ":: Unable to start dev\n");

    // Make sure that link is up
    ret = rte_eth_link_get(port_id, &link);
    if (ret != 0 || link.link_status != ETH_LINK_UP)
      rte_exit(EXIT_FAILURE, ":: Link is not up\n");
    
    // Reset statistics. If we don't do the reset, the port stats will not
    // be accurate upon application exit.
    ret = rte_eth_stats_reset(port_id);
    if (ret != 0)
      rte_exit(EXIT_FAILURE, ":: Unable to reset stats\n");
  }
}

static void launch()
{
  unsigned lcore_id;
  // Launch one worker thread per lcore
  rte_eal_mp_remote_launch(launch_lcores, NULL, CALL_MAIN);
  RTE_LCORE_FOREACH_WORKER(lcore_id)
  {
    if (rte_eal_wait_lcore(lcore_id) < 0)
    {
      break;
    }
  }
}

static void cleanup_dpdk()
{
  int ret;
  unsigned port_id;
  struct rte_eth_stats eth_stats;

  // Stop devs
  for(port_id = 0; port_id < NB_PORTS; port_id++)
  {
    // Print interface stats
    ret = rte_eth_stats_get(port_id, &eth_stats);
    if (ret != 0)
      rte_exit(EXIT_FAILURE, ":: Unable to get port stats\n");
    rte_log(RTE_LOG_INFO, 0, "Port ID: %d, Mem alloc fails: %lu, Dropped: %lu, Err received: %lu, Failed transmitted: %lu\n", port_id, eth_stats.rx_nombuf, eth_stats.imissed, eth_stats.ierrors, eth_stats.oerrors);

    // Print out warning if there was packet loss
    if ((eth_stats.rx_nombuf + eth_stats.imissed + eth_stats.ierrors) > 0)
      rte_log(RTE_LOG_WARNING, 0, ":: PACKET LOSS!\n");

    ret = rte_eth_dev_stop(port_id);
    if (ret != 0)
      rte_exit(EXIT_FAILURE, ":: Unable to stop dev\n");
    rte_eth_dev_close(port_id);

    // Cleanup rings
    rte_ring_free(rings[port_id]);
  }

  // Cleanup EAL
  rte_eal_cleanup();
}

int main(__attribute__((unused)) int argc, __attribute__((unused)) char **argv)
{
  // Do DPDK setup
  setup_dpdk();

  // Launch lcore threads
  launch();

  // Do DPDK cleanup
  cleanup_dpdk();

  return 0;
}
