#include "dpdk_ms4r_rx.h"
#include "hrzrHeaderParser.h"
#include "xcorr.h"
#include <iostream>
#include <rte_memcpy.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static void signal_handler(int signum)
{
  if (signum == SIGINT || signum == SIGTERM)
    force_quit = true;
}

static bool pkt_is_relevant(rte_mbuf *mbuf, msr4hdr *hdr)
{
  // Not considering non-IPv4 packets
  if (hdr->ether_hdr.ether_type != htons(RTE_ETHER_TYPE_IPV4))
    return false;

  // Not considering non-UDP packets
  if (hdr->ipv4_hdr.next_proto_id != IPPROTO_UDP)
    return false;

  // Considering everything else
  return true;
}

static void lcore_rx()
{
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
  uint32_t *metadata;

  // Keep track of number of samples in capture buffer
  uint32_t nb_samples_capbuf = 0;

  // Number of samples to write to the capture buffer
  uint32_t nb_samples_capbuf_write;

  // Number of samples that can be written to the capture buffer
  uint32_t nb_samples_capbuf_avail;

  // Which is the index of the first sample to be used in the packet?
  uint16_t idx_first_sample = 0;

  // Counter for skipped packets after wrtiting the capture buffer to file
  uint32_t nb_samples_skipped = 0;

  // Sync is initially not done
  bool sync_done = false;

  // Sync is initially not active
  bool sync_active = false;

  // If calibration is enabled, it is initially not done
  bool calib_done;
  bool calib_discard_done;
  if (ENABLE_CALIBRATION)
  {
    calib_done = false;
    calib_discard_done = false;
  }
  else
  {
    calib_done = true;
    calib_discard_done = true;
  }

  // Calibration is initially not active
  bool calib_active = false;

  // Number of samples to skip in the sync phase
  uint64_t nb_samples_sync_discard;

  // Bool to indicate whether samples are currently being skipped to give
  // enough time to dump the capture buffers to files
  bool skip_active = false;

  // Timesamp in ns, read from the meta data
  uint64_t meta_ts;

  // Sample rate in MHz, read from the meta data for debug output
  double meta_sample_rate;

  // Carrier frequency in GHz, read from the meta data for debug output
  double meta_carrier_freq;

  // Ring to enqueue capture buffer pointer
  rte_ring *ring;

  // Number of samples per capture (always capturing for the duration of 2
  // slots to ensure that one complete slot is included in the capture file)
  uint32_t nb_samples_per_capture = ceil(2.0 * double(SLOT_DURATION) * double(MSR4_SAMPLING_FREQUENCY));

  // Number of samples per calibration
  uint32_t nb_samples_per_calib = ceil(double(CALIB_CAP_DURATION) * double(MSR4_SAMPLING_FREQUENCY));

  // Variable to the number of samples to capture based on whether we are in
  // calibration or capture mode
  uint32_t nb_samples_capture;
  if (ENABLE_CALIBRATION)
  {
    // Initially collect enough samples to finish calibration
    nb_samples_capture = nb_samples_per_calib;
  }
  else
  {
    // No calibration, so always collect enough samples to finish a capture
    nb_samples_capture = nb_samples_per_capture;
  }

  // Number of samples to skip after each captured slot
  uint32_t nb_samples_skip_capture = ceil(double(MSR4_SAMPLING_FREQUENCY) / double(SLOTS_PER_SECOND)) - nb_samples_per_capture;

  // Variable that will hold the number of samples to be skipped after
  // calibration or after capture
  uint32_t nb_samples_skip;

  // Initialize memory to hold capture buffer
  uint8_t *capbuf[NUM_CAPTURE_BUFFERS];
  for (int i = 0; i < NUM_CAPTURE_BUFFERS; i++)
  {
    capbuf[i] = (uint8_t *)rte_malloc(NULL, WRITE_BUFFER_SIZE, 0);
    if (capbuf[i] == NULL)
      rte_exit(EXIT_FAILURE, "Port %d :: Could not allocate memory.\n", port_id);
  }
  uint8_t current_buffer_idx = 0;

  // Allocate data structure to hold info on calibration data passed between
  // cores
  //struct calib_data *calib_data = (struct calib_data *)rte_malloc(NULL, sizeof(struct calib_data), 0);

  // Get lcore id
  lcore_id = rte_lcore_id();

  // Get port id (lcores 1 through 4 are running the rx threads)
  port_id = lcore_id - 1;

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
      if (!pkt_is_relevant(mbuf, hdr))
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
        // Get payload
        payload = rte_pktmbuf_mtod_offset(mbuf, uint8_t *, sizeof(struct msr4hdr));
        //printf("Samples in capbuf %d\n", nb_samples_capbuf);
        // Parse payload and write samples to capture buffer
        rte_memcpy(capbuf[current_buffer_idx] + nb_samples_capbuf, payload, MSR4_PAYLOAD_SIZE);
        nb_samples_capbuf += MSR4_PAYLOAD_SIZE;
        rx_bytes += MSR4_PAYLOAD_SIZE;
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
            rte_exit(EXIT_FAILURE, "Port %d :: Unable to insert capture buffer pointer into ring! Port %d\n", port_id);
          }
          //flip buffer
          current_buffer_idx += 1;
          if (current_buffer_idx == NUM_CAPTURE_BUFFERS)
            current_buffer_idx = 0;

          nb_samples_capbuf = 0;

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
    rte_free(capbuf);
}

static void lcore_dump()
{
  int lcore_id;
  int ring_id;
  int port_id;
  struct rte_ring *ring;
  int ret;
  std::FILE *file_capture;
  std::string fname_capture;
  std::string path_capture;

  // File index
  uint32_t idx_file = 0;

  // Pointer to capture buffer that will be obtained from queue
  uint8_t *capbuf[1];

  // Get lcore id
  lcore_id = rte_lcore_id();

  // Determine port id (lcores 5 to 8 are running the dump threads)
  port_id = lcore_id - 5;

  // Determine ring id
  ring_id = port_id;

  // Get ring that triggers the data dump once an element is inserted
  ring = rings[ring_id];

  // Print out that we are ready to dump
  rte_log(RTE_LOG_INFO, 0, "%lu - Port %d - Ready to dump data!\n", std::time(NULL), port_id);

  // Initially no file write is active
  fwrite_active[port_id] = false;

  // Amount of data that has been written to file
  size_t size_fwrite;
  int fd = -1;
  // Allocate sample buffer
  //std::complex<float> *samples =(std::complex<float> *)rte_malloc(NULL, nb_samples_per_capture * sizeof(std::complex<float>), 0);
  bool once = false;
  while (!force_quit)
  {
    // Dequeue one element from the ring
    ret = rte_ring_sc_dequeue(ring, (void **)capbuf);
    if (ret != 0)
    {
      // Nothing dequeued
      continue;
    }

    // Assemble capture filename
    fname_capture = "capture_" + std::to_string(port_id) + "_" + std::to_string(idx_file) + ".bin";

    // Assemble file path
    path_capture = "/media/nvme-stripe/" + fname_capture;

    // Open capture file for writing
    //file_capture = fopen(path_capture.c_str(), "wb");
    fd = open(path_capture.c_str(),O_WRONLY | O_CREAT);

    if (fd < 0)
    {
      throw std::runtime_error("Could not open file for writing!");
    }

    // Write samples to file
    //size_fwrite = fwrite(capbuf[0], 1, WRITE_BUFFER_SIZE, file_capture);
    size_fwrite = write(fd, capbuf[0], WRITE_BUFFER_SIZE);
    if (size_fwrite != WRITE_BUFFER_SIZE)
    {
      
      throw std::runtime_error("Failed to write to file!");
    }

    // Close capture file
    //fclose(file_capture);
    close(fd);

    // Increment file index
    idx_file = (idx_file + 1) % 10000;

    // Mark file write as inactive. No need for mutex here, because there
    // should be plenty of time between access by two different cores
    fwrite_active[port_id] = false;
    if (!once) {
      rte_log(RTE_LOG_INFO, 0, "%lu - Port %d - First capture buffer written\n", std::time(NULL), port_id);
      once = true;
    }
  }
}

static int launch_lcores(__rte_unused void *dummy)
{
  // Get lcore id
  int lcore_id = rte_lcore_id();

  if (lcore_id <= 4)
  {
    // Lcores 1-4 handle packet RX
    lcore_rx();
  }
  else if (lcore_id >= 5 && lcore_id <= 8)
  {
    // Lcores 5-8 handle file dump
    lcore_dump();
  }
  else
  {
    throw std::runtime_error("Invalid lcore!");
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
  struct rte_eth_link link = {0};
  char ring_name[16];

  // Register signal handler
  force_quit = false;
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  // Always using all four ports
  int nb_ports = 4;

  // Assemble command line arguments. Using 2 lcores per port, an additional
  // one for calibration
  std::vector<const char *> argv{"dpdk", "-l", "1,2,3,4,5,6,7,8"};

  // Initialize EAL
  ret = rte_eal_init(argv.size(), (char **)argv.data());
  if (ret < 0)
    rte_exit(EXIT_FAILURE, ":: RTE init failed\n");

  // Get number of interfaces
  int nr_ports = rte_eth_dev_count_avail();
  
  if (nr_ports != nb_ports)
    rte_exit(EXIT_FAILURE, ":: Need to have 4 ports!\n");
  
  // Determine size of mbuf pool
  nb_mbufs = RTE_MAX(nb_ports * (nb_rxd + RTE_MAX_PKT_BURST +
                                 nb_ports * RTE_MEMPOOL_CACHE_SIZE),
                     8192U);

  // Create mbuf pool
  mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs, RTE_MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  if (mbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, ":: Unable to init membuf pool\n");

  RTE_ETH_FOREACH_DEV(port_id)
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
    ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd, rte_eth_dev_socket_id(port_id), &rxq_conf, mbuf_pool);
    if (ret != 0)
      rte_exit(EXIT_FAILURE, ":: Uanble to configure RX queue\n");

    // Configure TX queue (E810 needs this, we will not actually use it!)
    ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd, rte_eth_dev_socket_id(port_id), &txq_conf);
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

  RTE_ETH_FOREACH_DEV(port_id)
  {
    // Start the device
    ret = rte_eth_dev_start(port_id);
    if (ret != 0)
      rte_exit(EXIT_FAILURE, ":: Unable to start dev\n");

    // Make sure that link is up
    ret = rte_eth_link_get(port_id, &link);
    if (ret != 0 || link.link_status != RTE_ETH_LINK_UP)
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
  int ret;
  unsigned lcore_id;

  // Launch one worker thread per lcore
  rte_eal_mp_remote_launch(launch_lcores, NULL, CALL_MAIN);
  RTE_LCORE_FOREACH_WORKER(lcore_id)
  {
    if (rte_eal_wait_lcore(lcore_id) < 0)
    {
      ret = -1;
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
  RTE_ETH_FOREACH_DEV(port_id)
  {
    // Print interface stats
    ret = rte_eth_stats_get(port_id, &eth_stats);
    if (ret != 0)
      rte_exit(EXIT_FAILURE, ":: Unable to get port stats\n");
    rte_log(RTE_LOG_INFO, 0, "Port ID: %d, Mem alloc fails: %d, Dropped: %d, Err received: %d, Failed transmitted: %d\n", port_id, eth_stats.rx_nombuf, eth_stats.imissed, eth_stats.ierrors, eth_stats.oerrors);

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

  // Free calibration ring
  rte_ring_free(ring_calib);

  // Cleanup EAL
  rte_eal_cleanup();
}

int main(int argc, char **argv)
{
  // Do DPDK setup
  setup_dpdk();

  // Launch lcore threads
  launch();

  // Do DPDK cleanup
  cleanup_dpdk();

  return 0;
}
