#include "util.h"

bool pkt_is_relevant(msr4hdr *hdr)
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

void copy_to_ringbuf(uint8_t *dst_buffer, uint32_t &offset_in_buffer, uint8_t *payload, size_t n_samples_to_copy)
{
  rte_memcpy(dst_buffer + offset_in_buffer, payload, n_samples_to_copy);
  offset_in_buffer += n_samples_to_copy;
}