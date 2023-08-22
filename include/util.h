#pragma once
#include "dpdk_ms4r_rx.h"

bool pkt_is_relevant(msr4hdr *hdr);
void copy_to_ringbuf(uint8_t *dst_buffer, uint32_t &offset_in_buffer, uint8_t *payload, size_t n_samples_to_copy);