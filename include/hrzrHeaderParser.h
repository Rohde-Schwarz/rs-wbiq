#pragma once

#include <cinttypes>

class HrzrHeaderParser
{
public:
  enum class PacketType
  {
    DATA = 0,
    DATA_END_OF_BURST,
    FLOW_CONTROL,
    COMMAND,
    COMMAND_RESPONSE,
    COMMAND_RESPONSE_ERROR,
    METADATA,
  };

  static PacketType getControlFromHeader(uint64_t hrzr);
  static uint16_t getSequenceNumberFromHeader(uint64_t hrzr);
};
