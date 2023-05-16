#include "hrzrHeaderParser.h"

#include "exceptions.h"
#include <arpa/inet.h>

HrzrHeaderParser::PacketType HrzrHeaderParser::getControlFromHeader(uint64_t hrzr)
{
  auto control = (static_cast<uint8_t>(hrzr) & 0xD0) >> 4;
  switch (control)
  {
  case 0x00:
    return PacketType::DATA;
  case 0x01:
    return PacketType::DATA_END_OF_BURST;
  case 0x04:
    return PacketType::FLOW_CONTROL;
  case 0x08:
    return PacketType::COMMAND;
  case 0x0C:
    return PacketType::COMMAND_RESPONSE;
  case 0x0D:
    return PacketType::COMMAND_RESPONSE_ERROR;
  case 0x05:
    return PacketType::METADATA;
  default:
    throw InvalidHrzrHeader("Could not match control.");
  }
}

uint16_t HrzrHeaderParser::getSequenceNumberFromHeader(uint64_t hrzr)
{
  uint16_t squ_nr_raw = static_cast<uint16_t>(hrzr) & 0xFF0F;
  uint16_t squ_nr = ntohs(squ_nr_raw);
  return squ_nr;
}
