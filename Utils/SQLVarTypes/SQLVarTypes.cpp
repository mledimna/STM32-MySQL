/**
 * @file SQLVarTypes.cpp
 * @author Mathieu LE DIMNA (mathieu-ledimna@outlook.com)
 * @brief MySQL var types operations
 * @version 0.1
 * @date 2021-05-06
 * 
 * @copyright Copyright (c) 2021
 * 
 */
#include "SQLVarTypes.h"

/**
 * @brief Read Fixed-Length Int from MySQL Packet
 * 
 * @param packet Pointer to first byte of MySQL Packet
 * @param offset Offset from start pointer to read
 * @param size Number of bytes coding the Integer
 * @return uint32_t Unsigned 32 bits integer value
 */
uint32_t readFixedLengthInt(const uint8_t *packet, int offset, int size)
{
  uint32_t value = 0;

  for (int i = 0; i < size; i++)
  {
    // value |= *(packet + offset + i) << (i * 8);
    value += ((uint32_t)packet[offset+i])*((uint32_t)pow(10,i));
  }

  return value;
}

/**
 * @brief Read Length Encoded Int from MySQL Packet
 * 
 * @param packet Pointer to first byte of MySQL Packet
 * @param offset Offset from start pointer to read
 * @return uint32_t Unsigned 32 bits integer value
 */
uint32_t readLenEncInt(const uint8_t *packet, int offset)
{
  uint32_t value = 0;

  if (packet[offset] < 251)
    value = packet[offset];
  else if (packet[offset] == 0xFC)
  {
    for (int i = 0; i < 2; i++)
      value |= packet[i + 1 + offset] << (i * 8);
  }
  else if (packet[offset] == 0xFD)
  {
    for (int i = 0; i < 3; i++)
      value |= packet[i + 1 + offset] << (i * 8);
  }
  else if (packet[offset] == 0xFE)
  {
    for (int i = 0; i < 8; i++)
      value |= packet[i + 1 + offset] << (i * 8);
  }
  return value;
}

/**
 * @brief Read Length Encoded String from MySQL Packet
 * 
 * @param pString Pointer to string to fill
 * @param packet Pointer to first char of MySQL Packet
 * @param offset Offset from start pointer to read
 */
void readLenEncString(char *pString, const uint8_t *packet, int offset)
{
  int str_size = readLenEncInt(packet, offset);

  if (packet[offset] < 251)
    memcpy(pString, packet + 1 + offset, str_size);
  else if (packet[offset] == 0xFC)
    memcpy(pString, packet + 3 + offset, str_size);
  else if (packet[offset] == 0xFD)
    memcpy(pString, packet + 4 + offset, str_size);
  else if (packet[offset] == 0xFE)
    memcpy(pString, packet + 9 + offset, str_size);

  pString[str_size] = '\0';
}

char *readLenEncString_alloc(const uint8_t *packet, int offset)
{
  int str_size = readLenEncInt(packet, offset);
  char *str = (char *)malloc(sizeof(char) * (str_size + 1));

  if (packet[offset] < 251)
    memcpy(str, packet + 1 + offset, str_size);
  else if (packet[offset] == 0xFC)
    memcpy(str, packet + 3 + offset, str_size);
  else if (packet[offset] == 0xFD)
    memcpy(str, packet + 4 + offset, str_size);
  else if (packet[offset] == 0xFE)
    memcpy(str, packet + 9 + offset, str_size);

  str[str_size] = '\0';

  return str;
}

/**
 * @brief Store 
 * 
 * @param buff 
 * @param value 
 * @param size 
 */
void store_int(uint8_t *buff, long value, int size)
{
  memset(buff, 0, size);
  if (value < 0xff)
    buff[0] = (uint8_t)value;
  else if (value < 0xffff)
  {
    buff[0] = (uint8_t)value;
    buff[1] = (uint8_t)(value >> 8);
  }
  else if (value < 0xffffff)
  {
    buff[0] = (uint8_t)value;
    buff[1] = (uint8_t)(value >> 8);
    buff[2] = (uint8_t)(value >> 16);
  }
  else
  {
    buff[0] = (uint8_t)value;
    buff[1] = (uint8_t)(value >> 8);
    buff[2] = (uint8_t)(value >> 16);
    buff[3] = (uint8_t)(value >> 24);
  }
}
