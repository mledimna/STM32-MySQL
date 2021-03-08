#ifndef PACKETS_H
#define PACKETS_H

#include <mbed.h>

typedef enum{
    PACKET_OK = 0x00,
    PACKET_ERR = 0x01,
    PACKET_EOF = 0x02,
    PACKET_UNKNOWN = 0x03
}Packet_Type;

Packet_Type identifyPacket(uint8_t* packet, int packet_length);

#endif