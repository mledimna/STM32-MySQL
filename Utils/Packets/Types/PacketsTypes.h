#ifndef PACKETS_H
#define PACKETS_H

#include <mbed.h>
#include "../SQLVarTypes/SQLVarTypes.h"

typedef enum
{
    PACKET_OK = 0x00,
    PACKET_UNKNOWN = 0x01,
    PACKET_EOF = 0xFE,
    PACKET_ERR = 0xFF
} Packet_Type;

class MySQL_Packet
{
public:
    MySQL_Packet(const uint8_t *pPacket)
    {
        this->mPayloadLength = readFixedLengthInt(pPacket, 0, 3);
        this->mPacketNumber = readFixedLengthInt(pPacket, 3, 1);
        this->mPayload = (uint8_t *)malloc(sizeof(uint8_t) * this->mPayloadLength);
        memcpy(this->mPayload, pPacket + 4, this->mPayloadLength);
    }

    MySQL_Packet()
    {
        this->mPayloadLength = 0;
        this->mPacketNumber = 0;
        this->mPayload = NULL;
    }

    ~MySQL_Packet()
    {
        free(this->mPayload);
        this->mPayload = NULL;
        this->mPayloadLength = 0;
        this->mPacketNumber = 0;
    }

    Packet_Type getPacketType(void);

    uint32_t getPacketLength(void)
    {
        return this->mPayloadLength + 4;
    }

    uint32_t mPacketNumber = 0;
    uint32_t mPayloadLength = 0;
    uint8_t *mPayload = NULL;
};

#endif