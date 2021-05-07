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
        // Get payload length (3 first bytes of MySQLpacket)
        this->mPayloadLength = readFixedLengthInt(pPacket, 0, 3);
        this->mPacketNumber = readFixedLengthInt(pPacket, 3, 1);

        this->mPayload = (uint8_t *)malloc(sizeof(uint8_t) * this->mPayloadLength);
        memcpy(this->mPayload, pPacket + 4, this->mPayloadLength);
    }

    ~MySQL_Packet()
    {
        free(this->mPayload);
        this->mPayload = NULL;
        this->mPayloadLength = 0;
        this->mPacketNumber = 0;
    }

    const uint8_t *getPayload(void)
    {
        return mPayload;
    }

    uint32_t getPayloadLength(void)
    {
        return this->mPayloadLength;
    }

    uint32_t getPacketLength(void)
    {
        return this->mPayloadLength + 4;
    }

    uint32_t getPacketNumber(void)
    {
        return this->mPacketNumber;
    }

    Packet_Type getPacketType(void);

    string toString(void)
    {
        string str = "";
        str += "Packet n°" + to_string(mPacketNumber) + " (" + to_string(mPayloadLength + 4) + "B) has a payload of " + to_string(mPayloadLength) + "B";
        return str;
    }

private:
    uint32_t mPacketNumber = 0;
    uint32_t mPayloadLength = 0;
    uint8_t *mPayload = NULL;
};

#endif