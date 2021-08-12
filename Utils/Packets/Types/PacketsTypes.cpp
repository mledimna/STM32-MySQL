#include "PacketsTypes.h"

Packet_Type MySQL_Packet::getPacketType(void)
{
    Packet_Type type = PACKET_UNKNOWN;

    switch (this->mPayload[0])
    {
    case 0x00:
        type = PACKET_OK;
        break;

    case 0xFE:
        if (this->mPayloadLength >= 8)
        {
            type = PACKET_TEXTRESULTSET;
        }
        else
        {
            type = PACKET_EOF;
        }
        break;

    case 0xFF:
        type = PACKET_ERR;
        break;

    default:
        type = PACKET_TEXTRESULTSET;
        break;
    }

    return type;
}