#include "PacketsTypes.h"

Packet_Type MySQL_Packet::getPacketType(void)
{
    Packet_Type type = PACKET_UNKNOWN;

    switch (this->getPayload()[0])
    {
    case 0x00:
        type = PACKET_OK;
        break;

    case 0xFE:
        type = PACKET_EOF;
        break;

    case 0xFF:
        type = PACKET_ERR;
        break;

    default:
        break;
    }

    return type;
}