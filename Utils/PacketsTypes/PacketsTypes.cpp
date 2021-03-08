#include "PacketsTypes.h"

Packet_Type identifyPacket(uint8_t* packet, int packet_length){
    Packet_Type type = PACKET_UNKNOWN;

    if(packet_length>0){
        switch(packet[4]){
            case 0x00:
                type = PACKET_OK;
            break;

            case 0xFF:
                type = PACKET_ERR;
            break;

            case 0xFE:
                type = PACKET_EOF;
            break;

            default:
            break;
        }
    }

    return type;
}