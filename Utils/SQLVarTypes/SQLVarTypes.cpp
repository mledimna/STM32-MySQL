#include "SQLVarTypes.h"

int get_lcb_len(uint8_t* buffer, int offset) {
  int read_len = buffer[offset];
  if (read_len > 250) {
    // read type:
	uint8_t type = buffer[offset+1];
    if (type == 0xfc)
      read_len = 2;
    else if (type == 0xfd)
      read_len = 3;
    else if (type == 0xfe)
      read_len = 8;
  }
  return read_len;
}

char* read_string(uint8_t* buffer, int *offset){
    char *str = NULL;
    int len = get_lcb_len(buffer, *offset);
    char head = buffer[*(offset)];

    if(head==0xFE) return NULL;
    
    str = (char*)malloc(len+1);
    memcpy(str, (char *)&buffer[*offset+1], len);
    str[len] = '\0';

    return str;
}

int readInt(uint8_t * packet, int offset, int size) {
  int value = 0;

  for(int i=0; i<size; i++) value |= packet[i+offset]<<(i*8);

  return value;
}

int readLenEncInt(uint8_t * packet, int offset) {
  int value = 0;

  if(packet[offset]<251) return packet[offset];
  else if(packet[offset]==0xFC){
      for(int i=0; i<2; i++) value |= packet[i+1+offset]<<(i*8);
  }
  else if(packet[offset]==0xFD){
      for(int i=0; i<3; i++) value |= packet[i+1+offset]<<(i*8);
  }
  else if(packet[offset]==0xFE){
      for(int i=0; i<8; i++) value |= packet[i+1+offset]<<(i*8);
  }

  return value;
}

char* readLenEncString(uint8_t * packet, int offset){
    char* str = NULL;
    int str_size = readLenEncInt(packet, offset);

    str = (char*)malloc(sizeof(char)*(str_size+1));

    if(packet[offset]<251) for(int i=0; i<str_size; i++) str[i] = packet[i+1+offset];
    else if(packet[offset]==0xFC) for(int i=0; i<str_size; i++) str[i] = packet[i+3+offset];
    else if(packet[offset]==0xFD) for(int i=0; i<str_size; i++) str[i] = packet[i+4+offset];
    else if(packet[offset]==0xFE) for(int i=0; i<str_size; i++) str[i] = packet[i+9+offset];

    str[str_size] = '\0';

    return str;
}

void store_int(uint8_t *buff, long value, int size){
    memset(buff, 0, size);
    if (value < 0xff)
        buff[0] = (uint8_t)value;
    else if (value < 0xffff) {
        buff[0] = (uint8_t)value;
        buff[1] = (uint8_t)(value >> 8);
    } else if (value < 0xffffff) {
        buff[0] = (uint8_t)value;
        buff[1] = (uint8_t)(value >> 8);
        buff[2] = (uint8_t)(value >> 16);
    } else if (value < 0xffffff) {
        buff[0] = (uint8_t)value;
        buff[1] = (uint8_t)(value >> 8);
        buff[2] = (uint8_t)(value >> 16);
        buff[3] = (uint8_t)(value >> 24);
    }
}
