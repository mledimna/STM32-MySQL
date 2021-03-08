#ifndef SQL_TYPES_H
#define SQL_TYPES_H

#include "mbed.h"

int get_lcb_len(int offset);
char *read_string(int *offset);
int readInt(uint8_t * packet, int offset, int size);
int readLenEncInt(uint8_t * packet, int offset);
char* readLenEncString(uint8_t * packet, int offset);
void store_int(uint8_t *buff, long value, int size);

#endif