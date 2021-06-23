/**
 * @file SQLVarTypes.h
 * @author Mathieu LE DIMNA (mathieu-ledimna@outlook.com)
 * @brief MySQL var types operations
 * @version 0.1
 * @date 2021-05-06
 * 
 * @copyright Copyright (c) 2021
 * 
 */
#ifndef SQL_TYPES_H
#define SQL_TYPES_H

#include "mbed.h"

uint32_t readFixedLengthInt(const uint8_t * packet, int offset, int size);
uint32_t readLenEncInt(const uint8_t * packet, int offset);
void store_int(uint8_t *buff, long value, int size);

void readLenEncString(char* pString, const uint8_t * packet, int offset);
char* readLenEncString_alloc(const uint8_t * packet, int offset);

#endif