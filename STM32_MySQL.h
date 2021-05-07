/**
 * @file STM32_MySQL.h
 * @author Mathieu LE DIMNA (mathieu-ledimna@outlook.com)
 * @brief STM32-MySQL library using Mbed framework
 * @version 2.0
 * @date 2021-04-30
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#ifndef STM32_MYSQL_H
#define STM32_MYSQL_H

#include <iostream>
#include <vector>
#include <string>
#include "mbed.h"
#include "EthernetInterface.h"
<<<<<<< HEAD
#include "./Utils/PacketsTypes/PacketsTypes.h"
=======
#include "./Utils/Packets/Types/PacketsTypes.h"
>>>>>>> 47383dd... Hot Fix
#include "./Utils/SHA1/SHA1.h"
#include "./Utils/SQLVarTypes/SQLVarTypes.h"

#define RECV_SIZE 1024

typedef struct
{
    char catalog[50] = {'\0'};
    char schema[50] = {'\0'};
    char table[50] = {'\0'};
    char org_table[50] = {'\0'};
    char name[50] = {'\0'};
    char org_name[50] = {'\0'};
    int fields_len = 0;
    int character_set = 0;
    int column_len = 0;
    int type = 0;
    int flags = 0;
    int decimals = 0;
} TypeDef_ColumnDefinition;

<<<<<<< HEAD
typedef struct{
    char* database; //Database Name
    TypeDef_Table* table; //Table struct pointer
}TypeDef_Database;
=======
typedef struct
{
    char *Table_Name = NULL;    
    int Column_Count = 0;       //Number of columns
    int Row_Count = 0;          //Number of rows
    char **Column_Names = NULL; //Column names
    char ***Row_Values = NULL;  //Row Values
} TypeDef_Table;

typedef struct
{
    char *Database_Name = NULL;  //Database Name
    TypeDef_Table *Table = NULL; //Table struct pointer
} TypeDef_Database;
>>>>>>> 47383dd... Hot Fix

class MySQL
{
public:
    MySQL(TCPSocket *pTCPSocket, const char *server_ip);
    ~MySQL(void);
<<<<<<< HEAD
    
    bool connect(const char* user, const char* password);
=======
    bool connect(const char *user, const char *password);
>>>>>>> 47383dd... Hot Fix
    bool disconnect();
    bool query(const char *pQuery);
<<<<<<< HEAD
    
    void printDatabase(TypeDef_Database* Database);
    

    private:
    TCPSocket* tcp_socket = NULL;
    const char* server_ip = NULL;
    uint8_t *buffer = NULL;
    uint8_t seed[20] = {0};

    uint8_t** recieve(int* packets_count);
    int mysql_write(char * message, uint16_t len);
    TypeDef_Database* parseTable(uint8_t** packets_received,int packets_count);
    void freeRecievedPackets(uint8_t** packets_received, int* packets_count);
    TypeDef_Database* freeDatabase(TypeDef_Database* Database);
=======
    void printDatabase(void);

private:
    TCPSocket *mTcpSocket = NULL;
    const char *mServerIP = NULL;

    uint8_t *mBuffer = NULL;
    uint32_t mBufferSize = 0;

    std::vector<MySQL_Packet*> mPacketsRecieved;

    uint8_t mSeed[20] = {0};                

    TypeDef_Database* mDatabase = NULL;

    // IO Functions
    bool recieve(void);
    int write(char *message, uint16_t len);
>>>>>>> 47383dd... Hot Fix
    int send_authentication_packet(const char *user, const char *password);
    void flush_packet(void);
    void parse_handshake_packet(void);
    bool parseTable(void);
    int getNewOffset(const uint8_t *packet, int offset);
    int check_ok_packet(void);
    int scramble_password(const char *password, uint8_t *pwd_hash);
<<<<<<< HEAD
    void read_packet();
    void parse_handshake_packet();
    int check_ok_packet();
    int getNewOffset(uint8_t * packet, int offset);
=======
    
    void freeBuffer(void);
    void freeRecievedPackets(void);
    void freeDatabase(void);
>>>>>>> 47383dd... Hot Fix
};

#endif