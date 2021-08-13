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
#include "./Utils/Packets/Types/PacketsTypes.h"
#include "./Utils/SHA1/SHA1.h"
#include "./Utils/SQLVarTypes/SQLVarTypes.h"

/**
 * @brief Used to send query over TCP socket.
 * It MUST be equal to framework max TCP send buffer size
 * otherwise TCP dialog will be interrupted by an overflow
 * causing MYSQL query interruption and unintelligible
 * request to server. 
 */
#define SEND_SIZE (MBED_CONF_LWIP_TCP_MSS * 2)

/**
 * @brief Used to recieve RECV_SIZE bytes from server.
 * This does not limit the recieve size, incoming data
 * will then be sored into mBuffer which is a dynamic 
 * size buffer.
 */
#define RECV_SIZE (SEND_SIZE)

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

/**
 * @brief Stores the SELECT query result.
 * 
 */
typedef struct
{
    char *Table_Name = NULL;
    int Column_Count = 0;
    int Row_Count = 0;
    char **Column_Names = NULL;
    char ***Row_Values = NULL;
} TypeDef_Table;

/**
 * @brief Stores the SELECT query results.
 * 
 */
typedef struct
{
    char *Database_Name = NULL;
    TypeDef_Table *Table = NULL;
} TypeDef_Database;

/**
 * @brief Stores the raw MySQL packet
 * 
 * @param payload_length Size of the payload in bytes.
 * @param sequence_id MySQL packet number in current dialog.
 * @param payload MySQL query result of size `payload_length`.
 */
typedef struct
{
    uint8_t payload_length[3];
    uint8_t sequence_id;
    uint8_t *payload;
} mysql_packet_t;

class MySQL
{
public:
    MySQL(TCPSocket *pTCPSocket, const char *server_ip);
    ~MySQL(void);
    bool connect(const char *user, const char *password);
    bool disconnect();
    bool query(const char *pQuery);
    void printDatabase(void);

private:
    // User-configured TCP socket attached to NetworkInterface
    TCPSocket *mTcpSocket = NULL;

    // MySQL Server IP
    const char *mServerIP = NULL;

    // mBuffer stores the raw bytes recieved from TCP socket
    uint8_t *mBuffer = NULL;
    uint32_t mBufferSize = 0;

    // MySQL packets parsed from mBuffer
    std::vector<MySQL_Packet*> mPacketsRecieved;

    // Seed used to hash password through SHA-1
    uint8_t mSeed[20] = {0};

    // Stores the recieved table following a SELECT query
    TypeDef_Database *mDatabase = NULL;

    bool recieve(void);
    nsapi_size_or_error_t write(char *message, uint16_t len);
    
    int send_authentication_packet(const char *user, const char *password);
    void parse_handshake_packet(void);
    
    bool parse_textresultset(void);
    void free_recieved_packets(void);

    int getNewOffset(const uint8_t *packet, int offset);
    int check_ok_packet(void);
    int scramble_password(const char *password, uint8_t *pwd_hash);

    void flush_packet(void);
    void freeBuffer(void);
    void freeDatabase(void);

    void print_packets_types(void);
};

#endif