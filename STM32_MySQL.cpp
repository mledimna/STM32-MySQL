/**
 * @file STM32_MySQL.cpp
 * @author Mathieu LE DIMNA (mathieu-ledimna@outlook.com)
 * @brief STM32-MySQL library using Mbed framework
 * @version 2.0
 * @date 2021-04-30
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include "STM32_MySQL.h"

/**
 * @brief Creates a MySQL object
 * 
 * @param pTCPSocket Attached socket to a network interface
 * @param server_ip MySQL server IP address
 */
MySQL::MySQL(TCPSocket *pTCPSocket, const char *server_ip) : mTcpSocket(pTCPSocket), mServerIP(server_ip)
{
}

/**
 * @brief Destroys the MySQL object
 * 
 */
MySQL::~MySQL(void)
{
    //Close MySQL Session
    this->disconnect();

    this->freeDatabase();
    this->freeRecievedPackets();
    this->freeBuffer();
}

/**
 * @brief Connect to MySQL under specific session
 * 
 * @param user Username
 * @param password Password
 * @return true Connection established and session opened
 * @return false Unable to connect or login
 */
bool MySQL::connect(const char *user, const char *password)
{
    bool ret = false;
    SocketAddress server;

    if (mTcpSocket == NULL)
        return false;

    //Set MySQL server IP
    if (!server.set_ip_address(mServerIP))
        return false;

    //Set MySQL server port number
    server.set_port(3306);

    //Set socket Timeout
    mTcpSocket->set_timeout(1000);

    if (mTcpSocket != NULL)
    {
        //Connect to server
        if (mTcpSocket->connect(server) != 0)
            return false;

        //Read hadshake packet
        flush_packet();

        //Parse packet
        parse_handshake_packet();

        //Send authentification to server
        ret = (send_authentication_packet(user, password) > 0) ? true : false;

        return ret;
    }
    return false;
}

/**
 * @brief Disconnects from MySQL server by closing session
 * 
 * @return true OK
 * @return false Unable to send disconnect command to server
 */
bool MySQL::disconnect()
{
    uint8_t COM_QUIT[] = {0x01, 0x00, 0x00, 0x00, 0x01};

    //Send COM_QUIT packet (Payload : 0x01)
    if (this->write((char *)COM_QUIT, 5) > 0)
        return true;

    return false;
}

/**
 * @brief Parse mBuffer member into vector of pointer MySQL_Packet classes
 * 
 * @return true mPackets filled
 * @return false mPackets emptied
 */
bool MySQL::recieve(void)
{
    // Fixed-Size buffer to recieve raw data from TCP socket
    uint8_t data[RECV_SIZE] = {0x00};

    // Socket return type to check if there was something to read or if an error occured
    nsapi_size_or_error_t recv_len = 0;

    this->freeBuffer();

    //To avoid blocking the actual thread, set the recieve timeout to 1000ms
    mTcpSocket->set_timeout(100);

    // Recieve loop
    do
    {
        //Store recieved data in fixed-size buffer
        recv_len = mTcpSocket->recv(data, RECV_SIZE);

        //If there was something to read
        if (recv_len > 0)
        {
            this->mBufferSize += recv_len;
            //If it's the first byte, use malloc, else use realloc for length-variable table
            if (this->mBufferSize == 0)
                this->mBuffer = (uint8_t *)malloc(this->mBufferSize);
            else
                this->mBuffer = (uint8_t *)realloc(this->mBuffer, sizeof(uint8_t) * this->mBufferSize);

            //If malloc or realloc worked, append the recieved data to the last allocated index, else return error to user
            if (this->mBuffer != NULL)
                memcpy(this->mBuffer + (this->mBufferSize - recv_len), data, recv_len);
            else
                return false;
        }
    } while (recv_len > 0);

    //If there was nothing to read, return an error to the user
    if (this->mBufferSize > 0)
    {
        // Parse the received block into packets.
        for (int offset = 0; offset < (int)this->mBufferSize;)
        {
            // Add packet to vector
            this->mPacketsRecieved.push_back(new MySQL_Packet(this->mBuffer + offset));
            // Increment offset used to parse packets from mBuffer
            offset += this->mPacketsRecieved.back()->getPacketLength();
        }
        // Cean free allocades memory for mBuffer
        this->freeBuffer();

        __NOP();

        return true;
    }
    return false;
}

/**
 * @brief Send bytes over TCP socket to MySQL server
 * 
 * @param message 
 * @param len 
 * @return int 
 */
int MySQL::write(char *message, uint16_t len)
{
    //Send raw data to socket
    return mTcpSocket->send((void *)message, len);
}

/**
 * @brief Send a simple query and expect Table as result
 * 
 * @param pQuery Query
 * @param Database Database structure to store results
 * @return bool state
 */
bool MySQL::query(const char *pQuery)
{
    int packet_len = 0;
    int payload_len = 0;
    int ret = 0;

    this->freeBuffer();
    this->freeRecievedPackets();
    this->freeDatabase();

    // Query length + COM_QUERY Flag
    payload_len = strlen(pQuery) + 1;

    // Header + Payload length
    packet_len = payload_len + 4;

    struct mysql_packet_t
    {
        uint8_t payload_len[3] = {0};
        uint8_t sequence_id = 0;
        uint8_t query_type = 0;
        uint8_t payload[2048] = {0};
    };

    struct mysql_packet_t mysql_packet;

    // Set payload length
    store_int((uint8_t *)mysql_packet.payload_len, payload_len, 3);

    // Sequence ID to 0 : initiator
    mysql_packet.sequence_id = 0;

    // Query type to 0x03 (COM_QUERY)
    mysql_packet.query_type = 0x03;

    // Copy request into payload
    memcpy(mysql_packet.payload, pQuery, payload_len - 1);

    // Write data over TCP socket
    ret += this->write((char *)&mysql_packet, packet_len);

    if (ret > 0)
    {
        //Receive results
        if (this->recieve())
        {
            int packet_count = (int)this->mPacketsRecieved.size();

            if (packet_count == 1)
            {
                Packet_Type packet_type = this->mPacketsRecieved.at(0)->getPacketType();

                switch (packet_type)
                {
                case PACKET_OK:
                    return true;

                case PACKET_ERR:
                    return false;

                case PACKET_EOF:
                    return false;

                case PACKET_UNKNOWN:
                    return false;
                }
            }
            else if (packet_count > 1)
            {
                bool ret = this->parseTable();
                this->freeRecievedPackets();
                return ret;
            }
        }
    }
    return false;
}

/**
 * @brief Free packets vector content and empties it
 * 
 */
void MySQL::freeRecievedPackets(void)
{
    if (this->mPacketsRecieved.size() > 0)
    {
        for (int i = 0; i < (int)this->mPacketsRecieved.size(); i++)
        {
            delete this->mPacketsRecieved.at(i);
        }
        this->mPacketsRecieved.clear();
    }
}

/**
 * @brief Parses recieved packets considered as a table result
 * 
 * @return true Table parsed
 * @return false Unable to parse table
 */
bool MySQL::parseTable(void)
{
    // Used to keep track of the actual packet
    int packet_offset = 0;
    Packet_Type packet_type = PACKET_OK;
    const uint8_t *packet = NULL;

    // Clean already allocated Database
    this->freeDatabase();

    //Allocate memory for database structure
    this->mDatabase = (TypeDef_Database *)malloc(sizeof(TypeDef_Database));

    //Allocate memory for table structure
    this->mDatabase->Table = (TypeDef_Table *)malloc(sizeof(TypeDef_Table));

    //Set defaut values
    this->mDatabase->Database_Name = NULL;
    this->mDatabase->Table->Table_Name = NULL;
    this->mDatabase->Table->Column_Count = 0;
    this->mDatabase->Table->Row_Count = 0;
    this->mDatabase->Table->Column_Names = NULL;
    this->mDatabase->Table->Row_Values = NULL;

    packet = this->mPacketsRecieved.at(packet_offset)->getPayload();
    packet_type = this->mPacketsRecieved.at(packet_offset)->getPacketType();

    //Store the column count into the table structure
    this->mDatabase->Table->Column_Count = readFixedLengthInt(packet, 0, 1);

    //Allocate enough memory for the column names
    this->mDatabase->Table->Column_Names = (char **)malloc(this->mDatabase->Table->Column_Count);

    packet_offset++;
    packet = this->mPacketsRecieved.at(packet_offset)->getPayload();
    packet_type = this->mPacketsRecieved.at(packet_offset)->getPacketType();

    //This structure stores the strings sent to the client
    for (int i = 0; packet_type != PACKET_EOF; i++)
    {
        //Check the next packet type to exit the for loop if needed
        packet_offset++;
        packet = this->mPacketsRecieved.at(packet_offset)->getPayload();
        packet_type = this->mPacketsRecieved.at(packet_offset)->getPacketType();
    }

    packet_offset++;
    packet = this->mPacketsRecieved.at(packet_offset)->getPayload();
    packet_type = this->mPacketsRecieved.at(packet_offset)->getPacketType();

    //Row parsing : if the recieved packet is not an EOF or ERR packet
    if (packet_type == PACKET_UNKNOWN)
    {
        //Allocate 3D array (first dimension is columns)
        this->mDatabase->Table->Row_Values = (char ***)malloc(sizeof(char **) * this->mDatabase->Table->Column_Count);

        for (int row = 0; packet_type != PACKET_EOF; row++)
        {
            //Increment number of rows
            this->mDatabase->Table->Row_Count = row + 1;

            int str_offset = 0;
            //Get row values
            for (int col = 0; col < this->mDatabase->Table->Column_Count; col++)
            {
                //Allocate 3D array (Second dimension is rows)
                if (row == 0)
                    this->mDatabase->Table->Row_Values[col] = (char **)malloc(sizeof(char *) * (row + 1));
                else
                    this->mDatabase->Table->Row_Values[col] = (char **)realloc(this->mDatabase->Table->Row_Values[col], sizeof(char *) * (row + 1));

                //Allocate 3D array (Third dimension is strings)

                int str_size = readLenEncInt(packet, str_offset);
                this->mDatabase->Table->Row_Values[col][row] = (char *)malloc(sizeof(char) * (str_size + 1));
                readLenEncString(this->mDatabase->Table->Row_Values[col][row], packet, str_offset);
                str_offset += str_size + 1;
            }
            //Increment offset
            packet_offset++;
            packet = this->mPacketsRecieved.at(packet_offset)->getPayload();
            packet_type = this->mPacketsRecieved.at(packet_offset)->getPacketType();
        }
        return true;
    }

    return false;
}

/**
 * @brief Prints the recieved table to the default stdout buffer
 * 
 */
void MySQL::printDatabase(void)
{
    if (this->mDatabase != NULL)
    {
        TypeDef_Table *table = this->mDatabase->Table;

        if (table != NULL)
        {
            int nb_columns = this->mDatabase->Table->Column_Count;
            int nb_rows = this->mDatabase->Table->Row_Count;

            //Print Database name and selected table name
            printf("Database : %s, Table : %s\r\n", this->mDatabase->Database_Name, table->Table_Name);

            for (int y = 0; y < nb_rows; y++)
            {
                for (int x = 0; x < nb_columns; x++)
                {
                    printf("\t%s : %s\r\n", table->Column_Names[x], table->Row_Values[x][y]);
                }
                printf("\r\n");
            }
        }
    }
}

/**
 * @brief Free database struct
 * 
 */
void MySQL::freeDatabase(void)
{
    __NOP();
    if (this->mDatabase != NULL)
    {
        __NOP();
        if (this->mDatabase->Table != NULL)
        {
            int nb_columns = this->mDatabase->Table->Column_Count;
            int nb_rows = this->mDatabase->Table->Row_Count;

            if (nb_rows > 0)
            {

                for (int col = 0; col < nb_columns; col++)
                {
                    for (int row = 0; row < nb_rows; row++)
                    {
                        // Free field value
                        free(this->mDatabase->Table->Row_Values[col][row]);
                    }
                    // Free row
                    free(this->mDatabase->Table->Row_Values[col]);
                    // Free column
                    // free(this->mDatabase->Table->Column_Names[col]);
                }
            }

            // Free table name
            free(this->mDatabase->Table->Table_Name);
            free(this->mDatabase->Table->Column_Names);
            free(this->mDatabase->Table->Row_Values);

            //Free table struct pointer
            free(this->mDatabase->Table);
        }
        // Free database name
        free(this->mDatabase->Database_Name);

        // Free database main pointer
        free(this->mDatabase);
        this->mDatabase = NULL;
    }
}

/**
 * @brief Responds to the server handshake sequence by logging in using User and Password
 * 
 * @param user MySQL user
 * @param password MySQL session password
 * @return int Bytes sent through TCP socket
 */
int MySQL::send_authentication_packet(const char *user, const char *password)
{
    int status = 0;
    int i = 0;
    uint8_t *scramble;
    int p_size;
    int size_send = 4;

    if (this->mBuffer != NULL)
        this->freeBuffer();

    this->mBuffer = (unsigned char *)malloc(256);
    for (int i = 0; i < 256; i++)
    {
        this->mBuffer[i] = 0;
    }

    // client flags
    this->mBuffer[size_send] = 0x85;
    this->mBuffer[size_send + 1] = 0xa6;
    this->mBuffer[size_send + 2] = 0x03;
    this->mBuffer[size_send + 3] = 0x00;
    size_send += 4;

    // max_allowed_packet
    this->mBuffer[size_send] = 0;
    this->mBuffer[size_send + 1] = 0;
    this->mBuffer[size_send + 2] = 0;
    this->mBuffer[size_send + 3] = 1;
    size_send += 4;

    // charset - default is 8
    this->mBuffer[size_send] = 0x08;
    size_send += 1;
    for (i = 0; i < 24; i++)
        this->mBuffer[size_send + i] = 0x00;
    size_send += 23;

    // user name
    memcpy(this->mBuffer + size_send, user, strlen(user));
    size_send += strlen(user) + 1;
    this->mBuffer[size_send - 1] = 0x00;

    // password - see scramble password
    scramble = (uint8_t *)malloc(20);
    if (scramble_password(password, scramble))
    {
        this->mBuffer[size_send] = 0x14;
        size_send += 1;
        for (int i = 0; i < 20; i++)
            this->mBuffer[i + size_send] = scramble[i];
        size_send += 20;
        this->mBuffer[size_send] = 0x00;
    }
    free(scramble);

    // terminate password response
    this->mBuffer[size_send] = 0x00;
    size_send += 1;

    // database
    this->mBuffer[size_send + 1] = 0x00;
    size_send += 1;

    // Write packet size
    p_size = size_send - 4;
    store_int(this->mBuffer, p_size, 3);
    this->mBuffer[3] = 0x01;

    status = write((char *)this->mBuffer, size_send);
    flush_packet(); //To flush TCP socket
    return status;
}

/**
 * @brief Hash password using server seed
 * 
 * @param password MySQL session password
 * @param pwd_hash server seed
 * @return int (0 : Error | 1 : OK)
 */
int MySQL::scramble_password(const char *password, uint8_t *pwd_hash)
{
    SHA1Context sha;
    int word = 0, shift = 24, count = 3;
    uint8_t hash1[20];
    uint8_t hash2[20];
    uint8_t hash3[20];
    uint8_t pwd_buffer[40];

    if (strlen(password) == 0)
        return 0;

    // hash1
    SHA1Reset(&sha);
    SHA1Input(&sha, (const unsigned char *)password, strlen(password));
    SHA1Result(&sha);
    for (int i = 0; i < 20; i++)
    {
        hash1[i] = (sha.Message_Digest[word] >> shift);
        shift = shift - 8;
        if (i == count)
        {
            shift = 24;
            word++;
            count += 4;
        }
    }
    word = 0;
    shift = 24;
    count = 3;

    // hash2
    SHA1Reset(&sha);
    SHA1Input(&sha, (const unsigned char *)hash1, 20);
    SHA1Result(&sha);
    for (int i = 0; i < 20; i++)
    {
        hash2[i] = (sha.Message_Digest[word] >> shift);
        shift = shift - 8;
        if (i == count)
        {
            shift = 24;
            word++;
            count += 4;
        }
    }
    word = 0;
    shift = 24;
    count = 3;

    // hash3 of seed + hash2
    SHA1Reset(&sha);
    memcpy(pwd_buffer, &mSeed, 20);
    memcpy(pwd_buffer + 20, hash2, 20);
    SHA1Input(&sha, (const unsigned char *)pwd_buffer, 40);
    SHA1Result(&sha);
    for (int i = 0; i < 20; i++)
    {
        hash3[i] = (sha.Message_Digest[word] >> shift);
        shift = shift - 8;
        if (i == count)
        {
            shift = 24;
            word++;
            count += 4;
        }
    }
    word = 0;
    shift = 24;
    count = 3;

    // XOR for hash4
    for (int i = 0; i < 20; i++)
        pwd_hash[i] = hash1[i] ^ hash3[i];

    return 1;
}

/**
 * @brief Cleans TCP socket
 * 
 */
void MySQL::flush_packet()
{
    uint8_t *data_rec = NULL;
    int packet_len = 0;

    this->freeBuffer();

    data_rec = (uint8_t *)malloc(RECV_SIZE);
    packet_len = mTcpSocket->recv(data_rec, RECV_SIZE);

    packet_len -= 4;

    // Check for valid packet.
    if (packet_len < 0)
        packet_len = 0;

    this->mBuffer = (unsigned char *)malloc(packet_len + 4);

    if (this->mBuffer == NULL)
        return;

    for (int i = 4; i < packet_len + 4; i++)
        this->mBuffer[i] = data_rec[i];

    free(data_rec);

    data_rec = NULL;
}

/**
 * @brief Parse handshake sent by server
 * 
 */
void MySQL::parse_handshake_packet()
{
    int i = 5;
    do
    {
        i++;
    } while (this->mBuffer[i - 1] != 0x00);

    // Capture the first 8 characters of seed
    i += 4; // Skip thread id
    for (int j = 0; j < 8; j++)
        mSeed[j] = this->mBuffer[i + j];

    // Capture rest of seed
    i += 27; // skip ahead
    for (int j = 0; j < 12; j++)
        mSeed[j + 8] = this->mBuffer[i + j];
}

/**
 * @brief Free mBuffer
 * 
 */
void MySQL::freeBuffer(void)
{
    if (this->mBuffer != NULL)
    {
        // Clean reset mBuffer size and content
        memset(this->mBuffer, 0, this->mBufferSize);
        this->mBufferSize = 0;
        free(this->mBuffer);
        this->mBuffer = NULL;
    }
}
