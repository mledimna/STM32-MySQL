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
 * @brief Construct a new MySQL::MySQL object
 * 
 * @param pTCPSocket Binded socket to your network interface
 * @param server_ip MySQL server IP address
 */
MySQL::MySQL(TCPSocket *pTCPSocket, const char *server_ip) : mTcpSocket(pTCPSocket), mServerIP(server_ip)
{
}

/**
 * @brief Destroy the MySQL::MySQL object
 * 
 */
MySQL::~MySQL(void)
{
    //Close MySQL Session
    this->disconnect();

    //free buffer if not NULL
    if (this->mBuffer != NULL)
        this->freeBuffer();

    this->freeRecievedPackets();
    this->freeDatabase();
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
<<<<<<< HEAD
    if(data_recieved_length==0) return NULL;

    int payload_len = 0; //To store the packet payload length

    //Parse the received block into packets
    for(int offset=0; offset<data_recieved_length; offset+=4+payload_len){
        
        (*packets_count)++;//Increment the number of packets received
        payload_len = readInt(data_recieved, offset, 3);//Read the actual packet payload length

        //Use malloc for the first packet, then use realloc
        if(offset==0)packets_recieved = (uint8_t**)malloc(sizeof(uint8_t*));
        else packets_recieved = (uint8_t**)realloc(packets_recieved,sizeof(uint8_t*)*(*packets_count));
=======
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
>>>>>>> 47383dd... Hot Fix

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

<<<<<<< HEAD
TypeDef_Database* MySQL::query(const char *pQuery, TypeDef_Database* Database){
    static char * packet = NULL;
=======
/**
 * @brief Send a simple query and expect Table as result
 * 
 * @param pQuery Query
 * @param Database Database structure to store results
 * @return TypeDef_Database* Database
 */
bool MySQL::query(const char *pQuery)
{
    static char *packet = NULL;
>>>>>>> 47383dd... Hot Fix
    int packet_len = 0;
    int payload_len = 0;
    int ret = 0;

    this->freeDatabase();
    this->freeRecievedPackets();

    // Query length + COM_QUERY Flag
    payload_len = strlen(pQuery) + 1;

    // Header + Payload length
    packet_len = payload_len + 4;

    //Allocate memory for the packet
    packet = (char *)malloc(packet_len);
    if (packet == NULL)
        return false;

    //Set 3 first bytes as the payload length
<<<<<<< HEAD
    store_int((uint8_t*)packet, payload_len, 3);
=======
    store_int((uint8_t *)packet, payload_len, 3);
>>>>>>> 47383dd... Hot Fix

    //Edit protocol related bytes
    packet[3] = 0x00; //Sequence ID : Initiator
    packet[4] = 0x03; //Set flag to COM_QUERY

<<<<<<< HEAD
    //Table of tables of packets
    uint8_t** packets_received = NULL;
    //Number of tables of packets in table of tables of packets :)
    int packets_count = 0;

    payload_len = strlen(pQuery)+1; //Query length + COM_QUERY Flag
    packet_len = payload_len+4; //Header + Payload length

    packet = (char*)malloc(packet_len); //Allocate memory for the packet

    if(packet==NULL) return false;

    store_int((uint8_t*)packet, payload_len, 3);

    packet[3] = 0x00; //Sequence ID : Initiator
    packet[4] = 0x03; //Set flag to COM_QUERY
    
=======
>>>>>>> 47383dd... Hot Fix
    //Insert query into packet
    memcpy(packet + 5, pQuery, strlen(pQuery));

    //Send the query
    ret = this->write(packet, packet_len);
    free(packet);

<<<<<<< HEAD
    if(packets_received==NULL) return false;
    
    packet_len = readInt(packets_received[0], 0, 3)+4;
    uint8_t packet_type = identifyPacket(packets_received[0], readInt(packets_received[0], 0, 3)+4);

    if(packet_type==PACKET_OK) {
        //To avoid opening another thread on https://stackoverflow.com/
        this->freeRecievedPackets(packets_received, &packets_count);

        return true;
    }
    else if(packet_type==PACKET_ERR) {
        char* str = NULL;
        str = readLenEncString(packets_received[0], 12);
        
        free(str);
=======
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
>>>>>>> 47383dd... Hot Fix

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

<<<<<<< HEAD
    //If the first packet is not a column_count packet, free allocated memory and return NULL
    if(identifyPacket(packets_received[0], readInt(packets_received[0], 0, 3))!=PACKET_UNKNOWN){
        Database = this->freeDatabase(Database);
        return NULL;
    }
=======
    packet = this->mPacketsRecieved.at(packet_offset)->getPayload();
    packet_type = this->mPacketsRecieved.at(packet_offset)->getPacketType();
>>>>>>> 47383dd... Hot Fix

    //Store the column count into the table structure
    this->mDatabase->Table->Column_Count = readFixedLengthInt(packet, 0, 1);

    //Allocate enough memory for the column names
    this->mDatabase->Table->Column_Names = (char **)malloc(this->mDatabase->Table->Column_Count);

<<<<<<< HEAD
    //Column parsing
    type = PACKET_UNKNOWN;
    for(int i=1; type==PACKET_UNKNOWN; i++){
        int offset = 4;//Start at 4 to skip the payload header
        int payload_size = readInt(packets_received[i],0,3);

        //This structure stores the strings sent to the client
        TypeDef_ColumnDefinition column_def;
=======
    packet_offset++;
    packet = this->mPacketsRecieved.at(packet_offset)->getPayload();
    packet_type = this->mPacketsRecieved.at(packet_offset)->getPacketType();
>>>>>>> 47383dd... Hot Fix

    //This structure stores the strings sent to the client
    for (int i = 0; packet_type != PACKET_EOF; i++)
    {
        int offset = 0;
/*
        //Get catalog value
<<<<<<< HEAD
        column_def.catalog = readLenEncString(packets_received[i], offset);
        offset = this->getNewOffset(packets_received[i],offset);
        if(column_def.catalog==NULL) {
            Database = this->freeDatabase(Database);
            return NULL;
        }

        //Get schema value
        column_def.schema = readLenEncString(packets_received[i], offset);
        offset = this->getNewOffset(packets_received[i],offset);
        if(column_def.schema==NULL) {
            Database = this->freeDatabase(Database);
            return NULL;
        }

        //Get table value
        column_def.table = readLenEncString(packets_received[i], offset);
        offset = this->getNewOffset(packets_received[i],offset);
        if(column_def.table==NULL) {
            Database = this->freeDatabase(Database);
            return NULL;
        }

        //Get org tabe value
        column_def.org_table = readLenEncString(packets_received[i], offset);
        offset = this->getNewOffset(packets_received[i],offset);
        if(column_def.org_table==NULL) {
            Database = this->freeDatabase(Database);
            return NULL;
        }

        //Get column name value
        column_def.name = readLenEncString(packets_received[i], offset);
        offset = this->getNewOffset(packets_received[i],offset);
        if(column_def.name==NULL) {
            Database = this->freeDatabase(Database);
            return NULL;
        }

        //Get column org name value
        column_def.org_name = readLenEncString(packets_received[i], offset);
        offset = this->getNewOffset(packets_received[i],offset);
        if(column_def.org_name==NULL) {
            Database = this->freeDatabase(Database);
            return NULL;
        }

        if(i==1){
            //Don't free the table, schema and name to store it
            free(column_def.catalog);
            free(column_def.org_table);
            free(column_def.org_name);

            //Attribute allocated pointer to database and table names
            Database->database = column_def.schema;
            Database->table->table = column_def.table;
        }
        else{
            //Don't free the name to store it
            free(column_def.catalog);
            free(column_def.schema);
            free(column_def.table);
            free(column_def.org_table);
            free(column_def.org_name);
        }
=======
        readLenEncString(column_def.catalog, packet, offset);
        offset = this->getNewOffset(packet, offset);

        //Get schema value
        readLenEncString(column_def.schema, packet, offset);
        offset = this->getNewOffset(packet, offset);

        //Get table value
        readLenEncString(column_def.table, packet, offset);
        offset = this->getNewOffset(packet, offset);

        //Get org table value
        readLenEncString(column_def.org_table, packet, offset);
        offset = this->getNewOffset(packet, offset);

        //Get column name value
        readLenEncString(column_def.name, packet, offset);
        offset = this->getNewOffset(packet, offset);

        //Get column org name value
        readLenEncString(column_def.org_name, packet, offset);
        offset = this->getNewOffset(packet, offset);
>>>>>>> 47383dd... Hot Fix

        //Attribute the column name to the column description value
        this->mDatabase->Table->Column_Names[i] = (char *)malloc(strlen(column_def.name) + 1);
        memcpy(this->mDatabase->Table->Column_Names[i], column_def.name, strlen(column_def.name) + 1);
*/
        //Check the next packet type to exit the for loop if needed
<<<<<<< HEAD
        type = identifyPacket(packets_received[i+1], payload_size+4);

        //If the next packet is an EOF, just jump it by adding 2 to packet offset
        if(type==PACKET_EOF) packet_offset = i+2;
=======
        packet_offset++;
        packet = this->mPacketsRecieved.at(packet_offset)->getPayload();
        packet_type = this->mPacketsRecieved.at(packet_offset)->getPacketType();
>>>>>>> 47383dd... Hot Fix
    }

    // this->freeRecievedPackets();
    // return true;
    /*
    //Attribute allocated pointer to database and table names
    this->mDatabase->Database_Name = (char *)malloc(strlen(column_def.schema) + 1);
    memcpy(this->mDatabase->Database_Name, column_def.schema, strlen(column_def.schema) + 1);

<<<<<<< HEAD
    type = identifyPacket(packets_received[packet_offset], readLenEncInt(packets_received[packet_offset], 0)+4);
=======
    this->mDatabase->Table->Table_Name = (char *)malloc(strlen(column_def.table) + 1);
    memcpy(this->mDatabase->Table->Table_Name, column_def.table, strlen(column_def.table) + 1);
    */
    packet_offset++;
    packet = this->mPacketsRecieved.at(packet_offset)->getPayload();
    packet_type = this->mPacketsRecieved.at(packet_offset)->getPacketType();
>>>>>>> 47383dd... Hot Fix

    //Row parsing
    //If the recieved packet is not an EOF or ERR packet
    if (packet_type == PACKET_UNKNOWN)
    {
        //Allocate 3D array (first dimension is columns)
        this->mDatabase->Table->Row_Values = (char ***)malloc(sizeof(char **) * this->mDatabase->Table->Column_Count);

<<<<<<< HEAD
    for(int i=packet_offset; type==PACKET_UNKNOWN; i++){
        int offset = 4;
        int payload_size = readInt(packets_received[i],0,3);

        int nb_rows = (i+1)-packet_offset; //Increment the number of rows

        //Get row values
        for(int j=0; j<Database->table->nb_columns; j++){

            //Allocate 3D array (Second dimension is rows)
            if(nb_rows==1) Database->table->rows[j] = (char**)malloc(sizeof(char*));
            else Database->table->rows[j] = (char**)realloc(Database->table->rows[j],sizeof(char*)*nb_rows);

            //Check allocation integrity
            if(Database->table->rows[j]==NULL){
                Database = this->freeDatabase(Database);
                return NULL;
            }

            //Allocate 3D array (Third dimension is strings)
            Database->table->rows[j][nb_rows-1] = readLenEncString(packets_received[i], offset);
            
            //Check allocation integrity
            if(Database->table->rows[j][nb_rows-1]==NULL){
                Database = this->freeDatabase(Database);
                return NULL;
=======
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
>>>>>>> 47383dd... Hot Fix
            }
            //Increment offset
            packet_offset++;
            packet = this->mPacketsRecieved.at(packet_offset)->getPayload();
            packet_type = this->mPacketsRecieved.at(packet_offset)->getPacketType();
        }
<<<<<<< HEAD

        //Increment number of rows
        Database->table->nb_rows = nb_rows;

        //To check if next packet is EOF_PACKET (end of loop)
        type = identifyPacket(packets_received[i+1], payload_size+4);
=======
        return true;
>>>>>>> 47383dd... Hot Fix
    }

    return false;
}

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
    }
}

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

int MySQL::check_ok_packet()
{
    int type = this->mBuffer[4];
    if (type != PACKET_OK)
        return type;
    return 0;
}

int MySQL::getNewOffset(const uint8_t *packet, int offset)
{
    //Reads the length encoded variable value to jump it
    int str_size = readLenEncInt(packet, offset);
<<<<<<< HEAD

    if(packet[offset]<251) offset += 1+str_size;
    else if(packet[offset]==0xFC) offset += 3+str_size;
    else if(packet[offset]==0xFD) offset += 4+str_size;
    else if(packet[offset]==0xFE) offset += 9+str_size;

  return offset;
}
=======
    uint8_t len = *(packet + offset);

    if (len < 251)
        offset += 1 + str_size;
    else if (len == 0xFC)
        offset += 3 + str_size;
    else if (len == 0xFD)
        offset += 4 + str_size;
    else if (len == 0xFE)
        offset += 9 + str_size;

    return offset;
}

void MySQL::freeBuffer(void)
{
    // Clean reset mBuffer size and content
    memset(this->mBuffer, 0, this->mBufferSize);
    this->mBufferSize = 0;
    free(this->mBuffer);
    this->mBuffer = NULL;
}
>>>>>>> 47383dd... Hot Fix
