/*
 * Copyright (c) 2015, 2016, 2020
 * * Mathieu Le Dimna <mathieu-ledimna@outlook.com> (Initial Autor)
 * Ivan P. Ucherdzhiev  <ivanucherdjiev@gmail.com> (Co-Author)
 * All Rights Reserved
 */
 
 /*This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.*/

#include "mbed.h"
#include "STM32_MySQL.h"
#include "sha1.h"
#include "EthernetInterface.h"

#define RECV_SIZE               50000

MySQL::MySQL(TCPSocket* sock):tcp_socket(sock){}

int MySQL::connect(char* user, char* password){
    int i = -1;
    unsigned int count = 0;
    int ret=0;
    
    if (tcp_socket!=NULL) {
        read_packet();
        parse_handshake_packet();
        ret = send_authentication_packet(user, password);
        return ret;
    }

    return 0;
}

void MySQL::disconnect()
{
	//tcp_echoclient_connection_close(); // Add here you function to close the connection with the server
}

TypeDef_Database* MySQL::recieve(void){
    TypeDef_Database* Database = NULL;

    int data_recieved_length = 0; //Packet Length
    uint8_t* data_recieved = NULL; //Used to store recieved MySQL server response

    int packets_count = 0; //Number of received packets
    uint8_t** packets_received = NULL; //Table to store the received packets

    uint8_t data = 0x00; //Buffer for recieved data
    nsapi_size_or_error_t ret = 0; //Socket return type to check if there was something to read or if an error occured

    //To avoid blocking the actual thread, set the recieve timeout to 1000ms
    tcp_socket->set_timeout(1000);

    //While there is something to read from the socket we execute the following algorithm
    while(ret>=0){
        //Store recieved data
        ret = tcp_socket->recv(&data, 1);
        
        //If there was something to read
        if(ret>=0){
            data_recieved_length++;

            //If it's the first byte, use malloc, else use realloc for length-variable table
            if(data_recieved_length==0) data_recieved = (uint8_t*)malloc(sizeof(uint8_t));
            else data_recieved = (uint8_t*)realloc(data_recieved, sizeof(uint8_t)*data_recieved_length);

            //If malloc or realloc worked, append the recieved data to the last allocated index
            //Else return erro to user
            if(data_recieved!=NULL) data_recieved[data_recieved_length-1] = data;
            else{
                return NULL;
            }
        }
    }

    //If there was nothing to read, return an error to the user
    if(data_recieved_length==0) return NULL;

    int payload_len = 0; //To store the packet payload length

    //Parse the received block into packets
    for(int offset=0; offset<data_recieved_length; offset+=4+payload_len){
        
        packets_count++;//Increment the number of packets received
        payload_len = this->readInt(data_recieved, offset, 3);//Read the actual packet payload length

        //Use malloc for the first packet, the use realloc
        if(offset==0)packets_received = (uint8_t**)malloc(sizeof(uint8_t*));
        else packets_received = (uint8_t**)realloc(packets_received,sizeof(uint8_t*)*packets_count);

        //Allocate enought memory to store the packet data
        if(packets_received!=NULL) packets_received[packets_count-1] = (uint8_t*)malloc(sizeof(uint8_t)*(payload_len+4));
        else {
            printf("Memory allocation error...\r\n");
            return NULL;
        }

        //Attribute actual values to the allocated packet
        for(int i=0; i<payload_len+4; i++) packets_received[packets_count-1][i] = data_recieved[offset+i];
    }

    //To avoid opening another thread on https://stackoverflow.com/
    free(data_recieved);    

    Database = this->parseTable(packets_received,packets_count);

    //To avoid opening another thread on https://stackoverflow.com/
    for(int i=0; i<packets_count; i++) free(packets_received[i]);
    free(packets_received);

    //No error, something available
    return Database;
}

int MySQL::mysql_write(char * message, uint16_t len) {
	return tcp_socket->send((void*)message, len);
}

Packet_Type MySQL::identifyPacket(uint8_t* packet, int packet_length){
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

TypeDef_Database* MySQL::query(const char *pQuery, TypeDef_Database* Database){
    char * packet = NULL;
    int packet_len = 0;
    int payload_len = 0;
    int ret = 0;

    /*
    COM_QUERY : 
        The SQL packet length is :
            -4 bytes : Header (Payload length<3> + Sequence ID<1>)
            -1 byte : 0x03 (COM_QUERY Flag<1>)
            -n byte(s) : Query length<n>
    */
    if(Database!=NULL) this->freeDatabase(Database);

    payload_len = strlen(pQuery)+1; //Query length + COM_QUERY Flag
    packet_len = payload_len+4; //Header + Payload length

    packet = (char*)malloc(packet_len); //Allocate memory for the packet

    this->store_int((uint8_t*)packet, payload_len, 3);

    packet[3] = 0x00; //Sequence ID : Initiator
    packet[4] = 0x03; //Set flag to COM_QUERY
    
    //Insert query into packet
    for(int i=0; i<strlen(pQuery); i++) packet[i+5] = pQuery[i];
    
    //Send the query
    ret = this->mysql_write(packet,packet_len);

    //Receive results
    Database = this->recieve();

    //this->printDatabase(Database);

    //To avoid opening another thread on https://stackoverflow.com/
    free(packet);

    return Database;
}

TypeDef_Database* MySQL::parseTable(uint8_t** packets_received,int packets_count){

    TypeDef_Database* Database = NULL;//Pointer of TypedDef_Database to return
    Packet_Type type = PACKET_UNKNOWN;//To read from identifyPacket function
    int packet_offset = 0;//To keep track of which packet we are at

    //5 packets received minimum for a SELECT * FROM query :
    if(packets_count<5) return NULL;
    if(packets_received==NULL) return NULL;

    //Allocate memory for database structure
    Database = (TypeDef_Database*) malloc(sizeof(TypeDef_Database));
    if(Database==NULL) return NULL;

    //Allocate memory for table structure
    Database->table = (TypeDef_Table*)malloc(sizeof(TypeDef_Table));
    if(Database->table==NULL) return NULL;

    //If the first packet is not a column_count packet, free allocated memory and return NULL
    if(this->identifyPacket(packets_received[0], this->readInt(packets_received[0], 0, 3))!=PACKET_UNKNOWN){
        this->freeDatabase(Database);
        return NULL;
    }

    //Store the column count into the table structure
    Database->table->nb_columns = packets_received[0][4];

    //Allocate enough memory for the column names
    Database->table->columns = (char**)malloc(sizeof(char*)*Database->table->nb_columns);
    if(Database->table->columns==NULL){
        this->freeDatabase(Database);
        return NULL;
    }

    //Column parsing
    type = PACKET_UNKNOWN;
    for(int i=1; type==PACKET_UNKNOWN; i++){
        int offset = 4;//Start at 4 to skip the payload header
        int str_size = 0;
        int payload_size = this->readInt(packets_received[i],0,3);

        //This structure stores the strings sent to the client
        TypeDef_ColumnDefinition column_def;

        //Get catalog value
        column_def.catalog = this->readLenEncString(packets_received[i], offset);
        offset = this->getNewOffset(packets_received[i],offset);
        if(column_def.catalog==NULL) {
            this->freeDatabase(Database);
            return NULL;
        }

        //Get schema value
        column_def.schema = this->readLenEncString(packets_received[i], offset);
        offset = this->getNewOffset(packets_received[i],offset);
        if(column_def.schema==NULL) {
            this->freeDatabase(Database);
            return NULL;
        }

        //Get table value
        column_def.table = this->readLenEncString(packets_received[i], offset);
        offset = this->getNewOffset(packets_received[i],offset);
        if(column_def.table==NULL) {
            this->freeDatabase(Database);
            return NULL;
        }

        //Get org tabe value
        column_def.org_table = this->readLenEncString(packets_received[i], offset);
        offset = this->getNewOffset(packets_received[i],offset);
        if(column_def.org_table==NULL) {
            this->freeDatabase(Database);
            return NULL;
        }

        //Get column name value
        column_def.name = this->readLenEncString(packets_received[i], offset);
        offset = this->getNewOffset(packets_received[i],offset);
        if(column_def.name==NULL) {
            this->freeDatabase(Database);
            return NULL;
        }

        //Get column org name value
        column_def.org_name = this->readLenEncString(packets_received[i], offset);
        offset = this->getNewOffset(packets_received[i],offset);
        if(column_def.org_name==NULL) {
            this->freeDatabase(Database);
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

        //Attribute the column name to the column description value
        Database->table->columns[i-1] = column_def.name;

        //Check the next packet type to exit the for loop if needed
        type = this->identifyPacket(packets_received[i+1], payload_size+4);

        //If the next packet is an EOF, just jump it by adding 2 to packet offset
        if(type==PACKET_EOF) packet_offset = i+2;
    }

    //Row parsing
    type = PACKET_UNKNOWN;

    Database->table->rows = (char***)malloc(sizeof(char**)*Database->table->nb_columns);
    if(Database->table->rows==NULL){
        this->freeDatabase(Database);
        return NULL;
    }

    for(int i=packet_offset; type==PACKET_UNKNOWN; i++){
        int offset = 4;
        int payload_size = this->readInt(packets_received[i],0,3);
        int nb_rows = (i+1)-packet_offset; //Increment the number of packets

        Database->table->nb_rows = nb_rows;

        //Get row values
        for(int j=0; j<Database->table->nb_columns; j++){
            if(nb_rows==1) Database->table->rows[j] = (char**)malloc(sizeof(char*));
            else Database->table->rows[j] = (char**)realloc(Database->table->rows[j],sizeof(char*)*nb_rows);

            if(Database->table->rows[j]==NULL){
                this->freeDatabase(Database);
                return NULL;
            }

            Database->table->rows[j][nb_rows-1] = this->readLenEncString(packets_received[i], offset);
            
            if(Database->table->rows[j][nb_rows-1]==NULL){
                this->freeDatabase(Database);
                return NULL;
            }

            offset = this->getNewOffset(packets_received[i],offset);
        }
        type = this->identifyPacket(packets_received[i+1], payload_size+4);
    }

    return Database;
}

void MySQL::printDatabase(TypeDef_Database* Database){

    if(Database!=NULL){
        TypeDef_Table* table = Database->table;

        if(table!=NULL){
            int nb_columns = Database->table->nb_columns;
            int nb_rows = Database->table->nb_rows;

            printf("Database : %s, Table : %s\r\n",Database->database,table->table);
            for(int y=0; y<nb_rows; y++){
                for(int x=0; x<nb_columns; x++){
                    printf("\t%s : %s\r\n",table->columns[x],table->rows[x][y]);
                }
                printf("\r\n");
            }
        }
    }
}

void MySQL::freeDatabase(TypeDef_Database* Database){
    if(Database!=NULL){
        TypeDef_Table* table = Database->table;

        if(table!=NULL){
            int nb_columns = Database->table->nb_columns;
            int nb_rows = Database->table->nb_rows;

            for(int x=0; x<nb_columns; x++){
                for(int y=0; y<nb_rows; y++){
                    free(table->rows[x][y]);
                }
                free(table->rows[x]);
            }
            free(table->rows);
            free(table->table);
            table->nb_columns = 0;
            table->nb_rows = 0;
        }
        free(table);

        free(Database->database);
        free(Database);
    }
}

int MySQL::send_authentication_packet(char *user, char *password)
{
	int status = 0;

	int i = 0;
	int len = 0;
	//unsigned char test[256];
	uint8_t *scramble;
	int p_size;
	int size_send = 4;

  if (buffer != NULL)
	  free(buffer);

  buffer = (unsigned char*)malloc(256);
  for (int i = 0 ; i<256; i++)
  {
	  buffer[i] = 0;
  }

  // client flags
  buffer[size_send] = 0x85;
  buffer[size_send+1] = 0xa6;
  buffer[size_send+2] = 0x03;
  buffer[size_send+3] = 0x00;
  size_send += 4;

  // max_allowed_packet
  buffer[size_send] = 0;
  buffer[size_send+1] = 0;
  buffer[size_send+2] = 0;
  buffer[size_send+3] = 1;
  size_send += 4;

  // charset - default is 8
  buffer[size_send] = 0x08;
  size_send += 1;
  for( i = 0; i < 24; i++)
    buffer[size_send+i] = 0x00;
  size_send += 23;

  // user name
  memcpy(&buffer[size_send], user, strlen(user));
  size_send += strlen(user) + 1;
  buffer[size_send-1] = 0x00;

  // password - see scramble password
  scramble = (uint8_t*)malloc(20);
  if (scramble_password(password, scramble)) {
    buffer[size_send] = 0x14;
    size_send += 1;
    for (int i = 0; i < 20; i++)
      buffer[i+size_send] = scramble[i];
    size_send += 20;
    buffer[size_send] = 0x00;
  }
  free(scramble);

  // terminate password response
  buffer[size_send] = 0x00;
  size_send += 1;

  // database
  buffer[size_send+1] = 0x00;
  size_send += 1;

  // Write packet size
  p_size = size_send - 4;
  store_int(&buffer[0], p_size, 3);
  buffer[3] = 0x01;
  len = strlen((char*)buffer);

  status = mysql_write((char*)buffer,size_send);
  read_packet();//To flush TCP socket
  return status;
}

int MySQL::scramble_password(char *password, uint8_t *pwd_hash) {
	SHA1Context sha;
  int i = 0;
  int word = 0, shift = 24, count = 3;
  uint8_t hash1[20];
  uint8_t hash2[20];
  uint8_t hash3[20];
  uint8_t pwd_buffer[40];

  if (strlen(password) == 0)
    return 0;

  // hash1
  SHA1Reset(&sha);
  SHA1Input(&sha, (const unsigned char *) password, strlen(password));
  SHA1Result(&sha);
  for(int i = 0; i<20 ; i++)
  {
	hash1[i] = (sha.Message_Digest[word] >> shift);
  	shift = shift - 8;
  	if(i==count)
  	{
  		shift = 24;
  		word++;
  		count +=4;
  	}

  }
  word = 0;
  shift = 24;
  count = 3;

  // hash2
  SHA1Reset(&sha);
  SHA1Input(&sha, (const unsigned char *) hash1, 20);
  SHA1Result(&sha);
  for (int i = 0; i<20 ; i++)
    {
	  hash2[i] = (sha.Message_Digest[word] >> shift);
    	shift = shift - 8;
    	if(i==count)
    	{
    		shift = 24;
    		word++;
    		count +=4;
    	}

    }
  word = 0;
  shift = 24;
  count = 3;

  // hash3 of seed + hash2
  SHA1Reset(&sha);
  memcpy(pwd_buffer, &seed, 20);
  memcpy(pwd_buffer+20, hash2, 20);
  SHA1Input(&sha, (const unsigned char *) pwd_buffer, 40);
  SHA1Result(&sha);
  for (int i = 0; i<20 ; i++)
      {
	  hash3[i] = (sha.Message_Digest[word] >> shift);
      	shift = shift - 8;
      	if(i==count)
      	{
      		shift = 24;
      		word++;
      		count +=4;
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

void MySQL::read_packet() {
  uint8_t *data_rec = NULL;
  uint8_t local[4];
  int packet_len = 0;
  int i = 0;

  if (buffer != NULL) {
      free(buffer);
      buffer = NULL;
  }
    data_rec = (uint8_t*)malloc(RECV_SIZE);
    pack_len = tcp_socket->recv(data_rec, RECV_SIZE);

    pack_len -= 4;

  // Check for valid packet.
  if (packet_len < 0) packet_len = 0;

  buffer = (unsigned char*)malloc(packet_len+4);
  
  if (buffer == NULL) return;

  for (int i = 0; i < 4; i++) buffer[i] = local[i];
  for (int i = 4; i < packet_len+4; i++) buffer[i] = data_rec[i];

  memset( data_rec, '\0', sizeof(*data_rec) );
  free(data_rec);

  data_rec = NULL;
}

void MySQL::parse_handshake_packet() {

	int j = 0;
  int i = 5;
  do {
    i++;
  } while (buffer[i-1] != 0x00);

  // Capture the first 8 characters of seed
  i += 4; // Skip thread id
  for (int j = 0; j < 8; j++)
    seed[j] = buffer[i+j];

  // Capture rest of seed
  i += 27; // skip ahead
  for (int j = 0; j < 12; j++)
    seed[j+8] = buffer[i+j];
}

int MySQL::check_ok_packet() {
  int type = buffer[4];
  if (type != OK_PACKET)
    return type;
  return 0;
}

int MySQL::getNewOffset(uint8_t * packet, int offset) {
    int str_size = this->readLenEncInt(packet, offset);

    if(packet[offset]<251) offset += 1+str_size;
    else if(packet[offset]==0xFC) offset += 3+str_size;
    else if(packet[offset]==0xFD) offset += 4+str_size;
    else if(packet[offset]==0xFE) offset += 9+str_size;

  return offset;
}

int MySQL::get_lcb_len(int offset) {
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

char* MySQL::read_string(int *offset){
    int len = get_lcb_len(*offset);
    char *str = NULL;
    char head = buffer[*(offset)];

    if(head==0xFE) return NULL;
    
    str = (char*)malloc(len+1);
    memcpy(str, (char *)&buffer[*offset+1], len);
    str[len] = '\0';

    return str;
}

int MySQL::read_int(int offset, int size){
  int value = 0;
  int new_size = 0;
  int i;

  if (size == 0) new_size = get_lcb_len(offset);
  if (size == 1) return buffer[offset];

  new_size = size;

  int shifter = (new_size - 1) * 8;

  for (int i = new_size; i > 0; i--) {
    value += (uint8_t)(buffer[i-1] << shifter);
    shifter -= 8;
  }

  return value;
}

int MySQL::readInt(uint8_t * packet, int offset, int size) {
  int value = 0;

  for(int i=0; i<size; i++) value |= packet[i+offset]<<(i*8);

  return value;
}

int MySQL::readLenEncInt(uint8_t * packet, int offset) {
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

char* MySQL::readLenEncString(uint8_t * packet, int offset){
    char* str = NULL;
    int str_size = this->readLenEncInt(packet, offset);

    str = (char*)malloc(sizeof(char)*(str_size+1));

    if(packet[offset]<251) for(int i=0; i<str_size; i++) str[i] = packet[i+1+offset];
    else if(packet[offset]==0xFC) for(int i=0; i<str_size; i++) str[i] = packet[i+3+offset];
    else if(packet[offset]==0xFD) for(int i=0; i<str_size; i++) str[i] = packet[i+4+offset];
    else if(packet[offset]==0xFE) for(int i=0; i<str_size; i++) str[i] = packet[i+9+offset];

    str[str_size] = '\0';

    return str;
}

void MySQL::store_int(uint8_t *buff, long value, int size){
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
