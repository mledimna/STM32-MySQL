#ifndef STM32_MYSQL_H
#define STM32_MYSQL_H

#include "mbed.h"

#define OK_PACKET     0x00
#define EOF_PACKET    0xfe
#define EOM_MES		  0xffaa
#define ERROR_PACKET  0xff
#define MAX_FIELDS    8//Maximum number of fields. Reduce to save memory. Default=32
#define VERSION_STR   "1.0.4ga"
#define WITH_SELECT
#define DEST_PORT ((uint16_t)3306)

typedef enum{
    PACKET_OK = 0x00,
    PACKET_ERR = 0x01,
    PACKET_EOF = 0x02,
    PACKET_UNKNOWN = 0x03
}Packet_Type;

typedef struct {
char *name;
char *data;
} field_struct;


typedef struct {
int num_fields;
char *db;
char *table;
field_struct *fields[MAX_FIELDS];
} column_names;

// Structure for storing row data.
typedef struct {
char *values[MAX_FIELDS];
} row_values;

class MySQL{
    public:
    MySQL(TCPSocket* sock);

    int connect(char* user, char* password);
    void disconnect();

    int cmd_query(const char *query);
    column_names *get_columns();

    /*
    NEW FUNCTIONS :
        -Dynamic allocation
        -Thread Safe
    */
    int query(const char* query);
    bool recieve(void);
    Packet_Type identifyPacket(uint8_t* packet, int packet_length);
    int readInt(uint8_t * packet, int offset, int size);
    /*
    END NEW FUNCTIONS
    */

    int getBuffer(uint8_t* ext_buffer);

    private:
    TCPSocket* tcp_socket = NULL;
    unsigned int tries = 0;
    unsigned char *buffer = NULL;
    char *server_version = NULL;
    uint8_t seed[20] = {0};
    int packet_len = 0;

    column_names columns = {0};
    int columns_read = 0;
    int num_cols = 0;

    /* extern varibles which comes from the packet receiving source*/
    uint8_t *data_rec = 0; // pointer to the received data from MYSQL server
    unsigned short int pack_rec = 0; // Varible which indicate is packet received
    unsigned int pack_len = 0; // varible which indicate the lent of the received packet from MYSQL server

    int cmd_query_P(const char *query);
    int mysql_write(char * message, uint16_t len);
    void read_packet_limit();

    row_values *get_next_row();
    void free_columns_buffer();
    void free_row_buffer();
    void show_results();
    int clear_ok_packet();

    // Methods for handling packets
    int send_authentication_packet(char *user, char *password);
    void read_packet();
    void parse_handshake_packet();
    int check_ok_packet();
    int run_query(int query_len);

    // Utility methods
    int scramble_password(char *password, uint8_t *pwd_hash);
    int get_lcb_len(int offset);
    int read_int(int offset, int size);
    void store_int(uint8_t *buff, long value, int size);

    char *read_string(int *offset);
    int get_field(field_struct *fs, int *off);
    int get_fields();
    int get_row_values( int *off);
    void do_query(const char *q);
};

#endif