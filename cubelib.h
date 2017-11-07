#ifndef _CUBE_LIB_
#define _CUBE_LIB_

#include <stdio.h> // connectsock
#include <unistd.h> // write_all
#include <stdlib.h> // connectsock decimalToBinary
#include <string.h> // sendall connectsock
#include <assert.h> // write_all
#include <sys/types.h> // sendall connectsock
#include <sys/socket.h> // connectsock
#include <netinet/in.h> // connectsock
#include <arpa/inet.h> // connectsock
#include <netdb.h> // connectsock
//--------------------------------------------------------------------------------------------------------------------

/*-------------------------------------------------------------------------------------------------------

        #ifdef DEBUG
        printf("\n[DBG] %s() : line_%d : \n", __FUNCTION__, __LINE__,  );
        #endif // DEBUG

    {
        fprintf( stderr, "\n[ERR] %s() : line_%d : ", __FUNCTION__, __LINE__ - 2 );
        perror("");
        exit( 1 );
    }
--------------------------------------------------------------------------------------------------------*/
int sendall(int s, char *buf, int *len);
unsigned char* decimalToBinary( int dec, int length );
ssize_t write_all (int fd, const void* buffer, size_t count);
int connectTCP( const char *host, const char *service );
int connectUDP( const char *host, const char* service );
int passiveUDP( const char *service );
int passiveTCP( const char *service, int qlen );

#define RTT_DELAY 200
#define THRESHOLD 65535
#define PAYLOAD_SIZE 512
#define WINDOW_SIZE 10240
#define HEADER_LENGTH 20
#define PSEUDO_HEADER_LENGTH 12
#define SEGMENT_SIZE PSEUDO_HEADER_LENGTH+HEADER_LENGTH+PAYLOAD_SIZE


uint16_t cumulate_checksum( char* segment, int segment_len );
void build_segment( char* segment, char* pseudo_header, char* tcp_header, char* payload, uint16_t payload_len );
int disassemble_segment( char* segment, int segment_len, char* pseudo_header, char* tcp_header, char* payload, uint16_t* payload_len, char** current_win, uint16_t* flags_type );
const char* identify_flags( uint16_t flags_type );
void seq_ack_num_info( uint32_t seq_num, uint32_t ack_num, int op );
void set_pseudo_header( char* pseudo_header, uint32_t source_addr, uint32_t destination_addr, uint16_t zeros_protocol, uint16_t tcp_len );
void set_tcp_header( char* tcp_header, uint16_t source_port, uint16_t destination_port, uint32_t seq_num, uint32_t ack_num, uint16_t data_offset_flags, uint16_t win_size, uint16_t checksum, uint16_t ugn_ptr );
#endif
