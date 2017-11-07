#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "cubelib.h"
#include <time.h>
#include <pthread.h>

#define BUF_SIZE 1500

char buf[BUF_SIZE];
char *NAT_map[2][2] = { { "10260", "10265" } };


void rand_srcAddr()
{
    if( rand() % 2 )
    {
        NAT_map[1][0] = "192.168.0.2";
        NAT_map[1][1] = "192.168.0.3";
    }
    else
    {
        NAT_map[1][0] = "192.168.0.3";
        NAT_map[1][1] = "192.168.0.2";
    }
}


void run_cli( char* dest_ip, char* dest_port, char* src_port )
{
    int dest_socket;
    int temp_i;
    int segment_len = 0;
    uint16_t payload_len = 0;
    uint16_t flags_type;
    uint32_t nextseqnum = 0;
    uint32_t nextacknum = 0;
    char payload[PAYLOAD_SIZE];
    char segment[SEGMENT_SIZE];
    char tcp_header[HEADER_LENGTH];

    srand( time( NULL ) );

    nextseqnum = rand() % 10000 + 1;

//--------------------------------------------------------------------------------------------------------------------
//Header
//  1. Tcp header
    /*
    0~1   (16 bits) : Source port
    2~3   (16 bits) : Destination port
    4~7   (32 bits) : Sequence number
    8~11  (32 bits) : Ack number
    12~13 (4  bits) : Data offset ( header length )
          (3  bits) : Reserved
          (9  bits) : Flags( Ns|CWR|ECE|URG|ACK|PSH|RST|SYN|FIN )
    14~15 (16 bits) : Window size
    16~17 (16 bits) : Checksum
    18~19 (16 bits) : Urgent pointer
    */
//      set Source port
    uint16_t source_port = 0;
//      set Destination port
    uint16_t destination_port = 0;
//      set Sequence number
    uint32_t seq_num = 0;
//      set Ack number
    uint32_t ack_num = 0;
//      set Data offset + Flags
    uint16_t data_offset_flags = 0;
//      set Window size
    uint16_t win_size = WINDOW_SIZE;
//      set Checksum
    uint16_t checksum = 0;
//      set Urgent pointer
    uint16_t ugn_ptr = 0;
//  ---------------------
//  2. pseudo header
    char pseudo_header[PSEUDO_HEADER_LENGTH];
    /*
    0~3   (32  bits) : Source address
    4~7   (32  bits) : Destination address
    8     (8   bits) : Zeros
    9     (8   bits) : Protocol
    10~11 (16  bits) : TCP length ( tcp header + payload )
    */
//      set Source address
    uint32_t source_addr = 0;
//      set Destination address
    uint32_t destination_addr = 0;
//      set Zeros + Protocol
    uint16_t zeros_protocol = 6;
//      set Tcp length
    uint16_t tcp_len = 0;
//--------------------------------------------------------------------------------------------------------------------
//create socket
//  create destination socket
    struct sockaddr_in dest;
    dest.sin_addr.s_addr = inet_addr( dest_ip );
    dest.sin_family = AF_INET;
    dest.sin_port = htons( ( unsigned short )atoi( dest_port ) );
    int dest_len = sizeof( dest );

    if( ( dest_socket = socket( AF_INET, SOCK_DGRAM, 0 ) ) < 0 )
    {
        fprintf( stderr, "\n[ERR] %s() : line_%d : ", __FUNCTION__, __LINE__ - 2 );
        perror("");
        exit( 1 );
    }
//  bind source port with socket
    struct sockaddr_in src;
    int src_len = sizeof( src );
    src.sin_addr.s_addr = htonl( INADDR_ANY );
    src.sin_port = htons( ( uint16_t )atoi( src_port ) );
    src.sin_family = AF_INET;

    if( bind( dest_socket, ( struct sockaddr* ) &src, src_len ) < 0 )
    {
        fprintf( stderr, "\n[ERR] %s() : line_%d : ", __FUNCTION__, __LINE__ - 2 );
        perror("");
        exit( 1 );
    }
//--------------------------------------------------------------------------------------------------------------------
    rand_srcAddr();
    puts("------------NAT translation table------------");
    puts("  WAN side addr\t|\tLAN side addr");
    printf("192.168.0.1 : %s \t%s : %s\n", NAT_map[0][0], NAT_map[1][0], NAT_map[0][0] );
    printf("192.168.0.1 : %s \t%s : %s\n", NAT_map[0][1], NAT_map[1][1], NAT_map[0][1] );
    if( strcmp( src_port, NAT_map[0][0] ) == 0 )
        printf("Client's IP is %s\n", NAT_map[1][0] );
    else if( strcmp( src_port, NAT_map[0][1] ) == 0 )
        printf("Client's IP is %s\n", NAT_map[1][1] );

//--------------------------------------------------------------------------------------------------------------------
    puts("=====Start the three-way handshake=====");
//3-way handshack -- SYN

//  send SYN
//      1. set tcp header
    source_port = ( uint16_t )atoi( src_port );
    destination_port = ( uint16_t )atoi( dest_port );
    seq_num = nextseqnum;
    ack_num = nextacknum;
    data_offset_flags = HEADER_LENGTH;
    data_offset_flags = ( data_offset_flags << 12 ) + 0x0002;
    win_size = WINDOW_SIZE;
    checksum = 0;
    ugn_ptr = 0;

    set_tcp_header( tcp_header, source_port, destination_port, seq_num, ack_num, data_offset_flags, win_size, checksum, ugn_ptr );

//      2. set payload
    memset( payload, 0, PAYLOAD_SIZE );
    payload_len = 0;

//      3.set pseudo header
    source_addr = inet_addr( "192.168.0.1" );
    destination_addr = dest.sin_addr.s_addr;
    zeros_protocol = 6;
    tcp_len = HEADER_LENGTH + payload_len;

    set_pseudo_header( pseudo_header, source_addr, destination_addr, zeros_protocol, tcp_len );

//      4. build segment
    build_segment( segment, pseudo_header, tcp_header, payload, payload_len );
    segment_len = PSEUDO_HEADER_LENGTH + HEADER_LENGTH + payload_len;
    checksum = cumulate_checksum( segment, tcp_len + PSEUDO_HEADER_LENGTH );

    *( uint16_t* )( segment + PSEUDO_HEADER_LENGTH + 16 ) = checksum;
//      5. send
    sendto( dest_socket, segment, segment_len, 0, ( struct sockaddr* ) &dest, dest_len );
    printf("Send a packet(%s) to %s : %hu\t\n", identify_flags( 0x0002 ), inet_ntoa( dest.sin_addr ), ntohs( dest.sin_port ) );


//--------------------------------------------------------------------------------------------------------------------
//  wait SYN/ACK

    memset( segment, 0, SEGMENT_SIZE );
    segment_len = recvfrom( dest_socket, segment, SEGMENT_SIZE, 0, ( struct sockaddr* ) &dest, &dest_len );

    if( disassemble_segment( segment, segment_len, pseudo_header, tcp_header, payload, &payload_len, NULL, &flags_type ) == 0 )
    {
        nextseqnum = *( uint32_t* )( tcp_header + 8 );
        if( payload_len == 0 )
            payload_len++;
        nextacknum = *( uint32_t* )( tcp_header + 4 ) + payload_len;
        printf("Receive a packet(%s) from %s : %hu\n", identify_flags( flags_type ), inet_ntoa( dest.sin_addr ), ntohs( dest.sin_port ) );
        seq_ack_num_info( *( uint32_t* )( tcp_header + 4 ), *( uint32_t* )( tcp_header + 8 ), 0 );
    }

//--------------------------------------------------------------------------------------------------------------------
//  send ACK
//      1. set tcp header
    source_port = ( uint16_t )atoi( src_port );
    destination_port = dest.sin_port;
    seq_num = nextseqnum;
    ack_num = nextacknum;
    data_offset_flags = HEADER_LENGTH;
    data_offset_flags = ( data_offset_flags << 12 ) + 0x0010;
    win_size = WINDOW_SIZE;
    checksum = 0;
    ugn_ptr = 0;

    set_tcp_header( tcp_header, source_port, destination_port, seq_num, ack_num, data_offset_flags, win_size, checksum, ugn_ptr );

//      2. set payload
    memset( payload, 0, PAYLOAD_SIZE );
    payload_len = 0;

//      3.set pseudo header
    source_addr = inet_addr( "192.168.0.1" );
    destination_addr = dest.sin_addr.s_addr;
    zeros_protocol = 6;
    tcp_len = HEADER_LENGTH + payload_len;

    set_pseudo_header( pseudo_header, source_addr, destination_addr, zeros_protocol, tcp_len );


//      4. build segment
    build_segment( segment, pseudo_header, tcp_header, payload, payload_len );
    segment_len = PSEUDO_HEADER_LENGTH + HEADER_LENGTH + payload_len;

    *( uint16_t* )( segment + PSEUDO_HEADER_LENGTH + 16 ) = cumulate_checksum( segment, segment_len );

//      5. send
    sendto( dest_socket, segment, segment_len, 0, ( struct sockaddr* ) &dest, dest_len );
    printf("Send a packet(%s) to %s : %hu\n", identify_flags( 0x0010 ), inet_ntoa( dest.sin_addr ), ntohs( dest.sin_port ) );

    puts("=====Complete the three-way handshake=====");
//--------------------------------------------------------------------------------------------------------------------
//receive a file from server
    printf("Receive a file from %s : %hu\n", inet_ntoa( dest.sin_addr ), ntohs( dest.sin_port ) );
    FILE *file;
    if( ( file = fopen( "recv_data", "wb" ) ) == 0 )
    {
        fprintf( stderr, "\n[ERR] %s() : line_%d : ", __FUNCTION__, __LINE__ - 2 );
        perror("");
        exit( 1 );
    }

    //--------------------------------------------------------------------------------------------------------------------
    while( 1 )
    {
        //--------------------------------------------------------------------------------------------------------------------
        for( temp_i = 0 ; temp_i < 2 ; temp_i++ )
        {
            memset( segment, 0, SEGMENT_SIZE );
            segment_len = recvfrom( dest_socket, segment, SEGMENT_SIZE, 0, ( struct sockaddr* ) &dest, &dest_len );
            if( disassemble_segment( segment, segment_len, pseudo_header, tcp_header, payload, &payload_len, NULL, &flags_type ) == 0 )
            {
                nextseqnum = *( uint32_t* )( tcp_header + 8 );
                if( payload_len == 0 )
                    payload_len++;
                nextacknum = *( uint32_t* )( tcp_header + 4 ) + payload_len;
            }
            if( flags_type != 0x0001 )
            {
                seq_ack_num_info( *( uint32_t* )( tcp_header + 4 ), *( uint32_t* )( tcp_header + 8 ), 0 );
                fwrite( payload, 1, payload_len, file );
            }
            else
            {
                fclose( file );
                puts("=====Start the four-way handshake=====");
                printf("Receive a packet(%s) from %s : %hu\n", identify_flags( flags_type ), inet_ntoa( dest.sin_addr ), ntohs( dest.sin_port ) );
                seq_ack_num_info( *( uint32_t* )( tcp_header + 4 ), *( uint32_t* )( tcp_header + 8 ), 0 );
                goto escp;
            }
        }
        //--------------------------------------------------------------------------------------------------------------------
        //      1. set tcp header
        source_port = ( uint16_t )atoi( src_port );
        destination_port = dest.sin_port;
        seq_num = nextseqnum;
        ack_num = nextacknum;

        data_offset_flags = HEADER_LENGTH;
        data_offset_flags = ( data_offset_flags << 12 ) + 0x0010;
        win_size = WINDOW_SIZE;
        checksum = 0;
        ugn_ptr = 0;

        set_tcp_header( tcp_header, source_port, destination_port, seq_num, ack_num, data_offset_flags, win_size, checksum, ugn_ptr );

//      2. set payload
        memset( payload, 0, PAYLOAD_SIZE );
        payload_len = 0;

//      3.set pseudo header
        source_addr = inet_addr( "192.168.0.1" );
        destination_addr = dest.sin_addr.s_addr;
        zeros_protocol = 6;
        tcp_len = HEADER_LENGTH + payload_len;

        set_pseudo_header( pseudo_header, source_addr, destination_addr, zeros_protocol, tcp_len );

//      4. build segment
        build_segment( segment, pseudo_header, tcp_header, payload, payload_len );
        segment_len = PSEUDO_HEADER_LENGTH + HEADER_LENGTH + payload_len;

        *( uint16_t* )( segment + PSEUDO_HEADER_LENGTH + 16 ) = cumulate_checksum( segment, segment_len );

//      5. send
        sendto( dest_socket, segment, segment_len, 0, ( struct sockaddr* ) &dest, dest_len );
        usleep( 200000 );
    }
//--------------------------------------------------------------------------------------------------------------------
    escp:
//  send ACK
//      1. set payload
    memset( payload, 0, PAYLOAD_SIZE );
    payload_len = 0;

//      2. set tcp header
    source_port = ( uint16_t )atoi( src_port );
    destination_port = ( uint16_t )atoi( dest_port );
    seq_num = nextseqnum;
    ack_num = nextacknum;
    data_offset_flags = HEADER_LENGTH;
    data_offset_flags = ( data_offset_flags << 12 ) + 0x0010;
    win_size = WINDOW_SIZE;
    checksum = 0;
    ugn_ptr = 0;

    set_tcp_header( tcp_header, source_port, destination_port, seq_num, ack_num, data_offset_flags, win_size, checksum, ugn_ptr );

//      3.set pseudo header
    source_addr = inet_addr( "192.168.0.1" );
    destination_addr = dest.sin_addr.s_addr;
    zeros_protocol = 6;
    payload_len = 0;
    tcp_len = HEADER_LENGTH + payload_len;

    set_pseudo_header( pseudo_header, source_addr, destination_addr, zeros_protocol, tcp_len );

//      4. build segment
    build_segment( segment, pseudo_header, tcp_header, payload, payload_len );
    segment_len = PSEUDO_HEADER_LENGTH + HEADER_LENGTH + payload_len;

    checksum = cumulate_checksum( segment, tcp_len + PSEUDO_HEADER_LENGTH );
    *( uint16_t* )( segment + PSEUDO_HEADER_LENGTH + 16 ) = checksum;

    sendto( dest_socket, segment, segment_len, 0, ( struct sockaddr* ) &dest, dest_len );
    printf("Send a packet(%s) to %s : %hu\t\n", identify_flags( 0x0010 ), inet_ntoa( dest.sin_addr ), ntohs( dest.sin_port ) );

//--------------------------------------------------------------------------------------------------------------------
//  send ACK
//      1. set payload
    memset( payload, 0, PAYLOAD_SIZE );
    payload_len = 0;

//      2. set tcp header
    source_port = ( uint16_t )atoi( src_port );
    destination_port = ( uint16_t )atoi( dest_port );
    seq_num = nextseqnum;
    ack_num = nextacknum;
    data_offset_flags = HEADER_LENGTH;
    data_offset_flags = ( data_offset_flags << 12 ) + 0x0001;
    win_size = WINDOW_SIZE;
    checksum = 0;
    ugn_ptr = 0;

    set_tcp_header( tcp_header, source_port, destination_port, seq_num, ack_num, data_offset_flags, win_size, checksum, ugn_ptr );

//      3.set pseudo header
    source_addr = inet_addr( "192.168.0.1" );
    destination_addr = dest.sin_addr.s_addr;
    zeros_protocol = 6;
    payload_len = 0;
    tcp_len = HEADER_LENGTH + payload_len;

    set_pseudo_header( pseudo_header, source_addr, destination_addr, zeros_protocol, tcp_len );

//      4. build segment
    build_segment( segment, pseudo_header, tcp_header, payload, payload_len );
    segment_len = PSEUDO_HEADER_LENGTH + HEADER_LENGTH + payload_len;

    checksum = cumulate_checksum( segment, tcp_len + PSEUDO_HEADER_LENGTH );
    *( uint16_t* )( segment + PSEUDO_HEADER_LENGTH + 16 ) = checksum;

    sendto( dest_socket, segment, segment_len, 0, ( struct sockaddr* ) &dest, dest_len );
    printf("Send a packet(%s) to %s : %hu\t\n", identify_flags( 0x0001 ), inet_ntoa( dest.sin_addr ), ntohs( dest.sin_port ) );

//--------------------------------------------------------------------------------------------------------------------
    //  wait ACK


    memset( segment, 0, SEGMENT_SIZE );
    segment_len = recvfrom( dest_socket, segment, SEGMENT_SIZE, 0, ( struct sockaddr* ) &dest, &dest_len );

    if( disassemble_segment( segment, segment_len, pseudo_header, tcp_header, payload, &payload_len, NULL, &flags_type ) == 0 )
    {
        nextseqnum = *( uint32_t* )( tcp_header + 8 );
        if( payload_len == 0 )
            payload_len++;
        nextacknum = *( uint32_t* )( tcp_header + 4 ) + payload_len;
        printf("Receive a packet(%s) from %s : %hu\n", identify_flags( flags_type ), inet_ntoa( dest.sin_addr ), ntohs( dest.sin_port ) );
        seq_ack_num_info( *( uint32_t* )( tcp_header + 4 ), *( uint32_t* )( tcp_header + 8 ), 0 );
    }

//--------------------------------------------------------------------------------------------------------------------
    puts("=====Complete the four-way handshake=====");
//--------------------------------------------------------------------------------------------------------------------



    close( dest_socket );
}
int main( int argc, char* argv[] )
{
    if( argc == 4 )
        run_cli( argv[1], argv[2], argv[3] );
//    printf("%s %s\n%s %s\n",NAT_map[0][0],NAT_map[0][1],NAT_map[1][0],NAT_map[1][1]);
    return 0;
}
