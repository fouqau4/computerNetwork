#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cubelib.h"
#include <netinet/in.h>
#include <arpa/inet.h> //inet_ntoa
#include <time.h>

#define BUF_SIZE 1500

char buf[BUF_SIZE];

uint32_t nextseqnum = 0;
uint32_t nextacknum = 0;

void create_data()
{
    int temp_i;
    char table[62];
    char c;
    for( temp_i = 0, c = '0' ; temp_i < 10 ; temp_i++ )
        table[temp_i] = c++;
    for( temp_i = 10, c = 'a' ; temp_i < 36 ; temp_i++ )
        table[temp_i] = c++;
    for( temp_i = 36, c = 'A' ; temp_i < 62 ; temp_i++ )
        table[temp_i] = c++;
    FILE *data;
    if( ( data = fopen( "data", "w" ) ) == 0 )
    {
        fprintf( stderr, "\n[ERR] %s() : line_%d : ", __FUNCTION__, __LINE__ - 2 );
        perror("");
        exit( 1 );
    }
    srand( time( NULL ) );
    for( temp_i = 0 ; temp_i < 10243 ; temp_i++ )
    {
        fputc( table[rand() % 62], data );
    }
    fclose( data );
}

void show_parameter(char* src_port)
{
    puts("=====Parameter=====");
    printf("The RTT delay = %d ms\n", RTT_DELAY);
    printf("The threshold = %d bytes\n", THRESHOLD);
    printf("The MSS = %d bytes\n", PAYLOAD_SIZE);
    printf("The buffer size = %d bytes\n", WINDOW_SIZE);
    printf("Server's IP is 127.0.0.1\n");
    printf("Server is listening on port %s\n", src_port );
    puts("===============");
}

void run_srv( char* src_port )
{
    show_parameter(src_port);
    struct sockaddr_in cli;
    int cli_len = sizeof( cli );
    int temp_i;
    int segment_len = 0;
    uint16_t flags_type;
    uint16_t payload_len = 0;
    char payload[PAYLOAD_SIZE];
    char segment[PSEUDO_HEADER_LENGTH + HEADER_LENGTH + PAYLOAD_SIZE];

    srand( time( NULL ) );

    nextseqnum = rand() % 10000 + 1;

//--------------------------------------------------------------------------------------------------------------------
//Header
//  1. Tcp header
    char tcp_header[HEADER_LENGTH];
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
    uint16_t win_size = 0;
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
    10~11 (16  bits) : TCP length
    */
//      set Source address
    uint32_t source_addr = 0;
//      set Destination address
    uint32_t destination_addr = 0;
//      set Zeros + Protocol
    uint16_t zeros_protocol = 6;
    *( uint8_t* )( pseudo_header + 8 ) = zeros_protocol;
//      set Tcp length
    uint16_t tcp_len = 0;
//--------------------------------------------------------------------------------------------------------------------
//create socket
    puts("Listening for client...");
    int connect_socket = passiveUDP( src_port );
//--------------------------------------------------------------------------------------------------------------------
//3-way handshack -- SYN
//  wait for SYN
    memset( segment, 0, SEGMENT_SIZE );
    segment_len = recvfrom( connect_socket, segment, sizeof( segment ), 0, ( struct sockaddr* ) &cli, &cli_len );
    puts("=====Start the three-way handshake=====");
    struct sockaddr_in temp;
    if( disassemble_segment( segment, segment_len, pseudo_header, tcp_header, payload, &payload_len, NULL, &flags_type ) == 0 )
    {
        nextseqnum = *( uint32_t* )( tcp_header + 8 );
        if( payload_len == 0 )
            payload_len++;
        temp.sin_addr.s_addr = *( uint32_t* )pseudo_header;
        nextacknum = *( uint32_t* )( tcp_header + 4 ) + payload_len;
        printf("Receive a packet(%s) from %s : %hu\n", identify_flags( flags_type ), inet_ntoa( temp.sin_addr ), ntohs( cli.sin_port ) );
        seq_ack_num_info( *( uint32_t* )( tcp_header + 4 ), *( uint32_t* )( tcp_header + 8 ), 0 );
    }

//  reply SYN, ACK
//--------------------------------------------------------------------------------------------------------------------
//      1. set tcp header
    source_port = ( uint16_t )atoi( src_port );
    destination_port = ntohs( cli.sin_port );
    seq_num = nextseqnum;
    ack_num = nextacknum;
    data_offset_flags = HEADER_LENGTH;
    data_offset_flags = ( data_offset_flags << 12 ) + 0x0012;
    win_size = WINDOW_SIZE;
    checksum = 0;
    ugn_ptr = 0;

    set_tcp_header( tcp_header, source_port, destination_port, seq_num, ack_num, data_offset_flags, win_size, checksum, ugn_ptr );

//      2. set payload
    memset( payload, 0, PAYLOAD_SIZE );
    payload_len = 0;

//      3.set pseudo header
    source_addr = *( uint32_t* )( pseudo_header + 4 );
    destination_addr = cli.sin_addr.s_addr;
    zeros_protocol = 6;
    tcp_len = HEADER_LENGTH + payload_len;

    set_pseudo_header( pseudo_header, source_addr, destination_addr, zeros_protocol, tcp_len );

//      4. build segment
    build_segment( segment, pseudo_header, tcp_header, payload, payload_len );
    segment_len = PSEUDO_HEADER_LENGTH + HEADER_LENGTH + payload_len;

    *( uint16_t* )( segment + PSEUDO_HEADER_LENGTH + 16 ) = cumulate_checksum( segment, segment_len );

//      5. send

    sendto( connect_socket, segment, segment_len, 0, ( struct sockaddr* ) &cli, cli_len );
    printf("Send a packet(%s) to %s : %hu\t\n", identify_flags( 0x0012 ), inet_ntoa( temp.sin_addr ), ntohs( cli.sin_port ) );
    seq_ack_num_info( *( uint32_t* )( tcp_header + 4 ), *( uint32_t* )( tcp_header + 8 ), 1 );
//--------------------------------------------------------------------------------------------------------------------
//  wait ACK
    memset( segment, 0, SEGMENT_SIZE );
    segment_len = recvfrom( connect_socket, segment, sizeof( segment ), 0, ( struct sockaddr* ) &cli, &cli_len );

    if( disassemble_segment( segment, segment_len, pseudo_header, tcp_header, payload, &payload_len, NULL, &flags_type ) == 0 )
    {
        nextseqnum = *( uint32_t* )( tcp_header + 8 );
        if( payload_len == 0 )
            payload_len++;
        nextacknum = *( uint32_t* )( tcp_header + 4 ) + payload_len;
        printf("Receive a packet(%s) from %s : %hu\n", identify_flags( flags_type ), inet_ntoa( temp.sin_addr ), ntohs( cli.sin_port ) );
        seq_ack_num_info( *( uint32_t* )( tcp_header + 4 ), *( uint32_t* )( tcp_header + 8 ), 0 );
    }

    puts("=====Complete the three-way handshake=====");
//--------------------------------------------------------------------------------------------------------------------
    //open file
    FILE *data;
    if( ( data = fopen( "data", "rb" ) ) == 0 )
    {
        fprintf( stderr, "\n[ERR] %s() : line_%d : ", __FUNCTION__, __LINE__ - 2 );
        perror("");
        exit( 1 );
    }

    //find the size of file
    fseek( data, 0, SEEK_END );
    uint32_t data_size = ftell( data );
    rewind( data );
    printf("Start to send the file, the file size is %d bytes\n", data_size );
    //store the data of file, and close the file stream
    char data_buffer[data_size];
    memset( data_buffer, 0, data_size );
    fread( data_buffer, 1, data_size, data );
    fclose( data );

    //send segments to client
    uint32_t cwnd = 1, rwnd = WINDOW_SIZE, current = 0;
    int  bytes_left = data_size;
    puts("*****Slow Start*****");
    while( bytes_left > 0 )
    {
        for( temp_i = 0 ; temp_i < 2 ; temp_i++ )
        {
            printf("cwnd = %d, rwnd = %d, threshold = %d\n", cwnd, rwnd - cwnd / 2, THRESHOLD );
            //--------------------------------------------------------------------------------------------------------------------
//      1. set tcp header
            source_port = ( uint16_t )atoi( src_port );
            destination_port = ntohs( cli.sin_port );
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
            memcpy( payload, data_buffer + current, cwnd );
            if( bytes_left < cwnd )
                payload_len = bytes_left;
            else
                payload_len = cwnd;
            bytes_left -= cwnd;
            current += payload_len;
            if( cwnd < PAYLOAD_SIZE )
                cwnd *= 2;

//      3.set pseudo header
            source_addr = *( uint32_t* )( pseudo_header + 4 );
            destination_addr = cli.sin_addr.s_addr;
            zeros_protocol = 6;
            tcp_len = HEADER_LENGTH + payload_len;

            set_pseudo_header( pseudo_header, source_addr, destination_addr, zeros_protocol, tcp_len );

//      4. build segment
            build_segment( segment, pseudo_header, tcp_header, payload, payload_len );
            segment_len = PSEUDO_HEADER_LENGTH + HEADER_LENGTH + payload_len;

            *( uint16_t* )( segment + PSEUDO_HEADER_LENGTH + 16 ) = cumulate_checksum( segment, segment_len );

//      5. send

            sendto( connect_socket, segment, segment_len, 0, ( struct sockaddr* ) &cli, cli_len );
            printf("\tSend a packet at : %hu byte\n", payload_len );
            usleep( 200000 );
            nextseqnum += payload_len;
            if( bytes_left < 0 )
                goto escp;
        }
        //--------------------------------------------------------------------------------------------------------------------
        memset( segment, 0, SEGMENT_SIZE );
        segment_len = recvfrom( connect_socket, segment, sizeof( segment ), 0, ( struct sockaddr* ) &cli, &cli_len );

        if( disassemble_segment( segment, segment_len, pseudo_header, tcp_header, payload, &payload_len, NULL, &flags_type ) == 0 )
        {
            nextseqnum = *( uint32_t* )( tcp_header + 8 );
            if( payload_len == 0 )
                payload_len++;
            nextacknum = *( uint32_t* )( tcp_header + 4 ) + payload_len;
            seq_ack_num_info( *( uint32_t* )( tcp_header + 4 ), *( uint32_t* )( tcp_header + 8 ), 0 );
        }
    }
    escp:
    puts("=====Start the four-way handshake=====");
// send FIN
    //--------------------------------------------------------------------------------------------------------------------
//      1. set tcp header
    source_port = ( uint16_t )atoi( src_port );
    destination_port = ntohs( cli.sin_port );
    seq_num = nextseqnum;
    ack_num = nextacknum;
    data_offset_flags = HEADER_LENGTH;
    data_offset_flags = ( data_offset_flags << 16 ) + 0x0001;
    win_size = WINDOW_SIZE;
    checksum = 0;
    ugn_ptr = 0;

    set_tcp_header( tcp_header, source_port, destination_port, seq_num, ack_num, data_offset_flags, win_size, checksum, ugn_ptr );

//      2. set payload
    memset( payload, 0, PAYLOAD_SIZE );
    payload_len = 0;

//      3.set pseudo header
    source_addr = *( uint32_t* )( pseudo_header + 4 );
    destination_addr = cli.sin_addr.s_addr;
    zeros_protocol = 6;
    tcp_len = HEADER_LENGTH + payload_len;

    set_pseudo_header( pseudo_header, source_addr, destination_addr, zeros_protocol, tcp_len );

//      4. build segment
    build_segment( segment, pseudo_header, tcp_header, payload, payload_len );
    segment_len = PSEUDO_HEADER_LENGTH + HEADER_LENGTH + payload_len;

    *( uint16_t* )( segment + PSEUDO_HEADER_LENGTH + 16 ) = cumulate_checksum( segment, segment_len );

//      5. send

    sendto( connect_socket, segment, segment_len, 0, ( struct sockaddr* ) &cli, cli_len );
    printf("Send a packet(%s) to %s : %hu\t\n", identify_flags( 0x0001 ), inet_ntoa( temp.sin_addr ), ntohs( cli.sin_port ) );
    seq_ack_num_info( nextseqnum, nextacknum, 1 );

//--------------------------------------------------------------------------------------------------------------------
    //  wait for ACK
    memset( segment, 0, SEGMENT_SIZE );
    segment_len = recvfrom( connect_socket, segment, sizeof( segment ), 0, ( struct sockaddr* ) &cli, &cli_len );

    if( disassemble_segment( segment, segment_len, pseudo_header, tcp_header, payload, &payload_len, NULL, &flags_type ) == 0 )
    {
        nextseqnum = *( uint32_t* )( tcp_header + 8 );
        if( payload_len == 0 )
            payload_len++;
        nextacknum = *( uint32_t* )( tcp_header + 4 ) + payload_len;
        printf("Receive a packet(%s) from %s : %hu\n", identify_flags( flags_type ), inet_ntoa( temp.sin_addr ), ntohs( cli.sin_port ) );
        seq_ack_num_info( *( uint32_t* )( tcp_header + 4 ), *( uint32_t* )( tcp_header + 8 ), 0 );
    }
//--------------------------------------------------------------------------------------------------------------------
    //  wait for ACK
    memset( segment, 0, SEGMENT_SIZE );
    segment_len = recvfrom( connect_socket, segment, sizeof( segment ), 0, ( struct sockaddr* ) &cli, &cli_len );

    if( disassemble_segment( segment, segment_len, pseudo_header, tcp_header, payload, &payload_len, NULL, &flags_type ) == 0 )
    {
        nextseqnum = *( uint32_t* )( tcp_header + 8 );
        if( payload_len == 0 )
            payload_len++;
        nextacknum = *( uint32_t* )( tcp_header + 4 ) + payload_len;
        printf("Receive a packet(%s) from %s : %hu\n", identify_flags( flags_type ), inet_ntoa( temp.sin_addr ), ntohs( cli.sin_port ) );
        seq_ack_num_info( *( uint32_t* )( tcp_header + 4 ), *( uint32_t* )( tcp_header + 8 ), 0 );
    }
//--------------------------------------------------------------------------------------------------------------------
// send ACK

//      1. set tcp header
    source_port = ( uint16_t )atoi( src_port );
    destination_port = ntohs( cli.sin_port );
    seq_num = nextseqnum;
    ack_num = nextacknum;
    data_offset_flags = HEADER_LENGTH;
    data_offset_flags = ( data_offset_flags << 16 ) + 0x0010;
    win_size = WINDOW_SIZE;
    checksum = 0;
    ugn_ptr = 0;

    set_tcp_header( tcp_header, source_port, destination_port, seq_num, ack_num, data_offset_flags, win_size, checksum, ugn_ptr );

//      2. set payload
    memset( payload, 0, PAYLOAD_SIZE );
    payload_len = 0;

//      3.set pseudo header
    source_addr = *( uint32_t* )( pseudo_header + 4 );
    destination_addr = cli.sin_addr.s_addr;
    zeros_protocol = 6;
    payload_len = 0;
    tcp_len = HEADER_LENGTH + payload_len;

    set_pseudo_header( pseudo_header, source_addr, destination_addr, zeros_protocol, tcp_len );

//      4. build segment
    build_segment( segment, pseudo_header, tcp_header, payload, payload_len );
    segment_len = PSEUDO_HEADER_LENGTH + HEADER_LENGTH + payload_len;

    *( uint16_t* )( segment + PSEUDO_HEADER_LENGTH + 16 ) = cumulate_checksum( segment, segment_len );

//      5. send

    sendto( connect_socket, segment, segment_len, 0, ( struct sockaddr* ) &cli, cli_len );
    printf("Send a packet(%s) to %s : %hu\t\n", identify_flags( 0x0010 ), inet_ntoa( temp.sin_addr ), ntohs( cli.sin_port ) );
    seq_ack_num_info( nextseqnum, nextacknum, 1 );

//--------------------------------------------------------------------------------------------------------------------

    puts("=====Complete the four-way handshake=====");

    close( connect_socket );
}

int main( int argc, char* argv[] )
{
    create_data();
    if( argc == 2)
        run_srv( argv[1] );
    return 0;
}
