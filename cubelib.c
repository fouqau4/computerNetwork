#include "cubelib.h"


//--------------------------------------------------------------------------------------------------------------------
//#include <sys/types.h>
//#include <sys/socket.h>
int sendall(int s, char *buf, int *len)
{
    int total = 0; // 我們已經送出多少 bytes 的資料
    int bytesleft = *len; // 我們還有多少資料要送
    int n;

    while(total < *len)
    {
        n = send(s, buf+total, bytesleft, 0);
        if (n == -1)
        {
            break;
        }
        total += n;
        bytesleft -= n;
    }

    *len = total; // 傳回實際上送出的資料量

    return n==-1?-1:0; // 失敗時傳回 -1、成功時傳回 0
}


//--------------------------------------------------------------------------------------------------------------------
//#include <stdlib.h>
unsigned char* decimalToBinary( int dec, int length )
{
    unsigned char *binary;
    binary = (char*)malloc( length + 1 );
    memset( binary, 0, length + 1 );

    int temp_i;
    for( temp_i = length-1 ; temp_i >= 0; temp_i--)
    {
        if(dec > 0)
        {
            binary[temp_i] = dec%2 + '0';
            dec /= 2;
        }
        else
            binary[temp_i] = '0';
    }
    binary[length] = '\0';

    return binary;
}

//--------------------------------------------------------------------------------------------------------------------
//#include <assert.h>
//#include <unistd.h>
//#include <stdlib.h>
ssize_t write_all (int fd, const void* buffer, size_t count)
{

    size_t left_to_write = count;

    while (left_to_write > 0)
    {

        size_t written = write (fd, buffer, count);

        if (written == -1)

            /* An error occurred; bail.  */

            return -1;

        else

            /* Keep count of how much more we need to write.  */

            left_to_write -= written;

    }

    /* We should have written no more than COUNT bytes!   */

    assert (left_to_write == 0);

    /* The number of bytes written is exactly COUNT.  */

    return count;

}
//--------------------------------------------------------------------------------------------------------------------
//#include <string.h>
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>
//#include <netdb.h>
//#include <stdio.h>

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif // INADDR_NONE

int connectsock( const char *host, const char *service, const char *transport )
{
    struct hostent *phe;
    struct servent *pse;
    struct protoent *ppe;
    struct sockaddr_in sin;
    int sock, type;

    memset( &sin, 0, sizeof( sin ) );
    sin.sin_family = AF_INET;

    if( pse = getservbyname( service, transport ) )
        sin.sin_port = pse->s_port;
    else if( ( sin.sin_port = htons( ( u_short )atoi( service ) ) ) == 0 )
    {
        fprintf( stderr, "\n[ERR] %s() : line_%d : ", __FUNCTION__, __LINE__ - 2 );
        perror("");
        exit( 1 );
    }

    if( phe = gethostbyname( host ) )
        memcpy( &sin.sin_addr, phe->h_addr, phe->h_length );
    else if( ( sin.sin_addr.s_addr = inet_addr( host ) ) == INADDR_NONE )
    {
        fprintf( stderr, "\n[ERR] %s() : line_%d : ", __FUNCTION__, __LINE__ - 2 );
        perror("");
        exit( 1 );
    }

    if( ( ppe = getprotobyname( transport ) ) == 0 )
    {
        fprintf( stderr, "\n[ERR] %s() : line_%d : ", __FUNCTION__, __LINE__ - 2 );
        perror("");
        exit( 1 );
    }

    if( strcmp( transport, "udp") == 0 )
        type = SOCK_DGRAM;
    else
        type = SOCK_STREAM;

    sock = socket( PF_INET, type, ppe->p_proto );
    if( sock < 0 )
    {
        fprintf( stderr, "\n[ERR] %s() : line_%d : ", __FUNCTION__, __LINE__ - 2 );
        perror("");
        exit( 1 );
    }

    if( connect( sock, ( struct sockaddr * )&sin, sizeof( sin ) ) < 0 )
    {
        fprintf( stderr, "\n[ERR] %s() : line_%d : ", __FUNCTION__, __LINE__ - 2 );
        perror("");
        exit( 1 );
    }

    return sock;
}
//--------------------------------------------------------------------------------------------------------------------
int connectTCP( const char *host, const char *service )
{
    return connectsock( host, service, "tcp" );
}
//--------------------------------------------------------------------------------------------------------------------
int connectUDP( const char *host, const char* service )
{
    return connectsock( host, service, "udp" );
}
//--------------------------------------------------------------------------------------------------------------------
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
//#include <stdlib.h>
//#include <stdio.h>
//#include <string.h>
//#include <netdb.h>
unsigned short portbase = 0;
int passivesock( const char *service, const char *transport, int qlen )
{
    struct servent *pse;
    struct protoent *ppe;
    struct sockaddr_in sin;
    int sock, type;
    memset( &sin, 0, sizeof( sin ) );
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;

    if( pse = getservbyname( service, transport ) )
        sin.sin_port = htons( ntohs( ( unsigned short )atoi( service ) ) + portbase );
    else if( (sin.sin_port = htons( ( unsigned short )atoi( service ) ) ) == 0 )
    {
        fprintf( stderr, "\n[ERR] %s() : line_%d : ", __FUNCTION__, __LINE__ - 2 );
        perror("");
        exit( 1 );
    }

    if( ( ppe = getprotobyname( transport ) ) == 0 )
    {
        fprintf( stderr, "\n[ERR] %s() : line_%d : ", __FUNCTION__, __LINE__ - 2 );
        perror("");
        exit( 1 );
    }

    if( strcmp( transport, "udp" ) == 0 )
        type = SOCK_DGRAM;
    else
        type = SOCK_STREAM;

    if( ( sock = socket( PF_INET, type, ppe->p_proto ) ) < 0 )
    {
        fprintf( stderr, "\n[ERR] %s() : line_%d : ", __FUNCTION__, __LINE__ - 2 );
        perror("");
        exit( 1 );
    }

    if( bind( sock, ( struct sockaddr* ) &sin, sizeof( sin ) ) < 0 )
    {
        fprintf( stderr, "\n[ERR] %s() : line_%d : ", __FUNCTION__, __LINE__ - 2 );
        perror("");
        exit( 1 );
    }

    if( type == SOCK_STREAM && listen( sock, qlen ) < 0 )
    {
        fprintf( stderr, "\n[ERR] %s() : line_%d : ", __FUNCTION__, __LINE__ - 2 );
        perror("");
        exit( 1 );
    }

    return sock;
}
//--------------------------------------------------------------------------------------------------------------------
int passiveUDP( const char *service )
{
    return passivesock( service, "udp", 0 );
}
//--------------------------------------------------------------------------------------------------------------------
int passiveTCP( const char *service, int qlen )
{
    return passivesock( service, "tcp", qlen );
}
//--------------------------------------------------------------------------------------------------------------------
uint16_t cumulate_checksum( char* segment, int segment_len )
{
    int temp_i;
    uint32_t temp_ui32t;
//  cumulate checksum ( pseudo header + tcp header + tcp payload )
    uint32_t checksum_temp = 0;

    for( temp_i = 0 ; temp_i < segment_len ; temp_i += 2 )
    {
        checksum_temp += *( uint16_t* )( segment + temp_i );
        if( checksum_temp > 0xffff )
        {
            checksum_temp = checksum_temp % 0x10000 + 0x0001;
        }
    }
    return ( uint16_t )( ~checksum_temp );
}
//--------------------------------------------------------------------------------------------------------------------
void build_segment( char* segment, char* pseudo_header, char* tcp_header, char* payload, uint16_t payload_len )
{
    memset( segment, 0, SEGMENT_SIZE );
    memcpy( segment, pseudo_header, PSEUDO_HEADER_LENGTH );
    memcpy( segment + PSEUDO_HEADER_LENGTH, tcp_header, HEADER_LENGTH );
    memcpy( segment + PSEUDO_HEADER_LENGTH + HEADER_LENGTH, payload, payload_len );
}
//--------------------------------------------------------------------------------------------------------------------
int disassemble_segment( char* segment, int segment_len, char* pseudo_header, char* tcp_header, char* payload, uint16_t* payload_len, char** current_win, uint16_t* flags_type )
{

//--------------------------------------------------------------------------------------------------------------------
//check checksum
    uint16_t x = ~cumulate_checksum( segment, segment_len );
    if( x != 0xffff )
    {
//        printf("\n[Checksum] : -----   Incorrect : %x.\nseglen = %d\n", x, segment_len );
//        printf("seqnum = %u, acknum = %u\n\n", *( uint32_t* )( segment + PSEUDO_HEADER_LENGTH + 4 ), *( uint32_t* )( segment + PSEUDO_HEADER_LENGTH + 8 ) );
//        puts(segment + 32);
//        return -1;
    }

//--------------------------------------------------------------------------------------------------------------------
//disassemble segment
    memset( pseudo_header, 0, PSEUDO_HEADER_LENGTH );
    memset( tcp_header, 0, HEADER_LENGTH );
    memset( payload, 0, PAYLOAD_SIZE );

    memcpy( pseudo_header, segment, PSEUDO_HEADER_LENGTH );
    memcpy( tcp_header, segment + PSEUDO_HEADER_LENGTH, HEADER_LENGTH );
    memcpy( payload, segment + PSEUDO_HEADER_LENGTH + HEADER_LENGTH, PAYLOAD_SIZE );

    *payload_len = *( uint16_t* )( pseudo_header + 10 ) - HEADER_LENGTH;
//--------------------------------------------------------------------------------------------------------------------
//put segment into window
    if( current_win != NULL )
    {
        if( *current_win == NULL )
        {
            *current_win = ( char* )malloc( segment_len );
            memcpy( *current_win, segment, segment_len );
        }
        else
        {
            puts("[Drop] : Receive buffer overflow");
            return -2;
        }
    }
//--------------------------------------------------------------------------------------------------------------------
//show set flags
    *flags_type = 0;
    if( ( *( uint16_t* )( tcp_header + 12 ) & 0x0001 ) == 0x0001 )
    {
//        printf("[Flags] : --FIN--\n");
        *flags_type += 0x0001;
    }
    if( ( *( uint16_t* )( tcp_header + 12 ) & 0x0002 ) == 0x0002 )
    {
//        printf("[Flags] : --SYN--\n");
        *flags_type += 0x0002;
    }
    if( ( *( uint16_t* )( tcp_header + 12 ) & 0x0010 ) == 0x0010 )
    {
//        printf("[Flags] : --ACK--\n");
        *flags_type += 0x0010;
    }

    return 0;
}
//--------------------------------------------------------------------------------------------------------------------
const char* identify_flags( uint16_t flags_type )
{
    switch( flags_type )
    {
    case 0x0001 :
        return "FIN";
    case 0x0002 :
        return "SYN";
    case 0x0010 :
        return "ACK";
    case 0x0011 :
        return "FIN/ACK";
    case 0x0012 :
        return "SYN/ACK";
    default :
        return "No flag was set.";
    }
}
//--------------------------------------------------------------------------------------------------------------------
void seq_ack_num_info( uint32_t seq_num, uint32_t ack_num, int op )
{
    if( op )
        printf("\tSend a packet (seq_num = %u, ack_num = %u)\n", seq_num, ack_num );
    else
        printf("\tReceive a packet (seq_num = %u, ack_num = %u)\n", seq_num, ack_num );
}
//--------------------------------------------------------------------------------------------------------------------
void set_pseudo_header( char* pseudo_header, uint32_t source_addr, uint32_t destination_addr, uint16_t zeros_protocol, uint16_t tcp_len )
{
    memset( pseudo_header, 0, PSEUDO_HEADER_LENGTH );
    *( uint32_t* )pseudo_header = source_addr;
    *( uint32_t* )( pseudo_header + 4 ) = destination_addr;
    *( uint16_t* )( pseudo_header + 8 ) = zeros_protocol;
    *( uint16_t* )( pseudo_header + 10 ) = tcp_len;
}
//--------------------------------------------------------------------------------------------------------------------
void set_tcp_header( char* tcp_header, uint16_t source_port, uint16_t destination_port, uint32_t seq_num, uint32_t ack_num, uint16_t data_offset_flags, uint16_t win_size, uint16_t checksum, uint16_t ugn_ptr )
{
    memset( tcp_header, 0, HEADER_LENGTH );
    *( uint16_t* )tcp_header = source_port;
    *( uint16_t* )( tcp_header + 2 ) = destination_port;
    *( uint32_t* )( tcp_header + 4 ) = seq_num;
    *( uint32_t* )( tcp_header + 8 ) = ack_num;
    *( uint16_t* )( tcp_header + 12 ) = data_offset_flags;
    *( uint16_t* )( tcp_header + 14 ) = win_size;
    *( uint16_t* )( tcp_header + 16 ) = checksum;
    *( uint16_t* )( tcp_header + 18 ) = ugn_ptr;
}
//--------------------------------------------------------------------------------------------------------------------
