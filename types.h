#ifndef TYPES_H
#define TYPES_H

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <errno.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdarg.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/time.h>

#pragma pack(1)

#define MAX_BUF_SIZE 1024 
#define MAX_PACKET_SIZE 1024
#define MAX_FN_LEN 512
#define MAX_CONNECTIONS 10

#define EXT_TCP_PORT 22222
#define MAX_ROUTER_COUNT 10

#define CC_EXT_PROTOCOL 253

#define CC_EXT_MSGTYPE 82
#define CC_EXT_DONE_MSGTYPE 83
#define CC_RELAY_MSGTYPE 81
#define CC_RELAY_BACK_MSGTYPE 84
#define CC_ENCRYPTED_EXT 98
#define CC_ENCRYPTED_EXT_DONE 99
#define CC_ENCRYPTED_RELAY 97
#define CC_ENCRYPTED_RELAY_REPLY 100
#define KILL_YOURSELF 145

#define FAKE_DIFFIE_HELLMAN 101
#define KEY_LEN 16
#define BLOCK_SIZE 16

#define ENC_PORT_LEN 16


typedef unsigned short ushort;
typedef unsigned long ulong;


struct up_msg
{
    unsigned short _pid;
    unsigned short _index;
};

struct circuit 
{
    unsigned short _iid;
    unsigned short _oid;
    unsigned short _iport;
    unsigned short _oport;
    unsigned long _iip;
    unsigned long _oip;

    circuit()
    {
    	_iid    =_oid = _iport = _oport = _iip = _oip = 0;
    }
};

struct cc_ext_done_msg
{
    unsigned char msg_type;
    unsigned short cid;
};

struct cc_relay_msg
{
    unsigned char msg_type;
    unsigned short cid;
};

struct cc_ext_msg
{
    unsigned char msg_type;
    unsigned short cid;
    unsigned short next_hop;
};

struct cc_deffie_hellman_msg
{
    unsigned char msg_type;
    unsigned short cid;
    //unsigned char key[KEY_LEN];
};

struct cc_encrypt_ext_msg
{
    unsigned char msg_type;
    unsigned short cid;
    //char encrypted_port[ENC_PORT_LEN];
};

struct psd_tcp 
{
    struct in_addr src;
    struct in_addr dst;
    unsigned char pad;
    unsigned char proto;
    unsigned short tcp_len;
    struct tcphdr tcp;
};

struct router_info
{
    int index;
    int pid;
    //char *sIP;
    unsigned long nIP;
    struct sockaddr_in r_addr;
    unsigned char key[KEY_LEN];
};


struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

void print_icmp_packet(char* Buffer , int Size);
void print_ip_header(char* Buffer, int Size);
void print_udp_packet(char *Buffer , int Size);
void print_tcp_packet(char* Buffer, int Size);


unsigned short in_cksum_tcp(int src, int dst, unsigned short *addr, int len);
unsigned short in_cksum(unsigned short *addr, int len);
unsigned short csum(unsigned short *ptr,int nbytes);
int sread(int fd, char *buf, int bufsize);
int get_all_interface_ip(struct router_info* rinfo);

int compute_circuit_id(int index, int seq);


int construct_relay_msg(char*buf, int buf_len,  unsigned short cID, char*payload, int payload_len, int msg_type, int stage, int flowNumber);

void encrypt_msg(char* inbuf,char* outbuf, int buflen, unsigned char key[]);
void decrypt_msg(char* inbuf, char* outbuf, int buflen, unsigned char key[]);

void encrypt_msg_with_padding(char* inbuf, int inlen, char** outbuf, int* outlen, unsigned char key[]);
void decrypt_msg_with_padding(char* inbuf, int inlen, char** outbuf, int* outlen, unsigned char key[]);


int key_to_hex_buf(unsigned char* key, char* buf, int len);
void print_packet_hex(char* buf, int len);

struct flow
{
    u_int32_t saddr;
    u_int32_t daddr;
    u_int16_t sport;
    u_int16_t dport;
    u_int8_t protocol;
};

#endif
