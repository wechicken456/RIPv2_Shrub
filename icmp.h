#ifndef ICMP_H
#define ICMP_H

#include "include.h"
#include "utils.h"

// http://www.tcpipguide.com/free/t_ICMPv4EchoRequestandEchoReplyMessages-2.htm
struct icmp_hdr {
    uint8_t     type;                /* message type */
    uint8_t     code;                /* type sub-code */
    uint16_t     cksum;
    uint16_t     ident;           /* Identifier */
    uint16_t     seq_num;         /* sequence number */
};


void print_icmp(struct icmp_hdr *icmp_packet);
unsigned char* process_icmp(struct icmp_hdr *icmp_packet, int pkt_len, int *reply_pkt_size);
#endif
