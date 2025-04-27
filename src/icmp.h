#ifndef ICMP_H
#define ICMP_H

#include "include.h"
#include "utils.h"
#include "ipv4.h"

// http://www.tcpipguide.com/free/t_ICMPv4EchoRequestandEchoReplyMessages-2.htm
struct icmp_hdr {
    uint8_t     type;                /* message type */
    uint8_t     code;                /* type sub-code */
    uint16_t     cksum;
    uint16_t     ident;           /* Identifier */
    uint16_t     seq_num;         /* sequence number */ 
};

/* https://datatracker.ietf.org/doc/html/rfc792 */
struct icmp_ttl_expired_message_hdr {
    uint8_t     type;                /* message type */
    uint8_t     code;                /* type sub-code */
    uint16_t     cksum;
    uint32_t     unused;
};

struct icmp_dest_unreachable_message_hdr {
    uint8_t     type;                /* message type */
    uint8_t     code;                /* type sub-code */
    uint16_t     cksum;
    uint32_t     unused;
};

void print_icmp(struct icmp_hdr *icmp_packet);

/* return an integer indicating the length of the ICMP packet (header + data).
 * This implementation is necessary in case the lower layer protocols (e.g. IPv4) need the ICMP packet size.
 * write the reply packet to iov[iov_idx]
 * where iov_idx (defined in `main.c`, included in `include.h`) is the index of the iov array to which the REPLY ICMP packet will be written. 
 */
int process_icmp(unsigned char *icmp_packet, int pkt_len, int iov_idx);
int iov_create_icmp_error(unsigned char *in_ipv4_pkt, int in_ipv4_len, int in_ipv4_hdr_len, uint8_t icmp_type, uint8_t icmp_code, int iov_idx);
#endif
