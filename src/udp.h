#ifndef UDP_H
#define UDP_H

#include "include.h"
#include "utils.h"


struct udp_hdr {
    uint16_t 	src_port;
    uint16_t 	dst_port;
    uint16_t    len;
    uint16_t    cksum;
};


void print_udp(struct udp_hdr *udp_datagram);
uint16_t udp_cksum(unsigned short *udp_datagram, uint16_t *ip_src, uint16_t *ip_dst, uint16_t udp_len);
/*
 * write the reply packet to iov[iov_idx]
 * where iov_idx (defined in `main.c`, included in `include.h`) is the index of the iov array to which the REPLY ICMP packet will be written. 
 */
int process_udp(unsigned char *udp_datagram, uint16_t *ip_src, uint16_t *ip_dst, uint16_t udp_len, int iov_idx);
#endif