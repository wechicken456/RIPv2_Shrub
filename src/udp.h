#ifndef UDP_H
#define UDP_H

#include "include.h"
#include "utils.h"


struct udp_hdr {
    uint8_t 	src_port[2];
    uint8_t 	dst_port[2];
    uint8_t     len[2];
    uint8_t     cksum[2];
};


void print_udp(struct udp_hdr *udp_datagram);
void process_udp(struct udp_hdr *udp_datagram);
#endif