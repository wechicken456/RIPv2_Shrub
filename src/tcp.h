#ifndef TCP_H
#define TCP_H

#include "include.h"
#include "utils.h"

struct tcp_hdr {
    uint8_t 	src_port[2];
    uint8_t 	dst_port[2];
    uint8_t 	sent_seq[4];
    uint8_t 	recv_ack[4];
    uint8_t 	data_off;
    uint8_t 	flags;
    uint8_t 	rx_win[2];
    uint8_t 	cksum[2];
    uint8_t 	tcp_urp[2];
};


void print_tcp_flags(uint8_t flags);
void print_tcp(struct tcp_hdr *tcp_segment);
void process_tcp(struct tcp_hdr *tcp_segment);
#endif

