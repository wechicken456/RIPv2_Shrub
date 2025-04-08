#ifndef IPV4_H
#define IPV4_H

#include "include.h"
#include "icmp.h"
#include "utils.h"

struct ipv4_hdr {
    uint8_t 	version_ihl;    
    uint8_t 	type_of_service;
    uint16_t 	total_len; 
    uint16_t 	frame_ident;
    uint16_t 	fragment_offset;
    uint8_t 	time_to_live;
    uint8_t 	next_proto_id;
    uint16_t 	hdr_checksum;
    uint8_t 	src_addr[4];
    uint8_t 	dst_addr[4];
};

unsigned char* process_ipv4(struct ipv4_hdr *ipv4_packet, int *reply_pkt_size);
#endif