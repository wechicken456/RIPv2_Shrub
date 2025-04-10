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

/* return an integer indicating the length of the IPv4 packet (including encapsulated packets).
 * Note that this function only allocates the IPv4 header, and not the encapsulated packets. The rest of the packet lives in the iov array.
 * So this return value doesn't indicate the BUFFER size  of the IPv4 header at iov[iov_idx], but the logical size of the entire packet, if it was contiguous.
 * write the reply packet to iov[iov_idx]
 * where iov_idx (defined in `main.c`, included in `include.h`) is the index of the iov array to which the REPLY IPv4 header will be written. 
 */
int process_ipv4(unsigned char *in_packet, int iov_idx);
#endif