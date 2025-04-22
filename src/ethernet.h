#ifndef ETHERNET_H
#define ETHERNET_H

#include "include.h"
#include "ipv4.h"
#include "utils.h"
#include <map>
struct eth_hdr {
    uint8_t  h_dest[6];   /* destination eth addr */
    uint8_t  h_source[6]; /* source ether addr    */
    uint16_t h_proto;            /* packet type ID field */
};

// https://en.wikipedia.org/wiki/Address_Resolution_Protocol
struct arp_ipv4_hdr {
    uint8_t     h_type[2];
    uint8_t     p_type[2];
    uint8_t     hlen_plen[2];
    uint8_t     op[2];
    uint8_t     sha[6];
    uint8_t     spa[4];
    uint8_t     tha[6];
    uint8_t     tpa[4];
};

/* MAC to IPv4 and IPv6 */
extern std::map<uint64_t, uint32_t> arp_cache_v4;
extern std::map<uint64_t, uint64_t> arp_cache_v6;

void print_ethernet(struct eth_hdr *peh);
int process_arp(struct arp_ipv4_hdr *arp_frame);

/* return an integer indicating the length of the ethernet packet (including encapsulated packets).
 * Note that this function only allocates the ethernet header, and not the encapsulated packets. The rest of the packet lives in the iov array.
 * So this return value doesn't indicate the BUFFER size of the ethernet packet (encapsulating IPv4, TCP ,etc ) at iov[iov_idx], 
 * but the logical size of the entire packet, if it was contiguous.
 * write the reply packet to iov[iov_idx]
 * where iov_idx (defined in `main.c`, included in `include.h`) is the index of the iov array to which the REPLY IPv4 header will be written. 
 */
int process_ethernet(unsigned char *in_packet, int iov_idx);
#endif