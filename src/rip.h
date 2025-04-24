#ifndef RIP_H
#define RIP_H

#include "include.h"
#include "utils.h"
#include <map>

/* https://datatracker.ietf.org/doc/html/rfc1058#section-3.2 */
struct rip_hdr {
    uint8_t     command;                /* message type */
    uint8_t     version;                /* type sub-code */
    uint16_t     zero;
    uint16_t     addr_family;           /* Identifier */
    uint16_t     zero2;
};

/* https://datatracker.ietf.org/doc/html/rfc1058#section-3 */
struct rip_entry {
    uint32_t ip_dst;
    uint32_t cost;
    uint32_t next_hop;
    uint32_t flag;
    time_t timer; 
};

extern std::map<uint32_t, struct rip_entry> rip_cache_v4;

/*
 * write the reply packet to iov[iov_idx]
 * where iov_idx (defined in `main.c`, included in `include.h`) is the index of the iov array to which the REPLY ICMP packet will be written. 
 */
int process_rip(unsigned char *rip_packet, uint32_t ipv4_src_addr, int pkt_len, int iov_idx);

#endif