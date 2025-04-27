#ifndef RIP_H
#define RIP_H

#include "include.h"
#include "utils.h"
#include <vector>

#define RIP_COST_INFINITY 16
#define RIP_ADDRESS_FAMILY 2
#define RIP_MULTICAST_ADDR htonl(0xE0000009)
#define ROUTE_CHANGE_FLAG 1
#define RIP_CACHE_ENTRY_STATE_ACTIVE 0
#define RIP_CACHE_ETNRY_STATE_DELETED 1

/* https://datatracker.ietf.org/doc/html/rfc1058#section-3.2 */
struct rip_hdr {
    uint8_t     command;                /* message type */
    uint8_t     version;                /* type sub-code */
    uint16_t     zero;
};

/* https://datatracker.ietf.org/doc/html/rfc2453#section-4 */
struct rip_message_entry {
    uint16_t addr_family;
    uint16_t route_tag;
    uint32_t ip_dst;
    uint32_t subnet_mask;
    uint32_t next_hop;
    uint32_t cost;
};

struct rip_cache_entry {
    uint16_t addr_family;
    uint16_t route_tag;
    uint32_t ip_dst;
    uint32_t subnet_mask;
    uint32_t next_hop;
    uint32_t cost;

    uint32_t flag;
    time_t timer; 
    int iface_idx;
    int is_directly_connected; 
    int is_default_route; /* 1 if the entry is the default route */
    uint32_t advertiser;  /* the ipv4 addr of the router that we learned this route from */
    int state; /* 0 = ACTIVE, 1 = DELETED */
};

extern std::vector<struct rip_cache_entry> rip_cache_v4;
extern pthread_mutex_t rip_cache_mutex;

/*
 * write the reply packet to iov[iov_idx]
 * where iov_idx (defined in `main.c`, included in `include.h`) is the index of the iov array to which the REPLY ICMP packet will be written. 
 */
int process_rip(unsigned char *rip_packet, uint32_t ipv4_src_addr, int pkt_len, int iov_idx);
void create_rip_threads();
void* loop_rip_broadcast(void* interface_idx);
int create_rip_broadcast_pkt(uint8_t *mac_addr, uint32_t ipv4_src_addr, int interface_idx, int request_all_routes);

void print_rip(unsigned char *pkt, int pkt_len);
void print_rip_entry(struct rip_message_entry *entry);
void print_rip_cache();
void print_rip_cache_entry(struct rip_cache_entry *entry);

int split_horizon_poisoned_reverse(int cost, int iface_idx, int from_iface_idx);
int create_rip_broadcast_msg(unsigned char **dst, int ipv4_src_addr);
extern int write_pcap(int interface_idx);
void signal_update();
#endif