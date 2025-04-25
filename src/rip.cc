#include "rip.h"
#include "ethernet.h"
#include "ipv4.h"
#include "udp.h"


/* print RIP header */
void print_rip(struct rip_hdr *hdr) {
    printf("\tRIP:\tCommand:\t%s\n", (hdr->command == 1) ? "Request" : "Reply");
    printf("\t\tVersion:\t%u\n", hdr->version);
    printf("\t\tAddr Family:\t%u\n", ntohs(hdr->addr_family));
    printf("\t\tZero 1:\t%u\n", ntohs(hdr->zero));
    printf("\t\tZero 2:\t%u\n", ntohs(hdr->zero2));
}

/* create a rip broadcast with the entries from rip_vcache_v4
 * and return the length of it 
 */
int create_rip_broadcast_pkt(uint8_t *mac_addr, uint32_t ipv4_src_addr, int interface_idx) {
    /* RIP packet */
    int rip_pkt_len = sizeof(struct rip_hdr) + sizeof(struct rip_entry) * rip_cache_v4.size();
    int total_pkt_len = rip_pkt_len + sizeof(struct udp_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct eth_hdr);
    unsigned char *pkt = (unsigned char*)malloc(total_pkt_len);
    if (!pkt) {
        perror("create_rip_broadcast: ");
        return -1;
    }

    unsigned char *rip_pkt = (unsigned char*)(pkt + sizeof(struct eth_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
    struct rip_hdr *hdr = (struct rip_hdr *)rip_pkt;
    if (!hdr) {
        perror("create_rip_broadcast: ");
        return -1;
    }
    hdr->command = 1;    // RIP request
    hdr->version = 1;    // RIP v1
    hdr->addr_family = htons(2);   // IPv4
    hdr->zero = 0;
    hdr->zero2 = 0;
    for (int i = 0 ; i < (int)rip_cache_v4.size(); i++) {
        uint32_t *entry = (uint32_t *)(rip_pkt + sizeof(struct rip_hdr) + 16 * i);
        entry[0] = rip_cache_v4[i].ip_dst;
        entry[1] = 0;
        entry[2] = 0;
        entry[3] = rip_cache_v4[i].cost;
    }

    /* UDP header */
    struct udp_hdr *udp_hdr = (struct udp_hdr *)(pkt + sizeof(struct eth_hdr) + sizeof(struct ipv4_hdr));
    if (!udp_hdr) {
        perror("create_rip_broadcast: ");
        return -1;
    }
    udp_hdr->src_port = htons(UDP_PORT_RIP);
    udp_hdr->dst_port = htons(UDP_PORT_RIP);
    udp_hdr->len = htons(rip_pkt_len + sizeof(struct udp_hdr));
    uint32_t ipv4_dst_addr = 0xFFFFFFFF;    // broadcast
    udp_hdr->cksum = udp_cksum((unsigned short *)udp_hdr, (uint16_t *)&ipv4_src_addr, (uint16_t*)&ipv4_dst_addr, rip_pkt_len + sizeof(struct udp_hdr));

    /* IPv4 header */
    struct ipv4_hdr *_ipv4_hdr = (struct ipv4_hdr *)(pkt + sizeof(struct eth_hdr));
    if (!_ipv4_hdr) {
        perror("create_rip_broadcast: ");
        return -1;
    }
    _ipv4_hdr->version_ihl = 0x45;                                          // IPv4, header length = 5 * 4 = 20 bytes
    _ipv4_hdr->type_of_service = 0;                                         // no ToS
    _ipv4_hdr->total_len = htons(total_pkt_len - sizeof(struct eth_hdr));   // Total length = IPv4 header + UDP datagram + RIP packet
    _ipv4_hdr->time_to_live = 1;                                            // TTL = 1 for RIP broadcasts as we only have to send to neighbors                                 
    _ipv4_hdr->next_proto_id = IPPROTO_UDP;                                 // UDP 
    memcpy(&_ipv4_hdr->src_addr, (uint8_t*)&ipv4_src_addr, 4);              // source IPv4 address
    memcpy(&_ipv4_hdr->dst_addr, (uint8_t*)&ipv4_dst_addr, 4);              // destination IPv4 address
    _ipv4_hdr->frame_ident = htons(0x0001);                                 // ID can be whatever
    _ipv4_hdr->fragment_offset = 0;                                         // no fragmentation
    _ipv4_hdr->hdr_checksum = 0;                                            // checksum is set to 0 before calculating it
    // checksum is cinterface_idxomputed over ONLY the header as per RFC 791
    _ipv4_hdr->hdr_checksum = in_cksum((unsigned short *)_ipv4_hdr, sizeof(ipv4_hdr), 0);
        
    /* Ethernet header */
    struct eth_hdr *_eth_hdr = (struct eth_hdr *)(pkt);
    if (!_eth_hdr) {
        perror("create_rip_broadcast: ");
        return -1;
    }
    _eth_hdr->h_proto = htons(ETHERTYPE_IPV4);    // IPv4
    for (int i = 0 ; i < 6; i++) {
        _eth_hdr->h_dest[i] = 0xFF;    // broadcast
        _eth_hdr->h_source[i] = interfaces[interface_idx].mac_addr[i];
    }
    iov[1].iov_base = pkt;
    iov[1].iov_len = total_pkt_len;
    iov_cnt = 2; /* as we only have this big iov, along with the pcap header */
    return total_pkt_len;
}

void* rip_broadcast(void* _interface_idx) {
    int interface_idx = *(int*)_interface_idx;
    int ret;
    uint32_t ipv4_src_addr = interfaces[interface_idx].ipv4_addr;
    unsigned char *mac_addr = interfaces[interface_idx].mac_addr;
    if (debug > 1) {
        printf("RIP broadcast thread %d spawned for interface ", interface_idx);
        uint32_t ipv4_addr = interfaces[interface_idx].ipv4_addr;
        print_addr_4((uint8_t*)&ipv4_addr);
        printf(" and MAC = %02x:%02x:%02x:%02x:%02x:%02x ", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
        printf("with SLEEP_TIME_RIP = %d\n", SLEEP_TIME_RIP);
        puts("");
    }
    while (1) {
        if (debug) printf("RIP broadcast thread %d: broadcasting RIP request to all neighbors...\n", interface_idx);
        int pkt_len = create_rip_broadcast_pkt(mac_addr, ipv4_src_addr, interface_idx);
        if (pkt_len <= 0) {
            fprintf(stderr, "[!] Failed to create RIP broadcast packet for interface %d...!!!\n", interface_idx);
            continue;
        }
        ret = write_pcap(interface_idx);
        if (ret < 0) {
            fprintf(stderr, "[!] Failed to write RIP broadcast packet for interface %d...!!!\n", interface_idx);
            continue;
        } else {
            if (debug) {
                printf("[+] RIP broadcast thread: Wrote RIP broadcast packet of length %d to interface ", pkt_len);
                print_addr_4((uint8_t*)&interfaces[interface_idx].ipv4_addr);
                puts("");
            }
        }
        sleep(SLEEP_TIME_RIP);
    }
}

/* 
 * Broadcast RIP requests to all interfaces every 30s.
 * This function should ONLY be called form the main thread, AFTER setting up ALL the interface threads.
 * That is, call it after all calls to the `setup` function in `main.cc`.
 * For each interface, it will spawn a thread for rip_broadcast(interface_idx), which will
 * broadcast RIP requests every 30s to that particular interface.
 */
void loop_rip() {
    pthread_t *rip_thread = (pthread_t*)malloc(sizeof(pthread_t) * num_interfaces);
    int *rip_thread_idx = (int*)malloc(sizeof(int) * num_interfaces);
    int ret;
    for (int i = 0 ; i < num_interfaces; i++) {
        rip_thread_idx[i] = i;
        ret = pthread_create(rip_thread + i, NULL, &rip_broadcast, (void*)&rip_thread_idx[i]);
        if (ret < 0) {
            fprintf(stderr, "[!] Failed to create RIP broadcast thread for interface %d...!!!\n", i);
            continue;
        }
    }
    for (int i = 0 ; i < num_interfaces; i++) {
        int *ret_ptr;
        ret = pthread_join(*(rip_thread + i), (void**)&ret_ptr);
        if (ret != 0) {
            perror("pthread_join");
            continue;
        }
        printf("pthread_join: RIP broadcast thread %d exitted with status %d\n", i, *ret_ptr);
    }
}

int process_rip(unsigned char *rip_packet, uint32_t ipv4_src_addr, int pkt_len, int iov_idx) {
    struct rip_hdr *hdr = (struct rip_hdr *)rip_packet;

    if (hdr->version == 0) {
        fprintf(stderr, "[!] INVALID RIP VERSION: %d\n", hdr->version);
        return -1;
    }

    /* As per the RFC, make sure it is from one of our interfaces */
    int from_interface_idx = -1;
    for (int i = 0 ; i < num_interfaces; i++) {
        if (interfaces[i].ipv4_addr == ipv4_src_addr) {
            from_interface_idx = i;
            break;
        }
    }
    if (from_interface_idx == -1) {
        fprintf(stderr, "[!] RIP packet is not from one of our interfaces. Ignoring...\n");
        return 0;
    }

    if (hdr->command == 1) {    // RIP request
        if (debug) print_rip(hdr);
    
        // construct a RIP reply packet
        unsigned char *rip_reply = (unsigned char*)malloc(pkt_len);
        struct rip_hdr *reply_hdr = (struct rip_hdr *)rip_reply;
        if (!reply_hdr) {
            perror("process_rip: ");
            return -1;
        }

        reply_hdr->command = 2;    // RIP reply
        reply_hdr->version = hdr->version;
        reply_hdr->addr_family = hdr->addr_family;
        reply_hdr->zero2 = 0;

        iov[iov_idx].iov_base = rip_reply;
        iov[iov_idx].iov_len = pkt_len;
        iov_cnt++;
        return pkt_len;

    } else if (hdr->command == 2) {     // RIP Response/Reply
        if (debug) print_rip(hdr);

        
    }

    return -1;
}
