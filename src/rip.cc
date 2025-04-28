#include "rip.h"
#include "ethernet.h"
#include "ipv4.h"
#include "udp.h"


/* print RIP header */
void print_rip(unsigned char *pkt, int pkt_len) {
    struct rip_hdr *hdr = (struct rip_hdr *)pkt;
    printf("\tRIP:\tCommand:\t\t%s\n", (hdr->command == 1) ? "Request" : "Reply");
    printf("\t\tVersion:\t\t%u\n", hdr->version);
    printf("\t\tZero:\t\t%u\n", ntohs(hdr->zero));
    int num_entries = (pkt_len - sizeof(struct rip_hdr)) / sizeof(struct rip_message_entry);
    for (int i= 0 ; i < num_entries; i++){
        printf("\t\tEntry %d:\n", i);
        struct rip_message_entry *entry = (struct rip_message_entry *)(pkt + sizeof(struct rip_hdr) + sizeof(struct rip_message_entry) * i);
        print_rip_entry(entry);
    }
}

void print_rip_entry(struct rip_message_entry *entry) {
    
    printf("\t\t- Address family:\t%u\n", ntohs(entry->addr_family));
    printf("\t\t- Route tag:\t%u\n", ntohs(entry->route_tag));
    printf("\t\t- IP dst:\t");
    print_addr_4((uint8_t*)&entry->ip_dst);
    puts("");
    printf("\t\t- Subnet mask:\t");
    print_addr_4((uint8_t*)&entry->subnet_mask);
    puts("");
    printf("\t\t- Next hop:\t");
    print_addr_4((uint8_t*)&entry->next_hop);
    puts("");
    printf("\t\t- Cost:\t%u\n", ntohl(entry->cost));
}

void print_rip_cache_entry(struct rip_cache_entry *entry) {
    printf("\t\t- Address family:\t%u\n", entry->addr_family);
    printf("\t\t- Route tag:\t%u\n", entry->route_tag);
    printf("\t\t- IP dst:\t");
    print_addr_4((uint8_t*)&entry->ip_dst);
    puts("");
    printf("\t\t- Subnet mask:\t");
    print_addr_4((uint8_t*)&entry->subnet_mask);
    puts("");
    printf("\t\t- Next hop:\t");
    print_addr_4((uint8_t*)&entry->next_hop);
    puts("");
    printf("\t\t- Cost:\t%u\n", entry->cost);
    printf("\t\t- Flag:\t%u\n", entry->flag);
    printf("\t\t- Timer:\t%ld\n", entry->timer);
    printf("\t\t- Interface idx:\t%u\n", entry->iface_idx);
    printf("\t\t- Is directly connected:\t%s\n", (entry->is_directly_connected) ? "Yes" : "No");
    printf("\t\t- Is default route:\t%s\n", (entry->is_default_route) ? "Yes" : "No");
    printf("\t\t- Advertiser:\t");
    print_addr_4((uint8_t*)&entry->advertiser);
    puts("");
}

void print_rip_cache() {
    printf("[*] RIP cache:\n");
    for (int i = 0 ; i < (int)rip_cache_v4.size(); i++) {
        printf("\tEntry %d:\n", i);
        print_rip_cache_entry(&rip_cache_v4[i]);
    }
}

uint32_t split_horizon_poisoned_reverse(uint32_t cost, int adverstiser_interface_idx, int dst_interface_idx) {
    if (adverstiser_interface_idx == dst_interface_idx) return RIP_COST_INFINITY;
    return cost;
}
/* create a rip broadcast with the entries from rip_vcache_v4
 * and return the length of it. Only called by rip_broadcast and hence the RIP thread. 
 * This is because it creates a whole reply packets (ether, ipv4, udp, rip) into a single iov,
 * which is different from how reply packets are created (check `iov` in `main.cc`).
 */
int create_rip_broadcast_pkt(uint8_t *mac_addr, uint32_t ipv4_src_addr, int interface_idx, int request_all_routes) {
    /* RIP packet */
    pthread_mutex_lock(&rip_cache_mutex);

    int rip_pkt_len;
    if (request_all_routes) rip_pkt_len = sizeof(struct rip_hdr) + sizeof(struct rip_message_entry);
    else rip_pkt_len = sizeof(struct rip_hdr) + sizeof(struct rip_message_entry) * rip_cache_v4.size();
    int total_pkt_len = rip_pkt_len + sizeof(struct udp_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct eth_hdr);
    unsigned char *pkt = (unsigned char*)malloc(total_pkt_len);
    if (!pkt) {
        perror("create_rip_broadcast: ");
        pthread_mutex_unlock(&rip_cache_mutex);
        return -1;
    }

    unsigned char *rip_pkt = (unsigned char*)(pkt + sizeof(struct eth_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
    struct rip_hdr *rip_hdr = (struct rip_hdr *)rip_pkt;
    if (!rip_hdr) {
        perror("create_rip_broadcast: ");
        pthread_mutex_unlock(&rip_cache_mutex);
        return -1;
    }
    
    // RIP request if we first get online, otherwise it's a broadcast response.
    rip_hdr->command = (request_all_routes) ? 1 : 2;   
    rip_hdr->version = 2;    // addrRIP v2
    rip_hdr->zero = 0;

    if (request_all_routes) {
        struct rip_message_entry *entry = (struct rip_message_entry *)(rip_pkt + sizeof(struct rip_hdr));
        entry->addr_family = 0;    // AF = 0 for all routes
        entry->route_tag = 0;    // no route tag
        entry->ip_dst = 0;
        entry->subnet_mask = 0;
        entry->next_hop = 0;
        entry->cost = htonl(RIP_COST_INFINITY);
    } else {

        for (int i = 0 ; i < (int)rip_cache_v4.size(); i++) {
            /* either a deleted entry, OR it is our default route, which we shouldn't advertise */
            struct rip_message_entry *entry = (struct rip_message_entry *)(rip_pkt + sizeof(struct rip_hdr) + 
                                                                            sizeof(rip_message_entry) * i);
            
            entry->addr_family = htons(RIP_ADDRESS_FAMILY);    // IPv4
            entry->route_tag = 0;    // no route tag
            entry->ip_dst = rip_cache_v4[i].ip_dst;
            entry->subnet_mask =  rip_cache_v4[i].subnet_mask;
            entry->next_hop = rip_cache_v4[i].next_hop;
            entry->cost = htonl(split_horizon_poisoned_reverse(rip_cache_v4[i].cost, rip_cache_v4[i].iface_idx, interface_idx));
        }
    }

    /* UDP header */
    struct udp_hdr *udp_hdr = (struct udp_hdr *)(pkt + sizeof(struct eth_hdr) + sizeof(struct ipv4_hdr));
    if (!udp_hdr) {
        perror("create_rip_broadcast: ");
        pthread_mutex_unlock(&rip_cache_mutex);
        return -1;
    }
    udp_hdr->src_port = htons(UDP_PORT_RIP);
    udp_hdr->dst_port = htons(UDP_PORT_RIP);
    udp_hdr->len = htons(rip_pkt_len + sizeof(struct udp_hdr));
    uint32_t ipv4_dst_addr = RIP_MULTICAST_ADDR;    // broadcast
    udp_hdr->cksum = 0;
    udp_hdr->cksum = udp_cksum((uint16_t *)udp_hdr, (uint16_t*)rip_pkt,  
                                (uint16_t*)&interfaces[interface_idx].ipv4_addr, (uint16_t*)&ipv4_dst_addr, 
                                (uint16_t)(rip_pkt_len + sizeof(struct udp_hdr)));

    /* IPv4 header */
    struct ipv4_hdr *_ipv4_hdr = (struct ipv4_hdr *)(pkt + sizeof(struct eth_hdr));
    if (!_ipv4_hdr) {
        perror("create_rip_broadcast: ");
        pthread_mutex_unlock(&rip_cache_mutex);
        return -1;
    }
    _ipv4_hdr->version_ihl = 0x45;                                          // IPv4, header length = 5 * 4 = 20 bytes
    _ipv4_hdr->type_of_service = 0;                                         // no ToS
    _ipv4_hdr->total_len = htons(total_pkt_len - sizeof(struct eth_hdr));   // Total length = IPv4 header + UDP datagram + RIP packet
    _ipv4_hdr->time_to_live = 1;                                            // TTL = 1 for RIP broadcasts as we only have to send to neighbors                                 
    _ipv4_hdr->next_proto_id = IPPROTO_UDP;                                 // UDP 
    memcpy(&_ipv4_hdr->src_addr, &interfaces[interface_idx].ipv4_addr, 4); 
    memcpy(&_ipv4_hdr->dst_addr, (uint8_t*)&ipv4_dst_addr, 4);              
    _ipv4_hdr->frame_ident = htons(0x2222);                                 // ID can be whatever
    _ipv4_hdr->fragment_offset = 0;                                         // no fragmentation
    _ipv4_hdr->hdr_checksum = 0;                                            // checksum is set to 0 before calculating it
    // checksum is cinterface_idxomputed over ONLY the header as per RFC 791
    _ipv4_hdr->hdr_checksum = in_cksum((unsigned short *)_ipv4_hdr, sizeof(struct ipv4_hdr), 0);
        
    /* Ethernet header */
    struct eth_hdr *_eth_hdr = (struct eth_hdr *)(pkt);
    if (!_eth_hdr) {
        perror("create_rip_broadcast: ");
        pthread_mutex_unlock(&rip_cache_mutex);
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

    pthread_mutex_unlock(&rip_cache_mutex);
    return total_pkt_len;
}

void* loop_rip_broadcast(void* _interface_idx) {
    int interface_idx = *(int*)_interface_idx;
    if (default_route_idx != -1 && interface_idx == default_route_idx) {
        fprintf(stderr, "[!] RIP broadcast thread for interface %d is the default route. ABORTING!!!\n", interface_idx);
        pthread_exit(NULL);
    }
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

    /* when we first go online, broadcast a request for the whole routing table from each host*/
    int pkt_len = create_rip_broadcast_pkt(mac_addr, ipv4_src_addr, interface_idx, 1);
    if (pkt_len <= 0) {
        fprintf(stderr, "[!] Failed to create RIP broadcast packet for interface %d...!!!\n", interface_idx);
        pthread_exit(&pkt_len);
    } else { 
        ret = write_pcap(interface_idx); 
        if (ret < 0) {
            fprintf(stderr, "[!] Failed to write RIP broadcast packet for interface %d...!!!\n", interface_idx);
            pthread_exit(&ret);
        } else {
            if (debug) {
                printf("[+] RIP broadcast thread: Wrote RIP broadcast packet of length %d to interface %d - ", pkt_len, interface_idx);
                print_addr_4((uint8_t*)&interfaces[interface_idx].ipv4_addr);
                puts("");
            }
        }
    }

    while (1) {
        sleep(SLEEP_TIME_RIP);
        if (debug) printf("RIP broadcast thread %d: broadcasting RIP request to all neighbors...\n", interface_idx);
        int pkt_len = create_rip_broadcast_pkt(mac_addr, ipv4_src_addr, interface_idx, 0);
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
                printf("[+] RIP broadcast thread: Wrote RIP broadcast packet of length %d to interface %d - ", pkt_len, interface_idx);
                print_addr_4((uint8_t*)&interfaces[interface_idx].ipv4_addr);
                puts("");
            }
        }
        
    }
}

/* 
 * Broadcast RIP requests to all interfaces every 30s.
 * This function should ONLY be called form the main thread, AFTER setting up ALL the interface threads.
 * That is, call it after all calls to the `setup` function in `main.cc`.
 * For each interface, it will spawn a thread for rip_broadcast(interface_idx), which will
 * broadcast RIP requests every 30s to that particular interface.
 */
void create_rip_threads() {
    pthread_t *rip_thread = (pthread_t*)malloc(sizeof(pthread_t) * num_interfaces);
    int *rip_thread_idx = (int*)malloc(sizeof(int) * num_interfaces);
    int ret;
    for (int i = 0 ; i < num_interfaces; i++) {
        rip_thread_idx[i] = i;
        ret = pthread_create(rip_thread + i, NULL, &loop_rip_broadcast, (void*)&rip_thread_idx[i]);
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


/*
 * different from `create_rip_broadcast_pkt` in that it only creates the RIP packet portion,
 * not the entire network packet to be sent.
 * This also creates a response/reply packet (command = 2) instead of request.
 * Use split hroizon poison reverse: set the cost of the an outgoing entry to RIP_COST_INFINITY  
 * if the interface that advertised this route to us is the same interface that we're sending the packet to.
 * See RFC: https://datatracker.ietf.org/doc/html/rfc2453#section-3.4.3
 * 
 * Write the address of the RIP packet to the the `dst` pointer and return the length of the packet.
 */
int create_rip_broadcast_msg(unsigned char **dst, int interface_idx) {
    pthread_mutex_lock(&rip_cache_mutex);

    int pkt_len = sizeof(struct rip_hdr) + sizeof(struct rip_message_entry) * rip_cache_v4.size();
   
    unsigned char *rip_pkt = (unsigned char*)malloc(pkt_len);
    if (!rip_pkt) {
        perror("create_rip_broadcast: ");
        pthread_mutex_unlock(&rip_cache_mutex);
        return -1;
    }
    struct rip_hdr *hdr = (struct rip_hdr *)rip_pkt;
    hdr->command = 2;    // RIP reply
    hdr->version = 2;    // RIP v2
    hdr->zero = 0;

    for (int i = 0 ; i < (int)rip_cache_v4.size(); i++) {
        struct rip_message_entry *entry = (struct rip_message_entry *)(rip_pkt + sizeof(struct rip_hdr) + 
                                                                        sizeof(rip_message_entry) * i);
        
        entry->addr_family = htons(RIP_ADDRESS_FAMILY);    // IPv4
        entry->route_tag = 0;    // no route tag
        entry->ip_dst = rip_cache_v4[i].ip_dst;
        entry->subnet_mask =  rip_cache_v4[i].subnet_mask;
        entry->next_hop = rip_cache_v4[i].next_hop;
        entry->cost = htonl(split_horizon_poisoned_reverse(rip_cache_v4[i].cost, rip_cache_v4[i].iface_idx, interface_idx));
    }
    pthread_mutex_unlock(&rip_cache_mutex);
    *dst = rip_pkt;
    return pkt_len;
}

void signal_update() {

}

/* Caller are reponsible for locknig mutexes!!! */
void delete_rip_cache_entry(int idx) {
    rip_cache_v4[idx].state = RIP_CACHE_ETNRY_STATE_DELETED;
    rip_cache_v4[idx].flag = 0;
    rip_cache_v4[idx].timer = time(NULL);
}

/*
 * Process an incoming (received) RIP packet and write the RIP reply packet to iov[iov_idx].
 * 
 */
int process_rip(unsigned char *incoming_rip_packet, uint32_t ipv4_src_addr, int pkt_len, int iov_idx) {
    struct rip_hdr *hdr = (struct rip_hdr *)incoming_rip_packet;
    if (debug) print_rip(incoming_rip_packet, pkt_len);

    if (hdr->version != 2) {
        fprintf(stderr, "[!] INVALID RIP VERSION: %d\n", hdr->version);
        return -1;
    }

    if (hdr->zero != 0) {
        fprintf(stderr, "[!] INVALID RIP ZERO: %d\n", ntohs(hdr->zero));
        return -1;
    }

    /* As per the RFC, make sure it is from one of our interfaces (from a directly-connected network)*/
    int from_interface_idx = -1;
    for (int i = 0 ; i < num_interfaces; i++) {
        if ((interfaces[i].ipv4_addr & interfaces[i].subnet_mask) == (ipv4_src_addr & interfaces[i].subnet_mask)) {
            if (debug) {
                printf("[*] Received RIP packet from interface ");
                print_addr_4((uint8_t*)&interfaces[i].ipv4_addr);
                puts("");
            }
            from_interface_idx = i;
            break;
        }
    }
    if (from_interface_idx == -1) {
        fprintf(stderr, "[!] RIP packet is not from one of our interfaces. Ignoring...\n");
        return 0;
    }
    //int reply_interface_idx = get_interface_for_route(ipv4_src_addr);
    if (hdr->command == 1) {    // RIP request
    
        /* construct a RIP reply packet by replacing the cost of each entry with the one in our RIP table
         * see RFC: https://datatracker.ietf.org/doc/html/rfc2453#section-3.9.1
         */
        unsigned char *reply_rip_pkt = (unsigned char*)malloc(pkt_len);
        if (!reply_rip_pkt) {
            perror("process_rip: malloc:");
            return -1;
        }
        memcpy(reply_rip_pkt, incoming_rip_packet, pkt_len); /* we can reuse most info from the input packet */
        hdr = (struct rip_hdr *)reply_rip_pkt;
        hdr->command = 2;   /* RIP repy */
        int num_entries = (pkt_len - sizeof(struct rip_hdr)) / sizeof(struct rip_message_entry);
        if (num_entries == 0) return -1;

        /* `ret` is the length of the rip packet at iov[iov_idx]
         * since it could a broadcast respose, instead of a 1-to-1 mapping,
         * it might have different length from the request.  */
        int ret = pkt_len;
        for (int i = 0 ; i < num_entries; i++) {
            struct rip_message_entry *request_rip_entry = (struct rip_message_entry*)(incoming_rip_packet + sizeof(struct rip_hdr) 
                                                                            + sizeof(struct rip_message_entry) * i);
            struct rip_message_entry *reply_rip_entry = (struct rip_message_entry*)(reply_rip_pkt + sizeof(struct rip_hdr) 
                                                                            + sizeof(struct rip_message_entry) * i);
            uint32_t request_entry_ip_dst = request_rip_entry->ip_dst;
            uint32_t request_entry_subnet_mask = request_rip_entry->subnet_mask;

            /* special case, asking for the entire routing table */
            if (request_rip_entry->addr_family == 0 && num_entries == 1) { 
                if (debug) {
                    printf("[*] Received RIP request for entire routing table from interface %d - \n", thread_interface_idx);
                    print_addr_4((uint8_t*)&interfaces[thread_interface_idx].ipv4_addr);
                    puts("");
                }
                /* `create_rip_broadcast_msg` will create a packet. so free this one */
                free(reply_rip_pkt);
                /* since it's a broadcast respose, it will have different length from the request */
                ret = create_rip_broadcast_msg(&reply_rip_pkt, thread_interface_idx);
                if (ret <= 0) {
                    fprintf(stderr, "[!] Failed to create RIP reply packet for interface %d...!!!\n", thread_interface_idx);
                    return ret;
                }
                break;
            }
            
            reply_rip_entry->cost = RIP_COST_INFINITY;    // default cost is infinity
            pthread_mutex_lock(&rip_cache_mutex);
            for (int j = 0 ; j < (int)rip_cache_v4.size(); j++) {
                if ((rip_cache_v4[j].ip_dst & rip_cache_v4[j].subnet_mask) == (request_entry_ip_dst & request_entry_subnet_mask)) {
                    reply_rip_entry->cost = split_horizon_poisoned_reverse(rip_cache_v4[j].cost, rip_cache_v4[j].iface_idx, thread_interface_idx);
                    break;
                }
            }
            pthread_mutex_unlock(&rip_cache_mutex);
            reply_rip_entry->cost = htonl(reply_rip_entry->cost);
        }

        if (debug > 2) {
            printf("[+] Created RIP reply packet: \n");
            if (debug > 1) print_rip(reply_rip_pkt, ret);
        }
        iov[iov_idx].iov_base = reply_rip_pkt;
        iov[iov_idx].iov_len = ret;
        iov_cnt++;
        return ret;

    } else if (hdr->command == 2) {     // RIP Response/Reply
        int num_entries = (pkt_len - sizeof(struct rip_hdr)) / sizeof(struct rip_message_entry);
        if (num_entries == 0) return -1;

        if (debug) {
            printf("[*] Received RIP response from interface %d - ", thread_interface_idx);
            print_addr_4((uint8_t*)&interfaces[thread_interface_idx].ipv4_addr);
            puts("");
        }
        
        pthread_mutex_lock(&rip_cache_mutex);
        for (int i = 0 ; i < num_entries; i++) {
            struct rip_message_entry *reply_rip_entry = (struct rip_message_entry*)(incoming_rip_packet + sizeof(struct rip_hdr) 
                                                        + sizeof(struct rip_message_entry) * i);
            uint32_t reply_entry_ip_dst = reply_rip_entry->ip_dst;
            uint32_t reply_entry_subnet_mask = reply_rip_entry->subnet_mask;
            uint32_t reply_entry_cost = ntohl(reply_rip_entry->cost);
            if (reply_entry_cost < 1 || reply_entry_cost > RIP_COST_INFINITY) {
                    if (debug > 1) {
                        printf("[!] Ignoring invalid RIP entry %d: ", i);
                        print_rip_entry(reply_rip_entry);
                    }
                    continue;
            }
            
            reply_entry_cost = std::min(reply_entry_cost + rip_cache_v4[thread_interface_idx].cost, (uint32_t)RIP_COST_INFINITY);
            int existed = 0; /* 0 if entry is not currently in our cache */
            for (size_t j = 0  ; j < rip_cache_v4.size(); j++) {
                if ((reply_entry_ip_dst & reply_entry_subnet_mask) == (rip_cache_v4[j].ip_dst & rip_cache_v4[j].subnet_mask)) {
                    /* if the entry is for one of our directly-connected network, do nothing */
                    if (rip_cache_v4[j].is_directly_connected) {
                        existed = 1;
                        break;
                    }

                    if (rip_cache_v4[j].next_hop == ipv4_src_addr) {
                        /* case same hop */
                        rip_cache_v4[j].timer = time(NULL);
                        existed = 1;
                        /* this route costs INFINITY, delete it */
                        if (reply_entry_cost == RIP_COST_INFINITY) {
                            if (rip_cache_v4[j].state != RIP_CACHE_ETNRY_STATE_DELETED) {
                                rip_cache_v4[j].state = RIP_CACHE_ETNRY_STATE_DELETED;
                                rip_cache_v4[j].cost = RIP_COST_INFINITY;
                                if (debug > 1) {
                                    printf("[!] Marked cache entry for deletion %ld: ", j);
                                }
                                delete_rip_cache_entry(j);
                                signal_update();
                            }
                        }
                        else if (reply_entry_cost != rip_cache_v4[j].cost) {
                            rip_cache_v4[j].cost = reply_entry_cost;
                            rip_cache_v4[j].advertiser = ipv4_src_addr;
                            rip_cache_v4[j].flag = ROUTE_CHANGE_FLAG;
                            rip_cache_v4[j].timer = time(NULL);
                            rip_cache_v4[j].iface_idx = thread_interface_idx;
                            rip_cache_v4[j].is_directly_connected = 0;
                            /* only set this entry as the default interface if we don't have a default interface 
                             * (which shoud be directly connected and checked at the beginning of this loop)
                             * but we were advertised about one by this entry (another router)
                             */
                            if (reply_entry_ip_dst == 0 && reply_entry_subnet_mask == 0) {
                                rip_cache_v4[j].is_default_route = 1;
                                default_route_idx = j;
                            } else {
                                rip_cache_v4[j].is_default_route = 0;
                            }
                            
                            if (debug > 1) {
                                printf("[*] Updated RIP entry %d: ", i);
                                print_rip_cache();
                            }
                            signal_update();
                        } else {
                            rip_cache_v4[j].timer = time(NULL);
                        }
                    } else {
                        /* case different hop and it has lower cost */
                        if (reply_entry_cost < rip_cache_v4[j].cost) {
                            rip_cache_v4[j].cost = reply_entry_cost;
                            rip_cache_v4[j].next_hop = ipv4_src_addr;
                            rip_cache_v4[j].advertiser = ipv4_src_addr;
                            rip_cache_v4[j].flag = ROUTE_CHANGE_FLAG;
                            rip_cache_v4[j].timer = time(NULL);
                            rip_cache_v4[j].iface_idx = thread_interface_idx;
                            rip_cache_v4[j].is_directly_connected = 0;
                            /* only set this entry as the default interface if we don't have a default interface 
                             * (which shoud be directly connected and checked at the beginning of this loop)
                             * but we were advertised about one by this entry (another router)
                             */
                            if (reply_entry_ip_dst == 0 && reply_entry_subnet_mask == 0) {
                                rip_cache_v4[j].is_default_route = 1;
                                default_route_idx = j;
                            } else {
                                rip_cache_v4[j].is_default_route = 0;
                            }
                            if (debug > 1) {
                                printf("[*] Updated RIP entry %d: ", i);
                                print_rip_cache();
                            }
                            signal_update();
                        }
                    }
                    
                   
                    existed = 1;
                    break;
                }
            }  

            if (!existed) {
                if (reply_entry_cost == RIP_COST_INFINITY) {
                    if (debug > 1) {
                        printf("[!] Not adding RIP entry %d with cost = RIP_COST_INFINITY: ", i);
                    }
                    continue;
                }
                rip_cache_v4.pb(rip_cache_entry {
                    .addr_family = RIP_ADDRESS_FAMILY,
                    .route_tag = ntohs(reply_rip_entry->route_tag),
                    .ip_dst = reply_entry_ip_dst,
                    .subnet_mask = reply_entry_subnet_mask,
                    .next_hop = ipv4_src_addr,
                    .cost = reply_entry_cost,

                    .flag = ROUTE_CHANGE_FLAG,
                    .timer = time(NULL),
                    .iface_idx = thread_interface_idx,
                    .is_directly_connected = 0,
                    .is_default_route = 0,
                    .advertiser = ipv4_src_addr,
                    .state = RIP_CACHE_ENTRY_STATE_ACTIVE
                });
                /* only set this entry as the default interface if we don't have a default interface 
                * (which shoud be directly connected and checked at the beginning of this loop)
                * but we were advertised about one by this entry (another router)
                */
                if (reply_entry_ip_dst == 0 && reply_entry_subnet_mask == 0) {
                    rip_cache_v4[rip_cache_v4.size() - 1].is_default_route = 1;
                    default_route_idx = rip_cache_v4.size() - 1;
                } else {
                    rip_cache_v4[rip_cache_v4.size() - 1].is_default_route = 0;
                }
                if (debug > 1) {
                    printf("[*] Added new RIP entry %d: ", i);
                    print_rip_cache();
                }
                signal_update();
            }
        }
        pthread_mutex_unlock(&rip_cache_mutex);
    }
    return -1;
}
